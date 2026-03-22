use argh::FromArgs;
use std::fs::{self, File, OpenOptions};
use std::path::PathBuf;
use std::process::exit;
use std::path::Path;
use std::io::{self, IsTerminal};

use keepass::{
    db::{Database, Group},
    DatabaseKey,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

// Define the default fields to exclude as a static array
const DEFAULT_FIELDS: &[&str] = &[
    "Title", "UserName", "Password", "URL", "Notes", "UUID", "TOTP", "Tags", "Uuid"
];

#[derive(FromArgs)]
/// A tool to extract specific fields or dump all field data from a KeePass database.
struct Args {
    /// path to the .kdbx database file
    #[argh(option, short = 'd')]
    database: PathBuf,

    /// name of the entry to search for
    #[argh(option, short = 'e')]
    entry: String,

    /// specific field to extract (e.g., 'Password', 'UserName')
    #[argh(option, short = 'f')]
    field: Option<String>,

    /// output folder; creates one file per field in provided entry
    #[argh(option, short = 'o')]
    folder: Option<PathBuf>,

    /// path to a KeePass key file (if required)
    #[argh(option, short = 'k')]
    key_file: Option<PathBuf>,

    /// path to a file containing the database password
    #[argh(option, short = 'p')]
    pw_file: Option<PathBuf>,

    /// if set, filters out default fields (Title, Password, etc.)
    #[argh(switch, short = 'x')]
    exclude_defaults: bool,
}

// Recursive helper to flatten all entries into one list
fn collect_all_entries(group: &Group) -> Vec<&keepass::db::Entry> {
    let mut entries: Vec<&keepass::db::Entry> = Vec::new();
    
    // Add entries in this group
    for entry in &group.entries {
        entries.push(entry);
    }
    
    // Recurse into sub-groups
    for sub_group in &group.groups {
        entries.extend(collect_all_entries(sub_group));
    }
    
    entries
}

fn main() {
    let args: Args = argh::from_env();

    // Check if database file exists.
    let db_path = args.database;
    if !db_path.exists() {
        eprintln!("Error: Database file not found at {:?}", db_path);
        exit(51);
    }

    // Read password from file or prompt.
    let password = if let Some(pw_file) = args.pw_file {
        fs::read_to_string(pw_file).expect("Failed to read password file").trim().to_string()
    }  else if io::stdin().is_terminal() {
        // If stdin is a terminal then prompt for the password.
        rpassword::prompt_password("Enter KeePass password: ").expect("Failed to read password")
    } else {
        // This is for your unit test and scripts. Ex: keepass-extract --database db.kdbx --entry "Gmail" <<< "$PASS"
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read line");
        input.trim_end_matches(['\r', '\n']).to_string()
    };

    // Build the database key, adding the key file if provided.
    let mut key = DatabaseKey::new().with_password(&password);
    if let Some(kf) = args.key_file {
        let mut kf_file = File::open(kf).expect("Failed to open key file");
        key = key.with_keyfile(&mut kf_file).expect("Invalid key file");
    }

    // Open and decrypt the database.
    let mut db_file = File::open(&db_path).unwrap();
    let db = Database::open(&mut db_file, key).expect("Failed to decrypt database");

    // Collect all entries in the database into a flat list for searching.
    let all_entries = collect_all_entries(&db.root);

    // Find the entry requested by the user.
    let matches: Vec<&keepass::db::Entry> = all_entries
        .iter()
        .filter(|e| e.get_title() == Some(&args.entry))
        .copied()
        .collect();

    // Handle no entry matches found.
    if matches.is_empty() {
        eprintln!("Error: Entry '{}' not found in database.", args.entry);
        eprintln!("\nAvailable entries (showing first 25):");
        
        for e in all_entries.iter().take(25) {
            eprintln!(" - {}", e.get_title().unwrap_or("(No Title)"));
        }
        
        exit(61);
    }

    // If we have matches, we'll export the first one. If there are multiple matches, we'll still export the first but exit with code 62 at the end.
    let entry = matches[0];
    let has_duplicates = matches.len() > 1;

    // Prepare export data based on whether a specific field was requested.
    let export_data: Vec<(String, String)> = if let Some(field_name) = &args.field {
        // Case: Specific field requested. If not found, exit(71).
        let value = entry.get(field_name)
            .map(|v| v.to_string())
            .unwrap_or_else(|| {
                eprintln!("Error: Field '{}' not found in entry '{}'.", field_name, args.entry);
                exit(71);
            });
        vec![(field_name.clone(), value)]
    } else {
        // Case: No specific field requested, export all fields except those matching the exclude regex (if provided).
        // Compile regex only if a string is provided; otherwise, allow all fields.
        entry.fields
            .iter()
            .filter(|(k, _)| {
                if args.exclude_defaults {
                    !DEFAULT_FIELDS.iter().any(|&default| k.eq_ignore_ascii_case(default))
                } else {
                    true
                }
            })
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect()
    };

    // Export to files if --folder is specified, otherwise print to stdout.
    if let Some(folder) = &args.folder {
        export_fields_to_files(&export_data, folder).expect("Failed to export files");
    } else {
        if args.field.is_some() {
            // If a specific --field was requested, print the value
            for (_, value) in &export_data {
                println!("{}", value);
            }
        } else {
            // If no --field was requested, print the list of field names
            for (name, _) in &export_data {
                eprintln!("{}", name);
            }
        }
    }

    if has_duplicates {
        exit(62);
    }
}

/// Sanitizes a string to be used as a safe filename.
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '/' | '\\' | '\0' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => c,
        })
        .collect::<String>()
        .to_string()
}

/// Creates files from key-value pairs in a target folder with 600 permissions.
fn export_fields_to_files<K, V>(fields: &[(K, V)], target_dir: &Path) -> std::io::Result<()> 
where 
    K: AsRef<str>, 
    V: AsRef<str> 
{
    // 1. Create the folder if it doesn't exist
    fs::create_dir_all(target_dir)?;

    for (key, value) in fields {
        let key_str = key.as_ref();
        let value_str = value.as_ref();
        
        let safe_name = sanitize_filename(key_str);
        let file_path = target_dir.join(safe_name);

        // 2. Open with Create + Write + Truncate (this is the "overwrite" logic)
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true) 
            .open(&file_path)?;

        // 3. Set permissions to 600 BEFORE writing if on Linux
        // This ensures the data is never sitting in a world-readable file
        #[cfg(unix)]
        {
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o600);
            file.set_permissions(perms)?;
        }

        // 4. Write the content (preserves all newlines)
        fs::write(&file_path, value_str)?;
    }

    Ok(())
}
