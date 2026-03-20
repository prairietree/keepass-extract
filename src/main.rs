use clap::Parser;
use keepass::{
    db::{Database, Group},
    DatabaseKey,
};

use std::fs::{self, File, OpenOptions};
use std::path::PathBuf;
use std::process::exit;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Parser)]
#[command(
    name = "KeePass Field Exporter",
    about = "A tool to extract specific fields or dump all field data from a KeePass database.",
    after_help = "EXAMPLES:\n\
                    List all entries:\n    kp_tool -d db.kdbx\n\n\
                    List fields for an entry:\n    kp_tool -d db.kdbx -e 'Gmail'\n\n\
                    Print a specific password:\n    kp_tool -d db.kdbx -e 'Gmail' -f 'Password'\n\n\
                    Export all fields to a folder:\n    kp_tool -d db.kdbx -e 'Gmail' -o ./gmail_secrets"
)]

struct Args {
    /// Path to the .kdbx database file
    #[arg(short, long)]
    database: Option<PathBuf>,

    /// Name of the entry to search for
    #[arg(short, long)]
    entry: Option<String>,

    /// Specific field to extract (e.g., 'Password', 'UserName', or custom fields)
    #[arg(short, long)]
    field: Option<String>,

    /// Output folder; creates one file per field with 600 permissions
    #[arg(short = 'o', long)]
    folder: Option<PathBuf>,

    /// Path to a KeePass key file (if required)
    #[arg(short, long)]
    key_file: Option<PathBuf>,

    /// Path to a file containing the database password
    #[arg(short, long)]
    pw_file: Option<PathBuf>,
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
    let args = Args::parse();

    let db_path = args.database.unwrap_or_else(|| exit(50));
    if !db_path.exists() { exit(51); }

    let password = if let Some(pw_file) = args.pw_file {
        fs::read_to_string(pw_file).expect("Failed to read password file").trim().to_string()
    } else {
        rpassword::prompt_password("Enter KeePass password: ").unwrap()
    };

    let mut key = DatabaseKey::new().with_password(&password);
    if let Some(kf) = args.key_file {
        let mut kf_file = File::open(kf).expect("Failed to open key file");
        key = key.with_keyfile(&mut kf_file).expect("Invalid key file");
    }

    let mut db_file = File::open(&db_path).unwrap();
    let db = Database::open(&mut db_file, key).expect("Failed to decrypt database");

    let all_entries = collect_all_entries(&db.root);

    let target_name = match args.entry {
        None => {
            for e in &all_entries {
                println!("{}", e.get_title().unwrap_or("(No Title)"));
            }
            exit(60);
        }
        Some(ref name) => name.clone(),
    };

    // Find matches
    let matches: Vec<&keepass::db::Entry> = all_entries.into_iter()
        .filter(|e| e.get_title() == Some(&target_name))
        .collect();

    if matches.is_empty() {
        exit(61); // 61: Entry not found
    }

    // matches[0] is the first &Entry
    let entry = matches[0];
    let has_duplicates = matches.len() > 1;

    // Prepare export data based on whether a specific field was requested.
    let export_data: Vec<(String, String)> = if let Some(field_name) = &args.field {
        // Case: Specific field requested. If not found, exit(71).
        let value = entry.get(field_name)
            .map(|v| v.to_string())
            .unwrap_or_else(|| exit(71));
        vec![(field_name.clone(), value)]
    } else {
        // Case: No specific field requested, export all fields. This is a Vec of (field_name, value).
        entry.fields
            .iter()
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
                println!("{}", name);
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
