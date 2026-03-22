use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const DB_PATH: &str = "tests/files/testpw.kdbx";
const PASS: &str = "test123\n";

#[test]
fn test_61_entry_not_found_with_folder() {
    let tmp_dir = tempdir().unwrap();
    let mut cmd = Command::cargo_bin("keepass-extract").unwrap();
    
    cmd.args([
        "--database", DB_PATH, 
        "--entry", "non-existent-entry",
        "--folder", tmp_dir.path().to_str().unwrap()
    ])
    .write_stdin(PASS)
    .assert()
    .failure()
    .code(61)
    .stdout("") 
    // Updated: Entry suggestions now go to stderr, and password prompt is gone
    .stderr(predicate::str::contains("Error: Entry 'non-existent-entry' not found"))
    .stderr(predicate::str::contains("Available entries")); 

    let count = fs::read_dir(tmp_dir.path()).unwrap().count();
    assert_eq!(count, 0, "Folder should be empty on exit 61");
}

#[test]
fn test_62_duplicate_entry_exports_first_match() {
    let tmp_dir = tempdir().unwrap();
    let mut cmd = Command::cargo_bin("keepass-extract").unwrap();
    
    cmd.args([
        "--database", DB_PATH, 
        "--entry", "same_name",
        "--folder", tmp_dir.path().to_str().unwrap(),
    ])
    .write_stdin(PASS)
    .assert()
    .failure()
    .code(62);

    // Verify files were still created for the first match found
    let files: Vec<_> = fs::read_dir(tmp_dir.path()).unwrap().collect();
    assert!(!files.is_empty(), "No files exported for duplicate entry");
}

#[test]
fn test_success_export_and_file_content_checks() {
    let tmp_dir = tempdir().unwrap();
    let dest = tmp_dir.path();
    
    let mut cmd = Command::cargo_bin("keepass-extract").unwrap();
    cmd.args([
        "--database", DB_PATH, 
        "--entry", "test-extract",
        "--folder", dest.to_str().unwrap(),
    ])
    .write_stdin(PASS)
    .assert()
    .success()
    .code(0)
    .stdout("")
    .stderr(""); // Password prompt is suppressed via is_terminal check

    // 1. Verify custom fields exist (assuming these are in your test db)
    assert!(dest.join(".env").exists());
    assert!(dest.join(".db_password.conf").exists());

    // 2. Verify standard fields exist because we used --exclude ""
    assert!(dest.join("UserName").exists());
    assert!(dest.join("Title").exists());

    // 3. Permission Checks (Unix only)
    #[cfg(unix)]
    {
        for entry in fs::read_dir(dest).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::metadata(&path).unwrap();
            let mode = metadata.permissions().mode();
            
            // Mask with 0o777 to check 600 (rw-------)
            assert_eq!(
                mode & 0o777, 
                0o600, 
                "File {:?} does not have 600 permissions (actual: {:o})", 
                path, mode & 0o777
            );
        }
    }
}
