use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const DB_PATH: &str = "tests/files/testpw.kdbx";
const KEY_PATH: &str = "tests/files/testkf.key"; // Added if needed for consistency
const PASS: &str = "test123\n";

#[test]
fn test_default_regex_filters_standard_fields() {
    let tmp_dir = tempdir().unwrap();
    let dest = tmp_dir.path();
    
    let mut cmd = Command::cargo_bin("keepass-extract").unwrap();
    cmd.args([
        "--database", DB_PATH, 
        "--entry", "test-extract",
        "--folder", dest.to_str().unwrap(),
        // No --exclude passed: uses default filter
    ])
    .write_stdin(PASS)
    .assert()
    .success();

    // Default filter should EXCLUDE these
    assert!(!dest.join("UserName").exists(), "UserName should have been filtered out");
    assert!(!dest.join("Password").exists(), "Password should have been filtered out");
    assert!(!dest.join("Title").exists(), "Title should have been filtered out");

    // Default filter should INCLUDE these
    assert!(dest.join(".env").exists(), "Custom field .env should be present");
    assert!(dest.join("my-file.txt").exists(), "Custom field my-file.txt should be present");
}

#[test]
fn test_empty_regex_includes_all_fields() {
    let tmp_dir = tempdir().unwrap();
    let dest = tmp_dir.path();
    
    let mut cmd = Command::cargo_bin("keepass-extract").unwrap();
    cmd.args([
        "--database", DB_PATH, 
        "--entry", "test-extract",
        "--folder", dest.to_str().unwrap(),
        "--exclude", "" // Empty string disables the filter
    ])
    .write_stdin(PASS)
    .assert()
    .success();

    // All fields should now exist
    assert!(dest.join("UserName").exists());
    assert!(dest.join("Title").exists());
    assert!(dest.join(".env").exists());
}

#[test]
fn test_custom_regex_filter() {
    let tmp_dir = tempdir().unwrap();
    let dest = tmp_dir.path();
    
    let mut cmd = Command::cargo_bin("keepass-extract").unwrap();
    cmd.args([
        "--database", DB_PATH, 
        "--entry", "test-extract",
        "--folder", dest.to_str().unwrap(),
        "--exclude", r"^\.env$" // Filter out ONLY the .env field
    ])
    .write_stdin(PASS)
    .assert()
    .success();

    // .env should be missing
    assert!(!dest.join(".env").exists(), ".env should be filtered by custom regex");
    
    // Everything else should be present (including standard fields since we replaced the default)
    assert!(dest.join("UserName").exists(), "UserName should be present (not in custom regex)");
    assert!(dest.join("my-file.txt").exists());
}
