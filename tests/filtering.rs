use assert_cmd::Command;
use tempfile::tempdir;

const DB_PATH: &str = "tests/files/testpw.kdbx";
const PASS: &str = "test123\n";

#[test]
fn test_exclude_defaults_filters_standard_fields() {
    let tmp_dir = tempdir().unwrap();
    let dest = tmp_dir.path();
    
    let mut cmd = Command::cargo_bin("keepass-extract").unwrap();
    cmd.args([
        "--database", DB_PATH, 
        "--entry", "test-extract",
        "--folder", dest.to_str().unwrap(),
        "--exclude-defaults",
    ])
    .write_stdin(PASS)
    .assert()
    .success();

    // These should be EXCLUDED because the flag is set
    assert!(!dest.join("UserName").exists(), "UserName should have been filtered out");
    assert!(!dest.join("Password").exists(), "Password should have been filtered out");
    assert!(!dest.join("Title").exists(), "Title should have been filtered out");

    // Custom fields should still be INCLUDED
    assert!(dest.join(".env").exists(), "Custom field .env should be present");
    assert!(dest.join("my-file.txt").exists(), "Custom field my-file.txt should be present");
}

#[test]
fn test_no_filter_includes_all_fields() {
    let tmp_dir = tempdir().unwrap();
    let dest = tmp_dir.path();
    
    let mut cmd = Command::cargo_bin("keepass-extract").unwrap();
    cmd.args([
        "--database", DB_PATH, 
        "--entry", "test-extract",
        "--folder", dest.to_str().unwrap(),
        // Omitting --exclude-defaults means no filtering happens
    ])
    .write_stdin(PASS)
    .assert()
    .success();

    // All fields (standard and custom) should now exist
    assert!(dest.join("UserName").exists(), "Standard field UserName should be present");
    assert!(dest.join("Title").exists(), "Standard field Title should be present");
    assert!(dest.join(".env").exists(), "Custom field .env should be present");
}
