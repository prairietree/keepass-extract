use assert_cmd::Command;
use predicates::prelude::*;

const DB_PATH: &str = "tests/files/testkf.kdbx";
const KEY_PATH: &str = "tests/files/keyfile";
const PASS: &str = "test123\n";

#[test]
fn test_02_no_entry_specified() {
    let mut cmd = Command::cargo_bin("keepass-extract").unwrap();
    cmd.args(["--database", DB_PATH, "--key-file", KEY_PATH])
        .write_stdin(PASS)
        .assert()
        .failure()
        .code(1)
        .stdout("")
        .stderr(predicate::str::contains("Required options not provided:"))
        .stderr(predicate::str::contains("--entry")); 
}

#[test]
fn test_61_entry_not_found() {
    let mut cmd = Command::cargo_bin("keepass-extract").unwrap();
    cmd.args([
        "--database", DB_PATH, 
        "--key-file", KEY_PATH, 
        "--entry", "non-existent-entry-name"
    ])
    .write_stdin(PASS)
    .assert()
    .failure()
    .code(61)
    .stdout(""); 
}

// Since no field or output directory is specified, the default behavior is to print all fields of the first matching entry to stderr and exit with code 62.
#[test]
fn test_62_multiple_entries_found() {
    let mut cmd = Command::cargo_bin("keepass-extract").unwrap();
    cmd.args([
        "--database", DB_PATH, 
        "--key-file", KEY_PATH, 
        "--entry", "same_name",
    ])
    .write_stdin(PASS)
    .assert()
    .failure()
    .code(62)
    .stdout("")
    .stderr(predicate::str::contains("UserName")); 
}

#[test]
fn test_success_entry_found_and_printed() {
    let mut cmd = Command::cargo_bin("keepass-extract").unwrap();
    cmd.args([
        "--database", DB_PATH, 
        "--key-file", KEY_PATH, 
        "--entry", "test-extract"
    ])
    .write_stdin(PASS)
    .assert()
    .success()
    .code(0)
    // Matching the fields from your sample run
    .stderr(predicate::str::contains("my-file.txt"))
    .stderr(predicate::str::contains(".db_password.conf"))
    .stderr(predicate::str::contains(".env"));
}
