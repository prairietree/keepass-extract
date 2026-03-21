use predicates::prelude::*;
use assert_cmd::Command;

#[test]
fn test_missing_database_argument_exit_code() {
    let mut cmd = Command::cargo_bin("keepass-extract").unwrap();
    
    // Verifies exit code 50 AND empty stdout
    cmd.assert()
        .failure()
        .code(2)
        .stdout("")
        .stderr(predicate::str::contains("required arguments were not provided")); 
 
}

#[test]
fn test_database_file_not_found_exit_code() {
    let mut cmd = Command::cargo_bin("keepass-extract").unwrap();
    
    cmd.args(["--database", "/tmp/non_existent_file_12345.kdbx", "--entry", "any-entry"])
        .assert()
        .failure()
        .code(51)
        .stdout("");
}
