use assert_cmd::Command;
use predicates::prelude::*;

const DB_PATH: &str = "tests/files/testpw.kdbx";
const PASS: &str = "test123\n";

#[test]
fn test_71_field_not_found_exits_cleanly() {
    let mut cmd = Command::cargo_bin("keepass-extract").unwrap();
    
    // We search for a real entry ("test-extract") 
    // but ask for a field that definitely isn't there ("non-existent-field")
    cmd.args([
        "--database", DB_PATH, 
        "--entry", "test-extract",
        "--field", "non-existent-field"
    ])
    .write_stdin(PASS)
    .assert()
    .failure()
    .code(71)
    .stdout("")
    .stderr("Error: Field 'non-existent-field' not found in entry 'test-extract'.\n");
}

#[test]
fn test_success_specific_field_to_stdout() {
    let mut cmd = Command::cargo_bin("keepass-extract").unwrap();
    
    // Test that requesting a valid field prints ONLY the value to stdout
    // (and no field names to stderr)
    cmd.args([
        "--database", DB_PATH, 
        "--entry", "test-extract",
        "--field", "UserName" 
    ])
    .write_stdin(PASS)
    .assert()
    .success()
    .code(0)
    .stdout(predicate::str::contains("test-dump-user")) // Assuming this is the value
    .stderr(""); // Should be empty because we provided a specific field
}
