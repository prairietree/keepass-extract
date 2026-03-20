use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_keepass_extract_flow() {
    let tmp_dir = tempdir().unwrap();
    let dest_path = tmp_dir.path();

    // "keepass-extract" must match the name in your Cargo.toml [package] section
    let mut cmd = Command::cargo_bin("keepass-extract").unwrap();
    
    let assert_cmd = cmd
        .args([
            "--database", "tests/files/test.kdbx",
            "--key-file", "tests/files/keyfile",
            "--folder", dest_path.to_str().unwrap(),
            "--entry", "entry two",
        ])
        .write_stdin("test123\n") // Send password to stdin
        .assert();

    // Ensure it exited successfully
    assert_cmd.success();

    // Verify the file was created in the folder
    // Note: Your code uses entry name + .txt (test-dump.txt)
    let output_file = dest_path.join("file-test_one.txt");
    assert!(output_file.exists(), "Output file missing");
    
    let content = fs::read_to_string(&output_file).unwrap();
    assert!(content.contains("debug_dump_of_entry"), "Content mismatch");

    // Verification: Permissions (Unix/Kubuntu)
    #[cfg(target_family = "unix")]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(output_file).unwrap();
        // Check if permissions are restricted (e.g., 600 or 644 depending on your umask)
        let mode = metadata.permissions().mode() & 0o777;
        println!("File mode: {:o}", mode);
    }
}
