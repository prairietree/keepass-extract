# KeePass Field Exporter

A command-line utility written in Rust for extracting data from KeePass (.kdbx) databases. It allows you to list entries, view specific fields, or export all fields (including custom ones) into individual files with secure Linux permissions (600).

## Features

- **Recursive Search**: Finds entries regardless of which group/folder they are in.
- **Custom Field Support**: Automatically detects and extracts user-defined custom fields.
- **Secure Export**: When exporting to a folder, files are created with `600` permissions (read/write for owner only) on Linux systems.
- **Flexible Authentication**: Supports both master passwords (interactive or via file) and key files.
- **Sanitized Output**: Automatically cleans field names to ensure they are safe for use as filenames.

## Installation

Ensure you have [Rust and Cargo](https://rustup.rs) installed.

```bash
git clone <your-repo-url>
cd keepass-field-exporter
cargo build --release
```

# Exit codes

## Database & Argument Errors

-  2: Missing required argument.
- 51: File Not Found. The specified database file was not found.

## Entry Lookup Errors

- 61: Entry Not Found. The entry name provided via --entry was not found in the database.
- 62: Multiple entries with the exact same name were found. The first match will be returned.

## Field Errors

- 71: Field Not Found. The field requested via --field does not exist within the selected entry. Nothing will be returned.