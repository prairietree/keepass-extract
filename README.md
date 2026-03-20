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
