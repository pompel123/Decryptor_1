# MFKeys Decrypt

Decrypts encrypted SubGhz keystore files on the Flipper Zero and writes the results to a text file. Supports both standard keystore files and RAW keystore files.

## What it does

- Reads all files from the app’s **keystore** folder
- Detects whether each file is a **standard** or **RAW** SubGhz keystore
- Decrypts them using the system keystore decryption (same as SubGhz)
- Writes all results into a single **decrypted_keys.txt** file

## Requirements

- Flipper Zero with **Momentum Firmware** (or firmware that provides the same SubGhz keystore APIs)
- **Your own** encrypted SubGhz keystore files — this app does not include any; you must copy the files you want to decrypt into the keystore folder yourself.

## Installation

1. Build the FAP or use a pre-built `.fap` from the project.
2. Copy the FAP to your Flipper, e.g.:
   - **SD card:** `qFlipper` → **SD Card** → `apps/Utilities/` (or any app folder you use)
   - Or place it in the same location as other external apps in your firmware layout.

## How to use

### 1. Put your keystore files in the keystore folder

This app does **not** ship with any keystore files. You need to use your own encrypted SubGhz keystore files (e.g. from your Flipper’s SubGhz app data or another source).

On the Flipper’s SD card, create the app data folder and copy your encrypted keystore files into **keystore**:

- **Path:** `apps_data/mfkeys_decrypt/keystore/`

Example (use your own filenames):

- `apps_data/mfkeys_decrypt/keystore/my_keystore`
- `apps_data/mfkeys_decrypt/keystore/another_file`

You can use any filenames; the app will process every file in that directory (non-directory entries).

### 2. Run the app

- Open **Applications** (or **Apps**) on the Flipper
- Run **MFKeys Decrypt** (under Utilities, or wherever you placed the FAP)
- The app will:
  - Open `apps_data/mfkeys_decrypt/keystore/`
  - Process each file (standard or RAW)
  - Write to `apps_data/mfkeys_decrypt/decrypted_keys.txt`

### 3. Get the results

- **Output file:** `apps_data/mfkeys_decrypt/decrypted_keys.txt`
- Copy it from the SD card via qFlipper (File Manager) or by mounting the SD card on your PC.

## Output format

### Header

The file starts with a short comment block describing the format.

### Standard keystore files

For each standard keystore file, the app writes:

- A comment line: `# File: <filename> (standard keystore)`
- One line per key: **`KEY:TYPE:NAME`**
  - **KEY:** 16‑digit hex key (e.g. `A1B2C3D4E5F60708`)
  - **TYPE:** numeric type
  - **NAME:** key name from the keystore

### RAW keystore files

For each RAW keystore file, the app writes:

- A comment line: `# File: <filename> (RAW keystore, N bytes)`
- A hex dump of the decrypted data (32 bytes per line, with offset)

RAW payloads larger than **480 bytes** are not decrypted; the app writes a comment instead.

### Unknown / failed files

- Unknown format: `# File: <filename> (unknown format, skipped)`
- Decrypt failure: `# (failed to decrypt)` or `# (failed to decrypt RAW data)` (or similar) near that file’s section.

## Supported file types

| Type        | Header / format                         | Output              |
|------------|-------------------------------------------|---------------------|
| Standard   | `Flipper SubGhz Keystore File` (v0)      | `KEY:TYPE:NAME`     |
| RAW        | `Flipper SubGhz Keystore RAW File` (v0)   | Hex dump (≤480 B)   |
| Other      | Anything else                             | Skipped (comment)   |

## Paths summary

| Purpose              | Path (on SD card)                          |
|----------------------|--------------------------------------------|
| Keystore input files | `apps_data/mfkeys_decrypt/keystore/`       |
| Decrypted output     | `apps_data/mfkeys_decrypt/decrypted_keys.txt` |

Each run **overwrites** `decrypted_keys.txt` with the result of processing all files currently in the keystore folder.

## Troubleshooting

- **“Failed to open directory”**  
  Ensure `apps_data/mfkeys_decrypt/keystore/` exists and contains the encrypted files.

- **“Failed to decrypt”**  
  The file may be corrupted, not a supported keystore format, or encrypted in a way this app doesn’t support (e.g. different firmware/keystore scheme).

- **RAW file skipped / “RAW data too large”**  
  RAW decryption is limited to 480 bytes per file.

- **No keys / empty output**  
  Check that the files are actually SubGhz keystore files and that they are in the `keystore` folder with read permission.

## License

See [LICENSE](LICENSE) in this repository.

## Author

.leviathan
