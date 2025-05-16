# encrypt_util: Secrets Encryption Utility

## 1. Overview

`encrypt_util` is a command-line utility developed in Rust. Its primary function is to securely encrypt sensitive credentials required by the `gdrive_upload_tool`. Specifically, it processes a Google Service Account JSON key and a Telegram Bot Token, bundling them into a single, encrypted output file. This methodology ensures that these critical secrets are never stored or transmitted in plaintext, significantly enhancing the security posture of the overall system.

The utility leverages robust, industry-standard cryptographic libraries and practices:
* **PBKDF2 (Password-Based Key Derivation Function 2)** is used to derive a strong encryption key from a user-provided PIN.
* **AES-256-GCM (Advanced Encryption Standard in Galois/Counter Mode)** is employed for the authenticated encryption of the bundled secrets.

## 2. Technical Architecture

### 2.1. Core Functionality
The utility executes the following sequence of operations:

1.  **Input Acquisition:**
    * Prompts the user for the local file path to their Google Service Account JSON key.
    * Prompts the user for their Telegram Bot Token.
    * Securely collects a user-defined PIN (with confirmation) via `rpassword`, which is essential for deriving the master encryption key.

2.  **Data Aggregation & Serialization:**
    * The content of the Google Service Account JSON file is read and stored as a UTF-8 string.
    * This string, along with the provided Telegram Bot Token, is encapsulated within a dedicated Rust struct (`EncryptedBundle`).
    * The `EncryptedBundle` instance is then serialized into a JSON string representation. This serialized string is the plaintext that will be encrypted.

3.  **Key Derivation (PBKDF2):**
    * A cryptographically secure random salt (16 bytes) is generated using `rand::rngs::OsRng`.
    * The user's PIN (as bytes) and the generated salt are fed into the PBKDF2 algorithm using HMAC-SHA256 as the pseudo-random function (PRF).
    * A high iteration count (currently configured to `600,000`) is enforced. This significantly increases the computational effort required for brute-force attacks against the PIN, thereby strengthening the key derivation process.
    * The output of PBKDF2 is a 256-bit (32-byte) derived key, which serves as the master key for AES-GCM.

4.  **Authenticated Encryption (AES-256-GCM):**
    * A cryptographically secure random nonce (12 bytes/96 bits, standard for AES-GCM) is generated using `rand::rngs::OsRng`.
    * The serialized JSON string of the `EncryptedBundle` (converted to bytes) is encrypted using AES-256-GCM with the 256-bit derived key and the 96-bit nonce.
    * AES-GCM is an AEAD (Authenticated Encryption with Associated Data) cipher. It provides:
        * **Confidentiality:** Ensures the plaintext cannot be read without the correct key.
        * **Integrity:** Ensures that any modification to the ciphertext will be detected during decryption.
        * **Authenticity:** Verifies that the ciphertext was created by a party holding the correct key.

5.  **Output File Generation:**
    * The salt, nonce, and the resulting ciphertext are individually hex-encoded to ensure they can be safely stored and transmitted within a JSON structure.
    * These hex-encoded strings are then serialized into a final JSON object (`EncryptedFileContent` struct).
    * This final JSON object is saved to a file named `encrypted_bundle.json` in the current working directory.

### 2.2. Output File Structure (`encrypted_bundle.json`)
The generated `encrypted_bundle.json` contains the necessary components for decryption:
```json
{
  "salt": "hex_encoded_16_byte_salt",
  "nonce": "hex_encoded_12_byte_nonce",
  "ciphertext": "hex_encoded_aes_256_gcm_ciphertext"
}
This file is intended to be hosted at a secure, private URL (e.g., a raw link from a private GitHub Gist) for consumption by the gdrive_upload_tool.3. Usage Instructions3.1. CompilationCompile the encrypt_util Rust project using Cargo. For an optimized release binary:cargo build --release -p encrypt_util
The executable will typically be located at your_workspace_root/target/release/encrypt_util.3.2. ExecutionExecute the compiled binary from a terminal:/path/to/your_workspace_root/target/release/encrypt_util
The utility will interactively prompt for:Path to the Google Service Account JSON file.Telegram Bot Token.A strong PIN for encryption (followed by a confirmation prompt).Upon successful completion, the encrypted_bundle.json file will be created in the directory from which the utility was run.4. Security Best PracticesPIN Strength & Uniqueness: The primary defense against unauthorized decryption is the user-chosen PIN. It should be strong, unique, and not easily guessable. Avoid using common passwords or easily inferable information.PBKDF2 Iteration Count: The configured iteration count (600,000) is a critical security parameter. While it makes the key derivation process slower (by design), it significantly hinders brute-force attacks. This value should be maintained or increased if greater security is required and performance allows.Storage of encrypted_bundle.json: Although the sensitive data within encrypted_bundle.json is encrypted, the file itself should be treated as sensitive. Store it in a location with robust access controls (e.g., a private Gist, a secure internal server). Public exposure of this file, while not immediately compromising the secrets (due to PIN protection), increases the attack surface.Principle of Least Privilege: The Google Service Account key itself should be configured with the minimum necessary permissions on Google Drive for the
