use aes_gcm::{
    aead::Aead,
    Aes256Gcm,
    Key,
    Nonce,
    KeyInit
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Write, self, BufRead};
use std::path::Path;
use rpassword::prompt_password;

const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const PBKDF2_ITERATIONS: u32 = 600_000;

// This struct will hold the secrets to be encrypted together
// It's crucial that gdrive_upload_tool expects to decrypt this exact structure
#[derive(Serialize, Deserialize)] // Removed Debug as it's not strictly needed for this struct's usage
struct EncryptedBundle {
    service_account_json_string: String, // The entire SA JSON as a string
    telegram_bot_token: String,
}

// This struct defines the content of the output JSON file
#[derive(Serialize, Deserialize)]
struct EncryptedFileContent {
    salt: String,
    nonce: String,
    ciphertext: String, // This will be the encrypted 'EncryptedBundle'
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting Google Service Account Key & Telegram Bot Token Encryption Utility...");

    let mut stdin_lines = io::stdin().lock().lines();

    // Get Service Account JSON path
    print!("Enter the path to your Google Service Account JSON file: ");
    io::stdout().flush()?;
    let service_account_path_input = stdin_lines.next().unwrap_or(Ok(String::new()))?;
    let service_account_path = service_account_path_input.trim();

    if service_account_path.is_empty() {
        eprintln!("Error: Service Account JSON path cannot be empty.");
        return Ok(());
    }
    if !Path::new(service_account_path).exists() {
        eprintln!("Error: Service Account JSON file not found at '{}'", service_account_path);
        return Ok(());
    }
    // Read the SA JSON file content into a string
    let service_account_json_bytes = fs::read(service_account_path)?;
    let service_account_json_string = String::from_utf8(service_account_json_bytes)
        .map_err(|e| format!("Service account JSON is not valid UTF-8: {}", e))?;
    println!("📄 Service Account JSON read successfully.");

    // Get Telegram Bot Token
    print!("Enter your Telegram Bot Token: ");
    io::stdout().flush()?;
    let telegram_bot_token = stdin_lines.next().unwrap_or(Ok(String::new()))?.trim().to_string();
    if telegram_bot_token.is_empty() {
        eprintln!("Error: Telegram Bot Token cannot be empty.");
        return Ok(());
    }
    println!("Telegram Bot Token received.");

    // Get PIN from user
    let pin = match prompt_password("Enter a strong PIN to encrypt the secrets: ") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error reading PIN: {}", e);
            return Err(e.into());
        }
    };
    let pin_confirm = match prompt_password("Confirm PIN: ") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error reading PIN confirmation: {}", e);
            return Err(e.into());
        }
    };

    if pin != pin_confirm {
        eprintln!("Error: PINs do not match.");
        return Ok(());
    }
    if pin.is_empty() {
        eprintln!("Error: PIN cannot be empty.");
        return Ok(());
    }
    println!("PIN for encryption received.");

    // Create the bundle to be encrypted
    let bundle_to_encrypt = EncryptedBundle {
        service_account_json_string, 
        telegram_bot_token,
    };

    // Serialize the bundle to a JSON string for encryption
    let bundle_json_string_for_encryption = serde_json::to_string(&bundle_to_encrypt)?;
    // For actual encryption, pretty-printing doesn't matter.
    let bundle_bytes_for_encryption = bundle_json_string_for_encryption.into_bytes();
    println!("Service Account Key and Bot Token combined and serialized for encryption.");

    // Generate Salt
    let mut salt = [0u8; SALT_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    println!("Salt generated.");

    // Derive Key using PBKDF2
    let mut derived_key_bytes = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        pin.as_bytes(),
        &salt,
        PBKDF2_ITERATIONS,
        &mut derived_key_bytes,
    );
    let key = Key::<Aes256Gcm>::from_slice(&derived_key_bytes);
    println!("Encryption key derived using PBKDF2 (this might take a moment)...");

    // Generate Nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    println!("Nonce generated.");

    // Encrypt the bundle bytes
    let cipher = Aes256Gcm::new(key);
    let ciphertext_bytes = cipher.encrypt(nonce, bundle_bytes_for_encryption.as_slice())
        .map_err(|e| format!("AES-GCM encryption failed: {}", e))?;
    println!("Secrets (SA Key & Bot Token) encrypted successfully with AES-GCM.");

    // Prepare data for the output JSON file
    let encrypted_file_output = EncryptedFileContent {
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext_bytes),
    };

    // Serialize to JSON and save to file
    // Using to_string_pretty for the output file makes it human-readable if opened directly.
    let output_json_string = serde_json::to_string_pretty(&encrypted_file_output)?;
    let output_path = "encrypted_bundle.json"; 
    fs::write(output_path, output_json_string)?;

    println!("	 Success! Encrypted bundle saved to '{}'", output_path);
    println!("	 Upload this '{}' file to your secure external URL.", output_path);
    println!("   This file now contains your encrypted Google Service Account key and Telegram Bot Token.");
    println!("   The Telegram Chat ID will be fetched separately by the upload tool.");

    Ok(())
}
