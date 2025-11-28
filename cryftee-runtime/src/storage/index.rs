//! Index module - handles module discovery, hashing, and signature verification

use std::path::Path;
use anyhow::{Result, Context};
use sha2::{Sha256, Digest};
use tracing::{debug, warn};

use super::ManifestEntry;

/// Compute the SHA-256 hash of a file
pub fn compute_file_hash(path: &Path) -> Result<String> {
    let contents = std::fs::read(path)
        .with_context(|| format!("Failed to read file for hashing: {:?}", path))?;
    
    let hash = Sha256::digest(&contents);
    Ok(format!("sha256:{}", hex::encode(hash)))
}

/// Verify that a module file matches its declared hash
pub fn verify_module_hash(module_dir: &Path, entry: &ManifestEntry) -> Result<bool> {
    let module_path = module_dir.join(&entry.dir).join(&entry.file);
    
    if !module_path.exists() {
        warn!("Module file not found: {:?}", module_path);
        return Ok(false);
    }

    let computed_hash = compute_file_hash(&module_path)?;
    let matches = computed_hash == entry.hash;
    
    if !matches {
        warn!(
            "Hash mismatch for module {}: expected {}, got {}",
            entry.id, entry.hash, computed_hash
        );
    } else {
        debug!("Hash verified for module {}", entry.id);
    }

    Ok(matches)
}

/// Compute canonical JSON for signature verification
pub fn canonical_json_for_signing(entry: &ManifestEntry) -> Result<String> {
    // Create a subset of fields for signing
    let signing_data = serde_json::json!({
        "id": entry.id,
        "version": entry.version,
        "hash": entry.hash,
        "minCryfteeVersion": entry.min_cryftee_version,
        "capabilities": entry.capabilities,
    });
    
    // Serialize to canonical JSON (sorted keys, no extra whitespace)
    serde_json::to_string(&signing_data).context("Failed to serialize signing data")
}

/// Verify module signature using Ed25519
pub fn verify_signature(
    entry: &ManifestEntry,
    public_key_hex: &str,
) -> Result<bool> {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};
    
    // Decode the public key
    let public_key_bytes = hex::decode(public_key_hex)
        .context("Invalid public key hex")?;
    
    let public_key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid public key length"))?;
    
    let verifying_key = VerifyingKey::from_bytes(&public_key_array)
        .context("Invalid Ed25519 public key")?;

    // Decode the signature
    let signature_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &entry.signature,
    ).context("Invalid signature base64")?;
    
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;
    
    let signature = Signature::from_bytes(&signature_array);

    // Compute the message to verify
    let message = canonical_json_for_signing(entry)?;

    // Verify
    match verifying_key.verify(message.as_bytes(), &signature) {
        Ok(_) => {
            debug!("Signature verified for module {}", entry.id);
            Ok(true)
        }
        Err(e) => {
            warn!("Signature verification failed for module {}: {}", entry.id, e);
            Ok(false)
        }
    }
}

/// Scan a module directory for available modules
pub fn scan_module_directory(module_dir: &Path) -> Result<Vec<String>> {
    let mut modules = Vec::new();
    
    if !module_dir.exists() {
        warn!("Module directory does not exist: {:?}", module_dir);
        return Ok(modules);
    }

    for entry in std::fs::read_dir(module_dir)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_dir() {
            // Check if it contains a module.wasm file
            let wasm_path = path.join("module.wasm");
            if wasm_path.exists() {
                if let Some(name) = path.file_name() {
                    modules.push(name.to_string_lossy().to_string());
                }
            }
        }
    }

    debug!("Found {} module directories", modules.len());
    Ok(modules)
}
