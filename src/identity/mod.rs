use crate::types::BackupManifest;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

pub struct AgentIdentity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn from_hex(s: &str) -> Result<Vec<u8>, &'static str> {
    if !s.len().is_multiple_of(2) {
        return Err("Odd length hex string");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "Invalid hex character"))
        .collect()
}

impl AgentIdentity {
    /// Loads the agent identity from the user's home directory (~/.aegis or ~/.bug-killer).
    #[allow(dead_code)]
    pub fn load_default() -> Result<Self, std::io::Error> {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        Self::get_or_create(Path::new(&home))
    }

    /// Loads the agent's persistent Ed25519 identity key, or generates a fresh one if missing.
    pub fn get_or_create(root: &Path) -> Result<Self, std::io::Error> {
        let identity_dir = root.join(".aegis");
        fs::create_dir_all(&identity_dir)?;
        let key_path = identity_dir.join("agent_identity.key");

        if key_path.exists() {
            let bytes = fs::read(&key_path)?;
            if bytes.len() != 32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Existing Ed25519 identity key is corrupt; refusing to replace trust root",
                ));
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            let signing_key = SigningKey::from_bytes(&key_bytes);
            let verifying_key = signing_key.verifying_key();
            return Ok(Self {
                signing_key,
                verifying_key,
            });
        }

        // Generate fresh cryptographic keypair using OS entropy
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        // Publish the complete key atomically and never replace an existing key.
        let key_bytes = signing_key.to_bytes();
        let mut temp = tempfile::NamedTempFile::new_in(&identity_dir)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temp.as_file_mut()
                .set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        temp.write_all(&key_bytes)?;
        temp.as_file_mut().sync_all()?;
        match temp.persist_noclobber(&key_path) {
            Ok(_) => {}
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                return Self::get_or_create(root);
            }
            Err(error) => return Err(error.error),
        }

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    pub fn public_key_hex(&self) -> String {
        to_hex(&self.verifying_key.to_bytes())
    }

    /// Cryptographically signs arbitrary byte slice with agent's Ed25519 private key.
    pub fn sign_bytes(&self, data: &[u8]) -> String {
        let sig: Signature = self.signing_key.sign(data);
        to_hex(&sig.to_bytes())
    }

    /// Verifies Ed25519 signature in hex format against agent's public key.
    pub fn verify_bytes(&self, data: &[u8], sig_hex: &str) -> Result<(), String> {
        let sig_bytes = from_hex(sig_hex).map_err(|e| format!("Invalid hex signature: {}", e))?;
        if sig_bytes.len() != 64 {
            return Err("Invalid Ed25519 signature length (expected 64 bytes)".into());
        }
        let mut fixed_sig = [0u8; 64];
        fixed_sig.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&fixed_sig);
        self.verifying_key
            .verify(data, &sig)
            .map_err(|e| format!("Signature verification failed: {}", e))
    }

    /// Computes the deterministic canonical digest of a backup manifest.
    pub fn compute_manifest_digest(manifest: &BackupManifest) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(manifest.backup_id.as_bytes());
        hasher.update(manifest.created_at.as_bytes());
        hasher.update(manifest.root_dir.as_bytes());
        for rec in &manifest.records {
            hasher.update(rec.relative_target_path.as_bytes());
            hasher.update(rec.original_sha256.as_bytes());
            hasher.update(rec.backup_file_name.as_bytes());
        }
        hasher.finalize().to_vec()
    }

    /// Signs a backup manifest with Ed25519 and embeds the public key and signature.
    pub fn sign_manifest(&self, manifest: &mut BackupManifest) {
        let digest = Self::compute_manifest_digest(manifest);
        let sig: Signature = self.signing_key.sign(&digest);

        manifest.signer_public_key = Some(self.public_key_hex());
        manifest.signature = Some(to_hex(&sig.to_bytes()));
    }

    /// Verifies the cryptographic integrity and authenticity of a backup manifest against the trusted local agent identity.
    pub fn verify_manifest_with_root(root: &Path, manifest: &BackupManifest) -> Result<(), String> {
        let identity = Self::get_or_create(root)
            .map_err(|e| format!("Failed to access local agent identity trust root: {}", e))?;

        let (pub_hex, sig_hex) = match (&manifest.signer_public_key, &manifest.signature) {
            (Some(p), Some(s)) => (p, s),
            _ => {
                return Err(
                    "Manifest lacks cryptographic signature (fail-closed untrusted)".into(),
                );
            }
        };

        if pub_hex != &identity.public_key_hex() {
            return Err(format!(
                "Untrusted signer: manifest signed by '{}' does not match local agent identity trust root '{}'",
                pub_hex,
                identity.public_key_hex()
            ));
        }

        let sig_bytes =
            from_hex(sig_hex).map_err(|e| format!("Invalid signature encoding: {}", e))?;
        if sig_bytes.len() != 64 {
            return Err("Invalid signature length".into());
        }
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_array);

        let digest = Self::compute_manifest_digest(manifest);
        identity
            .verifying_key
            .verify(&digest, &signature)
            .map_err(|_| {
                "Cryptographic signature verification failed: manifest has been tampered with"
                    .to_string()
            })?;

        Ok(())
    }

    /// Verifies the cryptographic integrity and authenticity of a backup manifest (structural check).
    #[allow(dead_code)]
    pub fn verify_manifest(manifest: &BackupManifest) -> Result<(), &'static str> {
        let (pub_hex, sig_hex) = match (&manifest.signer_public_key, &manifest.signature) {
            (Some(p), Some(s)) => (p, s),
            _ => return Err("Manifest lacks cryptographic signature (untrusted)"),
        };

        let pub_bytes = from_hex(pub_hex).map_err(|_| "Invalid public key encoding")?;
        if pub_bytes.len() != 32 {
            return Err("Invalid public key length");
        }
        let mut pk_array = [0u8; 32];
        pk_array.copy_from_slice(&pub_bytes);

        let verifying_key =
            VerifyingKey::from_bytes(&pk_array).map_err(|_| "Malformed Ed25519 public key")?;

        let sig_bytes = from_hex(sig_hex).map_err(|_| "Invalid signature encoding")?;
        if sig_bytes.len() != 64 {
            return Err("Invalid signature length");
        }
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_array);

        let digest = Self::compute_manifest_digest(manifest);
        verifying_key.verify(&digest, &signature).map_err(
            |_| "Cryptographic signature verification failed: manifest has been tampered with",
        )?;

        Ok(())
    }
}
