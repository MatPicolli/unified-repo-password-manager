//! Vault file format: JSON header + Argon2id-derived key + XChaCha20-Poly1305.
//! A vault may be "protected": its key then comes from the master password AND its own extra password.
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::aead::{rand_core::RngCore, Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

const FORMAT: &str = "urpm3-vault";
/// The `protected` flag is authenticated through the AAD (unprotected files keep the original AAD).
fn aad(protected: bool) -> &'static [u8] {
    if protected { b"urpm3/vault/v1/protected" } else { b"urpm3/vault/v1" }
}
pub const DOWNGRADED: &str = "Este cofre tinha senha própria e o arquivo no GitHub não tem mais. Por segurança ele não foi recarregado: bloqueie e entre de novo.";
pub const WRONG_PASSWORD: &str = "Senha mestra incorreta (ou arquivo corrompido).";
pub const WRONG_VAULT_PASSWORD: &str = "Senha do cofre incorreta.";
/// The UI matches on this text to ask for the vault's own password.
pub const NEEDS_VAULT_PASSWORD: &str = "Este cofre tem uma senha própria.";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Kdf {
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: String,
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    format: String,
    version: u32,
    #[serde(default)] // files from before vault passwords existed are unprotected
    protected: bool,
    kdf: Kdf,
    nonce: String,
    ciphertext: String,
}

/// Key derived for one vault file; cached while the vault is open so saving doesn't rerun Argon2.
#[derive(Clone)]
pub struct VaultKey {
    kdf: Kdf,
    protected: bool,
    key: [u8; 32],
}

impl Drop for VaultKey {
    fn drop(&mut self) {
        self.key.iter_mut().for_each(|b| unsafe { std::ptr::write_volatile(b, 0) });
    }
}

/// Argon2 input: the master password alone, or master + vault password, length-prefixed so
/// ("ab","c") and ("a","bc") can never collide.
fn secret(master: &str, extra: Option<&str>) -> String {
    match extra {
        Some(x) => format!("{}:{master}{x}", master.len()),
        None => master.to_string(),
    }
}

impl VaultKey {
    /// Fresh random salt with the default Argon2id cost.
    pub fn new(master: &str, extra: Option<&str>) -> Result<Self, String> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let kdf = Kdf { algorithm: "argon2id".into(), memory_kib: 65536, iterations: 3, parallelism: 4, salt: B64.encode(salt) };
        Self::derive(&secret(master, extra), kdf, extra.is_some())
    }

    fn derive(secret: &str, kdf: Kdf, protected: bool) -> Result<Self, String> {
        // Upper bounds stop a tampered file from making us allocate absurd memory.
        if kdf.algorithm != "argon2id" || kdf.memory_kib > 1 << 20 || kdf.iterations > 16 || kdf.parallelism > 16 {
            return Err("Parâmetros de derivação de chave inválidos no arquivo.".into());
        }
        let salt = B64.decode(&kdf.salt).map_err(|_| "Salt inválido no arquivo.")?;
        let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32)).map_err(|e| e.to_string())?;
        let mut key = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(secret.as_bytes(), &salt, &mut key)
            .map_err(|e| e.to_string())?;
        Ok(Self { kdf, protected, key })
    }

    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = XChaCha20Poly1305::new(Key::from_slice(&self.key))
            .encrypt(&nonce, Payload { msg: plaintext, aad: aad(self.protected) })
            .expect("XChaCha20-Poly1305 não falha ao cifrar");
        let file = VaultFile {
            format: FORMAT.into(),
            version: 1,
            protected: self.protected,
            kdf: self.kdf.clone(),
            nonce: B64.encode(nonce),
            ciphertext: B64.encode(ct),
        };
        serde_json::to_vec_pretty(&file).expect("serializar cabeçalho")
    }
}

/// Decrypts a vault file and returns its key (to re-seal on save) plus the plaintext.
/// `cached` (the key from when this vault was last opened) is reused if the file still uses it,
/// which skips Argon2 and the vault password prompt when reloading an open vault.
pub fn open(file: &[u8], cached: Option<&VaultKey>, master: &str, extra: Option<&str>) -> Result<(VaultKey, Vec<u8>), String> {
    let f: VaultFile = serde_json::from_slice(file).map_err(|_| "Arquivo de cofre inválido.")?;
    if f.format != FORMAT || f.version != 1 {
        return Err(format!("Formato de cofre não suportado: {} v{}", f.format, f.version));
    }
    let nonce = B64.decode(&f.nonce).map_err(|_| "Nonce inválido.")?;
    if nonce.len() != 24 {
        return Err("Nonce inválido.".into());
    }
    let ct = B64.decode(&f.ciphertext).map_err(|_| "Conteúdo cifrado inválido.")?;
    let vk = match cached {
        Some(k) if k.kdf == f.kdf && k.protected == f.protected => k.clone(),
        // A vault open with its own password must never silently reload (and later re-save) as master-only.
        Some(k) if k.protected && !f.protected => return Err(DOWNGRADED.into()),
        _ if f.protected && extra.is_none() => return Err(NEEDS_VAULT_PASSWORD.into()),
        _ => VaultKey::derive(&secret(master, extra.filter(|_| f.protected)), f.kdf, f.protected)?,
    };
    let pt = XChaCha20Poly1305::new(Key::from_slice(&vk.key))
        .decrypt(XNonce::from_slice(&nonce), Payload { msg: &ct, aad: aad(f.protected) })
        .map_err(|_| if f.protected { WRONG_VAULT_PASSWORD } else { WRONG_PASSWORD })?;
    Ok((vk, pt))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cheap(master: &str, extra: Option<&str>) -> VaultKey {
        let kdf = Kdf { algorithm: "argon2id".into(), memory_kib: 64, iterations: 1, parallelism: 1, salt: B64.encode([7u8; 16]) };
        VaultKey::derive(&secret(master, extra), kdf, extra.is_some()).unwrap()
    }

    #[test]
    fn roundtrip_and_fresh_nonce() {
        let k = cheap("senha certa", None);
        let a = k.seal(b"segredo");
        assert_ne!(a, k.seal(b"segredo"), "nonce must change per save");
        let (k2, pt) = open(&a, None, "senha certa", None).unwrap();
        assert_eq!(pt, b"segredo");
        assert_eq!(k2.kdf, k.kdf);
    }

    #[test]
    fn wrong_password_and_tamper_fail() {
        let file = cheap("certa", None).seal(b"x");
        assert_eq!(open(&file, None, "errada", None).err().unwrap(), WRONG_PASSWORD);
        let mut v: serde_json::Value = serde_json::from_slice(&file).unwrap();
        let mut ct = B64.decode(v["ciphertext"].as_str().unwrap()).unwrap();
        ct[0] ^= 1;
        v["ciphertext"] = B64.encode(ct).into();
        assert!(open(&serde_json::to_vec(&v).unwrap(), None, "certa", None).is_err());
    }

    #[test]
    fn protected_vault_needs_both_passwords() {
        let file = cheap("mestra", Some("extra")).seal(b"x");
        assert_eq!(open(&file, None, "mestra", None).err().unwrap(), NEEDS_VAULT_PASSWORD);
        assert_eq!(open(&file, None, "mestra", Some("outra")).err().unwrap(), WRONG_VAULT_PASSWORD);
        assert!(open(&file, None, "outra-mestra", Some("extra")).is_err());
        let (k, pt) = open(&file, None, "mestra", Some("extra")).unwrap();
        assert_eq!(pt, b"x");
        // An open vault reloads with its cached key, no password needed...
        assert_eq!(open(&k.seal(b"y"), Some(&k), "mestra", None).unwrap().1, b"y");
        // ...but not once the file was re-keyed elsewhere (new salt).
        let rekeyed = VaultKey::new("mestra", Some("nova")).unwrap().seal(b"z");
        assert_eq!(open(&rekeyed, Some(&k), "mestra", None).err().unwrap(), NEEDS_VAULT_PASSWORD);
    }

    #[test]
    fn protection_cannot_be_stripped() {
        let k = cheap("mestra", Some("extra"));
        // Header flipped to unprotected: AAD (and key) no longer match.
        let mut v: serde_json::Value = serde_json::from_slice(&k.seal(b"x")).unwrap();
        v["protected"] = false.into();
        assert!(open(&serde_json::to_vec(&v).unwrap(), None, "mestra", None).is_err());
        // Whole file swapped for a valid master-only one while the protected vault is open.
        let swapped = cheap("mestra", None).seal(b"x");
        assert_eq!(open(&swapped, Some(&k), "mestra", None).err().unwrap(), DOWNGRADED);
    }

    #[test]
    fn legacy_file_without_protected_field_opens() {
        let mut v: serde_json::Value = serde_json::from_slice(&cheap("m", None).seal(b"old")).unwrap();
        v.as_object_mut().unwrap().remove("protected");
        assert_eq!(open(&serde_json::to_vec(&v).unwrap(), None, "m", None).unwrap().1, b"old");
    }

    #[test]
    fn rejects_absurd_kdf_cost() {
        let mut v: serde_json::Value = serde_json::from_slice(&cheap("a", None).seal(b"x")).unwrap();
        v["kdf"]["memory_kib"] = (u32::MAX).into();
        assert!(open(&serde_json::to_vec(&v).unwrap(), None, "a", None).err().unwrap().contains("inválidos"));
    }
}
