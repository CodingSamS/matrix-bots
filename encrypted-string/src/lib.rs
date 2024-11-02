use aes_gcm::{
    aead::{Aead, AeadCore, OsRng},
    Aes256Gcm, Nonce,
};
use serde::{Deserialize, Serialize};
use std::str;

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedString {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
}

impl EncryptedString {
    pub fn new(cleartext: String, cipher: &Aes256Gcm) -> Result<Self, aes_gcm::Error> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let nonce_vec = nonce.to_vec();
        let ciphertext = cipher.encrypt(&nonce, cleartext.trim().as_bytes())?;
        Ok(EncryptedString {
            ciphertext,
            nonce: nonce_vec,
        })
    }

    pub fn get_decrypted_string(&self, cipher: &Aes256Gcm) -> anyhow::Result<String> {
        let plaintext_bytes =
            cipher.decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_ref())?;
        let plaintext = str::from_utf8(&plaintext_bytes)?;
        Ok(plaintext.to_string())
    }
}
