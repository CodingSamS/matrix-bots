use aes_gcm::{
    aead::{Aead, AeadCore, OsRng},
    Aes256Gcm, Nonce,
};
use matrix_sdk::{matrix_auth::MatrixSession, ruma::RoomId};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, str};

pub const INITIAL_DEVICE_DISPLAY_NAME: &str = "Mail Notif Bot";

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

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub matrix_user: String,
    pub matrix_password: EncryptedString,
    pub matrix_homeserver: String,
    pub matrix_room_id: Box<RoomId>,
    pub matrix_data_dir: PathBuf,
    pub mail_server_name: String,
    pub mail_from: String, // this is the src address that needs to match (protection against misuse)
    pub mail_to: String, // this is the dst address that needs to match (protection against misuse / option for multitenancy)
}

/// The data needed to re-build a client.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientSession {
    /// The URL of the homeserver of the user.
    pub homeserver: String,

    /// The path of the database.
    pub db_path: PathBuf,

    /// The passphrase of the database.
    pub passphrase: EncryptedString,
}

/// The full session to persist.
#[derive(Debug, Serialize, Deserialize)]
pub struct FullSession {
    /// The data to re-build the client.
    pub client_session: ClientSession,

    /// The Matrix user session.
    pub user_session: MatrixSession,
}
