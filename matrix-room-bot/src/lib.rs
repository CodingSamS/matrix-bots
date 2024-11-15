use crypto_box::PublicKey;
use encrypted_string::EncryptedString;
use matrix_sdk::ruma::RoomId;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf, str};

pub const INITIAL_DEVICE_DISPLAY_NAME: &str = "Forward Room Bot";

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub matrix_user: String,
    pub matrix_password: EncryptedString,
    pub matrix_homeserver: String,
    pub matrix_room_id: Box<RoomId>,
    pub matrix_data_dir: PathBuf,
    pub microservice_socket: SocketAddr,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SessionState {
    SessionExists,
    SessionMissing,
}

#[tarpc::service]
pub trait MatrixRoomServer {
    /// Receives the public key of the other side, processes it, and responds with the own one
    async fn sync_public_keys(alice_public_key: PublicKey) -> PublicKey;

    /// Loads the session for the client. sync_public_keys needs to be done beforehand. returns if it needs to restore or do interactive cross signing
    async fn load_cipher(
        encryption_key_ciphertext: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<SessionState, String>;

    /// sends message to matrix room
    async fn send(message: String) -> Result<(), String>;

    /// simple start
    async fn start() -> Result<(), String>;

    /// stop the application
    async fn stop() -> Result<(), String>;
}
