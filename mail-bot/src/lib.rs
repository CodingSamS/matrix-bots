use encrypted_string::EncryptedString;
use matrix_sdk::ruma::RoomId;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf, str};

pub const INITIAL_DEVICE_DISPLAY_NAME: &str = "Mail Notif Bot";

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
    pub microservice_socket: SocketAddr,
}
