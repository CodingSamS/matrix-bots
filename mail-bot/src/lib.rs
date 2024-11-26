use encrypted_string::EncryptedString;
use matrix_sdk::ruma::RoomId;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf, str};

pub const INITIAL_DEVICE_DISPLAY_NAME: &str = "Mail Notif Bot";

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub mail_server_name: String,
    pub mail_from: String, // this is the src address that needs to match (protection against misuse)
    pub mail_to: String, // this is the dst address that needs to match (protection against misuse / option for multitenancy)
    pub matrix_bot_microservice_socket: SocketAddr, // this is the socket the matrix microservice is listening on for messages
}
