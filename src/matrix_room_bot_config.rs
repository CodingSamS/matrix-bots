use crate::encrypted_string::EncryptedString;
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
