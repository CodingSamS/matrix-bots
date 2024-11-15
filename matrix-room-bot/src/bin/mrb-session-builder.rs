use aes_gcm::{aead::KeyInit, Aes256Gcm, Key};
use anyhow::bail;
use config::{Config, INITIAL_DEVICE_DISPLAY_NAME};
use log::{info, warn};
use matrix_sdk::config::SyncSettings;
use matrix_util::{login, restore_session};
use std::env;
use tokio::{
    fs,
    io::{stdin, AsyncBufReadExt, BufReader},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let config_path = match env::args().nth(1) {
        Some(path) => path,
        None => bail!("Usage: {} <path_to_config>", env::args().next().unwrap()),
    };

    let data = fs::read_to_string(config_path).await?;
    let config: Config = serde_json::from_str(&data)?;

    let session_file = &config.matrix_data_dir;

    let mut encryption_key_len = 0;
    let mut encryption_key = String::new();
    let mut stdin_reader = BufReader::new(stdin());
    while encryption_key_len != 32 {
        encryption_key = String::new();
        println!("Enter encryption key of byte length 32:");
        stdin_reader.read_line(&mut encryption_key).await.unwrap();
        encryption_key_len = encryption_key.trim().len();
    }
    info!("encryption key read successfully");

    let key: &Key<Aes256Gcm> = encryption_key.trim().as_bytes().into();
    let cipher = Aes256Gcm::new(&key);

    let client = if session_file.exists() {
        restore_session(session_file, &cipher).await?
    } else {
        login(
            session_file,
            &cipher,
            INITIAL_DEVICE_DISPLAY_NAME,
            &config.matrix_data_dir,
            config.matrix_homeserver,
            &config.matrix_user,
            &config.matrix_password,
        )
        .await?
    };

    client.sync(SyncSettings::new()).await?;

    warn!("sync finished");

    Ok(())
}
