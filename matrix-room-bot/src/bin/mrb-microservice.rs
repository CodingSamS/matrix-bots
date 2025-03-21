use aes_gcm::{aead::KeyInit, Aes256Gcm, Key};
use anyhow::bail;
use crypto_box::PublicKey;
use encrypted_startup::EncryptedStartupHelper;
use futures::{future, prelude::Future};
use futures_util::stream::StreamExt;
use log::{debug, info, warn};
use matrix_room_bot::{Config, MatrixRoomServer, SessionState};
use matrix_sdk::{
    config::SyncSettings, ruma::events::room::message::RoomMessageEventContent, Client,
};
use matrix_util::restore_session;
use std::{env, path::PathBuf, process::exit, sync::Arc};
use tarpc::{
    serde_transport::tcp,
    server::{BaseChannel, Channel},
    tokio_serde::formats::Bincode,
};
use tokio::{
    fs,
    sync::{Mutex, OnceCell},
    task::JoinHandle,
    time::{sleep, Duration},
};

async fn sync_client(client: Client) -> anyhow::Result<()> {
    let sync_settings = SyncSettings::new().timeout(Duration::from_secs(900)); // timeout for sync requests: 15 Minutes
    debug!("start sync");
    client.sync(sync_settings).await?;
    warn!("sync finished");
    Ok(())
}

async fn spawn(fut: impl Future<Output = ()> + Send + 'static) {
    tokio::spawn(fut);
}

async fn exit_with_delay(delay: u64) {
    info!("shutting down in 10 seconds");
    sleep(Duration::from_secs(delay)).await;
    exit(0);
}

#[derive(Clone)]
struct Server {
    helper: EncryptedStartupHelper,
    session_file: Arc<PathBuf>,
    config: Arc<Config>,
    client: Arc<Mutex<OnceCell<Client>>>,
    cipher: Arc<Mutex<OnceCell<Aes256Gcm>>>,
    matrix_sync_handle: Arc<Mutex<OnceCell<JoinHandle<anyhow::Result<()>>>>>,
}

impl Server {
    fn new(alice_public_key_option: Option<PublicKey>, config: Config) -> Self {
        Server {
            helper: EncryptedStartupHelper::new(alice_public_key_option),
            session_file: Arc::new(config.matrix_data_dir.join("session").to_owned()),
            config: Arc::new(config),
            client: Arc::new(Mutex::new(OnceCell::new())),
            cipher: Arc::new(Mutex::new(OnceCell::new())),
            matrix_sync_handle: Arc::new(Mutex::new(OnceCell::new())),
        }
    }
}

impl MatrixRoomServer for Server {
    async fn sync_public_keys(
        self,
        _: tarpc::context::Context,
        alice_public_key: PublicKey,
    ) -> PublicKey {
        self.helper.set_alice_public_key(alice_public_key).await;
        self.helper.bob_secret_key.public_key()
    }

    async fn load_cipher(
        self,
        _context: tarpc::context::Context,
        encryption_key_ciphertext: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<SessionState, String> {
        let decryption_result = self.helper.decrypt(encryption_key_ciphertext, nonce).await;
        match decryption_result {
            Ok(encryption_key) => {
                let key = Key::<Aes256Gcm>::from_slice(&encryption_key);
                let cipher = Aes256Gcm::new(&key);
                match self.cipher.lock().await.set(cipher) {
                    Ok(()) => match self.session_file.exists() {
                        true => Ok(SessionState::SessionExists),
                        false => Ok(SessionState::SessionMissing),
                    },
                    Err(_) => Err(String::from("Writing cipher failed")),
                }
            }
            Err(_) => Err(String::from("Decrypting the message failed")),
        }
    }

    async fn start(self, _: tarpc::context::Context) -> Result<(), String> {
        if self.session_file.exists() {
            if let Some(cipher) = self.cipher.lock().await.get() {
                if !self.matrix_sync_handle.lock().await.initialized() {
                    match restore_session(&self.session_file, cipher).await {
                        Ok(client) => {
                            if self.client.lock().await.set(client.to_owned()).is_err() {
                                return Err(String::from("Storing Matrix Client failed"));
                            }
                            let handle = tokio::spawn(sync_client(client));
                            if self.matrix_sync_handle.lock().await.set(handle).is_err() {
                                return Err(String::from("Storing Matrix Sync handle failed"));
                            };
                            info!("Session restored successfully");
                        }
                        Err(_) => return Err(String::from("Loading client session failed")),
                    };

                    Ok(())
                } else {
                    Err(String::from("Server already started"))
                }
            } else {
                Err(String::from("No cipher available. Load cipher first"))
            }
        } else {
            Err(String::from("Session file does not exist"))
        }
    }

    async fn stop(self, _: tarpc::context::Context) -> Result<(), String> {
        tokio::spawn(exit_with_delay(10));
        Ok(())
    }

    async fn send(self, _: tarpc::context::Context, message: String) -> Result<(), String> {
        let client_lock = self.client.lock().await;
        let Some(client) = client_lock.get() else {
            return Err(String::from("Client not initialised"));
        };
        let Some(room) = client.get_room(&self.config.matrix_room_id) else {
            return Err(String::from("room not found"));
        };
        match room
            .send(RoomMessageEventContent::text_plain(message))
            .await
        {
            Ok(_) => Ok(()),
            Err(_) => Err(String::from("Sending message to matrix room failed")),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // read config from cli
    env_logger::init();
    let config_path = match env::args().nth(1) {
        Some(path) => path,
        None => bail!("Usage: {} <path_to_config>", env::args().next().unwrap()),
    };

    let data = fs::read_to_string(config_path).await?;
    let config: Config = serde_json::from_str(&data)?;

    // start service
    info!("Starting Server");

    let mut listener = tcp::listen(&config.microservice_socket, Bincode::default).await?;
    listener.config_mut().max_frame_length(usize::MAX);

    let encrypted_matrix_server = Server::new(None, config);

    listener
        // ignore accept errors
        .filter_map(|r| future::ready(r.ok()))
        .map(BaseChannel::with_defaults)
        .map(|channel| {
            channel
                .execute(encrypted_matrix_server.clone().serve())
                .for_each(spawn)
        })
        // max 10 channels
        .buffer_unordered(10)
        .for_each(|_| async {})
        .await;

    info!("Executing main finished");
    Ok(())
}
