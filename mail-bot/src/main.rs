use aes_gcm::{aead::KeyInit, Aes256Gcm, Key};
use anyhow::bail;
use config::Config;
use crypto_box::PublicKey;
use encrypted_startup::{EncryptedStartup, EncryptedStartupHelper, SessionState};
use futures::{future, prelude::Future};
use futures_util::stream::StreamExt;
use log::{debug, error, info, warn};
use mail_server::mail_server;
use matrix_sdk::{
    config::SyncSettings,
    ruma::{events::room::message::RoomMessageEventContent, RoomId},
    Client,
};
use matrix_util::restore_session;
use retry::{delay::Fixed, retry};
use std::{env, path::PathBuf, process::exit, sync::Arc};
use tarpc::{
    serde_transport::tcp,
    server::{BaseChannel, Channel},
    tokio_serde::formats::Bincode,
};
use tokio::{
    fs,
    sync::{mpsc, Mutex, OnceCell},
    task::JoinHandle,
    time::{sleep, Duration},
};

const CHANNEL_BUFFER_SIZE: usize = 100;

async fn spawn(fut: impl Future<Output = ()> + Send + 'static) {
    tokio::spawn(fut);
}

async fn exit_with_delay(delay: u64) {
    info!("shutting down in 10 seconds");
    sleep(Duration::from_secs(delay)).await;
    exit(0);
}

#[derive(Clone)]
struct EncryptedMatrixServer {
    helper: EncryptedStartupHelper,
    session_file: Arc<PathBuf>,
    config: Arc<Config>,
    cipher: Arc<Mutex<OnceCell<Aes256Gcm>>>,
    mail_server_handle: Arc<Mutex<OnceCell<JoinHandle<anyhow::Result<()>>>>>,
    matrix_bot_handle: Arc<Mutex<OnceCell<JoinHandle<anyhow::Result<()>>>>>,
    matrix_sync_handle: Arc<Mutex<OnceCell<JoinHandle<anyhow::Result<()>>>>>,
}

impl EncryptedMatrixServer {
    fn new(alice_public_key_option: Option<PublicKey>, config: Config) -> Self {
        EncryptedMatrixServer {
            helper: EncryptedStartupHelper::new(alice_public_key_option),
            session_file: Arc::new(config.matrix_data_dir.join("session").to_owned()),
            config: Arc::new(config),
            cipher: Arc::new(Mutex::new(OnceCell::new())),
            mail_server_handle: Arc::new(Mutex::new(OnceCell::new())),
            matrix_bot_handle: Arc::new(Mutex::new(OnceCell::new())),
            matrix_sync_handle: Arc::new(Mutex::new(OnceCell::new())),
        }
    }
}

impl EncryptedStartup for EncryptedMatrixServer {
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
                if !self.mail_server_handle.lock().await.initialized()
                    && !self.matrix_bot_handle.lock().await.initialized()
                    && !self.matrix_sync_handle.lock().await.initialized()
                {
                    let client = match restore_session(&self.session_file, cipher).await {
                        Ok(client) => client,
                        Err(_) => return Err(String::from("Loading client session failed")),
                    };

                    info!("Session restored successfully");

                    let (tx, rx): (mpsc::Sender<String>, mpsc::Receiver<String>) =
                        mpsc::channel(CHANNEL_BUFFER_SIZE);

                    let handle = tokio::spawn(matrix_room_bot(
                        client.to_owned(),
                        rx,
                        self.config.matrix_room_id.to_owned(),
                    ));
                    self.mail_server_handle.lock().await.set(handle).unwrap();

                    let handle = tokio::spawn(mail_server(
                        tx,
                        self.config.mail_from.to_owned(),
                        self.config.mail_to.to_owned(),
                        self.config.mail_server_name.to_owned(),
                    ));
                    self.matrix_bot_handle.lock().await.set(handle).unwrap();

                    let handle = tokio::spawn(sync_client(client));
                    self.matrix_sync_handle.lock().await.set(handle).unwrap();

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

    let encrypted_matrix_server = EncryptedMatrixServer::new(None, config);

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
