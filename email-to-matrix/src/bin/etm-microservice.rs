use aes_gcm::{aead::KeyInit, Aes256Gcm, Key};
use anyhow::{bail, Context};
use config::Config;
use crypto_box::PublicKey;
use encrypted_startup::{EncryptedStartup, EncryptedStartupHelper, SessionState};
use futures::prelude::Future;
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
    sync::{
        mpsc::{self, Receiver, Sender},
        Mutex, OnceCell,
    },
    task::JoinHandle,
    time::Duration,
};

const CHANNEL_BUFFER_SIZE: usize = 100;

async fn matrix_room_bot(
    client: Client,
    mut rx: Receiver<String>,
    room_id: Box<RoomId>,
) -> anyhow::Result<()> {
    //   let room_id = &CONFIG.get().context("no config")?.matrix_room_id.clone();

    // remove this room variable and the test send later
    let test_room = match retry(Fixed::from_millis(5000).take(12), || {
        match client.get_room(&room_id) {
            Some(room) => Ok(room),
            None => Err("room not found"),
        }
    }) {
        Ok(room) => room,
        Err(_) => {
            error!("Finding the room failed");
            exit(1)
        }
    };

    debug!("start test send");
    // test send
    test_room
        .send(RoomMessageEventContent::text_plain("let's PARTY!!"))
        .await?;
    debug!("finished test send");

    // listen for events to send
    loop {
        debug!("wait for event");
        match rx.recv().await {
            Some(message) => {
                debug!("matrix room boot received message");
                match retry(Fixed::from_millis(5000).take(12), || {
                    match client.get_room(&room_id) {
                        Some(room) => Ok(room),
                        None => Err("room not found"),
                    }
                }) {
                    Ok(room) => {
                        debug!("room found");
                        match room
                            .send(RoomMessageEventContent::text_plain(&message))
                            .await
                        {
                            Ok(_) => debug!("message sent successfully to matrix room"),
                            Err(error) => error!(
                                "sending message to matrix room failed with error: {}",
                                error
                            ),
                        };
                    }
                    Err(_) => {
                        error!("Finding the room failed");
                        exit(1)
                    }
                };
            }
            None => {
                error!("Channel closed");
                exit(1);
            }
        }
    }
}

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

                    let (tx, rx): (Sender<String>, Receiver<String>) =
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
    let transport = listener
        .next()
        .await
        .context("listener.next(): Option contains None")??;

    let encrypted_matrix_server = EncryptedMatrixServer::new(None, config);

    BaseChannel::with_defaults(transport)
        .execute(EncryptedMatrixServer::serve(encrypted_matrix_server))
        .for_each(spawn)
        .await;

    info!("Executing main finished");

    // this loop fixes it somehow. to do: prevent the microservice from exiting!
    loop {}

    Ok(())
}
