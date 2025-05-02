use aes_gcm::{aead::KeyInit, Aes256Gcm, Key};
use anyhow::bail;
use crypto_box::PublicKey;
use log::{debug, info, warn};
use matrix_bots::{
    encrypted_startup::EncryptedStartupHelper,
    matrix_room_bot::{
        matrix_room_bot_server::{MatrixRoomBot, MatrixRoomBotServer},
        Empty, EncryptionData, PublicKeyMessage, SendMessage, SessionState, SessionStateEnum,
    },
    matrix_room_bot_config::Config,
    matrix_util::restore_session,
};
use matrix_sdk::{
    config::SyncSettings,
    ruma::{events::room::message::RoomMessageEventContent, RoomId},
    Client,
};
use std::{env, path::PathBuf, process::exit, sync::Arc};
use tokio::{
    fs,
    sync::{Mutex, OnceCell},
    task::JoinHandle,
    time::{sleep, Duration},
};
use tonic::{transport::Server, Request, Response, Status};

async fn sync_client(client: Client) -> anyhow::Result<()> {
    let sync_settings = SyncSettings::new().timeout(Duration::from_secs(900)); // timeout for sync requests: 15 Minutes
    debug!("start sync");
    client.sync(sync_settings).await?;
    warn!("sync finished");
    Ok(())
}

async fn exit_with_delay(delay: u64) {
    info!("shutting down in 10 seconds");
    sleep(Duration::from_secs(delay)).await;
    exit(0);
}

struct MatrixRoomBotImpl {
    helper: EncryptedStartupHelper,
    session_file: Arc<PathBuf>,
    client: Arc<Mutex<OnceCell<Client>>>,
    cipher: Arc<Mutex<OnceCell<Aes256Gcm>>>,
    matrix_sync_handle: Arc<Mutex<OnceCell<JoinHandle<anyhow::Result<()>>>>>,
    matrix_room_id: Box<RoomId>,
}

impl MatrixRoomBotImpl {
    fn new(
        alice_public_key_option: Option<PublicKey>,
        matrix_data_dir: PathBuf,
        matrix_room_id: Box<RoomId>, //        config: Config,
    ) -> Self {
        MatrixRoomBotImpl {
            helper: EncryptedStartupHelper::new(alice_public_key_option),
            session_file: Arc::new(matrix_data_dir.join("session").to_owned()),
            client: Arc::new(Mutex::new(OnceCell::new())),
            cipher: Arc::new(Mutex::new(OnceCell::new())),
            matrix_sync_handle: Arc::new(Mutex::new(OnceCell::new())),
            matrix_room_id,
        }
    }
}

#[tonic::async_trait]
impl MatrixRoomBot for MatrixRoomBotImpl {
    async fn sync_public_keys(
        &self,
        alice_public_key_message: Request<PublicKeyMessage>,
    ) -> Result<Response<PublicKeyMessage>, Status> {
        let Ok(alice_public_key) =
            PublicKey::from_slice(&alice_public_key_message.into_inner().public_key_bytes)
        else {
            return Err(Status::internal("Parsing bytes to public key failed"));
        };
        self.helper.set_alice_public_key(alice_public_key).await;
        Ok(PublicKeyMessage {
            public_key_bytes: self.helper.bob_secret_key.public_key().as_bytes().into(),
        }
        .into())
    }

    async fn load_cipher(
        &self,
        encryption_data_message: Request<EncryptionData>,
    ) -> Result<Response<SessionState>, Status> {
        let encryption_data = encryption_data_message.into_inner();
        let decryption_result = self
            .helper
            .decrypt(
                encryption_data.encryption_key_ciphertext,
                encryption_data.nonce,
            )
            .await;
        match decryption_result {
            Ok(encryption_key) => {
                let key = Key::<Aes256Gcm>::from_slice(&encryption_key);
                let cipher = Aes256Gcm::new(&key);
                match self.cipher.lock().await.set(cipher) {
                    Ok(()) => match self.session_file.exists() {
                        true => Ok(SessionState {
                            session_state: Some(SessionStateEnum::SessionExists.into()),
                        }
                        .into()),
                        false => Ok(SessionState {
                            session_state: Some(SessionStateEnum::SessionMissing.into()),
                        }
                        .into()),
                    },
                    Err(_) => Err(Status::internal("Writing cipher failed").into()),
                }
            }
            Err(_) => Err(Status::internal("Decrypting the message failed").into()),
        }
    }

    async fn start(&self, _: Request<Empty>) -> Result<Response<Empty>, Status> {
        if self.session_file.exists() {
            if let Some(cipher) = self.cipher.lock().await.get() {
                if !self.matrix_sync_handle.lock().await.initialized() {
                    match restore_session(&self.session_file, cipher).await {
                        Ok(client) => {
                            if self.client.lock().await.set(client.to_owned()).is_err() {
                                return Err(Status::internal("Storing Matrix Client failed").into());
                            }
                            let handle = tokio::spawn(sync_client(client));
                            if self.matrix_sync_handle.lock().await.set(handle).is_err() {
                                return Err(
                                    Status::internal("Storing Matrix Sync handle failed").into()
                                );
                            };
                            info!("Session restored successfully");
                        }
                        Err(_) => {
                            return Err(Status::internal("Loading client session failed").into())
                        }
                    };

                    Ok(Empty::default().into())
                } else {
                    Err(Status::internal("Server already started").into())
                }
            } else {
                Err(Status::internal("No cipher available. Load cipher first").into())
            }
        } else {
            Err(Status::internal("Session file does not exist").into())
        }
    }

    async fn stop(&self, _: Request<Empty>) -> Result<Response<Empty>, Status> {
        tokio::spawn(exit_with_delay(10));
        Ok(Empty::default().into())
    }

    async fn send(&self, message: Request<SendMessage>) -> Result<Response<Empty>, Status> {
        let client_lock = self.client.lock().await;
        let Some(client) = client_lock.get() else {
            return Err(Status::internal("Client not initialised").into());
        };
        let Some(room) = client.get_room(&self.matrix_room_id) else {
            return Err(Status::internal("room not found").into());
        };
        match room
            .send(RoomMessageEventContent::text_plain(
                message.into_inner().message,
            ))
            .await
        {
            Ok(_) => Ok(Empty::default().into()),
            Err(_) => Err(Status::internal("Sending message to matrix room failed").into()),
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

    let matrix_room_bot =
        MatrixRoomBotImpl::new(None, config.matrix_data_dir, config.matrix_room_id);

    Server::builder()
        .add_service(MatrixRoomBotServer::new(matrix_room_bot))
        .serve(config.microservice_socket)
        .await?;

    Ok(())
}
