use std::{
    env,
    fmt::Debug,
    net::IpAddr,
    path::{Path, PathBuf},
    process::exit,
    str,
};

use anyhow::{bail, Context};
use futures_util::stream::StreamExt;
use log::{debug, error, info, warn};
use mail_parser::MessageParser;
use mailin::SessionBuilder;
use rand::{distributions::Alphanumeric, thread_rng, Rng};

use matrix_sdk::{
    config::SyncSettings,
    encryption::verification::{
        format_emojis, Emoji, SasState, SasVerification, Verification, VerificationRequest,
        VerificationRequestState,
    },
    matrix_auth::MatrixSession,
    ruma::{
        events::{
            key::verification::request::ToDeviceKeyVerificationRequestEvent,
            room::message::RoomMessageEventContent,
        },
        RoomId, UserId,
    },
    Client,
};

use retry::delay::Fixed;
use retry::retry;

use serde::{Deserialize, Serialize};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use tokio::fs;
use tokio::io::{stdin, stdout, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::OnceCell;
use tokio::time::sleep;
use tokio::time::Duration;

const INITIAL_DEVICE_DISPLAY_NAME: &str = "Mail Notif Bot";
const CHANNEL_BUFFER_SIZE: usize = 100;
const MAIL_HANDLER_SEND_MAX_RETRIES: u32 = 5;
static CONFIG: OnceCell<Config> = OnceCell::const_new();
static CIPHER: OnceCell<Aes256Gcm> = OnceCell::const_new();

#[derive(Serialize, Deserialize, Debug)]
struct EncryptedString {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
}

impl EncryptedString {
    fn new(cleartext: String, cipher: &Aes256Gcm) -> Result<Self, aes_gcm::Error> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let nonce_vec = nonce.to_vec();
        let ciphertext = cipher.encrypt(&nonce, cleartext.trim().as_bytes())?;
        Ok(EncryptedString {
            ciphertext,
            nonce: nonce_vec,
        })
    }

    fn get_decrypted_string(&self, cipher: &Aes256Gcm) -> anyhow::Result<String> {
        let plaintext_bytes =
            cipher.decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_ref())?;
        let plaintext = str::from_utf8(&plaintext_bytes)?;
        Ok(plaintext.to_string())
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    matrix_user: String,
    matrix_password: EncryptedString,
    matrix_homeserver: String,
    matrix_room_id: Box<RoomId>,
    matrix_data_dir: PathBuf,
    mail_server_name: String,
    mail_from: String, // this is the src address that needs to match (protection against misuse)
    mail_to: String, // this is the dst address that needs to match (protection against misuse / option for multitenancy)
}

/// The data needed to re-build a client.
#[derive(Debug, Serialize, Deserialize)]
struct ClientSession {
    /// The URL of the homeserver of the user.
    homeserver: String,

    /// The path of the database.
    db_path: PathBuf,

    /// The passphrase of the database.
    passphrase: EncryptedString,
}

/// The full session to persist.
#[derive(Debug, Serialize, Deserialize)]
struct FullSession {
    /// The data to re-build the client.
    client_session: ClientSession,

    /// The Matrix user session.
    user_session: MatrixSession,
}

struct MailHandler {
    tx: Sender<String>,
    data: Vec<u8>,
    is_from_valid: bool,
    is_to_valid: bool,
}

impl MailHandler {
    fn new(tx: Sender<String>) -> Self {
        MailHandler {
            tx,
            data: Vec::new(),
            is_from_valid: false,
            is_to_valid: false,
        }
    }
}

impl mailin::Handler for MailHandler {
    fn helo(&mut self, _ip: IpAddr, _domain: &str) -> mailin::Response {
        (self.is_from_valid, self.is_to_valid) = (false, false);
        mailin::response::OK
    }

    fn mail(&mut self, _ip: IpAddr, _domain: &str, from: &str) -> mailin::Response {
        match from.contains(&CONFIG.get().unwrap().mail_from) {
            true => {
                self.is_from_valid = true;
                mailin::response::OK
            }
            false => {
                (self.is_from_valid, self.is_to_valid) = (false, false);
                mailin::response::NO_MAILBOX
            }
        }
    }

    fn rcpt(&mut self, to: &str) -> mailin::Response {
        match to.contains(&CONFIG.get().unwrap().mail_to) {
            true => {
                self.is_to_valid = true;
                mailin::response::OK
            }
            false => {
                (self.is_from_valid, self.is_to_valid) = (false, false);
                mailin::response::NO_MAILBOX
            }
        }
    }

    fn data_start(
        &mut self,
        _domain: &str,
        _from: &str,
        _is8bit: bool,
        _to: &[String],
    ) -> mailin::Response {
        match (self.is_from_valid, self.is_to_valid) {
            (true, true) => {
                self.data = Vec::new();
                mailin::response::START_DATA
            }
            _ => {
                (self.is_from_valid, self.is_to_valid) = (false, false);
                mailin::response::INTERNAL_ERROR
            }
        }
    }

    fn data(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match (self.is_from_valid, self.is_to_valid) {
            (true, true) => {
                self.data.extend_from_slice(buf);
                Ok(())
            }
            _ => {
                (self.is_from_valid, self.is_to_valid) = (false, false);
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "from or to is not valid",
                ))
            }
        }
    }

    fn data_end(&mut self) -> mailin::Response {
        match (self.is_from_valid, self.is_to_valid) {
            (true, true) => {
                let chat_message = match MessageParser::default().parse(&self.data) {
                    Some(message) => match (message.subject(), message.body_text(0)) {
                        (Some(subject), Some(body)) => {
                            format!("Subject: {}\n\n{}", subject.to_string(), body.to_string())
                        }
                        _ => {
                            warn!("Could not parse subject or body from mail");
                            return mailin::response::INTERNAL_ERROR;
                        }
                    },
                    None => {
                        warn!("Could not parse raw mail message");
                        return mailin::response::INTERNAL_ERROR;
                    }
                };
                /*
                let message = match parse_mail(&self.data) {
                    Ok(parsed_mail) => match parsed_mail.get_body() {
                        Ok(body) => body,
                        Err(error) => {
                            warn!("Extracting body failed with: {}", error);
                            return mailin::response::INTERNAL_ERROR;
                        }
                    },
                    Err(error) => {
                        warn!("Parsing mail failed with error: {}", error);
                        return mailin::response::INTERNAL_ERROR;
                    }
                };
                */
                for i in 1..=MAIL_HANDLER_SEND_MAX_RETRIES {
                    match self.tx.try_send(chat_message.to_owned()) {
                        Ok(_) => {
                            debug!("send handler->matrix thread: successful");
                            break;
                        }
                        Err(_) => {
                            warn!(
                                "send handler->matrix thread: failed (Try {}/{})",
                                i, MAIL_HANDLER_SEND_MAX_RETRIES
                            );
                            std::thread::sleep(Duration::from_secs(5));
                        }
                    };
                }
                (self.is_from_valid, self.is_to_valid) = (false, false);
                mailin::response::OK
            }
            _ => {
                (self.is_from_valid, self.is_to_valid) = (false, false);
                mailin::response::INTERNAL_ERROR
            }
        }
    }
}

async fn print_devices(user_id: &UserId, client: &Client) {
    info!("Devices of user {user_id}");

    for device in client
        .encryption()
        .get_user_devices(user_id)
        .await
        .unwrap()
        .devices()
    {
        if device.device_id()
            == client
                .device_id()
                .expect("We should be logged in now and know our device id")
        {
            continue;
        }

        info!(
            "   {:<10} {:<30} {:<}",
            device.device_id(),
            device.display_name().unwrap_or("-"),
            if device.is_verified() { "✅" } else { "❌" }
        );
    }
}

async fn wait_for_confirmation(sas: SasVerification, emoji: [Emoji; 7]) {
    println!("\nDo the emojis match: \n{}", format_emojis(emoji));
    print!("Confirm with `yes` or cancel with `no`: ");
    stdout()
        .flush()
        .await
        .expect("We should be able to flush stdout");

    let mut input = String::new();
    let mut stdin_reader = BufReader::new(stdin());
    stdin_reader
        .read_line(&mut input)
        .await
        .expect("error: unable to read user input");

    match input.trim().to_lowercase().as_ref() {
        "yes" | "true" | "ok" => sas.confirm().await.unwrap(),
        _ => sas.cancel().await.unwrap(),
    }
}

async fn sas_verification_handler(client: Client, sas: SasVerification) {
    println!(
        "Starting verification with {} {}",
        &sas.other_device().user_id(),
        &sas.other_device().device_id()
    );
    print_devices(sas.other_device().user_id(), &client).await;
    sas.accept().await.unwrap();

    let mut stream = sas.changes();

    while let Some(state) = stream.next().await {
        match state {
            SasState::KeysExchanged {
                emojis,
                decimals: _,
            } => {
                tokio::spawn(wait_for_confirmation(
                    sas.clone(),
                    emojis
                        .expect("We only support verifications using emojis")
                        .emojis,
                ));
            }
            SasState::Done { .. } => {
                let device = sas.other_device();

                println!(
                    "Successfully verified device {} {} {:?}",
                    device.user_id(),
                    device.device_id(),
                    device.local_trust_state()
                );

                print_devices(sas.other_device().user_id(), &client).await;

                break;
            }
            SasState::Cancelled(cancel_info) => {
                println!(
                    "The verification has been cancelled, reason: {}",
                    cancel_info.reason()
                );

                break;
            }
            SasState::Started { .. }
            | SasState::Accepted { .. }
            | SasState::Confirmed
            | SasState::Created { .. } => (),
        }
    }
}

async fn request_verification_handler(client: Client, request: VerificationRequest) {
    println!(
        "Accepting verification request from {}",
        request.other_user_id(),
    );
    request
        .accept()
        .await
        .expect("Can't accept verification request");

    let mut stream = request.changes();

    while let Some(state) = stream.next().await {
        match state {
            VerificationRequestState::Created { .. }
            | VerificationRequestState::Requested { .. }
            | VerificationRequestState::Ready { .. } => (),
            VerificationRequestState::Transitioned { verification } => {
                // We only support SAS verification.
                if let Verification::SasV1(s) = verification {
                    tokio::spawn(sas_verification_handler(client, s));
                    break;
                }
            }
            VerificationRequestState::Done | VerificationRequestState::Cancelled(_) => break,
        }
    }
}

/// Login with a new device.
async fn login(session_file: &Path) -> anyhow::Result<Client> {
    let mut rng = thread_rng();
    // Generate a random passphrase.
    let passphrase: String = (&mut rng)
        .sample_iter(Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let db_path = CONFIG
        .get()
        .context("no config")?
        .matrix_data_dir
        .join("db");

    let client = Client::builder()
        .homeserver_url(&CONFIG.get().context("no config")?.matrix_homeserver)
        // We use the SQLite store, which is enabled by default. This is the crucial part to
        // persist the encryption setup.
        // Note that other store backends are available and you can even implement your own.
        .sqlite_store(&db_path, Some(&passphrase))
        .build()
        .await?;

    let passphrase_encrypted =
        EncryptedString::new(passphrase, CIPHER.get().context("no cipher")?)?;

    let client_session = ClientSession {
        homeserver: CONFIG
            .get()
            .context("no config")?
            .matrix_homeserver
            .to_owned(),
        db_path,
        passphrase: passphrase_encrypted,
    };

    let password = &CONFIG
        .get()
        .context("no config")?
        .matrix_password
        .get_decrypted_string(CIPHER.get().context("no cipher")?)?;

    let matrix_auth = client.matrix_auth();
    matrix_auth
        .login_username(&CONFIG.get().context("no config")?.matrix_user, password)
        .initial_device_display_name(INITIAL_DEVICE_DISPLAY_NAME)
        .await?;

    let user_session = matrix_auth
        .session()
        .context("a logged in client should have a session")?;

    let serialised_session = serde_json::to_string(&FullSession {
        client_session,
        user_session,
    })?;

    fs::write(session_file, serialised_session).await?;

    // verify the client
    client.add_event_handler(
        |ev: ToDeviceKeyVerificationRequestEvent, client: Client| async move {
            let request = client
                .encryption()
                .get_verification_request(&ev.sender, &ev.content.transaction_id)
                .await
                .expect("Request object wasn't created");

            tokio::spawn(request_verification_handler(client, request));
        },
    );

    Ok(client)
}

/// Restore a previous session.
async fn restore_session(session_file: &Path) -> anyhow::Result<Client> {
    info!(
        "Previous session found in '{}'",
        session_file.to_string_lossy()
    );

    // The session was serialized as JSON in a file.
    let serialized_session = fs::read_to_string(session_file).await?;
    let FullSession {
        client_session,
        user_session,
    } = serde_json::from_str(&serialized_session)?;

    // Build the client with the previous settings from the session.
    let passphrase = client_session
        .passphrase
        .get_decrypted_string(CIPHER.get().context("no cipher")?)?;

    let client = Client::builder()
        .homeserver_url(&client_session.homeserver)
        .sqlite_store(&client_session.db_path, Some(&passphrase))
        .build()
        .await?;

    info!("Restoring session for {}…", user_session.meta.user_id);

    // Restore the Matrix user session.
    client.restore_session(user_session).await?;

    Ok(client)
}

async fn listen_to_socket_and_send_to_matrix(
    tx: Sender<String>,
    mut stream: TcpStream,
) -> anyhow::Result<()> {
    let handler = MailHandler::new(tx);

    let remote_addr = stream.peer_addr()?;

    let session = &mut SessionBuilder::new(
        CONFIG
            .get()
            .context("no config")?
            .mail_server_name
            .to_owned(),
    )
    .build(remote_addr.ip(), handler);

    let (stream_rx, mut stream_tx) = stream.split();

    let greeting = session.greeting().buffer()?;

    stream_tx.write(&greeting).await?;

    let mut buf_read = BufReader::new(stream_rx);
    let mut command = String::new();
    //    stream.set_read_timeout(Some(Duration::from_secs(60)))?;

    loop {
        command.clear();
        let len = buf_read.read_line(&mut command).await?;
        let response = if 0 < len {
            session.process(command.as_bytes())
        } else {
            break;
        };
        //debug!("Mailin response: {:?}", response);
        match response.action {
            mailin::Action::Close => {
                stream_tx.write(&response.buffer()?).await?;
                break;
            }
            mailin::Action::UpgradeTls => bail!("TLS requested"),
            mailin::Action::NoReply => continue,
            mailin::Action::Reply => {
                stream_tx.write(&response.buffer()?).await?;
                ()
            }
        }
    }

    Ok(())
}

async fn mail_server(tx: Sender<String>) -> anyhow::Result<()> {
    // handling incoming connections
    let Ok(socket) = TcpListener::bind("0.0.0.0:25000").await else {
        error!("binding socket failed");
        exit(1)
    };

    while let Ok((stream, _)) = socket.accept().await {
        match listen_to_socket_and_send_to_matrix(tx.clone(), stream).await {
            Ok(_) => (),
            Err(err) => warn!("failure processing message: {}", err),
        }
    }

    warn!("no incoming sockets left");

    Ok(())
}

async fn matrix_room_bot(client: Client, mut rx: Receiver<String>) -> anyhow::Result<()> {
    let room_id = &CONFIG.get().context("no config")?.matrix_room_id.clone();

    // remove this room variable and the test send later
    let test_room = match retry(Fixed::from_millis(5000).take(12), || {
        match client.get_room(room_id) {
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

    // test send
    test_room
        .send(RoomMessageEventContent::text_plain("let's PARTY!!"))
        .await?;

    // listen for events to send
    loop {
        debug!("wait for event");
        match rx.recv().await {
            Some(message) => {
                debug!("matrix room boot received message");
                match retry(Fixed::from_millis(5000).take(12), || {
                    match client.get_room(room_id) {
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

async fn _test_sender(tx: Sender<String>) -> anyhow::Result<()> {
    let mut count = 0;
    loop {
        tx.send(format!("test {}", count)).await.unwrap();
        count += 1;
        sleep(Duration::from_secs(300)).await;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let config_path = match env::args().nth(1) {
        Some(path) => path,
        None => bail!("Usage: {} <path_to_config>", env::args().next().unwrap()),
    };

    let data = fs::read_to_string(config_path).await?;
    let config: Config = serde_json::from_str(&data)?;
    match CONFIG.set(config) {
        Ok(()) => debug!("Writing Config to OnceLock was successful"),
        Err(_) => {
            error!("Writing Config to OnceLock failed");
            exit(1)
        }
    };

    let session_file = &CONFIG
        .get()
        .context("no config")?
        .matrix_data_dir
        .join("session");

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
    match CIPHER.set(cipher) {
        Ok(()) => debug!("Writing cipher to OnceLock was successful"),
        Err(_) => {
            error!("Writing cipher to OnceLock failed");
            exit(1)
        }
    };

    let client = if session_file.exists() {
        restore_session(&session_file).await?
    } else {
        login(&session_file).await?
    };

    let (tx, rx): (Sender<String>, Receiver<String>) = mpsc::channel(CHANNEL_BUFFER_SIZE);

    tokio::spawn(matrix_room_bot(client.to_owned(), rx));

    tokio::spawn(mail_server(tx));

    info!("server started");

    let sync_settings = SyncSettings::new().timeout(Duration::from_secs(900)); // timeout for sync requests: 15 Minutes

    client.sync(sync_settings).await?;

    warn!("sync finished");

    Ok(())
}
