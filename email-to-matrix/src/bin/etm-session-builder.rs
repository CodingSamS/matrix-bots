use aes_gcm::{aead::KeyInit, Aes256Gcm, Key};
use anyhow::{bail, Context};
use config::{ClientSession, Config, EncryptedString, FullSession, INITIAL_DEVICE_DISPLAY_NAME};
use futures_util::stream::StreamExt;
use log::{debug, error, info, warn};
use matrix_sdk::{
    config::SyncSettings,
    encryption::verification::{
        format_emojis, Emoji, SasState, SasVerification, Verification, VerificationRequest,
        VerificationRequestState,
    },
    ruma::{events::key::verification::request::ToDeviceKeyVerificationRequestEvent, UserId},
    Client,
};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use std::{env, path::Path, process::exit, str};
use tokio::fs;
use tokio::io::{stdin, stdout, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::OnceCell;

static CONFIG: OnceCell<Config> = OnceCell::const_new();
static CIPHER: OnceCell<Aes256Gcm> = OnceCell::const_new();

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
    // Generate a random passphrase.
    let passphrase: String = (&mut OsRng)
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

    client.sync(SyncSettings::new()).await?;

    warn!("sync finished");

    Ok(())
}
