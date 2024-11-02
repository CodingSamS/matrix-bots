use aes_gcm::Aes256Gcm;
use anyhow::Context;
use encrypted_string::EncryptedString;
use futures_util::stream::StreamExt;
use log::info;
use matrix_sdk::{
    encryption::verification::{
        format_emojis, Emoji, SasState, SasVerification, Verification, VerificationRequest,
        VerificationRequestState,
    },
    matrix_auth::MatrixSession,
    ruma::{events::key::verification::request::ToDeviceKeyVerificationRequestEvent, UserId},
    Client,
};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    str,
};
use tokio::{
    fs,
    io::{stdin, stdout, AsyncBufReadExt, AsyncWriteExt, BufReader},
};

/// The data needed to re-build a client.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientSession {
    /// The URL of the homeserver of the user.
    pub homeserver: String,

    /// The path of the database.
    pub db_path: PathBuf,

    /// The passphrase of the database.
    pub passphrase: EncryptedString,
}

/// The full session to persist.
#[derive(Debug, Serialize, Deserialize)]
pub struct FullSession {
    /// The data to re-build the client.
    pub client_session: ClientSession,

    /// The Matrix user session.
    pub user_session: MatrixSession,
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
pub async fn login(
    session_file: &Path,
    cipher: &Aes256Gcm,
    initial_device_display_name: &str,
    matrix_data_dir: &PathBuf,
    matrix_homeserver: String,
    matrix_user: &String,
    matrix_password: &EncryptedString,
) -> anyhow::Result<Client> {
    // Generate a random passphrase.
    let passphrase: String = (&mut OsRng)
        .sample_iter(Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let db_path = matrix_data_dir.join("db");

    let client = Client::builder()
        .homeserver_url(matrix_homeserver.to_owned())
        // We use the SQLite store, which is enabled by default. This is the crucial part to
        // persist the encryption setup.
        // Note that other store backends are available and you can even implement your own.
        .sqlite_store(&db_path, Some(&passphrase))
        .build()
        .await?;

    let passphrase_encrypted = EncryptedString::new(passphrase, cipher)?;

    let client_session = ClientSession {
        homeserver: matrix_homeserver,
        db_path,
        passphrase: passphrase_encrypted,
    };

    let password = matrix_password.get_decrypted_string(cipher)?;

    let matrix_auth = client.matrix_auth();
    matrix_auth
        .login_username(matrix_user, &password)
        .initial_device_display_name(initial_device_display_name)
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
pub async fn restore_session(session_file: &Path, cipher: &Aes256Gcm) -> anyhow::Result<Client> {
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
    let passphrase = client_session.passphrase.get_decrypted_string(cipher)?;

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
