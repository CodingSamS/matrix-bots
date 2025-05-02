use clap::Parser;
use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    ChaChaBox, PublicKey, SecretKey,
};
use matrix_bots::matrix_room_bot::{
    matrix_room_bot_client::MatrixRoomBotClient, Empty, EncryptionData, PublicKeyMessage,
};
use tonic::transport::Endpoint;

/// A program to send an encrypted message to an receiver
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Message to send
    #[arg(short, long)]
    message: String,

    /// IP of receiver
    #[arg(short, long)]
    server_addr: Endpoint,
}

async fn start(args: &Args, restart: bool) -> anyhow::Result<()> {
    let mut client = MatrixRoomBotClient::connect(args.server_addr.to_owned()).await?;

    if restart {
        // stop the server first and wait a duration in order to let systemd restart it
        client.stop(tonic::Request::new(Empty {})).await?;

        tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;

        client = MatrixRoomBotClient::connect(args.server_addr.to_owned()).await?;
    }

    // generate random key
    let alice_secret_key = SecretKey::generate(&mut OsRng);
    let alice_public_key = alice_secret_key.public_key();

    let response = client
        .sync_public_keys(PublicKeyMessage {
            public_key_bytes: alice_public_key.as_bytes().into(),
        })
        .await?;

    let bob_public_key = PublicKey::from_slice(&response.into_inner().public_key_bytes)?;

    let alice_box = ChaChaBox::new(&bob_public_key, &alice_secret_key);
    let nonce = ChaChaBox::generate_nonce(&mut OsRng);
    let ciphertext = alice_box.encrypt(&nonce, args.message.as_bytes())?;

    client
        .load_cipher(EncryptionData {
            encryption_key_ciphertext: ciphertext,
            nonce: nonce.to_vec(),
        })
        .await?;

    client.start(Empty {}).await?;

    Ok(())
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    match start(&args, false).await {
        Ok(()) => println!("Starting was successful"),
        Err(e) => {
            eprintln!("Error when trying to start: {}\nTrying to restart...", e);
            match start(&args, true).await {
                Ok(()) => println!("Restarting was successful"),
                Err(e) => eprintln!("Error when trying to restart: {}\nExiting...", e),
            }
        }
    }
}
