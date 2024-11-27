use anyhow::Context;
use clap::Parser;
use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    ChaChaBox, SecretKey,
};
use matrix_room_bot::MatrixRoomServerClient;
use std::net::SocketAddr;
use tarpc::{client, context, tokio_serde::formats::Bincode};

/// A program to send an encrypted message to an receiver
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Message to send
    #[arg(short, long)]
    message: String,

    /// IP of receiver
    #[arg(short, long)]
    server_addr: SocketAddr,
}

async fn start(args: &Args, restart: bool) -> anyhow::Result<()> {
    let mut transport = tarpc::serde_transport::tcp::connect(args.server_addr, Bincode::default);
    transport.config_mut().max_frame_length(usize::MAX);

    let mut client =
        MatrixRoomServerClient::new(client::Config::default(), transport.await?).spawn();

    if restart {
        // stop the server first and wait a duration in order to let systemd restart it
        client
            .stop(context::current())
            .await?
            .ok()
            .context("stop failed")?;
        tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;

        transport = tarpc::serde_transport::tcp::connect(args.server_addr, Bincode::default);
        transport.config_mut().max_frame_length(usize::MAX);

        client = MatrixRoomServerClient::new(client::Config::default(), transport.await?).spawn();
    }

    // generate random key
    let alice_secret_key = SecretKey::generate(&mut OsRng);
    let alice_public_key = alice_secret_key.public_key();

    let bob_public_key = client
        .sync_public_keys(context::current(), alice_public_key)
        .await?;

    let alice_box = ChaChaBox::new(&bob_public_key, &alice_secret_key);
    let nonce = ChaChaBox::generate_nonce(&mut OsRng);
    let ciphertext = alice_box.encrypt(&nonce, args.message.as_bytes())?;

    client
        .load_cipher(context::current(), ciphertext, nonce.to_vec())
        .await?
        .ok()
        .context("load cipher failed")?;

    client
        .start(context::current())
        .await?
        .ok()
        .context("start failed")?;

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
