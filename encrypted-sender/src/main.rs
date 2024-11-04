use clap::Parser;
use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    ChaChaBox, SecretKey,
};
use encrypted_startup::EncryptedStartupClient;
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

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let mut transport = tarpc::serde_transport::tcp::connect(args.server_addr, Bincode::default);
    transport.config_mut().max_frame_length(usize::MAX);

    let client =
        EncryptedStartupClient::new(client::Config::default(), transport.await.unwrap()).spawn();

    // generate random key
    let alice_secret_key = SecretKey::generate(&mut OsRng);
    let alice_public_key = alice_secret_key.public_key();

    let bob_public_key = client
        .sync_public_keys(context::current(), alice_public_key)
        .await
        .unwrap();

    let alice_box = ChaChaBox::new(&bob_public_key, &alice_secret_key);
    let nonce = ChaChaBox::generate_nonce(&mut OsRng);
    let ciphertext = alice_box.encrypt(&nonce, args.message.as_bytes()).unwrap();

    client
        .load_cipher(context::current(), ciphertext, nonce.to_vec())
        .await
        .unwrap()
        .unwrap();

    client.start(context::current()).await.unwrap().unwrap()
}
