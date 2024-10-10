use clap::Parser;
use crypto_box::{aead::OsRng, PublicKey, SecretKey};
use encrypted_message::Message;
use std::net::Ipv4Addr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// A program to send an encrypted message to an receiver
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Message to send
    #[arg(short, long)]
    message: String,

    /// IP of receiver
    #[arg(short, long)]
    ip: Ipv4Addr,

    /// Port of receiver
    #[arg(short, long)]
    port: u8,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut stream = TcpStream::connect(format!("{}:{}", args.ip, args.port)).await?;

    let message = Message::StringMessage(args.message);

    let d = serde_json::to_vec(&message)?;

    stream.write_all(&d).await?;

    let ip = args.ip;

    let alice_secret_key = SecretKey::generate(&mut OsRng);
    let alice_public_key = alice_secret_key.public_key().as_bytes().clone();

    let alice_public_key_receiving = PublicKey::from_bytes(alice_public_key);
    println!("Hello, world!");
    Ok(())
}
