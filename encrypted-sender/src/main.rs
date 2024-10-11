use clap::Parser;
use crypto_box::{aead::OsRng, PublicKey, SecretKey};
use encrypted_message::Message;
use std::net::Ipv4Addr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_serde::formats::SymmetricalBincode;
use tokio_util::codec::{FramedWrite, LengthDelimitedCodec};

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

    let socket = TcpStream::connect(format!("{}:{}", args.ip, args.port)).await?;

    // Delimit frames using a length header
    let length_delimited = FramedWrite::new(socket, LengthDelimitedCodec::new());

    // Serialize frames with Bincode
    let mut serialized =
        tokio_serde::SymmetricallyFramed::new(length_delimited, SymmetricalBincode::default());

    // generate random key
    let alice_secret_key = SecretKey::generate(&mut OsRng);
    let alice_public_key = alice_secret_key.public_key().as_bytes().clone();

    let message = Message::PublicKeyMessage(alice_public_key);
    serialized.send();

    // send public key to bob
    stream.write_all(&serde_json::to_vec(&Message::PublicKeyMessage(alice_public_key))?)

    let alice_public_key_receiving = PublicKey::from_bytes(alice_public_key);
    println!("Hello, world!");
    Ok(())
}
