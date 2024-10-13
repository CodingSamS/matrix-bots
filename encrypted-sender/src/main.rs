use anyhow::bail;
use clap::Parser;
use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    ChaChaBox, PublicKey, SecretKey,
};
use encrypted_message::Message;
use std::net::Ipv4Addr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_serde::{formats::SymmetricalBincode, Deserializer, Framed, Serializer};
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

    let (mut socket_reader, mut socket_writer) =
        TcpStream::connect(format!("{}:{}", args.ip, args.port))
            .await?
            .into_split();

    // generate random key
    let alice_secret_key = SecretKey::generate(&mut OsRng);
    let alice_public_key = Vec::from(alice_secret_key.public_key().as_bytes());

    let message = Message::PublicKeyMessage(alice_public_key);

    socket_writer
        .write_all(&serde_json::to_vec(&message)?)
        .await?;

    let mut buf = Vec::new();
    socket_reader.read_to_end(&mut buf).await?;

    let message: Message = serde_json::from_slice(&buf)?;

    let bob_public_key = match message {
        Message::StringMessage(_) => bail!("Wrong response when expecting bobs public key"),
        Message::PublicKeyMessage(key) => PublicKey::from_slice(&key)?,
    };

    let alice_box = ChaChaBox::new(&bob_public_key, &alice_secret_key);

    let nonce = ChaChaBox::generate_nonce(&mut OsRng);

    let ciphertext = alice_box.encrypt(&nonce, args.message.as_bytes())?;

    let message = Message::PublicKeyMessage(ciphertext.to_owned());

    socket_writer
        .write_all(&serde_json::to_vec(&message)?)
        .await?;

    println!("Hello, world!");
    Ok(())
}
