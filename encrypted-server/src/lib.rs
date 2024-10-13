use anyhow::{bail, Result};
use crypto_box::{
    aead::{Aead, OsRng},
    ChaChaBox, Nonce, PublicKey, SecretKey,
};
use futures::{
    future::{self, Ready},
    prelude::*,
};
use tarpc::{
    client, context,
    server::{self, incoming::Incoming, Channel},
};

#[tarpc::service]
trait EncryptedRPCs {
    /// Receives the public key of the other side, processes it, and responds with the own one
    async fn sync_public_keys(alice_public_key: PublicKey) -> PublicKey;

    /// Starts up the service. sync_public_keys needs to be done beforehand
    async fn start(encryption_key_ciphertext: Vec<u8>, nonce: Nonce) -> Result<()>;
}

pub struct EncryptedServer {
    encryption_key: Option<[u8; 32]>,
    bob_secret_key: SecretKey,
    bob_cha_cha_box: Option<ChaChaBox>,
}

impl EncryptedServer {
    fn new() -> Self {
        EncryptedServer {
            encryption_key: None,
            bob_secret_key: SecretKey::generate(&mut OsRng),
            bob_cha_cha_box: None,
        }
    }
}

impl EncryptedRPCs for EncryptedServer {
    async fn sync_public_keys(
        mut self,
        _: tarpc::context::Context,
        alice_public_key: PublicKey,
    ) -> PublicKey {
        self.bob_cha_cha_box = Some(ChaChaBox::new(&alice_public_key, &self.bob_secret_key));
        self.bob_secret_key.public_key()
    }

    fn start(
        mut self,
        _context: tarpc::context::Context,
        encryption_key_ciphertext: Vec<u8>,
        nonce: Nonce,
    ) -> Result<()> {
        match self.bob_cha_cha_box {
            Some(cha_cha_box) => {
                let t = Some(
                    cha_cha_box
                        .decrypt(&nonce, encryption_key_ciphertext.as_slice())?
                        .first_chunk::<32>()
                        .ok_or(String::from("Byte length of key is not 32"))?,
                );

                Ok(())
            }
            None => bail!("public keys not synced, yet!"),
        }
    }
}
