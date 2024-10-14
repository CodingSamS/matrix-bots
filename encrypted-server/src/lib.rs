use crypto_box::{
    aead::{Aead, OsRng},
    ChaChaBox, Nonce, PublicKey, SecretKey,
};
use futures::{
    future::{self, ready, Ready},
    prelude::*,
};
use tarpc::{
    client, context,
    server::{self, incoming::Incoming, Channel},
};

#[tarpc::service]
pub trait EncryptedRPCs {
    /// Receives the public key of the other side, processes it, and responds with the own one
    async fn sync_public_keys(alice_public_key: PublicKey) -> PublicKey;

    /// Starts up the service. sync_public_keys needs to be done beforehand
    async fn start(encryption_key_ciphertext: Vec<u8>, nonce: Vec<u8>) -> Result<(), String>;
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
    //    type SyncPublicKeysFut = Ready<PublicKey>;
    //    type StartFut = Ready<Result<()>>;

    async fn sync_public_keys(
        mut self,
        _: tarpc::context::Context,
        alice_public_key: PublicKey,
    ) -> PublicKey {
        self.bob_cha_cha_box = Some(ChaChaBox::new(&alice_public_key, &self.bob_secret_key));
        self.bob_secret_key.public_key()
    }

    async fn start(
        mut self,
        _context: tarpc::context::Context,
        encryption_key_ciphertext: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<(), String> {
        match self.bob_cha_cha_box {
            Some(cha_cha_box) => {
                let Ok(encrypted_vec) = cha_cha_box.decrypt(
                    &Nonce::clone_from_slice(&nonce),
                    encryption_key_ciphertext.as_slice(),
                ) else {
                    return Err(String::from("Decryption failed"));
                };

                let Some(first_chunk) = encrypted_vec.first_chunk::<32>() else {
                    return Err(String::from("Wrong encryption key length"));
                };

                self.encryption_key = Some(first_chunk.to_owned());

                Ok(())
            }
            None => Err(String::from("public keys not synced, yet!")),
        }
    }
}
