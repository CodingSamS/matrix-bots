use crypto_box::{
    aead::{Aead, OsRng},
    ChaChaBox, Nonce, PublicKey, SecretKey,
};
use futures::prelude::Future;
use log::{debug, error, info, warn};
use std::sync::Arc;
use tokio::sync::Mutex;

#[tarpc::service]
pub trait EncryptedStartup {
    /// Receives the public key of the other side, processes it, and responds with the own one
    async fn sync_public_keys(alice_public_key: PublicKey) -> PublicKey;

    /// Starts up the service. sync_public_keys needs to be done beforehand
    async fn start(encryption_key_ciphertext: Vec<u8>, nonce: Vec<u8>);
}

pub trait StartupFunction {
    async fn startup_function(encryption_key: [u8; 32]);
}

/*
#[derive(Clone)]
struct EncryptedMatrixServer {
    bob_secret_key: SecretKey,
    alice_public_key_option: Arc<Mutex<Option<PublicKey>>>,
}

impl EncryptedMatrixServer {
    pub fn new(alice_public_key_option: Arc<Mutex<Option<PublicKey>>>) -> Self {
        EncryptedMatrixServer {
            bob_secret_key: SecretKey::generate(&mut OsRng),
            alice_public_key_option,
        }
    }
}

impl EncryptedStartup for EncryptedMatrixServer {
    //    type SyncPublicKeysFut = Ready<PublicKey>;
    //    type StartFut = Ready<Result<()>>;

    async fn sync_public_keys(
        self,
        _: tarpc::context::Context,
        alice_public_key: PublicKey,
    ) -> PublicKey {
        let mut lock = self.alice_public_key_option.lock().await;
        *lock = Some(alice_public_key);
        self.bob_secret_key.public_key()
    }

    async fn start(
        self,
        _context: tarpc::context::Context,
        encryption_key_ciphertext: Vec<u8>,
        nonce: Vec<u8>,
    ) {
        match self.alice_public_key_option.lock().await.to_owned() {
            Some(alice_public_key) => {
                let cha_cha_box = ChaChaBox::new(&alice_public_key, &self.bob_secret_key);
                let Ok(encrypted_vec) = cha_cha_box.decrypt(
                    &Nonce::clone_from_slice(&nonce),
                    encryption_key_ciphertext.as_slice(),
                ) else {
                    error!("Decryption failed");
                    return;
                };

                let Some(first_chunk) = encrypted_vec.first_chunk::<32>() else {
                    error!("Wrong encryption key length");
                    return;
                };

                (self.startup_function)(first_chunk.to_owned());
            }
            None => error!("public keys not synced, yet!"),
        }
    }
}
*/
