use crypto_box::{aead::Aead, ChaChaBox, Nonce, PublicKey, SecretKey};
use std::sync::Arc;
use tokio::sync::Mutex;

#[tarpc::service]
pub trait EncryptedStartup {
    /// Receives the public key of the other side, processes it, and responds with the own one
    async fn sync_public_keys(alice_public_key: PublicKey) -> PublicKey;

    /// Starts up the service. sync_public_keys needs to be done beforehand
    async fn start(encryption_key_ciphertext: Vec<u8>, nonce: Vec<u8>);
}

#[derive(Clone)]
pub struct EncryptedStartupHelper {
    pub bob_secret_key: SecretKey,
    alice_public_key_option: Arc<Mutex<Option<PublicKey>>>,
}

impl EncryptedStartupHelper {
    pub fn new(alice_public_key_option: Arc<Mutex<Option<PublicKey>>>) -> Self {
        EncryptedStartupHelper {
            bob_secret_key: SecretKey::generate(&mut OsRng),
            alice_public_key_option,
        }
    }

    pub async fn set_alice_public_key(&self, alice_public_key: PublicKey) {
        let mut lock = self.alice_public_key_option.lock().await;
        *lock = Some(alice_public_key);
    }

    pub async fn decrypt(
        self,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<[u8; 32], &'static str> {
        match self.alice_public_key_option.lock().await.to_owned() {
            Some(alice_public_key) => {
                let cha_cha_box = ChaChaBox::new(&alice_public_key, &self.bob_secret_key);
                let Ok(encrypted_vec) =
                    cha_cha_box.decrypt(&Nonce::clone_from_slice(&nonce), ciphertext.as_slice())
                else {
                    return Err("Decryption failed");
                };

                let Some(first_chunk) = encrypted_vec.first_chunk::<32>() else {
                    return Err("Wrong encryption key length");
                };

                drop(cha_cha_box);

                Ok(first_chunk.to_owned())
            }
            None => Err("public keys not synced, yet!"),
        }
    }
}
