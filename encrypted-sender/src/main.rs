use crypto_box::aead::OsRng;
use crypto_box::PublicKey;
use crypto_box::SecretKey;

fn main() {
    let alice_secret_key = SecretKey::generate(&mut OsRng);
    let alice_public_key = alice_secret_key.public_key().as_bytes().clone();

    let alice_public_key_receiving = PublicKey::from_bytes(alice_public_key);
    println!("Hello, world!");
}
