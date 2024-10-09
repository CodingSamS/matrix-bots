use std::{io::stdin, str};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};

struct CipherWrapper {
    c: Aes256Gcm,
}

fn main() {
    let mut len = 0;
    let mut encryption_key = String::new();
    while len != 32 {
        encryption_key = String::new();
        println!("Please enter encryption key of byte length 32:");
        stdin().read_line(&mut encryption_key).unwrap();
        len = encryption_key.trim().len();
    }
    println!("encryption key string: <{}>", encryption_key.trim());
    let key: &Key<Aes256Gcm> = encryption_key.trim().as_bytes().into();

    let mut clear_text_input = String::new();
    println!("Please enter the string to be encrypted:");
    stdin().read_line(&mut clear_text_input).unwrap();
    println!("Clear text input: <{}>", clear_text_input.trim());

    let cipher = Aes256Gcm::new(&key);
    let cw = CipherWrapper { c: cipher };
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let nonce_vec = nonce.to_vec();
    println!("nonce: <{:?}>", nonce_vec);
    let nonce = Nonce::from_slice(&nonce_vec);
    let ciphertext =
        cw.c.encrypt(&nonce, clear_text_input.trim().as_bytes())
            .unwrap();
    println!("ciphertext: <{:?}>", ciphertext);
    let plaintext = cw.c.decrypt(&nonce, ciphertext.as_ref()).unwrap();
    println!(
        "clear text output: <{}>",
        str::from_utf8(&plaintext).unwrap()
    );
}
