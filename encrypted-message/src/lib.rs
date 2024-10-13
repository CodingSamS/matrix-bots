use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    StringMessage(String),
    PublicKeyMessage([u8; 32]),
}

fn test() {
    let t = Message::StringMessage(String::from("test"));
}
