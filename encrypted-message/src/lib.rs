pub enum Message {
    StringMessage(String),
    PublicKeyMessage([u8; 32]),
}
