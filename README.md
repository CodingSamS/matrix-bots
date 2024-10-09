# Email to Matrix

use smtp server library (maybe https://crates.io/crates/lettre)

use rust server sdk (https://crates.io/crates/matrix-sdk)

## first time starting

start the application by hand and interactively do the verification of the client

## Regular Start

uses systemd socket for starting the application. Therefore, 

0. change the service file (correct paths for executable and config file) and copy service/socket file to /etc/systemd/system and execute systemctl daemon-reload
1. start the socket: systemctl start email-to-matrix.socket
2. Then with ```echo "<encryption key>" > /run/email-to-matrix.stdin``` the service is started and directly receives the encryption key from the fifo socket.
3. With ```history -c``` the bash history is cleared afterwards in order to avoid leaking the encryption key

# Encrypted Sender

Uses https://crates.io/crates/clap for parsing command line arguments (receiver ip, receiver port, message content (string), path to message data). Uses https://crates.io/crates/crypto_box for sending it to receiver in an encrypted manner.

# Encryption Helper

This is a helper project for encrypting and decrypting stuff. This may be useful for prestaging encrypted config files in other projects.

