use anyhow::bail;
use log::{debug, error, warn};
use mail_parser::MessageParser;
use mailin::SessionBuilder;
use std::net::IpAddr;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::mpsc::Sender,
    time::Duration,
};

const MAIL_HANDLER_SEND_MAX_RETRIES: u32 = 5;

struct MailHandler<'a> {
    tx: Sender<String>,
    data: Vec<u8>,
    is_from_valid: bool,
    is_to_valid: bool,
    mail_from: &'a String,
    mail_to: &'a String,
}

impl<'a> MailHandler<'a> {
    fn new(tx: Sender<String>, mail_from: &'a String, mail_to: &'a String) -> Self {
        MailHandler {
            tx,
            data: Vec::new(),
            is_from_valid: false,
            is_to_valid: false,
            mail_from,
            mail_to,
        }
    }
}

impl<'a> mailin::Handler for MailHandler<'a> {
    fn helo(&mut self, _ip: IpAddr, _domain: &str) -> mailin::Response {
        (self.is_from_valid, self.is_to_valid) = (false, false);
        debug!("helo received");
        mailin::response::OK
    }

    fn mail(&mut self, _ip: IpAddr, _domain: &str, from: &str) -> mailin::Response {
        debug!("mail received");
        match from.contains(self.mail_from) {
            true => {
                self.is_from_valid = true;
                mailin::response::OK
            }
            false => {
                (self.is_from_valid, self.is_to_valid) = (false, false);
                mailin::response::NO_MAILBOX
            }
        }
    }

    fn rcpt(&mut self, to: &str) -> mailin::Response {
        debug!("rcpt received");
        match to.contains(self.mail_to) {
            true => {
                self.is_to_valid = true;
                mailin::response::OK
            }
            false => {
                (self.is_from_valid, self.is_to_valid) = (false, false);
                mailin::response::NO_MAILBOX
            }
        }
    }

    fn data_start(
        &mut self,
        _domain: &str,
        _from: &str,
        _is8bit: bool,
        _to: &[String],
    ) -> mailin::Response {
        debug!("data_start received");
        match (self.is_from_valid, self.is_to_valid) {
            (true, true) => {
                self.data = Vec::new();
                mailin::response::START_DATA
            }
            _ => {
                (self.is_from_valid, self.is_to_valid) = (false, false);
                mailin::response::INTERNAL_ERROR
            }
        }
    }

    fn data(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match (self.is_from_valid, self.is_to_valid) {
            (true, true) => {
                self.data.extend_from_slice(buf);
                Ok(())
            }
            _ => {
                (self.is_from_valid, self.is_to_valid) = (false, false);
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "from or to is not valid",
                ))
            }
        }
    }

    fn data_end(&mut self) -> mailin::Response {
        debug!("data_end received");
        match (self.is_from_valid, self.is_to_valid) {
            (true, true) => {
                let chat_message = match MessageParser::default().parse(&self.data) {
                    Some(message) => match (message.subject(), message.body_text(0)) {
                        (Some(subject), Some(body)) => {
                            format!("Subject: {}\n\n{}", subject.to_string(), body.to_string())
                        }
                        _ => {
                            warn!("Could not parse subject or body from mail");
                            return mailin::response::INTERNAL_ERROR;
                        }
                    },
                    None => {
                        warn!("Could not parse raw mail message");
                        return mailin::response::INTERNAL_ERROR;
                    }
                };
                for i in 1..=MAIL_HANDLER_SEND_MAX_RETRIES {
                    match self.tx.try_send(chat_message.to_owned()) {
                        Ok(_) => {
                            debug!("send handler->matrix thread: successful");
                            break;
                        }
                        Err(_) => {
                            warn!(
                                "send handler->matrix thread: failed (Try {}/{})",
                                i, MAIL_HANDLER_SEND_MAX_RETRIES
                            );
                            std::thread::sleep(Duration::from_secs(5));
                        }
                    };
                }
                (self.is_from_valid, self.is_to_valid) = (false, false);
                mailin::response::OK
            }
            _ => {
                (self.is_from_valid, self.is_to_valid) = (false, false);
                mailin::response::INTERNAL_ERROR
            }
        }
    }
}
async fn listen_to_mail_socket_and_send_to_tx(
    tx: Sender<String>,
    mut stream: TcpStream,
    mail_from: &String,
    mail_to: &String,
    mail_server_name: &String,
) -> anyhow::Result<()> {
    let handler = MailHandler::new(tx, mail_from, mail_to);

    let remote_addr = stream.peer_addr()?;

    let session = &mut SessionBuilder::new(mail_server_name).build(remote_addr.ip(), handler);

    let (stream_rx, mut stream_tx) = stream.split();

    let greeting = session.greeting().buffer()?;

    stream_tx.write(&greeting).await?;

    let mut buf_read = BufReader::new(stream_rx);
    let mut command = String::new();
    //    stream.set_read_timeout(Some(Duration::from_secs(60)))?;

    loop {
        command.clear();
        let len = buf_read.read_line(&mut command).await?;
        let response = if 0 < len {
            session.process(command.as_bytes())
        } else {
            break;
        };
        //debug!("Mailin response: {:?}", response);
        match response.action {
            mailin::Action::Close => {
                stream_tx.write(&response.buffer()?).await?;
                break;
            }
            mailin::Action::UpgradeTls => bail!("TLS requested"),
            mailin::Action::NoReply => continue,
            mailin::Action::Reply => {
                stream_tx.write(&response.buffer()?).await?;
                ()
            }
        }
    }

    Ok(())
}

pub async fn mail_server(
    tx: Sender<String>,
    mail_from: String,
    mail_to: String,
    mail_server_name: String,
) -> anyhow::Result<()> {
    // handling incoming connections
    let Ok(socket) = TcpListener::bind("0.0.0.0:25000").await else {
        error!("binding socket failed");
        bail!("binding socket failed")
    };

    while let Ok((stream, _)) = socket.accept().await {
        match listen_to_mail_socket_and_send_to_tx(
            tx.clone(),
            stream,
            &mail_from,
            &mail_to,
            &mail_server_name,
        )
        .await
        {
            Ok(_) => (),
            Err(err) => warn!("failure processing message: {}", err),
        }
    }

    warn!("no incoming sockets left");

    Ok(())
}
