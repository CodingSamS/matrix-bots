use anyhow::bail;
use log::{debug, warn};
use mail_parser::MessageParser;
use mailin::SessionBuilder;
use std::net::IpAddr;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

struct MailHandler<'a, 'b> {
    data: Vec<u8>,
    data_string: &'b mut Option<String>,
    is_from_valid: bool,
    is_to_valid: bool,
    mail_from: &'a String,
    mail_to: &'a String,
}

impl<'a, 'b> MailHandler<'a, 'b> {
    fn new(
        mail_from: &'a String,
        mail_to: &'a String,
        data_string: &'b mut Option<String>,
    ) -> Self {
        MailHandler {
            data: Vec::new(),
            data_string,
            is_from_valid: false,
            is_to_valid: false,
            mail_from,
            mail_to,
        }
    }
}

impl<'a, 'b> mailin::Handler for MailHandler<'a, 'b> {
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
                match MessageParser::default().parse(&self.data) {
                    Some(message) => match (message.subject(), message.body_text(0)) {
                        (Some(subject), Some(body)) => {
                            *self.data_string = Some(format!(
                                "Subject: {}\n\n{}",
                                subject.to_string(),
                                body.to_string()
                            ));
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

pub async fn listen_to_mail_socket_and_return_mail_string(
    mut stream: TcpStream,
    mail_from: &String,
    mail_to: &String,
    mail_server_name: &String,
) -> anyhow::Result<Option<String>> {
    let mut data_string = None;
    let handler = MailHandler::new(mail_from, mail_to, &mut data_string);

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
    Ok(data_string)
}
