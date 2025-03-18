use anyhow::bail;
use clap::Parser;
use matrix_room_bot::MatrixRoomServerClient;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tarpc::tokio_serde::formats::Bincode;

#[derive(Parser, Debug)]
#[command(name = "OPNSense Bot")]
#[command(version = "1.0")]
#[command(about = "A program used to check if an update is available on an OPNSense instance")]
struct Args {
    /// OPNSense Key
    #[arg(long)]
    opnsense_key: String,
    /// OPNSense Secret
    #[arg(long)]
    opnsense_secret: String,
    /// OPNSense address
    #[arg(long)]
    opnsense_address: SocketAddr,
    /// Socket Address of the microservice
    #[arg(long)]
    microservice_socket: SocketAddr,
}

#[derive(Serialize, Deserialize, Debug)]
struct Response {
    status_msg: String,
    status_reboot: String,
    status: String,
}

impl std::fmt::Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.status_reboot == "1" {
            f.write_fmt(format_args!(
                "Status: {} (reboot required)\nMessage: {}",
                self.status, self.status_msg
            ))
        } else {
            f.write_fmt(format_args!(
                "Status: {}\n Message: {}",
                self.status, self.status_msg
            ))
        }
    }
}

async fn get_microservice_client(
    microservice_socket: &SocketAddr,
) -> anyhow::Result<MatrixRoomServerClient> {
    let mut transport = tarpc::serde_transport::tcp::connect(microservice_socket, Bincode::default);
    transport.config_mut().max_frame_length(usize::MAX);
    Ok(MatrixRoomServerClient::new(tarpc::client::Config::default(), transport.await?).spawn())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let reqwest_client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    let response = reqwest_client
        .get(format!(
            "https://{}/api/core/firmware/status",
            args.opnsense_address
        ))
        .basic_auth(args.opnsense_key, Some(args.opnsense_secret))
        .send()
        .await?;

    match response.status() {
        StatusCode::OK => {
            let response_json: Response = serde_json::from_str(&response.text().await?)?;
            println!("{}", response_json);
            let matrix_client = get_microservice_client(&args.microservice_socket).await?;
            matrix_client
                .send(tarpc::context::current(), response_json.to_string())
                .await?
                .unwrap();
            /*{
                Ok(Ok(_)) => println!("2nd try of sending successful"),
                _ => bail!("sending message failed"),
            }*/
        }
        _ => bail!("Error retrieving URL"),
    }
    Ok(())
}
