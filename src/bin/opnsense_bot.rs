use anyhow::bail;
use clap::Parser;
use matrix_bots::{
    matrix_room_server::matrix_room_server_client::MatrixRoomServerClient,
    matrix_room_server::SendMessage,
};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tonic::transport::Endpoint;

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
    microservice_socket: Endpoint,
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

            let mut client =
                MatrixRoomServerClient::connect(args.microservice_socket.to_owned()).await?;

            let request = tonic::Request::new(SendMessage {
                message: response_json.to_string(),
            });

            client.send(request).await?;
        }
        _ => bail!("Error retrieving URL"),
    }
    Ok(())
}
