use anyhow::bail;
use clap::Parser;
use log::{debug, error, info, warn};
use mail_server::listen_to_mail_socket_and_return_mail_string;
use matrix_room_bot::MatrixRoomServerClient;
use std::net::SocketAddr;
use tarpc::tokio_serde::formats::Bincode;
use tokio::net::TcpListener;

#[derive(Parser, Debug)]
#[command(name = "Mail Bot")]
#[command(version = "1.0")]
#[command(
    about = "A program used to start a mail server that sends the message content to a microservice"
)]
struct Args {
    /// Mail server from address that needs to match
    #[arg(long)]
    mail_from: String,
    /// Mail recipient that needs to match
    #[arg(long)]
    mail_to: String,
    /// Mail server name
    #[arg(long)]
    mail_server_name: String,
    /// Mail server socket address
    #[arg(long)]
    mail_server_socket: SocketAddr,
    /// Socket Address of the microservice
    #[arg(long)]
    microservice_socket: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // read config from cli
    env_logger::init();

    let args = Args::parse();

    mail_server(
        args.mail_from,
        args.mail_to,
        args.mail_server_name,
        args.mail_server_socket,
        args.microservice_socket,
    )
    .await?;
    Ok(())
}

async fn get_microservice_client(
    microservice_socket: &SocketAddr,
) -> anyhow::Result<MatrixRoomServerClient> {
    let mut transport = tarpc::serde_transport::tcp::connect(microservice_socket, Bincode::default);
    transport.config_mut().max_frame_length(usize::MAX);
    Ok(MatrixRoomServerClient::new(tarpc::client::Config::default(), transport.await?).spawn())
}

async fn mail_server(
    mail_from: String,
    mail_to: String,
    mail_server_name: String,
    mail_server_socket: SocketAddr,
    microservice_socket: SocketAddr,
) -> anyhow::Result<()> {
    // handling incoming connections
    let Ok(socket) = TcpListener::bind(mail_server_socket).await else {
        error!("binding socket failed");
        bail!("binding socket failed")
    };

    let mut client = get_microservice_client(&microservice_socket).await?;

    while let Ok((stream, _)) = socket.accept().await {
        match listen_to_mail_socket_and_return_mail_string(
            stream,
            &mail_from,
            &mail_to,
            &mail_server_name,
        )
        .await
        {
            Ok(message_option) => match message_option {
                Some(message) => match client
                    .send(tarpc::context::current(), message.clone())
                    .await
                {
                    Ok(Ok(_)) => debug!("send successful"),
                    _ => {
                        info!("Sending failed. Rebuilding the client and trying again");
                        client = get_microservice_client(&microservice_socket).await?;
                        match client.send(tarpc::context::current(), message).await {
                            Ok(Ok(_)) => info!("2nd try of sending successful"),
                            _ => error!("sending message failed"),
                        }
                    }
                },
                None => debug!("mail message is empty"),
            },
            Err(err) => warn!("failure processing message: {}", err),
        }
    }

    warn!("no incoming sockets left");

    Ok(())
}
