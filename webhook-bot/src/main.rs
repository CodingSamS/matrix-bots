use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use clap::Parser;
use matrix_room_bot::MatrixRoomServerClient;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tarpc::tokio_serde::formats::Bincode;

#[derive(Parser, Debug)]
#[command(name = "Webhook Bot")]
#[command(version = "1.0")]
#[command(about = "A program used to receive webhooks and send them to the matrix room bot.")]
struct Args {
    /// HTTP Socket Address for receiving webhook
    #[arg(long)]
    webhook_socket: SocketAddr,
    /// Socket Address of the microservice
    #[arg(long)]
    microservice_socket: SocketAddr,
}

#[derive(Serialize, Deserialize, Debug)]
struct Message {
    sender: String,
    severity: String,
    message: String,
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{}: {} ({})",
            self.sender, self.message, self.severity
        ))
    }
}

struct MessageServer {
    microservice_socket: SocketAddr,
}

impl MessageServer {
    fn new(microservice_socket: SocketAddr) -> Self {
        MessageServer {
            microservice_socket,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let app_state = Arc::new(MessageServer::new(args.microservice_socket));
    let app = Router::new()
        .route("/message", post(message))
        .with_state(app_state);
    let listener = tokio::net::TcpListener::bind(args.webhook_socket).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn message(
    State(app_state): State<Arc<MessageServer>>,
    Json(payload): Json<Message>,
) -> StatusCode {
    let Ok(matrix_client) = get_microservice_client(app_state.microservice_socket).await else {
        return StatusCode::INTERNAL_SERVER_ERROR;
    };
    match matrix_client
        .send(tarpc::context::current(), payload.to_string())
        .await
    {
        Ok(Ok(_)) => StatusCode::OK,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn get_microservice_client(socket: SocketAddr) -> anyhow::Result<MatrixRoomServerClient> {
    let mut transport = tarpc::serde_transport::tcp::connect(socket, Bincode::default);
    transport.config_mut().max_frame_length(usize::MAX);
    Ok(MatrixRoomServerClient::new(tarpc::client::Config::default(), transport.await?).spawn())
}
