use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use clap::Parser;
use matrix_bots::{
    matrix_room_server::matrix_room_server_client::MatrixRoomServerClient,
    matrix_room_server::SendMessage,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tonic::transport::Endpoint;

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
    microservice_socket: Endpoint,
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
    microservice_socket: Endpoint,
}

impl MessageServer {
    fn new(microservice_socket: Endpoint) -> Self {
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
    let Ok(mut client) =
        MatrixRoomServerClient::connect(app_state.microservice_socket.to_owned()).await
    else {
        return StatusCode::INTERNAL_SERVER_ERROR;
    };

    let request = tonic::Request::new(SendMessage {
        message: payload.to_string(),
    });

    match client.send(request).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
