//! WebSocket para alertas en tiempo real — /ws/alerts
//! Los clientes se suscriben y reciben nuevas alertas via push

use axum::{
    extract::{State, WebSocketUpgrade, ws::{WebSocket, Message}},
    response::Response,
    routing::get,
    Router,
};
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::info;
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/", get(ws_handler))
}

async fn ws_handler(
    State(state): State<Arc<AppState>>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    info!("🔌 Cliente WebSocket conectado");

    // Enviar ping cada 10 segundos para mantener conexión activa
    let mut ticker = interval(Duration::from_secs(10));

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                // Enviar alertas nuevas del cache al cliente
                let alerts: Vec<_> = state
                    .alerts_cache
                    .iter()
                    .take(5)
                    .map(|e| e.value().clone())
                    .collect();

                let msg = serde_json::json!({
                    "type": "alerts_update",
                    "data": alerts
                });

                if socket.send(Message::Text(msg.to_string().into())).await.is_err() {
                    break; // Cliente desconectado
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {} // Ignorar otros mensajes del cliente
                }
            }
        }
    }

    info!("🔌 Cliente WebSocket desconectado");
}
