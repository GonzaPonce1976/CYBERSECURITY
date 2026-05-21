//! CyberSecurity DApp — Rust API Gateway
//! 
//! Servidor Axum que agrega datos de:
//! - Wazuh SIEM REST API
//! - AbuseIPDB, VirusTotal, GreyNoise, NVD/NIST, AlienVault OTX
//! 
//! Expone endpoints REST + WebSocket para el frontend dashboard.
//! Escribe eventos críticos en los Smart Contracts de Ethereum.

mod clients;
mod models;
mod routes;
mod state;

use axum::{Router, http::Method};
use std::sync::Arc;
use tower_http::cors::{CorsLayer, Any};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Cargar variables de entorno
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            let env_path = parent.join(".env");
            if env_path.exists() {
                dotenvy::from_path(env_path).ok();
            }
        }
    }
    dotenvy::dotenv().ok();

    // Inicializar logging estructurado
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cybersec_gateway=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("🔐 CyberSecurity DApp — Rust Gateway arrancando...");

    // Estado compartido de la aplicación
    let state = Arc::new(AppState::new().await?);

    // Configurar CORS para el frontend
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any);

    // Construir router con todas las rutas
    let app = Router::new()
        .nest("/api", routes::api_router())
        .nest("/ws", routes::ws_router())
        .layer(cors)
        .with_state(state);

    // Arrancar servidor
    let host = std::env::var("GATEWAY_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("GATEWAY_PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("{}:{}", host, port);

    info!("🚀 Gateway escuchando en http://{}", addr);
    info!("📡 WebSocket disponible en ws://{}/ws/alerts", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
