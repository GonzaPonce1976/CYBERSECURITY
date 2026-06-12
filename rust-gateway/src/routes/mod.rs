//! Módulo de rutas HTTP y WebSocket

pub mod alerts;
pub mod ip;
pub mod cve;
pub mod audit;
pub mod health;
pub mod ws;
pub mod ioc;

use axum::Router;
use std::sync::Arc;
use crate::state::AppState;

/// Construye el router principal de la API REST
pub fn api_router() -> Router<Arc<AppState>> {
    Router::new()
        .nest("/alerts", alerts::router())
        .nest("/ip",     ip::router())
        .nest("/cve",    cve::router())
        .nest("/audit",  audit::router())
        .nest("/health", health::router())
        .nest("/ioc",    ioc::router())
}

/// Construye el router de WebSocket
pub fn ws_router() -> Router<Arc<AppState>> {
    Router::new()
        .nest("/alerts", ws::router())
}
