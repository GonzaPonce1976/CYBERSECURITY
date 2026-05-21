//! Modelo de Audit (Auditoría)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Audit {
    pub id: String,
    pub event_type: String,
    pub timestamp: String,
    pub user: String,
    pub details: String,
}
