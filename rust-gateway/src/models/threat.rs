//! Modelo de Threat (Amenaza)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub description: String,
}
