//! Modelo de CVE (Common Vulnerabilities and Exposures)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cve {
    pub id: String,
    pub description: String,
    pub base_score: f64,
    pub severity: String,
}
