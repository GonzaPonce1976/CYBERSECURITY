//! Modelo de IP Report (Reporte de IP)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpReport {
    pub ip: String,
    pub reputation: i32,
    pub is_malicious: bool,
    pub reports: u32,
}
