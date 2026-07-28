use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArcatProject {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub dg_code: Option<String>,
    pub uo_code: Option<String>,
    pub uo_address: Option<String>,
    pub status: Option<String>,
    pub tech_stack: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ArcatProject {
    pub fn new(name: String, description: Option<String>, dg_code: Option<String>, uo_code: Option<String>, uo_address: Option<String>, status: Option<String>, tech_stack: Option<String>) -> Self {
        let now = Utc::now();
        ArcatProject {
            id: Uuid::new_v4().to_string(),
            name,
            description,
            dg_code,
            uo_code,
            uo_address,
            status,
            tech_stack,
            created_at: now,
            updated_at: now,
        }
    }
}
