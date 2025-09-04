use axum::{response::Json, http::StatusCode};
use serde_json::json;

pub async fn health_check() -> Result<Json<serde_json::Value>, StatusCode> {
    Ok(Json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "service": "rust-api",
        "version": "0.1.0"
    })))
}
