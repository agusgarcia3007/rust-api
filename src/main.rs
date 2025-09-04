mod auth;
mod config;
mod database;
mod dto;
mod entities;
mod handlers;
mod migration;
mod routes;
mod state;

use axum::http::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    HeaderValue, Method,
};
use sea_orm_migration::prelude::*;
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    config::Config,
    database::establish_connection,
    migration::Migrator,
    routes::create_routes,
    state::AppState,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rust_api=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::from_env()?;
    
    let db = establish_connection(&config.database_url).await?;
    
    Migrator::up(&db, None).await?;
    tracing::info!("Database migrations completed");

    let cors = CorsLayer::new()
        .allow_origin("http://localhost:4444".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
        .allow_credentials(true)
        .allow_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE]);

    let app_state = AppState {
        config: config.clone(),
        db,
    };

    let app = create_routes(app_state)
        .layer(cors)
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&format!("0.0.0.0:{}", config.port)).await?;
    tracing::info!("Server running on http://0.0.0.0:{}", config.port);
    
    axum::serve(listener, app).await?;

    Ok(())
}
