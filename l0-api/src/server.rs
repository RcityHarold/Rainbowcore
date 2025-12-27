//! API Server setup

use axum::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::routes::create_router;
use crate::state::{ApiConfig, AppState};
use l0_db::SurrealDatastore;
use soulbase_types::prelude::TenantId;

/// Create the API server
pub async fn create_server(
    config: ApiConfig,
    datastore: Arc<SurrealDatastore>,
) -> Result<(Router, SocketAddr), Box<dyn std::error::Error + Send + Sync>> {
    // Create app state
    let tenant_id = TenantId(config.tenant_id.clone());
    let state = AppState::new(datastore, tenant_id, config.node_id.clone()).await?;

    // Create router
    let mut router = create_router(state);

    // Add middleware
    router = router.layer(TraceLayer::new_for_http());

    if config.enable_cors {
        router = router.layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );
    }

    // Parse address
    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;

    Ok((router, addr))
}

/// Run the API server
pub async fn run_server(
    config: ApiConfig,
    datastore: Arc<SurrealDatastore>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (router, addr) = create_server(config, datastore).await?;

    tracing::info!("L0 API server listening on {}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

/// Start server in background (for testing)
pub async fn start_background_server(
    config: ApiConfig,
    datastore: Arc<SurrealDatastore>,
) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
    let (router, addr) = create_server(config, datastore).await?;

    // Bind to get actual address (useful when port is 0)
    let listener = TcpListener::bind(addr).await?;
    let actual_addr = listener.local_addr()?;

    // Spawn server in background
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router).await {
            tracing::error!("Server error: {}", e);
        }
    });

    Ok(actual_addr)
}
