use axum::{
    routing::{post, get},
    Router,
    Json,
    http::StatusCode,
};
use axum::extract::State;
use serde::{Deserialize, Serialize};
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use axum::http::HeaderMap;
use dotenvy::dotenv;

#[derive(Debug, Deserialize, Serialize)]
struct KeyEvent {
    key_type: u32,
    code: u32,
    value: u32,
}

#[derive(Debug, Deserialize, Serialize)]
struct TimestampedKeyEvent {
    event: KeyEvent,
    relative_time: u64, // Duration in milliseconds
}

#[derive(Debug, Deserialize)]
struct IngestPayload {
    events: Vec<TimestampedKeyEvent>,
}

#[derive(Clone)]
struct AppState{
    password_token: String,
}

#[tokio::main]
async fn main() {
    #[cfg(debug_assertions)]
    dotenv().ok();

    tracing_subscriber::fmt::init();

    let password_token = env::var("PASSWORD_TOKEN").unwrap_or_else(|_| {
        tracing::warn!("PASSWORD_TOKEN not set. API will be unprotected!");
        String::new()
    });
    let port = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let state = AppState {
        password_token,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/ingest", post(ingest_events))
        .with_state(state);

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let actual_addr = listener.local_addr().unwrap();

    tracing::info!("listening on {}", actual_addr);
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> String {
    return "Hello World :D".to_string(); 
}

async fn ingest_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<IngestPayload>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !state.password_token.is_empty() {
        match headers.get("Authorization") {
            Some(auth_header) if *auth_header == *state.password_token => {},
            _ => {
                return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "status": "error", "message": "Invalid password token" })));
            }
        }
    }

    for event in payload.events.iter() {
        tracing::info!("Received event: {:?}", event);
        //store events
    }

    (StatusCode::OK, Json(serde_json::json!({ "status": "success", "message": "Events ingested successfully" })))
}
