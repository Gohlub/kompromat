use std::{
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Instant, SystemTime},
};

use anyhow::Result;
use axum::{
    extract::{MatchedPath, Request},
    middleware::{self, Next},
    response::Response,
};
use clap::Parser;
use rusqlite::Connection;
use serde_json::json;

#[derive(Parser)]
#[command(
    version,
    about = "Register public manifests, verify proofs, and store encrypted dossier messages"
)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:3000")]
    listen: SocketAddr,
    #[arg(long, default_value = "kompromat.sqlite3")]
    database: PathBuf,
    /// Log request arrivals and responses to stderr as JSON, omitting request data.
    #[arg(long)]
    log: bool,
    /// HTTPS directory containing prebuilt CLI archives and .sha256 files.
    #[arg(long, default_value = kompromat::api::DEFAULT_RELEASE_BASE_URL)]
    release_base_url: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mut app = kompromat::api::app_with_releases(
        Connection::open(args.database)?,
        &args.release_base_url,
    )?;
    if args.log {
        app = app.layer(middleware::from_fn(log_request));
    }
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    eprintln!("listening on http://{}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn log_request(request: Request, next: Next) -> Response {
    static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);
    let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let start = Instant::now();
    let method = match request.method().as_str() {
        known @ ("GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "TRACE"
        | "CONNECT") => known,
        _ => "OTHER",
    };
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("unmatched", MatchedPath::as_str);
    log_event(json!({
        "event": "request", "request_id": request_id, "method": method, "route": route,
    }));
    let response = next.run(request).await;
    log_event(json!({
        "event": "response", "request_id": request_id, "status": response.status().as_u16(),
        "duration_ms": start.elapsed().as_millis(),
    }));
    response
}

fn log_event(mut event: serde_json::Value) {
    event["unix_ms"] = json!(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );
    let _ = writeln!(io::stderr().lock(), "{event}");
}
