use std::{net::SocketAddr, path::PathBuf};

use anyhow::Result;
use clap::Parser;
use rusqlite::Connection;

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
    /// HTTPS directory containing prebuilt CLI archives and .sha256 files.
    #[arg(long, default_value = kompromat::api::DEFAULT_RELEASE_BASE_URL)]
    release_base_url: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let app = kompromat::api::app_with_releases(
        Connection::open(args.database)?,
        &args.release_base_url,
    )?;
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    eprintln!("listening on http://{}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}
