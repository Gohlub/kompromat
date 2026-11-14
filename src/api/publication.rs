use axum::{
    Json, Router,
    extract::{OriginalUri, Path, Query, State},
    http::StatusCode,
    response::Html,
    routing::get,
};
use rusqlite::{Connection, TransactionBehavior, params};
use serde::Serialize;

use super::{
    ApiError, Database, PageQuery, bad_request, find_manifest, internal, registered_manifest,
};
use crate::{
    publication::{Listing, PublicationState, SignedPublication},
    threads::Page,
};

pub(super) fn initialize(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS publication_registry (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            registry_id TEXT NOT NULL
         );
         INSERT INTO publication_registry (singleton, registry_id)
            VALUES (1, lower(hex(randomblob(32)))) ON CONFLICT (singleton) DO NOTHING;
         CREATE TABLE IF NOT EXISTS hunt_publications (
            id INTEGER PRIMARY KEY,
            flag TEXT NOT NULL UNIQUE REFERENCES canaries(public_key),
            revision INTEGER NOT NULL CHECK (revision > 0),
            title TEXT,
            brief_url TEXT,
            CHECK ((title IS NULL) = (brief_url IS NULL))
         );
         CREATE INDEX IF NOT EXISTS listed_hunts ON hunt_publications(id) WHERE title IS NOT NULL;",
    )
}

pub(super) fn routes() -> Router<Database> {
    Router::new()
        .route("/", get(index))
        .route("/hunts", get(directory))
        .route("/dossiers/{flag}/publication", get(status).post(change))
}

fn current(connection: &Connection, flag: &str) -> Result<PublicationState, ApiError> {
    connection
        .query_row(
            "SELECT r.registry_id, coalesce(p.revision, 0), p.title, p.brief_url
             FROM publication_registry AS r LEFT JOIN hunt_publications AS p ON p.flag = ?1
             WHERE r.singleton = 1",
            [flag],
            |row| {
                let title: Option<String> = row.get(2)?;
                let listing = match title {
                    Some(title) => Some(Listing {
                        title,
                        brief_url: row.get(3)?,
                    }),
                    None => None,
                };
                Ok(PublicationState {
                    registry_id: row.get(0)?,
                    revision: row.get(1)?,
                    listing,
                })
            },
        )
        .map_err(internal)
}

async fn status(
    State(database): State<Database>,
    Path(flag): Path<String>,
) -> Result<Json<PublicationState>, ApiError> {
    let connection = database.lock().map_err(internal)?;
    find_manifest(&connection, &flag)?
        .defender_public_key
        .ok_or_else(|| bad_request("only hunts with a defender key can be listed"))?;
    Ok(Json(current(&connection, &flag)?))
}

async fn change(
    State(database): State<Database>,
    Path(flag): Path<String>,
    Json(change): Json<SignedPublication>,
) -> Result<Json<PublicationState>, ApiError> {
    let defender = registered_manifest(&database, &flag)?
        .defender_public_key
        .ok_or_else(|| bad_request("only hunts with a defender key can be listed"))?;
    change.verify(&defender, &flag).map_err(bad_request)?;
    let state = change.state;
    let mut connection = database.lock().map_err(internal)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(internal)?;
    let stored = current(&tx, &flag)?;
    if state.registry_id != stored.registry_id
        || stored.revision.checked_add(1) != Some(state.revision)
    {
        return Err((
            StatusCode::CONFLICT,
            "registry or publication revision differs".into(),
        ));
    }
    // Withdrawal keeps the revision even after the public fields have been removed.
    let (title, brief_url) = state
        .listing
        .as_ref()
        .map(|listing| (Some(&listing.title), Some(&listing.brief_url)))
        .unwrap_or_default();
    tx.execute(
        "INSERT INTO hunt_publications(flag, revision, title, brief_url) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (flag) DO UPDATE SET
            revision = excluded.revision, title = excluded.title, brief_url = excluded.brief_url",
        params![flag, state.revision, title, brief_url],
    )
    .map_err(internal)?;
    tx.commit().map_err(internal)?;
    Ok(Json(state))
}

#[derive(Serialize)]
struct PublicHunt {
    title: String,
    brief_url: String,
    /// Relative to the registry directory, including when mounted below an origin's root.
    hunt: String,
}

fn listed(database: &Database, query: &PageQuery) -> Result<Json<Page<PublicHunt>>, ApiError> {
    let connection = database.lock().map_err(internal)?;
    query.read(
        &connection,
        "SELECT id, title, brief_url, flag FROM hunt_publications
         WHERE title IS NOT NULL AND id > ?1 ORDER BY id LIMIT ?2",
        |after, limit| (after, limit),
        |row| {
            Ok(PublicHunt {
                title: row.get(1)?,
                brief_url: row.get(2)?,
                hunt: format!("dossiers/{}", row.get::<_, String>(3)?),
            })
        },
    )
}

async fn directory(
    State(database): State<Database>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Page<PublicHunt>>, ApiError> {
    listed(&database, &query)
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn index(
    State(database): State<Database>,
    Query(query): Query<PageQuery>,
    OriginalUri(uri): OriginalUri,
) -> Result<Html<String>, ApiError> {
    let Json(page) = listed(&database, &query)?;
    // In a nested router the directory itself may be served at /registry without a trailing slash.
    let last_segment = uri.path().rsplit('/').next().unwrap_or_default();
    let prefix = if last_segment.is_empty() {
        String::new()
    } else {
        format!("./{}/", escape(last_segment))
    };
    let mut html = String::from(
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>People’s Commissariat of Kompromat</title><main><h1>People’s Commissariat of Kompromat</h1>",
    );
    if page.items.is_empty() {
        html.push_str("<p>No listings on this page.</p>");
    } else {
        html.push_str(
            "<p>Check that the defender’s brief links back to the same hunt URL.</p><ul>",
        );
        for entry in page.items {
            let url = reqwest::Url::parse(&entry.brief_url).map_err(internal)?;
            let host = url
                .host_str()
                .ok_or_else(|| internal("brief URL missing a host"))?;
            html.push_str(&format!(
                "<li><strong>{}</strong> · <a href=\"{}\" rel=\"noreferrer\">Brief at {}</a> · <a href=\"{prefix}{}\">Hunt URL</a></li>",
                escape(&entry.title), escape(&entry.brief_url), escape(host), escape(&entry.hunt),
            ));
        }
        html.push_str("</ul>");
    }
    if let Some(after) = page.next_after {
        let limit = query
            .limit
            .map(|n| format!("&amp;limit={n}"))
            .unwrap_or_default();
        html.push_str(&format!(
            "<p><a href=\"?after={after}{limit}\">Next page</a></p>"
        ));
    }
    html.push_str(&format!(
        "<p><a href=\"{prefix}hunts\">JSON</a></p></main></html>"
    ));
    Ok(Html(html))
}
