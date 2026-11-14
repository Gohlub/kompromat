use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params, types::Type};
use serde::de::DeserializeOwned;

use super::{ApiError, Database, bad_request, find_manifest, insert_proof, internal};
use crate::threads::{Opening, Participants, ThreadMessage, verify_entry, verify_opening};

pub(super) fn initialize(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS finder_threads (
            finder TEXT PRIMARY KEY,
            flag TEXT NOT NULL,
            proof_signature TEXT NOT NULL,
            first_entry TEXT NOT NULL,
            UNIQUE (flag, proof_signature),
            FOREIGN KEY (flag, proof_signature) REFERENCES proofs(public_key, signature)
         );
         CREATE TABLE IF NOT EXISTS thread_entries (
            finder TEXT NOT NULL REFERENCES finder_threads(finder),
            nonce TEXT NOT NULL,
            document TEXT NOT NULL,
            PRIMARY KEY (finder, nonce)
         );",
    )
}

pub(super) fn routes() -> Router<Database> {
    Router::new()
        .route("/threads", post(open))
        .route("/dossiers/{public_key}/threads", get(list))
        .route("/threads/{finder}", get(get_thread))
        .route("/threads/{finder}/messages", get(messages).post(append))
}

async fn open(
    State(database): State<Database>,
    Json(opening): Json<Opening>,
) -> Result<(StatusCode, Json<Opening>), ApiError> {
    let mut connection = database.lock().map_err(internal)?;
    let manifest = find_manifest(&connection, &opening.participants.flag)?;
    verify_opening(&opening, &manifest).map_err(bad_request)?;

    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(internal)?;
    insert_proof(&tx, &opening.proof)?;
    let inserted = tx
        .execute(
            "INSERT INTO finder_threads (finder, flag, proof_signature, first_entry)
             VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
            params![
                opening.participants.finder,
                opening.participants.flag,
                opening.proof.signature,
                serde_json::to_string(&opening.first).map_err(internal)?,
            ],
        )
        .map_err(internal)?;
    let status = if inserted == 1 {
        StatusCode::CREATED
    } else {
        let stored = find_thread(&tx, &opening.participants.finder)?;
        if stored != opening {
            return Err((StatusCode::CONFLICT, "finder already has a thread".into()));
        }
        StatusCode::OK
    };
    tx.commit().map_err(internal)?;
    Ok((status, Json(opening)))
}

// Reconstitute the signed opening from the immutable manifest, proof and first entry.
const OPENINGS: &str = "SELECT t.flag, json_extract(c.document, '$.defender_public_key'),
            t.finder, t.first_entry, p.document
     FROM finder_threads AS t
     JOIN canaries AS c ON c.public_key = t.flag
     JOIN proofs AS p ON p.public_key = t.flag AND p.signature = t.proof_signature";

fn read_json<T: DeserializeOwned>(row: &Row<'_>, column: usize) -> rusqlite::Result<T> {
    let value: String = row.get(column)?;
    serde_json::from_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(column, Type::Text, Box::new(error))
    })
}

fn read_opening(row: &Row<'_>) -> rusqlite::Result<Opening> {
    Ok(Opening {
        participants: Participants {
            flag: row.get(0)?,
            defender: row.get(1)?,
            finder: row.get(2)?,
        },
        first: read_json(row, 3)?,
        proof: read_json(row, 4)?,
    })
}

fn find_thread(connection: &Connection, finder: &str) -> Result<Opening, ApiError> {
    connection
        .query_row(
            &format!("{OPENINGS} WHERE t.finder = ?1"),
            [finder],
            read_opening,
        )
        .optional()
        .map_err(internal)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "unknown finder thread".into()))
}

async fn get_thread(
    State(database): State<Database>,
    Path(finder): Path<String>,
) -> Result<Json<Opening>, ApiError> {
    let connection = database.lock().map_err(internal)?;
    Ok(Json(find_thread(&connection, &finder)?))
}

async fn list(
    State(database): State<Database>,
    Path(flag): Path<String>,
) -> Result<Json<Vec<Opening>>, ApiError> {
    let connection = database.lock().map_err(internal)?;
    find_manifest(&connection, &flag)?;
    let mut statement = connection
        .prepare(&format!("{OPENINGS} WHERE t.flag = ?1 ORDER BY t.rowid"))
        .map_err(internal)?;
    let openings = statement
        .query_map([flag], read_opening)
        .map_err(internal)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(internal)?;
    Ok(Json(openings))
}

async fn append(
    State(database): State<Database>,
    Path(finder): Path<String>,
    Json(entry): Json<ThreadMessage>,
) -> Result<(StatusCode, Json<ThreadMessage>), ApiError> {
    let mut connection = database.lock().map_err(internal)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(internal)?;
    let opening = find_thread(&tx, &finder)?;
    verify_entry(&opening.participants, &entry).map_err(bad_request)?;
    if entry.nonce == opening.first.nonce {
        return Err((StatusCode::CONFLICT, "nonce used by thread opening".into()));
    }
    let inserted = tx
        .execute(
            "INSERT INTO thread_entries (finder, nonce, document) VALUES (?1, ?2, ?3)
             ON CONFLICT (finder, nonce) DO NOTHING",
            params![
                finder,
                entry.nonce,
                serde_json::to_string(&entry).map_err(internal)?
            ],
        )
        .map_err(internal)?;
    let status = if inserted == 1 {
        StatusCode::CREATED
    } else {
        let stored: ThreadMessage = tx
            .query_row(
                "SELECT document FROM thread_entries WHERE finder = ?1 AND nonce = ?2",
                params![finder, entry.nonce],
                |row| read_json(row, 0),
            )
            .map_err(internal)?;
        if stored != entry {
            return Err((
                StatusCode::CONFLICT,
                "thread message nonce already used".into(),
            ));
        }
        StatusCode::OK
    };
    tx.commit().map_err(internal)?;
    Ok((status, Json(entry)))
}

async fn messages(
    State(database): State<Database>,
    Path(finder): Path<String>,
) -> Result<Json<Vec<ThreadMessage>>, ApiError> {
    let connection = database.lock().map_err(internal)?;
    find_thread(&connection, &finder)?;
    let mut statement = connection
        .prepare("SELECT document FROM thread_entries WHERE finder = ?1 ORDER BY rowid")
        .map_err(internal)?;
    let entries = statement
        .query_map([finder], |row| read_json(row, 0))
        .map_err(internal)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(internal)?;
    Ok(Json(entries))
}
