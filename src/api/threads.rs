use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params};

use super::{
    ApiError, Database, PageQuery, bad_request, find_manifest, internal, read_json,
    registered_manifest,
};
use crate::threads::{
    AcceptedOpening, CaptureReceipt, Opening, Page, ThreadMessage, verify_entry, verify_opening,
};

pub(super) fn initialize(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS finder_threads (
            finder TEXT PRIMARY KEY,
            flag TEXT NOT NULL REFERENCES canaries(public_key),
            document TEXT NOT NULL,
            sequence INTEGER NOT NULL CHECK (sequence > 0),
            accepted_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            UNIQUE (flag, sequence)
         );
         CREATE TABLE IF NOT EXISTS thread_entries (
            finder TEXT NOT NULL REFERENCES finder_threads(finder),
            nonce TEXT NOT NULL,
            document TEXT NOT NULL,
            sequence INTEGER NOT NULL CHECK (sequence > 0),
            PRIMARY KEY (finder, nonce),
            UNIQUE (finder, sequence)
         );",
    )
}

pub(super) fn routes() -> Router<Database> {
    Router::new()
        .route("/report", post(open))
        .route("/dossiers/{public_key}/threads", get(list))
        .route("/threads/{finder}", get(get_thread))
        .route("/threads/{finder}/messages", get(messages).post(append))
}

async fn open(
    State(database): State<Database>,
    Json(opening): Json<Opening>,
) -> Result<(StatusCode, Json<AcceptedOpening>), ApiError> {
    let manifest = registered_manifest(&database, &opening.participants.flag)?;
    verify_opening(&opening, &manifest).map_err(bad_request)?;

    let mut connection = database.lock().map_err(internal)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(internal)?;
    let inserted = tx
        .execute(
            "INSERT INTO finder_threads (finder, flag, document, sequence)
             VALUES (?1, ?2, ?3,
                 (SELECT coalesce(max(sequence), 0) + 1 FROM finder_threads WHERE flag = ?2))
             ON CONFLICT (finder) DO NOTHING",
            params![
                opening.participants.finder,
                opening.participants.flag,
                serde_json::to_string(&opening).map_err(internal)?,
            ],
        )
        .map_err(internal)?;
    let accepted = find_thread(&tx, &opening.participants.finder)?;
    let status = if inserted == 1 {
        StatusCode::CREATED
    } else {
        if accepted.opening != opening {
            return Err((StatusCode::CONFLICT, "finder already has a thread".into()));
        }
        StatusCode::OK
    };
    tx.commit().map_err(internal)?;
    Ok((status, Json(accepted)))
}

fn read_opening(row: &Row<'_>) -> rusqlite::Result<AcceptedOpening> {
    let opening: Opening = read_json(row, 0)?;
    Ok(AcceptedOpening {
        receipt: CaptureReceipt {
            dossier_id: opening.participants.finder.clone(),
            sequence: row.get(1)?,
            accepted_at: row.get(2)?,
        },
        opening,
    })
}

fn find_thread(connection: &Connection, finder: &str) -> Result<AcceptedOpening, ApiError> {
    connection
        .query_row(
            "SELECT document, sequence, accepted_at FROM finder_threads WHERE finder = ?1",
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
) -> Result<Json<AcceptedOpening>, ApiError> {
    let connection = database.lock().map_err(internal)?;
    Ok(Json(find_thread(&connection, &finder)?))
}

async fn list(
    State(database): State<Database>,
    Path(flag): Path<String>,
    Query(page): Query<PageQuery>,
) -> Result<Json<Page<CaptureReceipt>>, ApiError> {
    let connection = database.lock().map_err(internal)?;
    find_manifest(&connection, &flag)?;
    page.read(
        &connection,
        "SELECT sequence, finder, accepted_at FROM finder_threads
         WHERE flag = ?1 AND sequence > ?2 ORDER BY sequence LIMIT ?3",
        |after, limit| (flag.as_str(), after, limit),
        |row| {
            Ok(CaptureReceipt {
                dossier_id: row.get(1)?,
                sequence: row.get(0)?,
                accepted_at: row.get(2)?,
            })
        },
    )
}

async fn append(
    State(database): State<Database>,
    Path(finder): Path<String>,
    Json(entry): Json<ThreadMessage>,
) -> Result<(StatusCode, Json<ThreadMessage>), ApiError> {
    let opening = {
        let connection = database.lock().map_err(internal)?;
        find_thread(&connection, &finder)?.opening
    };
    verify_entry(&opening.participants, &entry).map_err(bad_request)?;
    if entry.nonce == opening.first.nonce {
        return Err((StatusCode::CONFLICT, "nonce used by thread opening".into()));
    }
    let mut connection = database.lock().map_err(internal)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(internal)?;
    let inserted = tx
        .execute(
            "INSERT INTO thread_entries (finder, nonce, document, sequence)
             VALUES (?1, ?2, ?3,
                 (SELECT coalesce(max(sequence), 0) + 1 FROM thread_entries WHERE finder = ?1))
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
    Query(page): Query<PageQuery>,
) -> Result<Json<Page<ThreadMessage>>, ApiError> {
    let connection = database.lock().map_err(internal)?;
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM finder_threads WHERE finder = ?1)",
            [&finder],
            |row| row.get(0),
        )
        .map_err(internal)?;
    if !exists {
        return Err((StatusCode::NOT_FOUND, "unknown finder thread".into()));
    }
    page.read(
        &connection,
        "SELECT sequence, document FROM thread_entries
         WHERE finder = ?1 AND sequence > ?2 ORDER BY sequence LIMIT ?3",
        |after, limit| (finder.as_str(), after, limit),
        |row| read_json(row, 1),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::{generate, threads};

    #[tokio::test]
    async fn receipts_and_message_order_survive_restart_and_retries() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records.sqlite3");
        let connect = || {
            // Use the application's real startup path, including foreign keys and schema setup.
            drop(crate::api::app(Connection::open(&path).unwrap()).unwrap());
            let connection = Connection::open(&path).unwrap();
            connection
                .pragma_update(None, "foreign_keys", "ON")
                .unwrap();
            Arc::new(Mutex::new(connection))
        };
        let database = connect();
        let (flag, manifest, _) = generate(Default::default());
        let (other_flag, other_manifest, _) = generate(Default::default());
        for manifest in [&manifest, &other_manifest] {
            database
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO canaries (public_key, document) VALUES (?1, ?2)",
                    params![
                        manifest.public_key,
                        serde_json::to_string(manifest).unwrap()
                    ],
                )
                .unwrap();
        }
        let secret = threads::fresh_secret();
        let first = threads::open(&flag, &manifest, &secret, "first report").unwrap();
        let other = threads::open(
            &other_flag,
            &other_manifest,
            &threads::fresh_secret(),
            "other flag",
        )
        .unwrap();
        let second =
            threads::open(&flag, &manifest, &threads::fresh_secret(), "second report").unwrap();
        let mut accepted = Vec::new();
        for opening in [&first, &other, &second] {
            let (status, Json(response)) = open(State(database.clone()), Json(opening.clone()))
                .await
                .unwrap();
            assert_eq!(status, StatusCode::CREATED);
            assert!(response.receipt.accepted_at.ends_with('Z'));
            accepted.push(response);
        }
        assert_eq!(accepted[0].receipt.sequence, 1);
        assert_eq!(accepted[1].receipt.sequence, 1);
        assert_eq!(accepted[2].receipt.sequence, 2);

        let reply = threads::encrypt(&first.participants, &secret, "first reply").unwrap();
        let finder = first.participants.finder.clone();
        for expected in [StatusCode::CREATED, StatusCode::OK] {
            let (status, _) = append(
                State(database.clone()),
                Path(finder.clone()),
                Json(reply.clone()),
            )
            .await
            .unwrap();
            assert_eq!(status, expected);
        }
        database.lock().unwrap().execute_batch("VACUUM;").unwrap();
        drop(database);

        let database = connect();
        let (status, Json(retried)) = open(State(database.clone()), Json(first.clone()))
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(retried, accepted[0]);
        for (flag, manifest, sequence) in [(&flag, &manifest, 3), (&other_flag, &other_manifest, 2)]
        {
            let opening =
                threads::open(flag, manifest, &threads::fresh_secret(), "after restart").unwrap();
            let (_, Json(response)) = open(State(database.clone()), Json(opening)).await.unwrap();
            assert_eq!(response.receipt.sequence, sequence);
        }
        let last = threads::encrypt(&first.participants, &secret, "after restart").unwrap();
        let (status, Json(stored)) = append(
            State(database.clone()),
            Path(finder.clone()),
            Json(last.clone()),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(stored, last);
        let Json(page) = messages(
            State(database.clone()),
            Path(finder.clone()),
            Query(PageQuery {
                after: None,
                limit: Some(1),
            }),
        )
        .await
        .unwrap();
        assert_eq!(page.items, vec![reply]);
        assert_eq!(page.next_after, Some(1));
        let Json(page) = messages(
            State(database),
            Path(finder),
            Query(PageQuery {
                after: page.next_after,
                limit: Some(1),
            }),
        )
        .await
        .unwrap();
        assert_eq!(page.items, vec![last]);
        assert_eq!(page.next_after, None);
    }
}
