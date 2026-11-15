use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use rusqlite::{Connection, OptionalExtension, Row, params};

use super::{
    ApiError, Database, PageQuery, bad_request, find_manifest, internal, read_json,
    registered_manifest,
};
use crate::dossiers::{
    AcceptedOpening, CaptureReceipt, DossierMessage, Opening, Page, verify_entry, verify_opening,
};

pub(super) fn initialize(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS dossiers (
            finder TEXT PRIMARY KEY,
            flag TEXT NOT NULL REFERENCES hunts(public_key),
            document TEXT NOT NULL,
            sequence INTEGER NOT NULL CHECK (sequence > 0),
            accepted_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            UNIQUE (flag, sequence)
         );
         CREATE TABLE IF NOT EXISTS dossier_messages (
            finder TEXT NOT NULL REFERENCES dossiers(finder),
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
        .route("/hunts/{flag}/dossiers", get(list))
        .route("/dossiers/{id}", get(get_dossier))
        .route("/dossiers/{id}/messages", get(messages).post(append))
}

async fn open(
    State(database): State<Database>,
    Json(opening): Json<Opening>,
) -> Result<(StatusCode, Json<AcceptedOpening>), ApiError> {
    let manifest = registered_manifest(&database, &opening.participants.flag)?;
    verify_opening(&opening, &manifest).map_err(bad_request)?;

    let connection = database.lock().map_err(internal)?;
    let inserted = connection
        .execute(
            "INSERT INTO dossiers (finder, flag, document, sequence)
             VALUES (?1, ?2, ?3,
                 (SELECT coalesce(max(sequence), 0) + 1 FROM dossiers WHERE flag = ?2))
             ON CONFLICT (finder) DO NOTHING",
            params![
                opening.participants.finder,
                opening.participants.flag,
                serde_json::to_string(&opening).map_err(internal)?,
            ],
        )
        .map_err(internal)?;
    let accepted = find_dossier(&connection, &opening.participants.finder)?;
    let status = if inserted == 1 {
        StatusCode::CREATED
    } else {
        if accepted.opening != opening {
            return Err((StatusCode::CONFLICT, "finder already has a dossier".into()));
        }
        StatusCode::OK
    };
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

fn find_dossier(connection: &Connection, finder: &str) -> Result<AcceptedOpening, ApiError> {
    connection
        .query_row(
            "SELECT document, sequence, accepted_at FROM dossiers WHERE finder = ?1",
            [finder],
            read_opening,
        )
        .optional()
        .map_err(internal)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "unknown dossier".into()))
}

async fn get_dossier(
    State(database): State<Database>,
    Path(finder): Path<String>,
) -> Result<Json<AcceptedOpening>, ApiError> {
    let connection = database.lock().map_err(internal)?;
    Ok(Json(find_dossier(&connection, &finder)?))
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
        "SELECT sequence, finder, accepted_at FROM dossiers
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
    Json(entry): Json<DossierMessage>,
) -> Result<(StatusCode, Json<DossierMessage>), ApiError> {
    let opening = {
        let connection = database.lock().map_err(internal)?;
        find_dossier(&connection, &finder)?.opening
    };
    verify_entry(&opening.participants, &entry).map_err(bad_request)?;
    if entry.nonce == opening.first.nonce {
        return Err((StatusCode::CONFLICT, "nonce used by dossier opening".into()));
    }
    let connection = database.lock().map_err(internal)?;
    let inserted = connection
        .execute(
            "INSERT INTO dossier_messages (finder, nonce, document, sequence)
             VALUES (?1, ?2, ?3,
                 (SELECT coalesce(max(sequence), 0) + 1 FROM dossier_messages WHERE finder = ?1))
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
        let stored: DossierMessage = connection
            .query_row(
                "SELECT document FROM dossier_messages WHERE finder = ?1 AND nonce = ?2",
                params![finder, entry.nonce],
                |row| read_json(row, 0),
            )
            .map_err(internal)?;
        if stored != entry {
            return Err((
                StatusCode::CONFLICT,
                "dossier message nonce already used".into(),
            ));
        }
        StatusCode::OK
    };
    Ok((status, Json(entry)))
}

async fn messages(
    State(database): State<Database>,
    Path(finder): Path<String>,
    Query(page): Query<PageQuery>,
) -> Result<Json<Page<DossierMessage>>, ApiError> {
    let connection = database.lock().map_err(internal)?;
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM dossiers WHERE finder = ?1)",
            [&finder],
            |row| row.get(0),
        )
        .map_err(internal)?;
    if !exists {
        return Err((StatusCode::NOT_FOUND, "unknown dossier".into()));
    }
    page.read(
        &connection,
        "SELECT sequence, document FROM dossier_messages
         WHERE finder = ?1 AND sequence > ?2 ORDER BY sequence LIMIT ?3",
        |after, limit| (finder.as_str(), after, limit),
        |row| read_json(row, 1),
    )
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier, Mutex},
        time::Duration,
    };

    use super::*;
    use crate::{dossiers, generate};

    #[test]
    fn separate_connections_allocate_unique_receipts_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records.sqlite3");
        drop(crate::api::app(Connection::open(&path).unwrap()).unwrap());
        let (flag, manifest, _) = generate(Default::default());
        Connection::open(&path)
            .unwrap()
            .execute(
                "INSERT INTO hunts (public_key, document) VALUES (?1, ?2)",
                params![
                    manifest.public_key,
                    serde_json::to_string(&manifest).unwrap()
                ],
            )
            .unwrap();
        let openings: Vec<_> = (0..8)
            .map(|_| dossiers::open(&flag, &manifest, &dossiers::fresh_secret(), "report").unwrap())
            .collect();
        let barrier = Barrier::new(openings.len());
        let mut sequences = std::thread::scope(|scope| {
            let writers: Vec<_> = openings
                .into_iter()
                .map(|opening| {
                    let (path, barrier) = (&path, &barrier);
                    scope.spawn(move || {
                        let connection = Connection::open(path).unwrap();
                        connection.busy_timeout(Duration::from_secs(5)).unwrap();
                        connection
                            .pragma_update(None, "foreign_keys", "ON")
                            .unwrap();
                        let database = Arc::new(Mutex::new(connection));
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .build()
                            .unwrap();
                        barrier.wait();
                        runtime.block_on(async {
                            let (status, Json(accepted)) =
                                open(State(database.clone()), Json(opening.clone()))
                                    .await
                                    .unwrap();
                            assert_eq!(status, StatusCode::CREATED);
                            let (status, Json(retried)) =
                                open(State(database), Json(opening)).await.unwrap();
                            assert_eq!(status, StatusCode::OK);
                            assert_eq!(retried, accepted);
                            accepted.receipt.sequence
                        })
                    })
                })
                .collect();
            writers
                .into_iter()
                .map(|writer| writer.join().unwrap())
                .collect::<Vec<_>>()
        });
        sequences.sort_unstable();
        assert_eq!(sequences, (1..=8).collect::<Vec<_>>());
    }

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
                    "INSERT INTO hunts (public_key, document) VALUES (?1, ?2)",
                    params![
                        manifest.public_key,
                        serde_json::to_string(manifest).unwrap()
                    ],
                )
                .unwrap();
        }
        let secret = dossiers::fresh_secret();
        let first = dossiers::open(&flag, &manifest, &secret, "first report").unwrap();
        let other = dossiers::open(
            &other_flag,
            &other_manifest,
            &dossiers::fresh_secret(),
            "other flag",
        )
        .unwrap();
        let second =
            dossiers::open(&flag, &manifest, &dossiers::fresh_secret(), "second report").unwrap();
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

        let reply = dossiers::encrypt(&first.participants, &secret, "first reply").unwrap();
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
                dossiers::open(flag, manifest, &dossiers::fresh_secret(), "after restart").unwrap();
            let (_, Json(response)) = open(State(database.clone()), Json(opening)).await.unwrap();
            assert_eq!(response.receipt.sequence, sequence);
        }
        let last = dossiers::encrypt(&first.participants, &secret, "after restart").unwrap();
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
