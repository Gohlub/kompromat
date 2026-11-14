use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use rusqlite::{
    Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params, types::Type,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::{ApiError, Database, bad_request, find_manifest, insert_proof, internal};
use crate::threads::{
    AcceptedOpening, CaptureReceipt, Opening, Participants, ThreadMessage, verify_entry,
    verify_opening,
};

pub(super) fn initialize(connection: &Connection) -> rusqlite::Result<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)?;
    tx.execute_batch(
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
    )?;
    let has_sequence: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM pragma_table_info('finder_threads') WHERE name = 'sequence')",
        [],
        |row| row.get(0),
    )?;
    if !has_sequence {
        // Recover the order the old inbox showed. Its schema recorded no clock time.
        tx.execute_batch(
            "ALTER TABLE finder_threads ADD COLUMN sequence INTEGER CHECK (sequence > 0);
             ALTER TABLE finder_threads ADD COLUMN accepted_at TEXT;
             WITH ordered AS MATERIALIZED (
                 SELECT finder, row_number() OVER (PARTITION BY flag ORDER BY rowid) AS position
                 FROM finder_threads
             )
             UPDATE finder_threads SET sequence = (
                 SELECT position FROM ordered WHERE ordered.finder = finder_threads.finder
             );
             CREATE UNIQUE INDEX finder_receipt_order ON finder_threads(flag, sequence);
             CREATE TRIGGER issue_finder_receipt AFTER INSERT ON finder_threads
             BEGIN
                 UPDATE finder_threads
                 SET sequence = (SELECT coalesce(max(sequence), 0) + 1 FROM finder_threads WHERE flag = NEW.flag),
                     accepted_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE finder = NEW.finder;
             END;",
        )?;
    }
    tx.commit()
}

pub(super) fn routes() -> Router<Database> {
    Router::new()
        .route("/threads", post(open))
        .route("/dossiers/{public_key}/threads", get(list))
        .route("/threads/{finder}", get(get_thread))
        .route("/threads/{finder}/messages", get(messages).post(append))
}

#[derive(Deserialize)]
struct ReceiptQuery {
    #[serde(default)]
    receipt: bool,
}

#[derive(Serialize)]
#[serde(untagged)]
enum OpeningView {
    Opening(Opening),
    Accepted(AcceptedOpening),
}

impl ReceiptQuery {
    fn view(&self, accepted: AcceptedOpening) -> OpeningView {
        if self.receipt {
            OpeningView::Accepted(accepted)
        } else {
            OpeningView::Opening(accepted.opening)
        }
    }
}

async fn open(
    State(database): State<Database>,
    Query(query): Query<ReceiptQuery>,
    Json(opening): Json<Opening>,
) -> Result<(StatusCode, Json<OpeningView>), ApiError> {
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
    Ok((status, Json(query.view(accepted))))
}

// Reconstitute the signed opening from the immutable manifest, proof and first entry.
const OPENINGS: &str = "SELECT t.flag, json_extract(c.document, '$.defender_public_key'),
            t.finder, t.first_entry, p.document, t.sequence, t.accepted_at
     FROM finder_threads AS t
     JOIN canaries AS c ON c.public_key = t.flag
     JOIN proofs AS p ON p.public_key = t.flag AND p.signature = t.proof_signature";

fn read_json<T: DeserializeOwned>(row: &Row<'_>, column: usize) -> rusqlite::Result<T> {
    let value: String = row.get(column)?;
    serde_json::from_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(column, Type::Text, Box::new(error))
    })
}

fn read_opening(row: &Row<'_>) -> rusqlite::Result<AcceptedOpening> {
    let opening = Opening {
        participants: Participants {
            flag: row.get(0)?,
            defender: row.get(1)?,
            finder: row.get(2)?,
        },
        first: read_json(row, 3)?,
        proof: read_json(row, 4)?,
    };
    Ok(AcceptedOpening {
        receipt: CaptureReceipt {
            dossier_id: opening.participants.finder.clone(),
            sequence: row.get(5)?,
            accepted_at: row.get(6)?,
        },
        opening,
    })
}

fn find_thread(connection: &Connection, finder: &str) -> Result<AcceptedOpening, ApiError> {
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
    Query(query): Query<ReceiptQuery>,
) -> Result<Json<OpeningView>, ApiError> {
    let connection = database.lock().map_err(internal)?;
    Ok(Json(query.view(find_thread(&connection, &finder)?)))
}

async fn list(
    State(database): State<Database>,
    Path(flag): Path<String>,
    Query(query): Query<ReceiptQuery>,
) -> Result<Json<Vec<OpeningView>>, ApiError> {
    let connection = database.lock().map_err(internal)?;
    find_manifest(&connection, &flag)?;
    let mut statement = connection
        .prepare(&format!("{OPENINGS} WHERE t.flag = ?1 ORDER BY t.sequence"))
        .map_err(internal)?;
    let openings = statement
        .query_map([flag], |row| {
            read_opening(row).map(|accepted| query.view(accepted))
        })
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
    let opening = find_thread(&tx, &finder)?.opening;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn older_dossiers_keep_their_per_flag_order_without_invented_times() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE proofs (
                 public_key TEXT, signature TEXT, PRIMARY KEY (public_key, signature)
             );
             CREATE TABLE finder_threads (
                 finder TEXT PRIMARY KEY, flag TEXT NOT NULL, proof_signature TEXT NOT NULL,
                 first_entry TEXT NOT NULL, UNIQUE (flag, proof_signature),
                 FOREIGN KEY (flag, proof_signature) REFERENCES proofs(public_key, signature)
             );",
        )
        .unwrap();
        let insert = |flag: &str, finder: &str| {
            db.execute(
                "INSERT OR IGNORE INTO proofs VALUES (?1, ?2)",
                [flag, finder],
            )
            .unwrap();
            db.execute(
                "INSERT INTO finder_threads (flag, finder, proof_signature, first_entry)
                 VALUES (?1, ?2, ?2, '{}') ON CONFLICT DO NOTHING",
                [flag, finder],
            )
            .unwrap()
        };
        let receipt = |finder: &str| -> (i64, Option<String>) {
            db.query_row(
                "SELECT sequence, accepted_at FROM finder_threads WHERE finder = ?1",
                [finder],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
        };

        insert("flag-a", "z");
        insert("flag-b", "a");
        insert("flag-a", "y");
        initialize(&db).unwrap();
        assert_eq!(receipt("z"), (1, None));
        assert_eq!(receipt("a"), (1, None));
        assert_eq!(receipt("y"), (2, None));
        assert_eq!(insert("flag-a", "c"), 1);
        let issued = receipt("c");
        let utc = issued.1.as_deref().unwrap();
        assert_eq!(issued.0, 3);
        assert!(utc.len() == 24 && utc.ends_with('Z'));

        initialize(&db).unwrap();
        assert_eq!(insert("flag-a", "c"), 0);
        assert_eq!(receipt("c"), issued);
        assert_eq!(insert("flag-b", "d"), 1);
        assert_eq!(receipt("d").0, 2);
    }
}
