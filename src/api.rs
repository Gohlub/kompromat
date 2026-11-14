//! An HTTP registry for public manifests, proofs of key possession, and encrypted messages.

mod threads;

use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::{get, post},
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::{EncryptedMessage, Manifest, Proof, validate_public_key, verify, verify_message};

type Database = Arc<Mutex<Connection>>;
type ApiError = (StatusCode, String);
pub const DEFAULT_RELEASE_BASE_URL: &str = "https://kompromat.sh/releases/latest/download";

pub fn app(connection: Connection) -> anyhow::Result<Router> {
    app_with_releases(connection, DEFAULT_RELEASE_BASE_URL)
}

pub fn app_with_releases(connection: Connection, release_base_url: &str) -> anyhow::Result<Router> {
    let url = reqwest::Url::parse(release_base_url)?;
    anyhow::ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.query().is_none()
            && url.fragment().is_none(),
        "release base URL must be an HTTPS directory URL"
    );
    let installer = include_str!("../install.sh").replace(
        DEFAULT_RELEASE_BASE_URL,
        &release_base_url
            .trim_end_matches('/')
            .replace('\'', "'\\''"),
    );
    // Physical table names are retained for compatibility with existing databases.
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         CREATE TABLE IF NOT EXISTS canaries (
             public_key TEXT PRIMARY KEY,
             document TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS proofs (
             public_key TEXT NOT NULL REFERENCES canaries(public_key),
             signature TEXT NOT NULL,
             document TEXT NOT NULL,
             PRIMARY KEY (public_key, signature)
         );
         CREATE TABLE IF NOT EXISTS record_entries (
             public_key TEXT NOT NULL REFERENCES canaries(public_key),
             nonce TEXT NOT NULL,
             document TEXT NOT NULL,
             PRIMARY KEY (public_key, nonce)
         );",
    )?;

    threads::initialize(&connection)?;
    Ok(Router::new()
        .route(
            "/cli",
            get(move || {
                let script = installer.clone();
                async move {
                    (
                        [("content-type", "text/x-shellscript; charset=utf-8")],
                        script,
                    )
                }
            }),
        )
        .route("/dossiers", post(register))
        .route("/dossiers/{public_key}", get(get_manifest))
        .route("/dossiers/{public_key}/proofs", get(list_proofs))
        .route("/dossiers/{public_key}/messages", get(list_messages))
        .route("/proofs", post(submit))
        .route("/messages", post(append_message))
        // Compatibility aliases for existing clients.
        .route("/canaries", post(register))
        .route("/canaries/{public_key}", get(get_manifest))
        .route("/canaries/{public_key}/proofs", get(list_proofs))
        .route("/canaries/{public_key}/record", get(list_messages))
        .route("/records", post(append_message))
        .merge(threads::routes())
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(Arc::new(Mutex::new(connection))))
}

fn internal(error: impl std::fmt::Display) -> ApiError {
    eprintln!("database error: {error}");
    (StatusCode::INTERNAL_SERVER_ERROR, "database error".into())
}

fn bad_request(error: impl std::fmt::Display) -> ApiError {
    (StatusCode::BAD_REQUEST, error.to_string())
}

fn find_manifest(connection: &Connection, public_key: &str) -> Result<Manifest, ApiError> {
    let document: Option<String> = connection
        .query_row(
            "SELECT document FROM canaries WHERE public_key = ?1",
            [public_key],
            |row| row.get(0),
        )
        .optional()
        .map_err(internal)?;
    let document = document.ok_or((
        StatusCode::NOT_FOUND,
        "no manifest registered for this public key".into(),
    ))?;
    serde_json::from_str(&document).map_err(internal)
}

async fn register(
    State(database): State<Database>,
    Json(manifest): Json<Manifest>,
) -> Result<(StatusCode, Json<Manifest>), ApiError> {
    validate_public_key(&manifest.public_key).map_err(bad_request)?;
    if let Some(defender) = manifest.defender_public_key.as_deref() {
        validate_public_key(defender).map_err(bad_request)?;
        if defender == manifest.public_key {
            return Err(bad_request("defender and flag must use different keys"));
        }
    }
    let connection = database.lock().map_err(internal)?;
    let inserted = connection
        .execute(
            "INSERT INTO canaries (public_key, document) VALUES (?1, ?2)
             ON CONFLICT (public_key) DO NOTHING",
            params![
                manifest.public_key,
                serde_json::to_string(&manifest).map_err(internal)?
            ],
        )
        .map_err(internal)?;
    if find_manifest(&connection, &manifest.public_key)? != manifest {
        return Err((
            StatusCode::CONFLICT,
            "public key already registered with different metadata".into(),
        ));
    }
    let status = if inserted == 1 {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(manifest)))
}

async fn get_manifest(
    State(database): State<Database>,
    Path(public_key): Path<String>,
) -> Result<Json<Manifest>, ApiError> {
    let connection = database.lock().map_err(internal)?;
    Ok(Json(find_manifest(&connection, &public_key)?))
}

async fn submit(
    State(database): State<Database>,
    Json(proof): Json<Proof>,
) -> Result<(StatusCode, Json<Proof>), ApiError> {
    validate_public_key(&proof.public_key).map_err(bad_request)?;
    let mut connection = database.lock().map_err(internal)?;
    let manifest = find_manifest(&connection, &proof.public_key)?;
    if manifest.defender_public_key.is_some()
        && (proof.reply.is_some() || !proof.message.is_empty())
    {
        return Err(bad_request("submit private reports to /threads"));
    }
    verify(&proof, &manifest).map_err(bad_request)?;
    let transaction = connection.transaction().map_err(internal)?;
    let inserted = insert_proof(&transaction, &proof)?;
    if let Some(reply) = &proof.reply {
        store_message(&transaction, reply)?;
    }
    transaction.commit().map_err(internal)?;
    let status = if inserted {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(proof)))
}

fn insert_proof(connection: &Connection, proof: &Proof) -> Result<bool, ApiError> {
    let inserted = connection
        .execute(
            "INSERT INTO proofs (public_key, signature, document) VALUES (?1, ?2, ?3)
             ON CONFLICT (public_key, signature) DO NOTHING",
            params![
                proof.public_key,
                proof.signature,
                serde_json::to_string(proof).map_err(internal)?,
            ],
        )
        .map_err(internal)?;
    if inserted == 0 {
        let stored: String = connection
            .query_row(
                "SELECT document FROM proofs WHERE public_key = ?1 AND signature = ?2",
                params![proof.public_key, proof.signature],
                |row| row.get(0),
            )
            .map_err(internal)?;
        if &serde_json::from_str::<Proof>(&stored).map_err(internal)? != proof {
            return Err((StatusCode::CONFLICT, "proof signature already used".into()));
        }
    }
    Ok(inserted == 1)
}

async fn list_proofs(
    State(database): State<Database>,
    Path(public_key): Path<String>,
) -> Result<Json<Vec<Proof>>, ApiError> {
    let connection = database.lock().map_err(internal)?;
    find_manifest(&connection, &public_key)?;
    let mut statement = connection
        .prepare("SELECT document FROM proofs WHERE public_key = ?1 ORDER BY rowid")
        .map_err(internal)?;
    let rows = statement
        .query_map([public_key], |row| row.get::<_, String>(0))
        .map_err(internal)?;
    let mut proofs = Vec::new();
    for row in rows {
        proofs.push(serde_json::from_str(&row.map_err(internal)?).map_err(internal)?);
    }
    Ok(Json(proofs))
}

async fn append_message(
    State(database): State<Database>,
    Json(entry): Json<EncryptedMessage>,
) -> Result<(StatusCode, Json<EncryptedMessage>), ApiError> {
    validate_public_key(&entry.public_key).map_err(bad_request)?;
    let connection = database.lock().map_err(internal)?;
    let manifest = find_manifest(&connection, &entry.public_key)?;
    if manifest.defender_public_key.is_some() {
        return Err(bad_request(
            "append private messages to their finder thread",
        ));
    }
    verify_message(&entry, &manifest.public_key).map_err(bad_request)?;
    let (status, stored) = store_message(&connection, &entry)?;
    Ok((status, Json(stored)))
}

fn store_message(
    connection: &Connection,
    entry: &EncryptedMessage,
) -> Result<(StatusCode, EncryptedMessage), ApiError> {
    let inserted = connection
        .execute(
            "INSERT INTO record_entries (public_key, nonce, document) VALUES (?1, ?2, ?3)
             ON CONFLICT (public_key, nonce) DO NOTHING",
            params![
                entry.public_key,
                entry.nonce,
                serde_json::to_string(entry).map_err(internal)?,
            ],
        )
        .map_err(internal)?;
    let document: String = connection
        .query_row(
            "SELECT document FROM record_entries WHERE public_key = ?1 AND nonce = ?2",
            params![entry.public_key, entry.nonce],
            |row| row.get(0),
        )
        .map_err(internal)?;
    let stored: EncryptedMessage = serde_json::from_str(&document).map_err(internal)?;
    if stored.ciphertext != entry.ciphertext {
        return Err((StatusCode::CONFLICT, "message nonce already used".into()));
    }
    let status = if inserted == 1 {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, stored))
}

async fn list_messages(
    State(database): State<Database>,
    Path(public_key): Path<String>,
) -> Result<Json<Vec<EncryptedMessage>>, ApiError> {
    let connection = database.lock().map_err(internal)?;
    find_manifest(&connection, &public_key)?;
    let mut statement = connection
        .prepare("SELECT document FROM record_entries WHERE public_key = ?1 ORDER BY rowid")
        .map_err(internal)?;
    let rows = statement
        .query_map([public_key], |row| row.get::<_, String>(0))
        .map_err(internal)?;
    let mut entries = Vec::new();
    for row in rows {
        entries.push(serde_json::from_str(&row.map_err(internal)?).map_err(internal)?);
    }
    Ok(Json(entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{Method, Request},
    };
    use serde_json::{Map, Value, json};
    use tower::ServiceExt;

    use crate::{decrypt_message, encrypt_message, generate, prove, prove_with_reply};

    #[tokio::test]
    async fn cli_endpoint_serves_installer_with_configured_release_host() {
        let router = app_with_releases(
            Connection::open_in_memory().unwrap(),
            "https://releases.example/kompromat",
        )
        .unwrap();
        let response = router
            .oneshot(Request::builder().uri("/cli").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["content-type"],
            "text/x-shellscript; charset=utf-8"
        );
        let script = String::from_utf8(
            to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(script.starts_with("#!/bin/sh"));
        assert!(script.contains("default_release_url='https://releases.example/kompromat'"));
        assert!(script.contains("Checksum mismatch"));
        assert!(
            app_with_releases(Connection::open_in_memory().unwrap(), "http://example.com").is_err()
        );
    }

    async fn request(
        app: &Router,
        method: Method,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, String) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        body.map(|value| value.to_string()).unwrap_or_default(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn finder_openings_and_messages_are_atomic_and_scoped() {
        use crate::threads::{encrypt, fresh_secret, open, participant_public};

        async fn read(router: &Router, uri: &str) -> Value {
            let (status, document) = request(router, Method::GET, uri, None).await;
            assert_eq!(status, StatusCode::OK);
            serde_json::from_str(&document).unwrap()
        }

        let file = tempfile::NamedTempFile::new().unwrap();
        let router = app(Connection::open(file.path()).unwrap()).unwrap();
        let (flag, mut manifest) = generate(Map::new());
        let defender = fresh_secret();
        let defender_public = participant_public(&defender).unwrap();
        manifest.defender_public_key = Some(defender_public.clone());
        for invalid in ["not a key".to_owned(), manifest.public_key.clone()] {
            let mut changed = manifest.clone();
            changed.defender_public_key = Some(invalid);
            assert_eq!(
                request(&router, Method::POST, "/dossiers", Some(json!(changed)))
                    .await
                    .0,
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            request(&router, Method::POST, "/dossiers", Some(json!(manifest)))
                .await
                .0,
            StatusCode::CREATED
        );
        let alice = fresh_secret();
        let alice_report = open(&flag, &defender_public, &alice, "Alice's report").unwrap();
        let bob_report = open(&flag, &defender_public, &fresh_secret(), "Bob's report").unwrap();
        for (report, status) in [
            (&alice_report, StatusCode::CREATED),
            (&alice_report, StatusCode::OK),
            (&bob_report, StatusCode::CREATED),
        ] {
            assert_eq!(
                request(&router, Method::POST, "/threads", Some(json!(report)))
                    .await
                    .0,
                status
            );
        }

        // A second opening with Alice's ID must leave neither an extra thread nor a proof.
        let conflicting = open(&flag, &defender_public, &alice, "new opening").unwrap();
        assert_eq!(
            request(&router, Method::POST, "/threads", Some(json!(conflicting)))
                .await
                .0,
            StatusCode::CONFLICT
        );
        let route = format!("/dossiers/{}", manifest.public_key);
        assert_eq!(
            read(&router, &format!("{route}/proofs")).await,
            json!([alice_report.proof, bob_report.proof])
        );

        let entries = format!("/threads/{}/messages", alice_report.participants.finder);
        let reply = encrypt(
            &alice_report.participants,
            &defender,
            "DEF's reply to Alice",
        )
        .unwrap();
        let wrong = format!("/threads/{}/messages", bob_report.participants.finder);
        assert_eq!(
            request(&router, Method::POST, &wrong, Some(json!(reply)))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            request(
                &router,
                Method::POST,
                &entries,
                Some(json!(alice_report.first))
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        for status in [StatusCode::CREATED, StatusCode::OK] {
            assert_eq!(
                request(&router, Method::POST, &entries, Some(json!(reply)))
                    .await
                    .0,
                status
            );
        }

        // These submissions would expose a note to the public or all holders of the flag.
        for (route, body) in [
            (
                "/proofs",
                json!(prove(&flag, "public note".into()).unwrap()),
            ),
            (
                "/proofs",
                json!(prove_with_reply(&flag, String::new(), "shared note").unwrap()),
            ),
            (
                "/records",
                json!(encrypt_message(&flag, "legacy message").unwrap()),
            ),
        ] {
            assert_eq!(
                request(&router, Method::POST, route, Some(body)).await.0,
                StatusCode::BAD_REQUEST
            );
        }
        let bare = prove(&flag, String::new()).unwrap();
        assert_eq!(
            request(&router, Method::POST, "/proofs", Some(json!(bare)))
                .await
                .0,
            StatusCode::CREATED
        );

        drop(router);
        let reopened = app(Connection::open(file.path()).unwrap()).unwrap();
        assert_eq!(
            read(&reopened, &format!("{route}/threads")).await,
            json!([alice_report, bob_report])
        );
        let alice_thread = format!("/threads/{}", alice_report.participants.finder);
        assert_eq!(read(&reopened, &alice_thread).await, json!(alice_report));
        assert_eq!(read(&reopened, &entries).await, json!([reply]));
        assert_eq!(read(&reopened, &wrong).await, json!([]));
        assert_eq!(
            read(&reopened, &format!("{route}/messages")).await,
            json!([])
        );
    }

    #[tokio::test]
    async fn legacy_freeform_metadata_does_not_enable_private_mode() {
        let router = app(Connection::open_in_memory().unwrap()).unwrap();
        let mut metadata = Map::new();
        metadata.insert(
            "defender_public_key".into(),
            json!("legacy application data"),
        );
        let (flag, manifest) = generate(metadata);
        let proof = prove_with_reply(&flag, String::new(), "shared note").unwrap();
        for (uri, body) in [("/dossiers", json!(manifest)), ("/proofs", json!(proof))] {
            assert_eq!(
                request(&router, Method::POST, uri, Some(body)).await.0,
                StatusCode::CREATED
            );
        }
    }

    #[tokio::test]
    async fn registry_and_proofs_are_persistent_and_idempotent() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let router = app(Connection::open(file.path()).unwrap()).unwrap();
        let (secret, dossier) = generate(Map::new());
        let proof = prove(&secret, "found it".into()).unwrap();
        for (route, document) in [("/dossiers", json!(dossier)), ("/proofs", json!(proof))] {
            for status in [StatusCode::CREATED, StatusCode::OK] {
                let (actual, response) =
                    request(&router, Method::POST, route, Some(document.clone())).await;
                assert_eq!(actual, status);
                assert_eq!(serde_json::from_str::<Value>(&response).unwrap(), document);
                assert!(!response.contains(&secret.secret_key));
            }
        }
        let mut changed = dossier.clone();
        changed
            .metadata
            .insert("label".into(), json!("replacement"));
        assert_eq!(
            request(&router, Method::POST, "/dossiers", Some(json!(changed)))
                .await
                .0,
            StatusCode::CONFLICT
        );
        drop(router);

        let reopened = app(Connection::open(file.path()).unwrap()).unwrap();
        let route = format!("/dossiers/{}", dossier.public_key);
        let (status, document) = request(&reopened, Method::GET, &route, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<Value>(&document).unwrap(),
            json!(dossier)
        );
        let (status, document) =
            request(&reopened, Method::GET, &format!("{route}/proofs"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<Value>(&document).unwrap(),
            json!([proof])
        );
    }

    #[tokio::test]
    async fn rejects_unknown_dossiers_tampering_and_secret_fields() {
        let router = app(Connection::open_in_memory().unwrap()).unwrap();
        let (secret, dossier) = generate(Map::new());
        let proof = prove(&secret, "original".into()).unwrap();
        assert_eq!(
            request(&router, Method::POST, "/proofs", Some(json!(proof)))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            request(
                &router,
                Method::GET,
                &format!("/dossiers/{}/proofs", dossier.public_key),
                None
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            request(
                &router,
                Method::POST,
                "/dossiers",
                Some(json!({"public_key": "00".repeat(32)}))
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            request(&router, Method::POST, "/dossiers", Some(json!(dossier)))
                .await
                .0,
            StatusCode::CREATED
        );

        let mut changed = proof.clone();
        changed.message.push('!');
        assert_eq!(
            request(&router, Method::POST, "/proofs", Some(json!(changed)))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        changed.signature = "00".repeat(64);
        assert_eq!(
            request(&router, Method::POST, "/proofs", Some(json!(changed)))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        for (route, mut document) in [("/dossiers", json!(dossier)), ("/proofs", json!(proof))] {
            document["secret_key"] = json!(secret.secret_key);
            assert_eq!(
                request(&router, Method::POST, route, Some(document))
                    .await
                    .0,
                StatusCode::UNPROCESSABLE_ENTITY
            );
        }
        let mut oversized = dossier.clone();
        oversized
            .metadata
            .insert("large".into(), json!("x".repeat(64 * 1024)));
        assert_eq!(
            request(&router, Method::POST, "/dossiers", Some(json!(oversized)))
                .await
                .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let (_, stored) = request(
            &router,
            Method::GET,
            &format!("/dossiers/{}/proofs", dossier.public_key),
            None,
        )
        .await;
        assert_eq!(stored, "[]");
    }

    #[tokio::test]
    async fn messages_are_encrypted_persistent_and_idempotent() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let router = app(Connection::open(file.path()).unwrap()).unwrap();
        let (secret, dossier) = generate(Map::new());
        let route = format!("/dossiers/{}/messages", dossier.public_key);
        request(&router, Method::POST, "/dossiers", Some(json!(dossier))).await;
        assert_eq!(
            request(&router, Method::GET, &route, None).await,
            (StatusCode::OK, "[]".into())
        );

        let message = "private evidence: key found inside the backup";
        let entry = encrypt_message(&secret, message).unwrap();
        for status in [StatusCode::CREATED, StatusCode::OK] {
            let (actual, response) =
                request(&router, Method::POST, "/messages", Some(json!(entry))).await;
            assert_eq!(actual, status);
            assert_eq!(
                serde_json::from_str::<Value>(&response).unwrap(),
                json!(entry)
            );
            assert!(!response.contains(message));
            assert!(!response.contains(&secret.secret_key));
        }

        let keypair = secret.keypair().unwrap();
        let mut resigned = entry.clone();
        resigned.signature = hex::encode(
            keypair
                .sign_simple(
                    crate::messages::CONTEXT,
                    &crate::messages::signed_bytes(&resigned).unwrap(),
                )
                .to_bytes(),
        );
        assert_ne!(resigned.signature, entry.signature);
        let (status, response) =
            request(&router, Method::POST, "/messages", Some(json!(resigned))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<Value>(&response).unwrap(),
            json!(entry)
        );

        let mut conflict = entry.clone();
        conflict.ciphertext.replace_range(
            ..2,
            if &entry.ciphertext[..2] == "00" {
                "01"
            } else {
                "00"
            },
        );
        conflict.signature = hex::encode(
            keypair
                .sign_simple(
                    crate::messages::CONTEXT,
                    &crate::messages::signed_bytes(&conflict).unwrap(),
                )
                .to_bytes(),
        );
        assert_eq!(
            request(&router, Method::POST, "/messages", Some(json!(conflict)))
                .await
                .0,
            StatusCode::CONFLICT
        );
        let second = encrypt_message(&secret, "additional private context").unwrap();
        assert_eq!(
            request(&router, Method::POST, "/messages", Some(json!(second)))
                .await
                .0,
            StatusCode::CREATED
        );
        drop(router);

        let database = std::fs::read(file.path()).unwrap();
        let stored = String::from_utf8_lossy(&database);
        assert!(!stored.contains(message));
        assert!(!stored.contains("additional private context"));
        assert!(!stored.contains(&secret.secret_key));
        let reopened = app(Connection::open(file.path()).unwrap()).unwrap();
        let (status, response) = request(&reopened, Method::GET, &route, None).await;
        assert_eq!(status, StatusCode::OK);
        let entries: Vec<EncryptedMessage> = serde_json::from_str(&response).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].signature, entry.signature);
        assert_eq!(decrypt_message(&secret, &entries[0]).unwrap(), message);
        assert_eq!(
            decrypt_message(&secret, &entries[1]).unwrap(),
            "additional private context"
        );
        assert!(!response.contains(message));
        assert!(!response.contains(&secret.secret_key));
    }

    #[tokio::test]
    async fn message_writes_require_valid_message_signatures() {
        let router = app(Connection::open_in_memory().unwrap()).unwrap();
        let (secret, dossier) = generate(Map::new());
        let entry = encrypt_message(&secret, "private message").unwrap();
        let route = format!("/dossiers/{}/messages", dossier.public_key);
        assert_eq!(
            request(&router, Method::POST, "/messages", Some(json!(entry)))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            request(&router, Method::GET, &route, None).await.0,
            StatusCode::NOT_FOUND
        );
        let (_, other) = generate(Map::new());
        for public in [&dossier, &other] {
            request(&router, Method::POST, "/dossiers", Some(json!(public))).await;
        }

        let mut changed = entry.clone();
        changed.ciphertext.replace_range(
            ..2,
            if &entry.ciphertext[..2] == "00" {
                "01"
            } else {
                "00"
            },
        );
        assert_eq!(
            request(&router, Method::POST, "/messages", Some(json!(changed)))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        changed = entry.clone();
        changed.public_key = other.public_key;
        assert_eq!(
            request(&router, Method::POST, "/messages", Some(json!(changed)))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        changed = entry.clone();
        changed.signature = prove(&secret, "public claim".into()).unwrap().signature;
        assert_eq!(
            request(&router, Method::POST, "/messages", Some(json!(changed)))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let proof = Proof {
            public_key: dossier.public_key,
            message: "public claim".into(),
            signature: entry.signature.clone(),
            reply: None,
        };
        assert_eq!(
            request(&router, Method::POST, "/proofs", Some(json!(proof)))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        for field in ["plaintext", "secret_key"] {
            let mut document = json!(entry);
            document[field] = json!("must remain local");
            assert_eq!(
                request(&router, Method::POST, "/messages", Some(document))
                    .await
                    .0,
                StatusCode::UNPROCESSABLE_ENTITY
            );
        }
        assert_eq!(request(&router, Method::GET, &route, None).await.1, "[]");
    }

    #[tokio::test]
    async fn proof_and_encrypted_reply_are_persisted_together() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let router = app(Connection::open(file.path()).unwrap()).unwrap();
        let (secret, dossier) = generate(Map::new());
        request(&router, Method::POST, "/dossiers", Some(json!(dossier))).await;
        let private = "private reply: the key was in the backup";
        let proof = prove_with_reply(&secret, "found it".into(), private).unwrap();
        for status in [StatusCode::CREATED, StatusCode::OK] {
            let (actual, response) =
                request(&router, Method::POST, "/proofs", Some(json!(proof))).await;
            assert_eq!(actual, status);
            assert_eq!(
                serde_json::from_str::<Value>(&response).unwrap(),
                json!(proof)
            );
            assert!(!response.contains(private));
            assert!(!response.contains(&secret.secret_key));
        }
        drop(router);
        let bytes = std::fs::read(file.path()).unwrap();
        let stored = String::from_utf8_lossy(&bytes);
        assert!(!stored.contains(private));
        assert!(!stored.contains(&secret.secret_key));

        let reopened = app(Connection::open(file.path()).unwrap()).unwrap();
        let base = format!("/dossiers/{}", dossier.public_key);
        let (_, proofs) = request(&reopened, Method::GET, &format!("{base}/proofs"), None).await;
        assert_eq!(
            serde_json::from_str::<Value>(&proofs).unwrap(),
            json!([proof])
        );
        let (_, response) =
            request(&reopened, Method::GET, &format!("{base}/messages"), None).await;
        let entries: Vec<EncryptedMessage> = serde_json::from_str(&response).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(decrypt_message(&secret, &entries[0]).unwrap(), private);
        assert!(!response.contains(private));
    }

    #[tokio::test]
    async fn changed_replies_cannot_be_submitted_with_a_proof() {
        let router = app(Connection::open_in_memory().unwrap()).unwrap();
        let (secret, dossier) = generate(Map::new());
        request(&router, Method::POST, "/dossiers", Some(json!(dossier))).await;
        let proof = prove_with_reply(&secret, "found it".into(), "original private reply").unwrap();
        let mut stripped = proof.clone();
        stripped.reply = None;
        let mut swapped = proof.clone();
        swapped.reply = Some(encrypt_message(&secret, "replacement reply").unwrap());
        let mut altered = proof;
        altered.reply.as_mut().unwrap().ciphertext.push_str("00");
        for invalid in [stripped, swapped, altered] {
            assert_eq!(
                request(&router, Method::POST, "/proofs", Some(json!(invalid)))
                    .await
                    .0,
                StatusCode::BAD_REQUEST
            );
        }
        for suffix in ["proofs", "messages"] {
            let route = format!("/dossiers/{}/{suffix}", dossier.public_key);
            assert_eq!(request(&router, Method::GET, &route, None).await.1, "[]");
        }
    }

    #[tokio::test]
    async fn reply_nonce_conflict_rolls_back_proof_insertion() {
        let router = app(Connection::open_in_memory().unwrap()).unwrap();
        let (secret, dossier) = generate(Map::new());
        request(&router, Method::POST, "/dossiers", Some(json!(dossier))).await;
        let proof = prove_with_reply(&secret, "found it".into(), "private reply").unwrap();
        verify(&proof, &dossier).unwrap();
        let mut existing = proof.reply.clone().unwrap();
        existing.ciphertext.replace_range(
            ..2,
            if &existing.ciphertext[..2] == "00" {
                "01"
            } else {
                "00"
            },
        );
        existing.signature = hex::encode(
            secret
                .keypair()
                .unwrap()
                .sign_simple(
                    crate::messages::CONTEXT,
                    &crate::messages::signed_bytes(&existing).unwrap(),
                )
                .to_bytes(),
        );
        assert_eq!(
            request(&router, Method::POST, "/messages", Some(json!(existing)))
                .await
                .0,
            StatusCode::CREATED
        );
        assert_eq!(
            request(&router, Method::POST, "/proofs", Some(json!(proof)))
                .await
                .0,
            StatusCode::CONFLICT
        );
        let base = format!("/dossiers/{}", dossier.public_key);
        assert_eq!(
            request(&router, Method::GET, &format!("{base}/proofs"), None)
                .await
                .1,
            "[]"
        );
        let (_, response) = request(&router, Method::GET, &format!("{base}/messages"), None).await;
        assert_eq!(
            serde_json::from_str::<Value>(&response).unwrap(),
            json!([existing])
        );
    }

    #[tokio::test]
    async fn legacy_routes_share_dossiers_and_messages() {
        let router = app(Connection::open_in_memory().unwrap()).unwrap();
        let (key, dossier) = generate(Map::new());
        assert_eq!(
            request(&router, Method::POST, "/canaries", Some(json!(dossier)))
                .await
                .0,
            StatusCode::CREATED
        );
        let (_, response) = request(
            &router,
            Method::GET,
            &format!("/dossiers/{}", dossier.public_key),
            None,
        )
        .await;
        assert_eq!(
            serde_json::from_str::<Value>(&response).unwrap(),
            json!(dossier)
        );
        let message = encrypt_message(&key, "private reply").unwrap();
        assert_eq!(
            request(&router, Method::POST, "/records", Some(json!(message)))
                .await
                .0,
            StatusCode::CREATED
        );
        for route in [
            format!("/dossiers/{}/messages", dossier.public_key),
            format!("/canaries/{}/record", dossier.public_key),
        ] {
            let (status, response) = request(&router, Method::GET, &route, None).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                serde_json::from_str::<Value>(&response).unwrap(),
                json!([message])
            );
        }
    }
}
