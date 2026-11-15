//! An HTTP registry for public manifests, proofs of key possession, and encrypted messages.

mod dossiers;
mod publication;

use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::{get, post},
};
use rusqlite::{Connection, OptionalExtension, Row, params, types::Type};
use serde::{Deserialize, de::DeserializeOwned};

use crate::dossiers::Page;
use crate::{Manifest, validate_public_key};

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
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "release base URL must be an HTTPS directory URL without credentials, query, or fragment"
    );
    let installer = include_str!("../install.sh").replace(
        DEFAULT_RELEASE_BASE_URL,
        &release_base_url
            .trim_end_matches('/')
            .replace('\'', "'\\''"),
    );
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         CREATE TABLE IF NOT EXISTS hunts (
             public_key TEXT PRIMARY KEY,
             document TEXT NOT NULL
         );",
    )?;

    dossiers::initialize(&connection)?;
    publication::initialize(&connection)?;
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
        .route("/hunts", post(register))
        .route("/hunts/{flag}", get(get_manifest))
        .merge(dossiers::routes())
        .merge(publication::routes())
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
            "SELECT document FROM hunts WHERE public_key = ?1",
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

fn registered_manifest(database: &Database, key: &str) -> Result<Manifest, ApiError> {
    let connection = database.lock().map_err(internal)?;
    find_manifest(&connection, key)
}

async fn register(
    State(database): State<Database>,
    Json(manifest): Json<Manifest>,
) -> Result<(StatusCode, Json<Manifest>), ApiError> {
    validate_public_key(&manifest.public_key).map_err(bad_request)?;
    validate_public_key(&manifest.defender_public_key).map_err(bad_request)?;
    if manifest.defender_public_key == manifest.public_key {
        return Err(bad_request("defender and flag must use different keys"));
    }
    let connection = database.lock().map_err(internal)?;
    let inserted = connection
        .execute(
            "INSERT INTO hunts (public_key, document) VALUES (?1, ?2)
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
    Ok(Json(registered_manifest(&database, &public_key)?))
}

#[derive(Deserialize)]
struct PageQuery {
    after: Option<i64>,
    limit: Option<u32>,
}

impl PageQuery {
    fn read<T, P: rusqlite::Params>(
        &self,
        connection: &Connection,
        sql: &str,
        bind: impl FnOnce(i64, u32) -> P,
        item: impl Fn(&Row<'_>) -> rusqlite::Result<T>,
    ) -> Result<Json<Page<T>>, ApiError> {
        const MAX_PAGE: u32 = 50;
        let after = self.after.unwrap_or(0);
        let limit = self.limit.unwrap_or(MAX_PAGE);
        if after < 0 || !(1..=MAX_PAGE).contains(&limit) {
            return Err(bad_request(
                "expected after >= 0 and limit between 1 and 50",
            ));
        }
        let mut statement = connection.prepare(sql).map_err(internal)?;
        let mut rows = statement.query(bind(after, limit + 1)).map_err(internal)?;
        let mut items = Vec::new();
        let mut last = None;
        while let Some(row) = rows.next().map_err(internal)? {
            if items.len() == limit as usize {
                return Ok(Json(Page {
                    items,
                    next_after: last,
                }));
            }
            last = Some(row.get(0).map_err(internal)?);
            items.push(item(row).map_err(internal)?);
        }
        Ok(Json(Page {
            items,
            next_after: None,
        }))
    }
}

fn read_json<T: DeserializeOwned>(row: &Row<'_>, column: usize) -> rusqlite::Result<T> {
    let value: String = row.get(column)?;
    serde_json::from_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(column, Type::Text, Box::new(error))
    })
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
        for invalid in ["http://example.com", "https://user:token@example.com"] {
            assert!(app_with_releases(Connection::open_in_memory().unwrap(), invalid).is_err());
        }
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
        use crate::dossiers::{encrypt, fresh_secret, open};

        async fn read(router: &Router, uri: &str) -> Value {
            let (status, document) = request(router, Method::GET, uri, None).await;
            assert_eq!(status, StatusCode::OK);
            serde_json::from_str(&document).unwrap()
        }

        let file = tempfile::NamedTempFile::new().unwrap();
        let router = app(Connection::open(file.path()).unwrap()).unwrap();
        let (flag, manifest, defender) = crate::generate(Map::new());
        for invalid in ["not a key".to_owned(), manifest.public_key.clone()] {
            let mut changed = manifest.clone();
            changed.defender_public_key = invalid;
            assert_eq!(
                request(&router, Method::POST, "/hunts", Some(json!(changed)))
                    .await
                    .0,
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            request(&router, Method::POST, "/hunts", Some(json!(manifest)))
                .await
                .0,
            StatusCode::CREATED
        );
        let alice = fresh_secret();
        let alice_report = open(&flag, &manifest, &alice, "Alice's report").unwrap();
        let bob_report = open(&flag, &manifest, &fresh_secret(), "Bob's report").unwrap();
        let mut forged = alice_report.clone();
        forged.proof.signature = "00".repeat(64);
        assert_eq!(
            request(&router, Method::POST, "/report", Some(json!(forged)))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let mut accepted = Vec::new();
        for (report, status) in [
            (&alice_report, StatusCode::CREATED),
            (&alice_report, StatusCode::OK),
            (&bob_report, StatusCode::CREATED),
        ] {
            let (actual, body) =
                request(&router, Method::POST, "/report", Some(json!(report))).await;
            assert_eq!(actual, status);
            let response: crate::dossiers::AcceptedOpening = serde_json::from_str(&body).unwrap();
            assert_eq!(&response.opening, report);
            if status == StatusCode::CREATED {
                assert_eq!(response.receipt.sequence, accepted.len() as i64 + 1);
                accepted.push(response.receipt);
            } else {
                assert_eq!(Some(&response.receipt), accepted.last());
            }
        }

        // A conflicting opening must not replace Alice's report or create another dossier.
        let conflicting = open(&flag, &manifest, &alice, "new opening").unwrap();
        assert_eq!(
            request(&router, Method::POST, "/report", Some(json!(conflicting)))
                .await
                .0,
            StatusCode::CONFLICT
        );
        let route = format!("/hunts/{}", manifest.public_key);
        let db = Connection::open(file.path()).unwrap();
        let stored_dossiers: i64 = db
            .query_row("SELECT count(*) FROM dossiers", [], |row| row.get(0))
            .unwrap();
        assert_eq!(stored_dossiers, 2);
        drop(db);

        let entries = format!("/dossiers/{}/messages", alice_report.participants.finder);
        let reply = encrypt(
            &alice_report.participants,
            &defender,
            "DEF's reply to Alice",
        )
        .unwrap();
        let wrong = format!("/dossiers/{}/messages", bob_report.participants.finder);
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
        let second_reply = encrypt(&alice_report.participants, &alice, "More evidence").unwrap();
        assert_eq!(
            request(&router, Method::POST, &entries, Some(json!(second_reply)))
                .await
                .0,
            StatusCode::CREATED
        );

        drop(router);
        let reopened = app(Connection::open(file.path()).unwrap()).unwrap();
        assert_eq!(
            read(&reopened, &format!("{route}/dossiers?limit=1")).await,
            json!({"items": [accepted[0]], "next_after": 1})
        );
        assert_eq!(
            read(&reopened, &format!("{route}/dossiers?limit=1&after=1")).await,
            json!({"items": [accepted[1]], "next_after": null})
        );
        assert_eq!(
            request(
                &reopened,
                Method::GET,
                &format!("{route}/dossiers?limit=51"),
                None
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        let alice_dossier = format!("/dossiers/{}", alice_report.participants.finder);
        assert_eq!(
            read(&reopened, &alice_dossier).await,
            json!({"opening": alice_report, "receipt": accepted[0]})
        );
        for obsolete in [
            format!("/threads/{}", alice_report.participants.finder),
            format!("/dossiers/{}/threads", manifest.public_key),
        ] {
            assert_eq!(
                request(&reopened, Method::GET, &obsolete, None).await.0,
                StatusCode::NOT_FOUND
            );
        }
        assert_eq!(
            read(&reopened, &format!("{entries}?limit=1")).await,
            json!({"items": [reply], "next_after": 1})
        );
        assert_eq!(
            read(&reopened, &format!("{entries}?after=1")).await,
            json!({"items": [second_reply], "next_after": null})
        );
        assert_eq!(
            read(&reopened, &wrong).await,
            json!({"items": [], "next_after": null})
        );
        let bytes = std::fs::read(file.path()).unwrap();
        let stored = String::from_utf8_lossy(&bytes);
        for secret in [
            "Alice's report",
            "DEF's reply to Alice",
            &flag.secret_key,
            &defender,
            &alice,
        ] {
            assert!(!stored.contains(secret));
        }
    }

    #[tokio::test]
    async fn registrations_and_reports_reject_invalid_or_secret_data() {
        use crate::dossiers::{encrypt, fresh_secret, open};

        let file = tempfile::NamedTempFile::new().unwrap();
        let router = app(Connection::open(file.path()).unwrap()).unwrap();
        let (flag, manifest, _) = crate::generate(Map::new());
        let finder = fresh_secret();
        let opening = open(&flag, &manifest, &finder, "private report").unwrap();
        assert_eq!(
            request(&router, Method::POST, "/report", Some(json!(opening)))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        let mut missing_defender = json!(manifest);
        missing_defender
            .as_object_mut()
            .unwrap()
            .remove("defender_public_key");
        assert_eq!(
            request(&router, Method::POST, "/hunts", Some(missing_defender))
                .await
                .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let mut secret_manifest = json!(manifest);
        secret_manifest["secret_key"] = json!(flag.secret_key);
        assert_eq!(
            request(&router, Method::POST, "/hunts", Some(secret_manifest))
                .await
                .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let mut invalid = manifest.clone();
        invalid.public_key = "00".repeat(32);
        assert_eq!(
            request(&router, Method::POST, "/hunts", Some(json!(invalid)))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let mut oversized = manifest.clone();
        oversized
            .metadata
            .insert("large".into(), json!("x".repeat(64 * 1024)));
        assert_eq!(
            request(&router, Method::POST, "/hunts", Some(json!(oversized)))
                .await
                .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        for status in [StatusCode::CREATED, StatusCode::OK] {
            assert_eq!(
                request(&router, Method::POST, "/hunts", Some(json!(manifest)))
                    .await
                    .0,
                status
            );
        }
        let mut changed = manifest.clone();
        changed
            .metadata
            .insert("label".into(), json!("replacement"));
        assert_eq!(
            request(&router, Method::POST, "/hunts", Some(json!(changed)))
                .await
                .0,
            StatusCode::CONFLICT
        );

        let mut changed = opening.clone();
        changed.first.ciphertext.push_str("00");
        assert_eq!(
            request(&router, Method::POST, "/report", Some(json!(changed)))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let mut secret_opening = json!(opening);
        secret_opening["first"]["plaintext"] = json!("must remain local");
        assert_eq!(
            request(&router, Method::POST, "/report", Some(secret_opening))
                .await
                .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            request(&router, Method::POST, "/report", Some(json!(opening)))
                .await
                .0,
            StatusCode::CREATED
        );
        let route = format!("/dossiers/{}/messages", opening.participants.finder);
        let entry = encrypt(&opening.participants, &finder, "follow-up").unwrap();
        let mut changed = entry.clone();
        changed.signature = "00".repeat(64);
        assert_eq!(
            request(&router, Method::POST, &route, Some(json!(changed)))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let mut changed = entry.clone();
        changed.sender = manifest.public_key.clone();
        assert_eq!(
            request(&router, Method::POST, &route, Some(json!(changed)))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let mut secret_entry = json!(entry);
        secret_entry["secret_key"] = json!(finder);
        assert_eq!(
            request(&router, Method::POST, &route, Some(secret_entry))
                .await
                .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let (_, empty) = request(&router, Method::GET, &route, None).await;
        assert_eq!(
            serde_json::from_str::<Value>(&empty).unwrap(),
            json!({"items": [], "next_after": null})
        );
        for route in ["/dossiers/unknown", "/dossiers/unknown/messages"] {
            assert_eq!(
                request(&router, Method::GET, route, None).await.0,
                StatusCode::NOT_FOUND
            );
        }
        drop(router);
        let reopened = app(Connection::open(file.path()).unwrap()).unwrap();
        let (_, saved) = request(
            &reopened,
            Method::GET,
            &format!("/hunts/{}", manifest.public_key),
            None,
        )
        .await;
        assert_eq!(
            serde_json::from_str::<Value>(&saved).unwrap(),
            json!(manifest)
        );
    }

    #[tokio::test]
    async fn private_message_history_is_bounded_and_can_be_continued() {
        use crate::dossiers::{DossierMessage, encrypt, fresh_secret, open};

        let router = app(Connection::open_in_memory().unwrap()).unwrap();
        let (flag, manifest, _) = crate::generate(Map::new());
        request(&router, Method::POST, "/hunts", Some(json!(manifest))).await;
        let finder = fresh_secret();
        let opening = open(&flag, &manifest, &finder, "opening").unwrap();
        request(&router, Method::POST, "/report", Some(json!(opening))).await;
        let route = format!("/dossiers/{}/messages", opening.participants.finder);
        let mut expected = Vec::new();
        for i in 0..51 {
            let entry = encrypt(&opening.participants, &finder, &i.to_string()).unwrap();
            assert_eq!(
                request(&router, Method::POST, &route, Some(json!(entry)))
                    .await
                    .0,
                StatusCode::CREATED
            );
            expected.push(entry);
        }
        let (status, response) = request(&router, Method::GET, &route, None).await;
        assert_eq!(status, StatusCode::OK);
        let page: Page<DossierMessage> = serde_json::from_str(&response).unwrap();
        assert_eq!(page.items, expected[..50]);
        assert_eq!(page.next_after, Some(50));
        let (status, response) =
            request(&router, Method::GET, &format!("{route}?after=50"), None).await;
        assert_eq!(status, StatusCode::OK);
        let page: Page<DossierMessage> = serde_json::from_str(&response).unwrap();
        assert_eq!(page.items, expected[50..]);
        assert_eq!(page.next_after, None);
        for query in ["after=-1", "limit=0", "limit=51"] {
            assert_eq!(
                request(&router, Method::GET, &format!("{route}?{query}"), None)
                    .await
                    .0,
                StatusCode::BAD_REQUEST
            );
        }
    }

    #[tokio::test]
    async fn only_current_defender_authorizations_change_the_public_directory() {
        use crate::publication::{Listing, PublicationState, sign};

        async fn get(router: &Router, path: &str) -> Value {
            let (status, body) = request(router, Method::GET, path, None).await;
            assert_eq!(status, StatusCode::OK);
            serde_json::from_str(&body).unwrap()
        }

        let file = tempfile::NamedTempFile::new().unwrap();
        let router = app(Connection::open(file.path()).unwrap()).unwrap();
        let other_registry = app(Connection::open_in_memory().unwrap()).unwrap();
        let (flag, hunt, defender) = crate::generate(Map::new());
        let (_, mut second, _) = crate::generate(Map::new());
        // The same defender may legitimately control multiple hunts.
        second.defender_public_key = hunt.defender_public_key.clone();
        for manifest in [&hunt, &second] {
            assert_eq!(
                request(&router, Method::POST, "/hunts", Some(json!(manifest)))
                    .await
                    .0,
                StatusCode::CREATED
            );
        }
        request(&other_registry, Method::POST, "/hunts", Some(json!(hunt))).await;
        assert_eq!(
            get(&router, "/hunts").await,
            json!({"items": [], "next_after": null})
        );
        let (_, html) = request(&router, Method::GET, "/", None).await;
        assert!(html.contains("No listings on this page."));
        let route = format!("/hunts/{}/publication", hunt.public_key);
        let second_route = format!("/hunts/{}/publication", second.public_key);
        let initial: PublicationState = serde_json::from_value(get(&router, &route).await).unwrap();
        assert_eq!(initial.revision, 0);
        assert!(initial.listing.is_none());
        let brief = Listing {
            title: "Open <hunt>".into(),
            brief_url: "https://def.example/terms?a=1&b=2".into(),
        };
        let publish = sign(&defender, &hunt.public_key, &initial, Some(brief.clone())).unwrap();
        let wrong_key = sign(
            &flag.secret_key,
            &hunt.public_key,
            &initial,
            Some(brief.clone()),
        )
        .unwrap();
        let mut changed = publish.clone();
        changed.state.listing.as_mut().unwrap().title = "Changed".into();
        let mut skipped = initial.clone();
        skipped.revision += 1;
        let out_of_order =
            sign(&defender, &hunt.public_key, &skipped, Some(brief.clone())).unwrap();
        for (service, path, command, expected) in [
            (&router, &route, &wrong_key, StatusCode::BAD_REQUEST),
            (&router, &route, &changed, StatusCode::BAD_REQUEST),
            (&router, &route, &out_of_order, StatusCode::CONFLICT),
            (&router, &second_route, &publish, StatusCode::BAD_REQUEST),
            (&other_registry, &route, &publish, StatusCode::CONFLICT),
            (&router, &route, &publish, StatusCode::OK),
            (&router, &route, &publish, StatusCode::CONFLICT),
        ] {
            assert_eq!(
                request(service, Method::POST, path, Some(json!(command)))
                    .await
                    .0,
                expected
            );
        }
        let entry = json!({
            "title": brief.title,
            "brief_url": brief.brief_url,
            "hunt": format!("hunts/{}", hunt.public_key)
        });
        assert_eq!(
            get(&router, "/hunts").await,
            json!({"items": [entry], "next_after": null})
        );
        let (_, html) = request(&router, Method::GET, "/", None).await;
        assert!(html.contains("Open &lt;hunt&gt;"));
        assert!(html.contains("https://def.example/terms?a=1&amp;b=2"));
        assert!(html.contains(&format!("href=\"hunts/{}\"", hunt.public_key)));
        assert!(!html.contains(&second.public_key));
        let nested = Router::new().nest("/games/registry", router.clone());
        let (status, nested_html) = request(&nested, Method::GET, "/games/registry", None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(nested_html.contains(&format!("href=\"./registry/hunts/{}\"", hunt.public_key)));
        assert!(nested_html.contains("href=\"./registry/hunts\""));

        let second_publish =
            sign(&defender, &second.public_key, &initial, Some(brief.clone())).unwrap();
        assert_eq!(
            request(
                &router,
                Method::POST,
                &second_route,
                Some(json!(second_publish))
            )
            .await
            .0,
            StatusCode::OK
        );
        let first_page = get(&router, "/hunts?limit=1").await;
        assert_eq!(first_page["items"], json!([entry]));
        let after = first_page["next_after"].as_i64().unwrap();
        let second_page = get(&router, &format!("/hunts?after={after}&limit=1")).await;
        assert_eq!(
            second_page["items"][0]["hunt"],
            format!("hunts/{}", second.public_key)
        );
        assert_eq!(second_page["next_after"], Value::Null);
        let (_, html) = request(&router, Method::GET, "/?limit=1", None).await;
        assert!(html.contains(&format!("?after={after}&amp;limit=1")));

        let withdraw = sign(&defender, &hunt.public_key, &publish.state, None).unwrap();
        assert_eq!(
            request(&router, Method::POST, &route, Some(json!(withdraw)))
                .await
                .0,
            StatusCode::OK
        );
        drop(router);
        let reopened = app(Connection::open(file.path()).unwrap()).unwrap();
        assert_eq!(get(&reopened, &route).await, json!(withdraw.state));
        assert_eq!(
            request(&reopened, Method::POST, &route, Some(json!(publish)))
                .await
                .0,
            StatusCode::CONFLICT
        );
        assert_eq!(get(&reopened, "/hunts").await, second_page);
        for manifest in [&hunt, &second] {
            let path = format!("/hunts/{}", manifest.public_key);
            assert_eq!(get(&reopened, &path).await, json!(manifest));
        }
    }
}
