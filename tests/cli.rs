use std::{
    fs,
    process::{Command, Output},
};

use serde_json::Value;
use tempfile::tempdir;

fn cli(dir: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kompromat"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn offline_proof_and_secret_file_protection() {
    let dir = tempdir().unwrap();
    let generated = cli(
        dir.path(),
        &[
            "generate",
            "--out",
            "secret.json",
            "--metadata",
            r#"{"label":"test"}"#,
        ],
    );
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let public: Value = serde_json::from_slice(&generated.stdout).unwrap();
    assert_eq!(public["metadata"]["label"], "test");
    assert!(public.get("secret_key").is_none());
    fs::write(dir.path().join("manifest.json"), generated.stdout).unwrap();
    let original_secret = fs::read(dir.path().join("secret.json")).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(dir.path().join("secret.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    assert!(
        !cli(dir.path(), &["generate", "--out", "secret.json"])
            .status
            .success()
    );
    assert_eq!(
        original_secret,
        fs::read(dir.path().join("secret.json")).unwrap()
    );
    assert!(
        !cli(
            dir.path(),
            &["generate", "--out", "bad.json", "--metadata", "[]"]
        )
        .status
        .success()
    );
    assert!(!dir.path().join("bad.json").exists());

    let proven = cli(
        dir.path(),
        &["prove", "secret.json", "--manifest", "manifest.json"],
    );
    assert!(
        proven.status.success(),
        "{}",
        String::from_utf8_lossy(&proven.stderr)
    );
    let mut proof: Value = serde_json::from_slice(&proven.stdout).unwrap();
    assert!(proof.get("secret_key").is_none());
    fs::write(dir.path().join("proof.json"), proven.stdout).unwrap();
    let verified = cli(
        dir.path(),
        &["verify", "proof.json", "--manifest", "manifest.json"],
    );
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&verified.stdout).unwrap()["valid"],
        true
    );

    proof["message"] = "changed".into();
    fs::write(
        dir.path().join("proof.json"),
        serde_json::to_vec(&proof).unwrap(),
    )
    .unwrap();
    assert!(
        !cli(
            dir.path(),
            &["verify", "proof.json", "--manifest", "manifest.json"]
        )
        .status
        .success()
    );
}

#[test]
fn manifest_output_is_created_once() {
    let dir = tempdir().unwrap();
    let path = dir.path();
    let generate = |flag: &str, defender: &str| {
        cli(
            path,
            &[
                "generate",
                "--out",
                flag,
                "--defender-out",
                defender,
                "--manifest-out",
                "manifest",
            ],
        )
    };
    let first = generate("flag", "defender");
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(first.stdout.is_empty());
    let saved = fs::read(path.join("manifest")).unwrap();
    let manifest: kompromat::Manifest = serde_json::from_slice(&saved).unwrap();
    let flag: kompromat::Key =
        serde_json::from_slice(&fs::read(path.join("flag")).unwrap()).unwrap();
    assert_eq!(manifest.public_key, flag.public_key().unwrap());
    assert_eq!(manifest.defender_public_key, flag.defender_public_key);

    let collision = generate("another-flag", "another-defender");
    assert!(!collision.status.success());
    assert_eq!(fs::read(path.join("manifest")).unwrap(), saved);
    assert!(!path.join("another-flag").exists());
    assert!(!path.join("another-defender").exists());
}

#[test]
fn generation_errors_preserve_existing_files() {
    let dir = tempdir().unwrap();
    let path = dir.path();
    fs::write(path.join("flag"), "existing flag").unwrap();
    let collision = cli(path, &["generate", "--out", "flag"]);
    assert!(!collision.status.success());
    assert!(collision.stdout.is_empty());
    assert_eq!(fs::read(path.join("flag")).unwrap(), b"existing flag");
    assert!(!path.join("defender.json").exists());

    fs::write(path.join("defender.json"), "existing defender").unwrap();
    let collision = cli(path, &["generate", "--out", "new-flag"]);
    assert!(!collision.status.success());
    assert!(collision.stdout.is_empty());
    assert_eq!(
        fs::read(path.join("defender.json")).unwrap(),
        b"existing defender"
    );
    assert!(!path.join("new-flag").exists());

    let shared = cli(path, &["generate", "--out", "new-flag", "--shared"]);
    assert!(!shared.status.success());
    assert!(String::from_utf8_lossy(&shared.stderr).contains("--shared"));
    assert!(!path.join("new-flag").exists());
}

#[test]
fn flag_input_must_be_a_regular_file_under_the_limit() {
    let dir = tempdir().unwrap();
    fs::File::create(dir.path().join("oversize"))
        .unwrap()
        .set_len(1024 * 1024 + 1)
        .unwrap();
    for (name, reason) in [
        ("oversize", "exceeds 1 MiB"),
        #[cfg(unix)]
        ("/dev/null", "must be a regular file"),
    ] {
        let output = cli(dir.path(), &["prove", name]);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(reason));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_writes_reject_unrelated_acknowledgments() {
    use axum::{
        Json, Router,
        routing::{get, post},
    };
    use kompromat::{Proof, encrypt_message, generate_shared, prove};
    use serde_json::json;

    let dir = tempdir().unwrap();
    let (key, manifest) = generate_shared(Default::default());
    let proof = prove(&key, "offline claim".into()).unwrap();
    fs::write(dir.path().join("flag"), serde_json::to_vec(&key).unwrap()).unwrap();
    fs::write(
        dir.path().join("proof"),
        serde_json::to_vec(&proof).unwrap(),
    )
    .unwrap();

    let other_proof = prove(&key, "other claim".into()).unwrap();
    let other_message = encrypt_message(&key, "other entry").unwrap();
    let public_key = manifest.public_key.clone();
    let app = Router::new()
        .route(
            "/dossiers/{flag}",
            get(move || async move { Json(manifest) }),
        )
        .route(
            "/proofs",
            post(move |Json(body): Json<Proof>| async move {
                if body.message.is_empty() {
                    Json(Value::Null)
                } else {
                    Json(json!(other_proof))
                }
            }),
        )
        .route(
            "/messages",
            post(move || async move { Json(other_message) }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    let hunt = format!("{api}/dossiers/{public_key}");
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    for (args, error) in [
        (&["report", "flag", "--api", &api][..], "invalid type: null"),
        (&["submit", "proof", "--api", &api], "different proof"),
        (
            &["attach", "flag", "--message", "reply", "--hunt", &hunt],
            "different message",
        ),
    ] {
        let output = cli(dir.path(), args);
        assert!(!output.status.success(), "{args:?}");
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains(error));
    }
    server.abort();
}
