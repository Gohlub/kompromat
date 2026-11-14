use std::{
    fs,
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, Command, Output, Stdio},
};

use serde_json::Value;
use tempfile::tempdir;

struct Api {
    child: Child,
    url: String,
}

impl Api {
    fn start(dir: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_kompromat-api"))
            .current_dir(dir)
            .args(["--listen", "127.0.0.1:0", "--database", "records.sqlite3"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut api = Self {
            child,
            url: String::new(),
        };
        let mut line = String::new();
        BufReader::new(api.child.stderr.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        api.url = line
            .trim()
            .strip_prefix("listening on ")
            .expect("API startup failed")
            .into();
        api
    }
}

impl Drop for Api {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn cli(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kompromat"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn finders_of_the_same_flag_have_separate_dossiers() {
    let dir = tempdir().unwrap();
    let path = dir.path();
    let api = Api::start(path);
    let manifest = success(cli(
        path,
        &[
            "generate",
            "--out",
            "flag.json",
            "--defender-out",
            "defender.json",
            "--api",
            &api.url,
        ],
    ));
    fs::write(path.join("manifest.json"), manifest.to_string()).unwrap();
    success(cli(path, &["register", "manifest.json", "--api", &api.url]));

    let mut threads = Vec::new();
    for (file, note) in [
        ("alice.json", "Alice found an export bug"),
        ("bob.json", "Bob found a cache bug"),
    ] {
        let report = success(cli(
            path,
            &[
                "report",
                "flag.json",
                "--message",
                note,
                "--finder-out",
                file,
            ],
        ));
        threads.push(report["thread"].as_str().unwrap().to_owned());
        let retry = success(cli(path, &["report", file]));
        assert_eq!(report["thread"], retry["thread"]);
    }
    let alice = &threads[0];
    let bob = &threads[1];
    assert_ne!(alice, bob);
    let inbox = success(cli(path, &["unlock", "defender.json"]));
    assert_eq!(inbox["threads"], serde_json::json!(threads));
    success(cli(
        path,
        &[
            "attach",
            "defender.json",
            "--thread",
            alice,
            "--message",
            "Which request?",
        ],
    ));
    success(cli(
        path,
        &["attach", "alice.json", "--message", "GET /export"],
    ));

    let transcript =
        serde_json::json!(["Alice found an export bug", "Which request?", "GET /export"]);
    assert_eq!(
        success(cli(path, &["unlock", "alice.json"]))["messages"],
        transcript
    );
    assert_eq!(
        success(cli(path, &["unlock", "defender.json", "--thread", alice]))["messages"],
        transcript
    );
    assert_eq!(
        success(cli(path, &["unlock", "bob.json"]))["messages"],
        serde_json::json!(["Bob found a cache bug"])
    );
    assert!(
        !cli(path, &["unlock", "bob.json", "--thread", alice])
            .status
            .success()
    );
    assert!(
        !cli(path, &["unlock", "flag.json", "--thread", alice])
            .status
            .success()
    );

    let opening = reqwest::blocking::get(format!("{}/threads/{alice}", api.url))
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .unwrap();
    assert!(!opening.contains("Alice found an export bug"));
    let shared: Vec<Value> = reqwest::blocking::get(format!(
        "{}/dossiers/{}/messages",
        api.url,
        manifest["public_key"].as_str().unwrap()
    ))
    .unwrap()
    .error_for_status()
    .unwrap()
    .json()
    .unwrap();
    assert!(shared.is_empty());
}

#[test]
fn shared_key_unlocks_encrypted_dossier_over_http_and_after_restart() {
    let dir = tempdir().unwrap();
    let public = success(cli(dir.path(), &["generate", "--out", "key.json"]));
    fs::write(dir.path().join("manifest.json"), public.to_string()).unwrap();
    fs::copy(dir.path().join("key.json"), dir.path().join("finder.json")).unwrap();
    let secret: Value =
        serde_json::from_slice(&fs::read(dir.path().join("key.json")).unwrap()).unwrap();
    let api = Api::start(dir.path());
    success(cli(
        dir.path(),
        &["register", "manifest.json", "--api", &api.url],
    ));
    let empty = success(cli(
        dir.path(),
        &["unlock", "finder.json", "--api", &api.url],
    ));
    assert_eq!(empty["messages"], serde_json::json!([]));
    let messages = [
        "Private instructions: leave a note here.",
        "Found in the archive. 🦀",
    ];
    for (key, message) in ["key.json", "finder.json"].into_iter().zip(messages) {
        let entry = success(cli(
            dir.path(),
            &["attach", key, "--message", message, "--api", &api.url],
        ));
        assert!(entry.get("ciphertext").is_some());
        assert!(!entry.to_string().contains(message));
        assert!(
            !entry
                .to_string()
                .contains(secret["secret_key"].as_str().unwrap())
        );
    }
    let response = reqwest::blocking::get(format!(
        "{}/dossiers/{}/messages",
        api.url,
        public["public_key"].as_str().unwrap()
    ))
    .unwrap()
    .error_for_status()
    .unwrap()
    .text()
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Vec<Value>>(&response).unwrap().len(),
        2
    );
    for message in messages {
        assert!(!response.contains(message));
    }
    drop(api);

    let restarted = Api::start(dir.path());
    let unlocked = success(cli(
        dir.path(),
        &["unlock", "finder.json", "--api", &restarted.url],
    ));
    assert_eq!(unlocked["messages"], serde_json::json!(messages));
    assert_eq!(unlocked["public_key"], public["public_key"]);
    success(cli(dir.path(), &["generate", "--out", "wrong.json"]));
    let wrong = cli(
        dir.path(),
        &["unlock", "wrong.json", "--api", &restarted.url],
    );
    assert!(!wrong.status.success());
    assert!(wrong.stdout.is_empty());
}

#[test]
fn proof_can_respond_privately_in_one_submission() {
    let dir = tempdir().unwrap();
    let public = success(cli(dir.path(), &["generate", "--out", "key.json"]));
    fs::write(dir.path().join("manifest.json"), public.to_string()).unwrap();
    let private = "Found in the internal backup; here is how.";
    let proof = success(cli(
        dir.path(),
        &["prove", "key.json", "--message", private],
    ));
    assert_eq!(proof["message"], "");
    assert!(proof["reply"]["ciphertext"].is_string());
    assert!(!proof.to_string().contains(private));
    fs::write(dir.path().join("proof.json"), proof.to_string()).unwrap();
    success(cli(
        dir.path(),
        &["verify", "proof.json", "--manifest", "manifest.json"],
    ));

    let mut stripped = proof.clone();
    stripped.as_object_mut().unwrap().remove("reply");
    fs::write(dir.path().join("stripped.json"), stripped.to_string()).unwrap();
    assert!(
        !cli(
            dir.path(),
            &["verify", "stripped.json", "--manifest", "manifest.json"]
        )
        .status
        .success()
    );

    let api = Api::start(dir.path());
    success(cli(
        dir.path(),
        &["register", "manifest.json", "--api", &api.url],
    ));
    for _ in 0..2 {
        assert_eq!(
            success(cli(
                dir.path(),
                &["submit", "proof.json", "--api", &api.url]
            )),
            proof
        );
    }
    let unlocked = success(cli(dir.path(), &["unlock", "key.json", "--api", &api.url]));
    assert_eq!(unlocked["messages"], serde_json::json!([private]));
    let response = reqwest::blocking::get(format!(
        "{}/dossiers/{}/proofs",
        api.url,
        public["public_key"].as_str().unwrap()
    ))
    .unwrap()
    .error_for_status()
    .unwrap()
    .text()
    .unwrap();
    assert!(!response.contains(private));
    assert_eq!(
        serde_json::from_str::<Value>(&response).unwrap(),
        serde_json::json!([proof])
    );
}

#[test]
fn report_defaults_to_access_proof_using_the_key_file_api() {
    let dir = tempdir().unwrap();
    let api = Api::start(dir.path());
    let public = success(cli(
        dir.path(),
        &["generate", "--out", "key.json", "--api", &api.url],
    ));
    fs::write(dir.path().join("manifest.json"), public.to_string()).unwrap();
    let key_path = dir.path().join("key.json");
    let mut key: Value = serde_json::from_slice(&fs::read(&key_path).unwrap()).unwrap();
    assert_eq!(key["api"], api.url);
    assert!(
        key["instructions"]
            .as_str()
            .unwrap()
            .contains("kompromat report PATH_TO_THIS_FILE.")
    );
    assert_eq!(key["instructions"], public["metadata"]["instructions"]);
    assert_eq!(key["submission"], public["metadata"]["submission"]);
    assert_eq!(key["submission"]["url"], format!("{}/proofs", api.url));
    assert_eq!(key["submission"]["method"], "POST");
    assert_eq!(key["submission"]["content_type"], "application/json");
    assert!(
        key["submission"]["http"]
            .as_str()
            .unwrap()
            .contains("--data-binary @proof.json")
    );
    assert!(
        !key["submission"]
            .to_string()
            .contains(key["secret_key"].as_str().unwrap())
    );
    success(cli(
        dir.path(),
        &["register", "manifest.json", "--api", &api.url],
    ));

    let proof = success(cli(dir.path(), &["report", "key.json"]));
    assert_eq!(proof["message"], "");
    assert!(proof.get("reply").is_none());
    assert!(
        !proof
            .to_string()
            .contains(key["secret_key"].as_str().unwrap())
    );
    fs::write(dir.path().join("proof.json"), proof.to_string()).unwrap();
    success(cli(
        dir.path(),
        &["verify", "proof.json", "--manifest", "manifest.json"],
    ));
    // Previously saved key files and the old verification flags still work.
    fs::write(
        dir.path().join("legacy.json"),
        serde_json::json!({"secret_key": key["secret_key"]}).to_string(),
    )
    .unwrap();
    success(cli(dir.path(), &["prove", "legacy.json"]));
    let help = cli(dir.path(), &["verify", "--help"]);
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("--manifest"));
    for alias in ["--dossier", "--canary"] {
        assert!(!help.contains(alias));
        success(cli(
            dir.path(),
            &["verify", "proof.json", alias, "manifest.json"],
        ));
    }

    let notes = ["Location of the canary", "Follow-up from the finder"];
    let mut expected_proofs = vec![proof];
    for (flag, note) in ["--message", "--reply"].into_iter().zip(notes) {
        let report = success(cli(dir.path(), &["report", "key.json", flag, note]));
        assert_eq!(report["message"], "");
        assert!(report["reply"]["ciphertext"].is_string());
        assert!(!report.to_string().contains(note));
        expected_proofs.push(report);
    }
    let listed: Vec<Value> = reqwest::blocking::get(format!(
        "{}/dossiers/{}/proofs",
        api.url,
        public["public_key"].as_str().unwrap()
    ))
    .unwrap()
    .error_for_status()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(listed, expected_proofs);
    let unlocked = success(cli(dir.path(), &["unlock", "key.json"]));
    assert_eq!(unlocked["messages"], serde_json::json!(notes));

    // A client can follow the JSON descriptor without invoking the report CLI.
    let seed = schnorrkel::MiniSecretKey::from_bytes(
        &hex::decode(key["secret_key"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let signing_key = seed.expand_to_keypair(schnorrkel::ExpansionMode::Ed25519);
    let submission = &key["submission"];
    let mut body = submission["body"].clone();
    body["signature"] = hex::encode(
        signing_key
            .sign_simple(
                b"kompromat:proof:v1",
                body["message"].as_str().unwrap().as_bytes(),
            )
            .to_bytes(),
    )
    .into();
    let response = reqwest::blocking::Client::new()
        .request(
            submission["method"].as_str().unwrap().parse().unwrap(),
            submission["url"].as_str().unwrap(),
        )
        .header("content-type", submission["content_type"].as_str().unwrap())
        .json(&body)
        .send()
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::CREATED);

    // The descriptor, rather than a hidden API default, drives report.
    key["api"] = "http://127.0.0.1:0".into();
    fs::write(&key_path, key.to_string()).unwrap();
    success(cli(dir.path(), &["report", "key.json"]));
    key["submission"]["url"] = "http://127.0.0.1:0/proofs".into();
    fs::write(key_path, key.to_string()).unwrap();
    success(cli(dir.path(), &["report", "key.json", "--api", &api.url]));
}
