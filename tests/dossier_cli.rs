use std::{
    fs,
    io::{BufRead, BufReader},
    net::TcpListener,
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
    fn hunt(&self, manifest: &Value) -> String {
        format!(
            "{}/dossiers/{}",
            self.url,
            manifest["public_key"].as_str().unwrap()
        )
    }

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
    let hunt = api.hunt(&manifest);

    let mut receipts = Vec::new();
    for (out_flag, file, note) in [
        (
            "--dossier-key-out",
            "alice.json",
            "Alice found an export bug",
        ),
        ("--finder-out", "bob.json", "Bob found a cache bug"),
    ] {
        let report = success(cli(
            path,
            &[
                "report",
                "flag.json",
                "--hunt",
                &hunt,
                "--message",
                note,
                out_flag,
                file,
            ],
        ));
        let receipt = &report["receipt"];
        assert_eq!(report["dossier_key_file"], file);
        assert_eq!(
            receipt["sequence"].as_u64(),
            Some(receipts.len() as u64 + 1)
        );
        assert!(receipt["accepted_at"].as_str().unwrap().ends_with('Z'));
        let key: Value = serde_json::from_slice(&fs::read(path.join(file)).unwrap()).unwrap();
        assert!(!report.to_string().contains(key["secret"].as_str().unwrap()));
        assert!(!report.to_string().contains(note));
        receipts.push(receipt.clone());
    }
    let alice = receipts[0]["dossier_id"].as_str().unwrap();
    let bob = receipts[1]["dossier_id"].as_str().unwrap();
    assert_ne!(alice, bob);
    let retry = success(cli(path, &["report", "alice.json"]));
    assert_eq!(retry["receipt"], receipts[0]);
    let inbox = success(cli(path, &["unlock", "defender.json"]));
    assert_eq!(inbox["receipts"], serde_json::json!(receipts));
    success(cli(
        path,
        &[
            "attach",
            "--key",
            "defender.json",
            "--dossier",
            alice,
            "--message",
            "Which request?",
        ],
    ));
    success(cli(
        path,
        &["attach", "--key", "alice.json", "--message", "GET /export"],
    ));

    let transcript = serde_json::json!([
        {"sender": "finder", "text": "Alice found an export bug"},
        {"sender": "defender", "text": "Which request?"},
        {"sender": "finder", "text": "GET /export"},
    ]);
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
        serde_json::json!([{"sender": "finder", "text": "Bob found a cache bug"}])
    );
    assert!(
        !cli(path, &["unlock", "bob.json", "--dossier", alice])
            .status
            .success()
    );
    assert!(
        !cli(path, &["unlock", "flag.json", "--thread", alice])
            .status
            .success()
    );

    let opening = reqwest::blocking::get(format!("{}/threads/{alice}?receipt=true", api.url))
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .unwrap();
    assert!(!opening.contains("Alice found an export bug"));
    let public_report: Value = serde_json::from_str(&opening).unwrap();
    assert_eq!(public_report["receipt"], receipts[0]);
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

    let capture = success(cli(path, &["report", "flag.json", "--hunt", &hunt]));
    let id = capture["receipt"]["dossier_id"].as_str().unwrap();
    let default_file = format!("dossier-key-{id}.json");
    assert_eq!(capture["dossier_key_file"], default_file);
    assert!(path.join(default_file).is_file());
}

#[test]
fn reports_verify_the_hunt_before_sending_any_writeup() {
    let dir = tempdir().unwrap();
    let path = dir.path();
    let registry = Api::start(path);
    let manifest = success(cli(
        path,
        &[
            "generate",
            "--out",
            "flag",
            "--defender-out",
            "def",
            "--api",
            &registry.url,
        ],
    ));
    fs::write(path.join("manifest"), manifest.to_string()).unwrap();
    success(cli(path, &["register", "manifest", "--api", &registry.url]));
    let hunt = registry.hunt(&manifest);

    let trap = TcpListener::bind("127.0.0.1:0").unwrap();
    let hostile_api = format!("http://{}", trap.local_addr().unwrap());
    let mut flag: Value = serde_json::from_slice(&fs::read(path.join("flag")).unwrap()).unwrap();
    flag["api"] = hostile_api.clone().into();
    let write_flag = |flag: &Value| fs::write(path.join("found"), flag.to_string()).unwrap();
    let report = [
        "report",
        "found",
        "--hunt",
        &hunt,
        "--message",
        "private",
        "--dossier-key-out",
        "saved",
    ];

    // Even with a hostile address in the flag, a valid report goes to the selected hunt.
    write_flag(&flag);
    let accepted = success(cli(path, &report));
    assert_eq!(accepted["receipt"]["sequence"], 1);
    let mut saved: Value = serde_json::from_slice(&fs::read(path.join("saved")).unwrap()).unwrap();
    assert_eq!(saved["api"], registry.url);
    // A captured file must never become another finder's follow-up credential.
    write_flag(&saved);
    assert!(
        !cli(
            path,
            &["attach", "found", "--hunt", &hunt, "--message", "private"]
        )
        .status
        .success()
    );
    assert!(
        !cli(path, &["report", "saved", "--api", &hostile_api])
            .status
            .success()
    );
    saved.as_object_mut().unwrap().remove("hunt");
    saved["api"] = hostile_api.clone().into();
    fs::write(path.join("old-key"), saved.to_string()).unwrap();
    assert!(
        !cli(
            path,
            &["attach", "--key", "old-key", "--message", "private"]
        )
        .status
        .success()
    );
    let retry = success(cli(path, &["report", "old-key", "--hunt", &hunt]));
    assert_eq!(retry["receipt"], accepted["receipt"]);
    fs::remove_file(path.join("saved")).unwrap();

    let other = success(cli(path, &["generate", "--out", "other"]));
    flag["defender_public_key"] = other["public_key"].clone();
    write_flag(&flag);
    assert!(!cli(path, &report).status.success());
    flag.as_object_mut().unwrap().remove("defender_public_key");
    write_flag(&flag);
    for args in [
        &report[..],
        &["report", "found", "--message", "private"],
        &["attach", "found", "--hunt", &hunt, "--message", "private"],
        &[
            "prove",
            "found",
            "--manifest",
            "manifest",
            "--message",
            "private",
        ],
        &["prove", "found", "--message", "private"],
    ] {
        let output = cli(path, args);
        assert!(!output.status.success(), "{args:?}");
        assert!(output.stdout.is_empty());
    }
    assert!(!path.join("saved").exists());
    trap.set_nonblocking(true).unwrap();
    assert_eq!(
        trap.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
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
            &[
                "attach",
                key,
                "--message",
                message,
                "--hunt",
                &api.hunt(&public),
            ],
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
    let later = success(cli(
        dir.path(),
        &[
            "unlock",
            "finder.json",
            "--api",
            &restarted.url,
            "--after",
            "1",
        ],
    ));
    assert_eq!(later["messages"], serde_json::json!([messages[1]]));
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
        &[
            "prove",
            "key.json",
            "--manifest",
            "manifest.json",
            "--message",
            private,
        ],
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
        let report = success(cli(
            dir.path(),
            &[
                "report",
                "key.json",
                "--hunt",
                &api.hunt(&public),
                flag,
                note,
            ],
        ));
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
