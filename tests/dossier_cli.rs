use std::{
    fs,
    io::{BufRead, BufReader},
    net::TcpListener,
    path::Path,
    process::{Child, Command, Output, Stdio},
};

use serde_json::{Value, json};
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

fn cli_stdin(dir: &Path, args: &[&str], input: &str) -> Output {
    use std::io::Write;
    let mut child = Command::new(env!("CARGO_BIN_EXE_kompromat"))
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn get_json(url: &str) -> Value {
    reqwest::blocking::get(url)
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
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
fn finders_of_the_same_flag_have_separate_dossiers_by_default() {
    let dir = tempdir().unwrap();
    let path = dir.path();
    let finder_dir = tempdir().unwrap();
    let finder = finder_dir.path();
    let flag = "flag.json";
    let api = Api::start(path);
    let manifest = success(cli(path, &["generate", "--out", flag, "--api", &api.url]));
    fs::copy(path.join(flag), finder.join(flag)).unwrap();
    fs::write(path.join("manifest.json"), manifest.to_string()).unwrap();
    let registered = cli(path, &["register", "manifest.json", "--api", &api.url]);
    let handoff = String::from_utf8(registered.stderr.clone()).unwrap();
    assert_eq!(success(registered), manifest);
    let hunt = handoff.trim_end().strip_prefix("Hunt: ").unwrap();

    let alice_note = "Alice found an export bug\nReproducción 🦀\n";
    let reply = "Which request?\nIncluí la ruta.\n";
    let mut receipts = Vec::new();
    for (file, note, piped) in [
        ("alice.json", alice_note, true),
        ("bob.json", "Bob found a cache bug", false),
    ] {
        let mut args = vec!["report", flag, "--hunt", hunt, "--dossier-key-out", file];
        let report = success(if piped {
            args.push("--message-stdin");
            cli_stdin(finder, &args, note)
        } else {
            args.extend(["--message", note]);
            cli(finder, &args)
        });
        let receipt = &report["receipt"];
        assert_eq!(report["dossier_key_file"], file);
        assert_eq!(
            receipt["sequence"].as_u64(),
            Some(receipts.len() as u64 + 1)
        );
        assert!(receipt["accepted_at"].as_str().unwrap().ends_with('Z'));
        let key: Value = serde_json::from_slice(&fs::read(finder.join(file)).unwrap()).unwrap();
        assert!(!report.to_string().contains(key["secret"].as_str().unwrap()));
        assert!(!report.to_string().contains(note.lines().next().unwrap()));
        receipts.push(receipt.clone());
    }
    let alice = receipts[0]["dossier_id"].as_str().unwrap();
    let bob = receipts[1]["dossier_id"].as_str().unwrap();
    assert_ne!(alice, bob);
    let inbox = success(cli(path, &["unlock", "defender.json"]));
    assert_eq!(inbox["receipts"], serde_json::json!(receipts));
    let ack = success(cli_stdin(
        path,
        &[
            "attach",
            "--key",
            "defender.json",
            "--dossier",
            alice,
            "--message-stdin",
        ],
        reply,
    ));
    assert!(!ack.to_string().contains("Which request?"));
    success(cli(
        finder,
        &["attach", "--key", "alice.json", "--message", "GET /export"],
    ));

    let transcript = serde_json::json!([
        {"sender": "finder", "text": alice_note},
        {"sender": "defender", "text": reply},
        {"sender": "finder", "text": "GET /export"},
    ]);
    assert_eq!(
        success(cli(finder, &["unlock", "alice.json"]))["messages"],
        transcript
    );
    assert_eq!(
        success(cli(path, &["unlock", "defender.json", "--dossier", alice]))["messages"],
        transcript
    );
    assert_eq!(
        success(cli(finder, &["unlock", "bob.json"]))["messages"],
        serde_json::json!([{"sender": "finder", "text": "Bob found a cache bug"}])
    );
    assert!(
        !cli(finder, &["unlock", "bob.json", "--dossier", alice])
            .status
            .success()
    );
    assert!(
        !cli(finder, &["unlock", flag, "--dossier", alice])
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
    let public_report: Value = serde_json::from_str(&opening).unwrap();
    assert_eq!(public_report["receipt"], receipts[0]);

    let capture = success(cli(finder, &["report", flag, "--hunt", hunt]));
    let id = capture["receipt"]["dossier_id"].as_str().unwrap();
    let default_file = format!("dossier-key-{id}.json");
    assert_eq!(capture["dossier_key_file"], default_file);
    assert!(finder.join(default_file).is_file());
}

#[test]
fn unacknowledged_reports_recover_the_original_receipt_after_restart() {
    use axum::{
        Json, Router,
        body::to_bytes,
        extract::Request,
        middleware::{self, Next},
        response::IntoResponse,
    };
    use std::{sync::mpsc, time::Duration};

    for drop_connection in [true, false] {
        let dir = tempdir().unwrap();
        let path = dir.path();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        let registry = || {
            let db = rusqlite::Connection::open(path.join("records.sqlite3")).unwrap();
            kompromat::api::app(db).unwrap()
        };
        // Retain the listening socket while replacing both the server and its SQLite connection.
        let serve = |app: Router| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap();
            let socket = listener.try_clone().unwrap();
            runtime.spawn(async move {
                let socket = tokio::net::TcpListener::from_std(socket).unwrap();
                axum::serve(socket, app).await.unwrap();
            });
            runtime
        };
        let (committed, receipt) = mpsc::channel();
        let mut first = Some(serve(registry().layer(middleware::from_fn(
            move |request: Request, next: Next| {
                let committed = committed.clone();
                async move {
                    let report = request.uri().path() == "/report";
                    let response = next.run(request).await;
                    if !report {
                        return response;
                    }
                    assert_eq!(response.status(), axum::http::StatusCode::CREATED);
                    let bytes = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
                    let mut ack: Value = serde_json::from_slice(&bytes).unwrap();
                    committed.send(ack.clone()).unwrap();
                    if drop_connection {
                        return std::future::pending().await;
                    }
                    ack["receipt"]["dossier_id"] = "different".into();
                    Json(ack).into_response()
                }
            },
        ))));
        let manifest = success(cli(path, &["generate", "--out", "flag", "--api", &api]));
        fs::write(path.join("manifest"), manifest.to_string()).unwrap();
        success(cli(path, &["register", "manifest", "--api", &api]));
        let hunt = format!(
            "{api}/dossiers/{}",
            manifest["public_key"].as_str().unwrap()
        );
        let accepted = std::thread::scope(|scope| {
            let reporter = scope.spawn(|| {
                cli(
                    path,
                    &[
                        "report",
                        "flag",
                        "--hunt",
                        &hunt,
                        "--message",
                        "original note",
                    ],
                )
            });
            let accepted = receipt.recv_timeout(Duration::from_secs(10)).unwrap();
            if drop_connection {
                drop(first.take());
            }
            let failed = reporter.join().unwrap();
            assert!(!failed.status.success());
            assert!(failed.stdout.is_empty());
            let key = format!(
                "dossier-key-{}.json",
                accepted["receipt"]["dossier_id"].as_str().unwrap()
            );
            let diagnostic = String::from_utf8(failed.stderr).unwrap();
            assert!(
                diagnostic.contains(&key) && diagnostic.contains("retry"),
                "{diagnostic}"
            );
            if !drop_connection {
                assert!(diagnostic.contains("different opening"), "{diagnostic}");
            }
            accepted
        });

        drop(first);
        let _restarted = serve(registry());
        let id = accepted["receipt"]["dossier_id"].as_str().unwrap();
        let key = format!("dossier-key-{id}.json");
        let retried = success(cli(path, &["report", &key]));
        assert_eq!(retried["receipt"], accepted["receipt"]);
        assert_eq!(retried["dossier_key_file"], key);
        assert_eq!(
            get_json(&format!("{hunt}/threads")),
            json!({"items": [accepted["receipt"]], "next_after": null})
        );
        assert_eq!(
            success(cli(path, &["unlock", "defender.json", "--dossier", id]))["messages"],
            json!([{"sender": "finder", "text": "original note"}])
        );
    }
}

#[test]
fn defender_can_publish_and_withdraw_the_registered_hunt() {
    let dir = tempdir().unwrap();
    let path = dir.path();
    let api = Api::start(path);
    let manifest = success(cli(path, &["generate", "--out", "flag", "--api", &api.url]));
    fs::write(path.join("manifest"), manifest.to_string()).unwrap();
    success(cli(path, &["register", "manifest", "--api", &api.url]));
    let directory = format!("{}/hunts", api.url);
    let empty = json!({"items": [], "next_after": null});
    assert_eq!(get_json(&directory), empty);
    let brief = "https://def.example/hunt";
    let publish = |key: &str| {
        cli(
            path,
            &["publish", key, "--title", "Archive hunt", "--brief", brief],
        )
    };
    assert!(!publish("flag").status.success());
    let published = publish("defender.json");
    assert!(
        published.status.success(),
        "{}",
        String::from_utf8_lossy(&published.stderr)
    );
    let listings = get_json(&directory);
    assert_eq!(listings["items"].as_array().unwrap().len(), 1);
    let listing = &listings["items"][0];
    assert_eq!(listing["title"], "Archive hunt");
    assert_eq!(listing["brief_url"], brief);
    assert_eq!(
        reqwest::Url::parse(&directory)
            .unwrap()
            .join(listing["hunt"].as_str().unwrap())
            .unwrap()
            .as_str(),
        api.hunt(&manifest)
    );
    let withdrawn = cli(path, &["withdraw", "defender.json"]);
    assert!(
        withdrawn.status.success(),
        "{}",
        String::from_utf8_lossy(&withdrawn.stderr)
    );
    assert_eq!(get_json(&directory), empty);
    assert_eq!(get_json(&api.hunt(&manifest)), manifest);
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
    assert!(path.join("def").is_file());
    assert!(!path.join("defender.json").exists());

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

    // Found files cannot choose a reporting address. The hunt is supplied independently.
    write_flag(&flag);
    assert!(!cli(path, &report).status.success());
    flag.as_object_mut().unwrap().remove("api");
    write_flag(&flag);
    let accepted = success(cli(path, &report));
    assert_eq!(accepted["receipt"]["sequence"], 1);
    let saved: Value = serde_json::from_slice(&fs::read(path.join("saved")).unwrap()).unwrap();
    assert_eq!(saved["hunt"], hunt);
    assert!(saved.get("api").is_none());

    // A found file cannot become an existing finder's credential for a new write-up.
    write_flag(&saved);
    assert!(!cli(path, &report).status.success());
    fs::remove_file(path.join("saved")).unwrap();

    flag["defender_public_key"] = manifest["public_key"].clone();
    write_flag(&flag);
    assert!(!cli(path, &report).status.success());
    flag.as_object_mut().unwrap().remove("defender_public_key");
    write_flag(&flag);
    for args in [
        &report[..],
        &["report", "found", "--message", "private"],
        &["attach", "--key", "found", "--message", "private"],
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
