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
fn offline_flow_and_secret_file_protection() {
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
        &["prove", "secret.json", "--message", "found it"],
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
