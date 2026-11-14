#[path = "kompromat/private.rs"]
mod private;

use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};
use kompromat::{
    DEFAULT_API, EncryptedMessage, Key, Manifest, Proof, decrypt_message, encrypt_message,
    generate_for_api, prove, prove_with_reply, threads::Page, validate_public_key, verify,
};
use reqwest::{Url, blocking::Client};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};

#[derive(Parser)]
#[command(
    version,
    about = "Create encrypted dossiers, prove key possession, and reply privately"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct ProofArgs {
    key: PathBuf,
    /// Encrypt a private note with the key file and include it in the proof.
    #[arg(long, visible_alias = "reply")]
    message: Option<String>,
}

impl ProofArgs {
    fn create_proof(&self, key: &Key) -> Result<Proof> {
        ensure!(
            self.message.is_none() || key.defender_public_key.is_none(),
            "use report to encrypt this note to the defender"
        );
        match &self.message {
            Some(note) => prove_with_reply(key, String::new(), note),
            None => prove(key, String::new()),
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Write a secret key file and print the public registration manifest to stdout.
    Generate {
        /// Path for the secret key file.
        #[arg(long)]
        out: PathBuf,
        /// Enable per-report dossiers and save the defender key at this new path.
        #[arg(long)]
        defender_out: Option<PathBuf>,
        /// Public metadata as a JSON object; do not include secrets.
        #[arg(long, default_value = "{}")]
        metadata: String,
        /// API address to include in the key; generation stays offline.
        #[arg(long, default_value = DEFAULT_API)]
        api: String,
    },
    /// Register a public manifest with the API.
    Register {
        manifest: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:3000")]
        api: String,
    },
    /// Create a proof locally and print it as JSON. The key stays local.
    Prove {
        #[command(flatten)]
        proof: ProofArgs,
        /// Independent hunt manifest. Required for an offline shared note.
        #[arg(long)]
        manifest: Option<PathBuf>,
    },
    /// Report a captured flag, or resubmit the original report using its dossier key.
    Report {
        #[command(flatten)]
        proof: ProofArgs,
        /// Hunt URL from the registry. Required for private reports and write-ups.
        #[arg(long, conflicts_with = "api")]
        hunt: Option<Url>,
        /// Save the private dossier key at this new path (default: dossier-key-<id>.json).
        #[arg(long, alias = "finder-out")]
        dossier_key_out: Option<PathBuf>,
        /// Override the API address in the key file.
        #[arg(long)]
        api: Option<String>,
    },
    /// POST a saved proof to the API.
    Submit {
        proof: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:3000")]
        api: String,
    },
    /// Verify a proof locally against an independently obtained public manifest.
    Verify {
        proof: PathBuf,
        #[arg(long, aliases = ["dossier", "canary"])]
        manifest: PathBuf,
    },
    /// Encrypt and sign a message locally, then append it to the dossier.
    Attach {
        /// Captured shared flag.
        #[arg(required_unless_present = "key", conflicts_with = "key")]
        flag: Option<PathBuf>,
        /// Local dossier or defender key for a private conversation.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Registry hunt URL for a shared flag or an older local dossier key.
        #[arg(long, conflicts_with = "api")]
        hunt: Option<Url>,
        /// Dossier to reply to with a defender key.
        #[arg(long, alias = "thread", value_name = "ID")]
        dossier: Option<String>,
        #[arg(long)]
        message: String,
        /// Override the API address in the key file.
        #[arg(long)]
        api: Option<String>,
    },
    /// Read messages with a key or list capture receipts with a defender key.
    Unlock {
        key: PathBuf,
        /// Registered hunt URL for shared flags and older dossier keys.
        #[arg(long, conflicts_with = "api")]
        hunt: Option<Url>,
        /// Continue an inbox or conversation after this cursor.
        #[arg(long, value_parser = clap::value_parser!(i64).range(0..))]
        after: Option<i64>,
        /// Dossier to read with a defender key. Omit to list capture receipts.
        #[arg(long, alias = "thread", value_name = "ID")]
        dossier: Option<String>,
        /// Override the API address in the key file.
        #[arg(long)]
        api: Option<String>,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum LocalKey {
    Flag(Box<Key>),
    Private(private::Credential),
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Generate {
            out,
            defender_out,
            metadata,
            api,
        } => {
            let metadata: Map<String, Value> =
                serde_json::from_str(&metadata).context("metadata must be a JSON object")?;
            if let Some(defender_out) = defender_out {
                check_hunt_url(&Url::parse(&api)?)?;
                return private::generate(&out, &defender_out, metadata, &api);
            }
            let (secret, manifest) = generate_for_api(metadata, &api);
            write_secret(&out, &secret)?;
            print_json(&manifest)?;
        }
        Command::Register { manifest, api } => {
            let manifest: Manifest = read_json(&manifest)?;
            validate_public_key(&manifest.public_key)?;
            let hunt = Url::parse(&format!(
                "{}/dossiers/{}",
                api.trim_end_matches('/'),
                manifest.public_key
            ))?;
            check_hunt_url(&hunt)?;
            let registered: Manifest = post(&api, "dossiers", &manifest)?;
            ensure!(
                registered == manifest,
                "API acknowledged a different manifest"
            );
            print_json(&registered)?;
            eprintln!("Hunt: {hunt}");
        }
        Command::Prove {
            proof: args,
            manifest,
        } => {
            let secret: Key = read_json(&args.key)?;
            if let Some(path) = manifest {
                read_json::<Manifest>(&path)?
                    .verify_flag(&secret.public_key()?, secret.defender_public_key.as_deref())?;
            } else {
                ensure!(
                    args.message.is_none(),
                    "supply --manifest from the registry for an offline shared note, or use report --hunt"
                );
            }
            print_json(&args.create_proof(&secret)?)?;
        }
        Command::Report {
            proof: args,
            api,
            hunt,
            dossier_key_out,
        } => {
            let secret = match read_json(&args.key)? {
                LocalKey::Private(credential) => {
                    ensure!(
                        args.message.is_none() && dossier_key_out.is_none(),
                        "retry the saved report without a new write-up or key"
                    );
                    return private::resend(&credential, &args.key, api.as_deref(), hunt.as_ref());
                }
                LocalKey::Flag(key) => key,
            };
            let api = if let Some(link) = hunt {
                let api = hunt_api(
                    &link,
                    &secret.public_key()?,
                    secret.defender_public_key.as_deref(),
                )?;
                if let Some(defender) = &secret.defender_public_key {
                    return private::report(
                        &secret,
                        defender,
                        args.message.as_deref().unwrap_or_default(),
                        dossier_key_out,
                        &api,
                        link.as_str(),
                    );
                }
                Some(api)
            } else {
                ensure!(
                    secret.defender_public_key.is_none() && args.message.is_none(),
                    "supply --hunt with the hunt URL from the registry"
                );
                api
            };
            ensure!(
                dossier_key_out.is_none(),
                "--dossier-key-out requires a private dossier"
            );
            let proof = args.create_proof(&secret)?;
            let url = if let Some(api) = api {
                format!("{}/proofs", api.trim_end_matches('/'))
            } else if let Some(submission) = &secret.submission {
                ensure!(
                    submission.method == "POST" && submission.content_type == "application/json",
                    "report requires a JSON POST submission"
                );
                submission.url.clone()
            } else {
                format!("{}/proofs", secret.api.trim_end_matches('/'))
            };
            print_json(&post_url(&url, &proof)?)?;
        }
        Command::Submit { proof, api } => {
            let proof: Proof = read_json(&proof)?;
            // Catch malformed/tampered proofs before sending the POST. The API
            // additionally checks that this public key has been registered.
            verify(
                &proof,
                &Manifest {
                    public_key: proof.public_key.clone(),
                    defender_public_key: None,
                    metadata: Map::new(),
                },
            )?;
            print_json(&post::<Proof>(&api, "proofs", &proof)?)?;
        }
        Command::Verify { proof, manifest } => {
            verify(&read_json(&proof)?, &read_json(&manifest)?)?;
            print_json(&json!({"valid": true}))?;
        }
        Command::Attach {
            flag,
            key,
            dossier,
            message,
            api,
            hunt,
        } => {
            if let Some(key) = key {
                return private::attach(
                    &read_json(&key)?,
                    dossier.as_deref(),
                    &message,
                    api.as_deref(),
                    hunt.as_ref(),
                );
            }
            let secret: Key = read_json(&flag.context("supply a shared flag or --key")?)?;
            ensure!(
                secret.defender_public_key.is_none(),
                "use the dossier key or defender key to attach"
            );
            ensure!(dossier.is_none(), "--dossier requires a defender key");
            let link = hunt.context("supply --hunt with the hunt URL from the registry")?;
            let api = hunt_api(&link, &secret.public_key()?, None)?;
            let entry = encrypt_message(&secret, &message)?;
            print_json(&post::<EncryptedMessage>(&api, "messages", &entry)?)?;
        }
        Command::Unlock {
            key,
            dossier,
            api,
            after,
            hunt,
        } => {
            let secret = match read_json(&key)? {
                LocalKey::Private(credential) => {
                    return private::unlock(
                        &credential,
                        dossier.as_deref(),
                        api.as_deref(),
                        after,
                        hunt.as_ref(),
                    );
                }
                LocalKey::Flag(key) => key,
            };
            ensure!(
                secret.defender_public_key.is_none(),
                "use the dossier key or defender key to unlock"
            );
            ensure!(dossier.is_none(), "--dossier requires a defender key");
            let public_key = secret.public_key()?;
            let api = if let Some(link) = hunt {
                hunt_api(&link, &public_key, None)?
            } else {
                api.unwrap_or_else(|| secret.api.clone())
            };
            let after = after.unwrap_or_default();
            let response = client()?
                .get(format!(
                    "{}/dossiers/{public_key}/messages?after={after}",
                    api.trim_end_matches('/')
                ))
                .send()?;
            let value = response_json_bound(response, 2 * 1024 * 1024)?;
            let page: Page<Value> = if value.is_array() {
                ensure!(after == 0, "registry does not support pagination");
                Page {
                    items: serde_json::from_value(value)?,
                    next_after: None,
                }
            } else {
                serde_json::from_value(value)?
            };
            ensure!(
                page.next_after
                    .is_none_or(|next| next > after && !page.items.is_empty()),
                "invalid continuation from facilitator"
            );
            let messages: Vec<Value> = page
                .items
                .into_iter()
                .map(|item| {
                    match serde_json::from_value::<EncryptedMessage>(item)
                        .ok()
                        .and_then(|entry| decrypt_message(&secret, &entry).ok())
                    {
                        Some(text) => Value::String(text),
                        None => json!({"error": "unreadable message"}),
                    }
                })
                .collect();
            let mut transcript = json!({"public_key": public_key, "messages": messages});
            if let Some(next) = page.next_after {
                transcript["next_after"] = next.into();
            }
            print_json(&transcript)?;
        }
    }
    Ok(())
}

fn check_hunt_url(link: &Url) -> Result<()> {
    let host = link.host_str().context("hunt URL must have a host")?;
    let local = host == "localhost"
        || host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    ensure!(
        link.scheme() == "https" || (link.scheme() == "http" && local),
        "use HTTPS for the hunt URL, or HTTP on loopback"
    );
    ensure!(
        link.username().is_empty()
            && link.password().is_none()
            && link.query().is_none()
            && link.fragment().is_none(),
        "hunt URL must have no credentials, query, or fragment"
    );
    Ok(())
}

fn hunt_base(link: &Url, flag_id: &str) -> Result<String> {
    check_hunt_url(link)?;
    validate_public_key(flag_id)?;
    ensure!(
        link.path().ends_with(&format!("/dossiers/{flag_id}")),
        "hunt URL does not select this flag"
    );
    Ok(link.join("../")?.as_str().trim_end_matches('/').to_owned())
}

fn hunt_api(link: &Url, flag_id: &str, defender: Option<&str>) -> Result<String> {
    let api = hunt_base(link, flag_id)?;
    let response = client()?.get(link.clone()).send()?;
    let manifest: Manifest = serde_json::from_value(response_json_bound(response, 128 * 1024)?)?;
    manifest.verify_flag(flag_id, defender)?;
    Ok(api)
}

fn write_secret(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).with_context(|| {
        format!(
            "cannot create {} (existing files are never overwritten)",
            path.display()
        )
    })?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        fs::remove_file(path)
            .with_context(|| format!("could not remove incomplete {}", path.display()))?;
        return Err(error.into());
    }
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("invalid JSON in {}", path.display()))
}

fn print_json(value: &impl Serialize) -> Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, value)?;
    writeln!(out)?;
    Ok(())
}

fn post<T: DeserializeOwned>(api: &str, resource: &str, body: &impl Serialize) -> Result<T> {
    let response = post_url(&format!("{}/{resource}", api.trim_end_matches('/')), body)?;
    Ok(serde_json::from_value(response)?)
}

fn post_url(url: &str, body: &impl Serialize) -> Result<Value> {
    // A submission is capped at 64 KiB; its acknowledgment can also include a receipt.
    response_json_bound(client()?.post(url).json(body).send()?, 128 * 1024)
}

fn client() -> Result<Client> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

fn response_json_bound(response: reqwest::blocking::Response, max_bytes: u64) -> Result<Value> {
    let status = response.status();
    let limit = if status.is_success() { max_bytes } else { 4096 };
    let mut bytes = Vec::new();
    response
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    ensure!(
        status.is_success(),
        "API returned {status}: {}",
        String::from_utf8_lossy(&bytes).escape_debug()
    );
    ensure!(
        bytes.len() as u64 <= limit,
        "API response exceeds {limit} bytes"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
