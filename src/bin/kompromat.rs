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
use clap::{Parser, Subcommand};
use kompromat::{
    DEFAULT_API, Key, MAX_MESSAGE_BYTES, Manifest, prove, publication::Listing,
    validate_public_key, verify,
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

#[derive(Subcommand)]
enum Command {
    /// Generate a flag and defender key for private reports.
    Generate {
        /// Path for the flag to plant.
        #[arg(long)]
        out: PathBuf,
        /// Save the defender key at this path (default: defender.json in the current directory).
        #[arg(long)]
        defender_out: Option<PathBuf>,
        /// Write the public manifest to a new file (default: stdout).
        #[arg(long)]
        manifest_out: Option<PathBuf>,
        /// Public metadata as a JSON object; do not include secrets.
        #[arg(long, default_value = "{}")]
        metadata: String,
        /// Registry address to save in the defender key; generation stays offline.
        #[arg(long, default_value = DEFAULT_API)]
        api: String,
    },
    /// Register a public manifest with the API.
    Register {
        manifest: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:3000")]
        api: String,
    },
    /// List a registered hunt in the public directory using its defender key.
    Publish {
        key: PathBuf,
        /// Title to show in the directory.
        #[arg(long)]
        title: String,
        /// Public HTTPS URL for the hunt brief.
        #[arg(long)]
        brief: String,
    },
    /// Remove a hunt from the public directory using its defender key.
    Withdraw { key: PathBuf },
    /// Create a proof locally and print it as JSON. The key stays local.
    Prove { key: PathBuf },
    /// Report a captured flag, or resubmit the original report using its dossier key.
    Report {
        key: PathBuf,
        /// Encrypt a note supplied on the command line.
        #[arg(long)]
        message: Option<String>,
        /// Read the complete UTF-8 note from standard input (up to 16 KiB).
        #[arg(long, conflicts_with = "message")]
        message_stdin: bool,
        /// Hunt URL from the registry. Required when reporting a captured flag.
        #[arg(long)]
        hunt: Option<Url>,
        /// Save the private dossier key at this new path (default: dossier-key-<id>.json).
        #[arg(long)]
        dossier_key_out: Option<PathBuf>,
    },
    /// Verify a proof locally against an independently obtained public manifest.
    Verify {
        proof: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Encrypt and sign a message locally, then append it to the dossier.
    Attach {
        /// Local dossier or defender key for a private conversation.
        #[arg(long)]
        key: PathBuf,
        /// Dossier to reply to with a defender key.
        #[arg(long, value_name = "ID")]
        dossier: Option<String>,
        /// Encrypt a note supplied on the command line.
        #[arg(long, required_unless_present = "message_stdin")]
        message: Option<String>,
        /// Read the complete UTF-8 note from standard input (up to 16 KiB).
        #[arg(long, conflicts_with = "message")]
        message_stdin: bool,
    },
    /// Read messages with a key or list capture receipts with a defender key.
    Unlock {
        key: PathBuf,
        /// Continue an inbox or conversation after this cursor.
        #[arg(long, value_parser = clap::value_parser!(i64).range(0..))]
        after: Option<i64>,
        /// Dossier to read with a defender key. Omit to list capture receipts.
        #[arg(long, value_name = "ID")]
        dossier: Option<String>,
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
            manifest_out,
            metadata,
            api,
        } => {
            let metadata: Map<String, Value> =
                serde_json::from_str(&metadata).context("metadata must be a JSON object")?;
            let api = registry_base(&api)?;
            let defender_out = defender_out
                .as_deref()
                .unwrap_or(Path::new("defender.json"));
            private::generate(&out, defender_out, manifest_out.as_deref(), metadata, &api)?;
        }
        Command::Register { manifest, api } => {
            let manifest: Manifest = read_json(&manifest)?;
            validate_public_key(&manifest.public_key)?;
            let hunt = hunt_url(&api, &manifest.public_key)?;
            let registered: Manifest = post(&api, "dossiers", &manifest)?;
            ensure!(
                registered == manifest,
                "API acknowledged a different manifest"
            );
            print_json(&registered)?;
            eprintln!("Hunt: {hunt}");
        }
        Command::Publish { key, title, brief } => {
            let listing = Listing {
                title,
                brief_url: brief,
            };
            private::publication(&key, Some(listing))?;
        }
        Command::Withdraw { key } => private::publication(&key, None)?,
        Command::Prove { key } => {
            print_json(&prove(&read_json(&key)?, String::new())?)?;
        }
        Command::Report {
            key,
            message,
            message_stdin,
            hunt,
            dossier_key_out,
        } => {
            let secret = match read_json(&key)? {
                LocalKey::Private(credential) => {
                    ensure!(
                        message.is_none()
                            && !message_stdin
                            && dossier_key_out.is_none()
                            && hunt.is_none(),
                        "retry the saved report without a new write-up, key path, or --hunt"
                    );
                    return private::resend(&credential, &key);
                }
                LocalKey::Flag(key) => key,
            };
            let link = hunt.context("supply --hunt with the hunt URL from the registry")?;
            let manifest =
                registered_hunt(&link, &secret.public_key()?, &secret.defender_public_key)?;
            let note = read_note(message, message_stdin)?.unwrap_or_default();
            private::report(&secret, &manifest, &note, dossier_key_out, link.as_str())?;
        }
        Command::Verify { proof, manifest } => {
            verify(&read_json(&proof)?, &read_json(&manifest)?)?;
            print_json(&json!({"valid": true}))?;
        }
        Command::Attach {
            key,
            dossier,
            message,
            message_stdin,
        } => {
            let message = read_note(message, message_stdin)?
                .context("supply --message or --message-stdin")?;
            private::attach(&read_json(&key)?, dossier.as_deref(), &message)?;
        }
        Command::Unlock {
            key,
            dossier,
            after,
        } => {
            private::unlock(&read_json(&key)?, dossier.as_deref(), after)?;
        }
    }
    Ok(())
}

fn hunt_url(api: &str, flag: &str) -> Result<Url> {
    registry_endpoint(api, &format!("dossiers/{flag}"))
}

fn registry_base(api: &str) -> Result<String> {
    Ok(registry_url(api)?.as_str().trim_end_matches('/').to_owned())
}

// The resource is built locally. Appending it keeps the registry's path prefix.
fn registry_endpoint(api: &str, resource: &str) -> Result<Url> {
    Ok(Url::parse(&format!("{}/{resource}", registry_base(api)?))?)
}

fn registry_url(raw: &str) -> Result<Url> {
    let link = Url::parse(raw).context("invalid registry URL")?;
    check_registry_url(&link)?;
    Ok(link)
}

fn check_registry_url(link: &Url) -> Result<()> {
    let host = link.host_str().context("registry URL must have a host")?;
    let local = host == "localhost"
        || host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    ensure!(
        link.scheme() == "https" || (link.scheme() == "http" && local),
        "use HTTPS for the registry URL, or HTTP on loopback"
    );
    ensure!(
        link.username().is_empty()
            && link.password().is_none()
            && link.query().is_none()
            && link.fragment().is_none(),
        "registry URL must have no credentials, query, or fragment"
    );
    Ok(())
}

fn hunt_base(link: &Url, flag_id: &str) -> Result<String> {
    check_registry_url(link)?;
    validate_public_key(flag_id)?;
    ensure!(
        link.path().ends_with(&format!("/dossiers/{flag_id}")),
        "hunt URL does not select this flag"
    );
    Ok(link.join("../")?.as_str().trim_end_matches('/').to_owned())
}

fn registered_hunt(link: &Url, flag_id: &str, defender: &str) -> Result<Manifest> {
    hunt_base(link, flag_id)?;
    let response = client()?.get(link.clone()).send()?;
    let manifest: Manifest = response_json_bound(response, 128 * 1024)?;
    manifest.verify_flag(flag_id, defender)?;
    Ok(manifest)
}

fn write_new_json(path: &Path, value: &impl Serialize) -> Result<()> {
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
    const LIMIT: u64 = 1024 * 1024;
    let metadata =
        fs::metadata(path).with_context(|| format!("cannot inspect {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "{} must be a regular file",
        path.display()
    );
    let file = fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    ensure!(
        file.metadata()?.is_file(),
        "{} must be a regular file",
        path.display()
    );
    let mut bytes = Vec::new();
    file.take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {}", path.display()))?;
    ensure!(
        bytes.len() as u64 <= LIMIT,
        "{} exceeds 1 MiB",
        path.display()
    );
    serde_json::from_slice(&bytes).with_context(|| format!("invalid JSON in {}", path.display()))
}

fn read_note(message: Option<String>, from_stdin: bool) -> Result<Option<String>> {
    if !from_stdin {
        return Ok(message);
    }
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(MAX_MESSAGE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .context("could not read message from stdin")?;
    ensure!(bytes.len() <= MAX_MESSAGE_BYTES, "message exceeds 16 KiB");
    let note = String::from_utf8(bytes).context("message must be UTF-8")?;
    Ok(Some(note))
}

fn print_json(value: &impl Serialize) -> Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, value)?;
    writeln!(out)?;
    Ok(())
}

fn post<T: DeserializeOwned>(api: &str, resource: &str, body: &impl Serialize) -> Result<T> {
    post_url(registry_endpoint(api, resource)?, body)
}

fn post_url<T: DeserializeOwned>(url: Url, body: &impl Serialize) -> Result<T> {
    // A submission is capped at 64 KiB; its acknowledgment can also include a receipt.
    let response = client()?.post(url).json(body).send()?;
    response_json_bound(response, 128 * 1024)
}

fn client() -> Result<Client> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

fn response_json_bound<T: DeserializeOwned>(
    response: reqwest::blocking::Response,
    max_bytes: u64,
) -> Result<T> {
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
