#[path = "kompromat/private.rs"]
mod private;
#[path = "kompromat/shared.rs"]
mod shared;

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
    DEFAULT_API, Key, MAX_MESSAGE_BYTES, Manifest, Proof, prove, prove_with_reply,
    publication::Listing, validate_public_key, verify,
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
    /// Encrypt a note supplied on the command line.
    #[arg(long, visible_alias = "reply")]
    message: Option<String>,
    /// Read the complete UTF-8 note from standard input (up to 16 KiB).
    #[arg(long, conflicts_with = "message")]
    message_stdin: bool,
}

impl ProofArgs {
    fn has_message(&self) -> bool {
        self.message.is_some() || self.message_stdin
    }

    fn create_proof(self, key: &Key) -> Result<Proof> {
        ensure!(
            !self.has_message() || key.defender_public_key.is_none(),
            "use report to encrypt this note to the defender"
        );
        match read_note(self.message, self.message_stdin)? {
            Some(note) => prove_with_reply(key, String::new(), &note),
            None => prove(key, String::new()),
        }
    }
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
        /// Encrypt a note supplied on the command line.
        #[arg(long, required_unless_present = "message_stdin")]
        message: Option<String>,
        /// Read the complete UTF-8 note from standard input (up to 16 KiB).
        #[arg(long, conflicts_with = "message")]
        message_stdin: bool,
        /// Registry for a shared flag. A private key already selects its registry.
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
                    !args.has_message(),
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
                        !args.has_message() && dossier_key_out.is_none(),
                        "retry the saved report without a new write-up or key"
                    );
                    return private::resend(&credential, &args.key, api.as_deref(), hunt.as_ref());
                }
                LocalKey::Flag(key) => key,
            };
            let api = if let Some(link) = hunt {
                let registered = registered_hunt(
                    &link,
                    &secret.public_key()?,
                    secret.defender_public_key.as_deref(),
                )?;
                if registered.manifest.defender_public_key.is_some() {
                    let note = read_note(args.message, args.message_stdin)?.unwrap_or_default();
                    return private::report(
                        &secret,
                        &registered.manifest,
                        &note,
                        dossier_key_out,
                        link.as_str(),
                    );
                }
                Some(registered.api)
            } else {
                ensure!(
                    secret.defender_public_key.is_none() && !args.has_message(),
                    "supply --hunt with the hunt URL from the registry"
                );
                api
            };
            ensure!(
                dossier_key_out.is_none(),
                "--dossier-key-out requires a private dossier"
            );
            let proof = args.create_proof(&secret)?;
            shared::report(&secret, api.as_deref(), &proof)?;
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
            shared::submit_proof(registry_endpoint(&api, "proofs")?, &proof)?;
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
            message_stdin,
            api,
            hunt,
        } => {
            let message = read_note(message, message_stdin)?
                .context("supply --message or --message-stdin")?;
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
            ensure!(dossier.is_none(), "--dossier requires a defender key");
            shared::attach(&secret, &message, hunt, api.as_deref())?;
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
            ensure!(dossier.is_none(), "--dossier requires a defender key");
            shared::unlock(&secret, hunt, api, after.unwrap_or_default())?;
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

struct RegisteredHunt {
    api: String,
    manifest: Manifest,
}

fn registered_hunt(link: &Url, flag_id: &str, defender: Option<&str>) -> Result<RegisteredHunt> {
    let api = hunt_base(link, flag_id)?;
    let response = client()?.get(link.clone()).send()?;
    let manifest: Manifest = response_json_bound(response, 128 * 1024)?;
    manifest.verify_flag(flag_id, defender)?;
    Ok(RegisteredHunt { api, manifest })
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
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Opening a planted FIFO must not block before we can inspect its type.
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    let file = options
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
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
