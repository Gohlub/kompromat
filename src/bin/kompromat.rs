#[path = "kompromat/private.rs"]
mod private;

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};
use kompromat::{
    DEFAULT_API, EncryptedMessage, Key, Manifest, Proof, decrypt_message, encrypt_message,
    generate_for_api, prove, prove_with_reply, validate_public_key, verify,
};
use reqwest::blocking::Client;
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
        /// Enable private finder threads; retain this separate secret file off-target.
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
    Prove(ProofArgs),
    /// Report a found flag, or retry a saved finder credential.
    Report {
        #[command(flatten)]
        proof: ProofArgs,
        /// Save this finder's private thread credential at this new path.
        #[arg(long)]
        finder_out: Option<PathBuf>,
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
        key: PathBuf,
        /// Finder thread to use with a defender credential.
        #[arg(long)]
        thread: Option<String>,
        #[arg(long)]
        message: String,
        /// Override the API address in the key file.
        #[arg(long)]
        api: Option<String>,
    },
    /// Read messages with a key or list threads with a defender credential.
    Unlock {
        key: PathBuf,
        /// Finder thread to read. Omit with a defender credential to list threads.
        #[arg(long)]
        thread: Option<String>,
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
                return private::generate(&out, &defender_out, metadata, &api);
            }
            let (secret, manifest) = generate_for_api(metadata, &api);
            write_secret(&out, &secret)?;
            print_json(&manifest)?;
        }
        Command::Register { manifest, api } => {
            let manifest: Manifest = read_json(&manifest)?;
            validate_public_key(&manifest.public_key)?;
            print_json(&post(&api, "dossiers", &manifest)?)?;
        }
        Command::Prove(args) => {
            let secret: Key = read_json(&args.key)?;
            print_json(&args.create_proof(&secret)?)?;
        }
        Command::Report {
            proof: args,
            api,
            finder_out,
        } => {
            let secret = match read_json(&args.key)? {
                LocalKey::Private(credential) => {
                    ensure!(
                        args.message.is_none() && finder_out.is_none(),
                        "retry the saved report without a new message or --finder-out"
                    );
                    return private::resend(&credential, &args.key, api.as_deref());
                }
                LocalKey::Flag(key) => key,
            };
            if let Some(defender) = &secret.defender_public_key {
                return private::report(
                    &secret,
                    defender,
                    args.message.as_deref().unwrap_or_default(),
                    finder_out,
                    api.as_deref().unwrap_or(&secret.api),
                );
            }
            ensure!(
                finder_out.is_none(),
                "--finder-out requires a private dossier"
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
            print_json(&post(&api, "proofs", &proof)?)?;
        }
        Command::Verify { proof, manifest } => {
            verify(&read_json(&proof)?, &read_json(&manifest)?)?;
            print_json(&json!({"valid": true}))?;
        }
        Command::Attach {
            key,
            thread,
            message,
            api,
        } => {
            let secret = match read_json(&key)? {
                LocalKey::Private(credential) => {
                    return private::attach(
                        &credential,
                        thread.as_deref(),
                        &message,
                        api.as_deref(),
                    );
                }
                LocalKey::Flag(key) => key,
            };
            ensure!(
                secret.defender_public_key.is_none(),
                "use a finder or defender credential to attach"
            );
            ensure!(thread.is_none(), "--thread requires a defender credential");
            let entry = encrypt_message(&secret, &message)?;
            print_json(&post(
                api.as_deref().unwrap_or(&secret.api),
                "messages",
                &entry,
            )?)?;
        }
        Command::Unlock { key, thread, api } => {
            let secret = match read_json(&key)? {
                LocalKey::Private(credential) => {
                    return private::unlock(&credential, thread.as_deref(), api.as_deref());
                }
                LocalKey::Flag(key) => key,
            };
            ensure!(
                secret.defender_public_key.is_none(),
                "use a finder or defender credential to unlock"
            );
            ensure!(thread.is_none(), "--thread requires a defender credential");
            let public_key = secret.public_key()?;
            let response = client()?
                .get(format!(
                    "{}/dossiers/{public_key}/messages",
                    api.as_deref().unwrap_or(&secret.api).trim_end_matches('/')
                ))
                .send()?;
            let entries: Vec<EncryptedMessage> = serde_json::from_value(response_json(response)?)?;
            // Verify/decrypt all entries before printing any plaintext.
            let messages = entries
                .iter()
                .map(|entry| decrypt_message(&secret, entry))
                .collect::<Result<Vec<_>>>()?;
            print_json(&json!({"public_key": public_key, "messages": messages}))?;
        }
    }
    Ok(())
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

fn post(api: &str, resource: &str, body: &impl Serialize) -> Result<Value> {
    post_url(&format!("{}/{resource}", api.trim_end_matches('/')), body)
}

fn post_url(url: &str, body: &impl Serialize) -> Result<Value> {
    response_json(client()?.post(url).json(body).send()?)
}

fn client() -> Result<Client> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

fn response_json(response: reqwest::blocking::Response) -> Result<Value> {
    let status = response.status();
    let text = response.text()?;
    ensure!(status.is_success(), "API returned {status}: {text}");
    Ok(serde_json::from_str(&text)?)
}
