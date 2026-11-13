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
use serde::{Serialize, de::DeserializeOwned};
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
    /// Report access in one step: create a proof and POST it with an optional encrypted reply.
    Report {
        #[command(flatten)]
        proof: ProofArgs,
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
        #[arg(long)]
        message: String,
        /// Override the API address in the key file.
        #[arg(long)]
        api: Option<String>,
    },
    /// Read the dossier's messages by decrypting them with the key file.
    Unlock {
        key: PathBuf,
        /// Override the API address in the key file.
        #[arg(long)]
        api: Option<String>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Generate { out, metadata, api } => {
            let metadata: Map<String, Value> =
                serde_json::from_str(&metadata).context("metadata must be a JSON object")?;
            let (secret, manifest) = generate_for_api(metadata, &api);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&out).with_context(|| {
                format!(
                    "cannot create {} (existing files are never overwritten)",
                    out.display()
                )
            })?;
            serde_json::to_writer_pretty(&mut file, &secret)?;
            writeln!(file)?;
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
        Command::Report { proof: args, api } => {
            let secret: Key = read_json(&args.key)?;
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
                    metadata: Map::new(),
                },
            )?;
            print_json(&post(&api, "proofs", &proof)?)?;
        }
        Command::Verify { proof, manifest } => {
            verify(&read_json(&proof)?, &read_json(&manifest)?)?;
            print_json(&json!({"valid": true}))?;
        }
        Command::Attach { key, message, api } => {
            let secret: Key = read_json(&key)?;
            let entry = encrypt_message(&secret, &message)?;
            print_json(&post(
                api.as_deref().unwrap_or(&secret.api),
                "messages",
                &entry,
            )?)?;
        }
        Command::Unlock { key, api } => {
            let secret: Key = read_json(&key)?;
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
