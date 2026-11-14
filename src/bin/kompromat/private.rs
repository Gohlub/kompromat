use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use kompromat::publication::{self, Listing, PublicationState};
use kompromat::{
    Key, Manifest,
    dossiers::{
        self, AcceptedOpening, CaptureReceipt, DossierMessage, Opening, Page, Participants,
    },
    validate_public_key,
};
use reqwest::Url;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};

use super::{
    client, hunt_base, post, print_json, registry_base, registry_endpoint, response_json_bound,
    write_new_json,
};

// A full page holds up to 50 messages of 16 KiB each, encoded as hex.
const MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;

// Local files. Only the public Opening or a signed DossierMessage goes on the wire.
#[derive(Deserialize, Serialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Credential {
    Defender {
        flag: String,
        secret: String,
        api: String,
    },
    Finder {
        opening: Box<Opening>,
        secret: String,
        hunt: String,
    },
}

impl Credential {
    fn secret(&self) -> &str {
        match self {
            Self::Defender { secret, .. } | Self::Finder { secret, .. } => secret,
        }
    }

    fn api(&self) -> Result<String> {
        match self {
            Self::Defender { api, .. } => registry_base(api),
            Self::Finder { opening, hunt, .. } => {
                hunt_base(&Url::parse(hunt)?, &opening.participants.flag)
            }
        }
    }

    fn manifest(&self) -> Result<Manifest> {
        let my_public = dossiers::participant_public(self.secret())?;
        let (flag, defender) = match self {
            Self::Defender { flag, .. } => (flag.as_str(), my_public),
            Self::Finder { opening, .. } => {
                ensure!(
                    opening.participants.finder == my_public,
                    "dossier key does not match its report"
                );
                (
                    opening.participants.flag.as_str(),
                    opening.participants.defender.clone(),
                )
            }
        };
        validate_public_key(flag)?;
        validate_public_key(&defender)?;
        Ok(Manifest {
            public_key: flag.to_owned(),
            defender_public_key: defender,
            metadata: Map::new(),
        })
    }

    fn opening(&self, dossier: Option<&str>, api: &str) -> Result<Opening> {
        let manifest = self.manifest()?;
        let opening = match self {
            Self::Finder { opening, .. } => {
                ensure!(
                    dossier.is_none(),
                    "the dossier key already selects its dossier"
                );
                opening.as_ref().clone()
            }
            Self::Defender { .. } => {
                let id = dossier.context("specify a dossier with --dossier")?;
                validate_public_key(id)?;
                let accepted: AcceptedOpening = get(api, &format!("dossiers/{id}"))?;
                ensure!(
                    accepted.opening.participants.finder == id && accepted.receipt.dossier_id == id,
                    "API returned a different dossier"
                );
                accepted.opening
            }
        };
        dossiers::verify_opening(&opening, &manifest)?;
        Ok(opening)
    }
}

pub(super) fn generate(
    flag_path: &Path,
    defender_path: &Path,
    manifest_path: Option<&Path>,
    metadata: Map<String, Value>,
    api: &str,
) -> Result<()> {
    ensure!(
        flag_path != defender_path,
        "choose a different --defender-out path from the flag"
    );
    let (flag, manifest, secret) = kompromat::generate(metadata);
    let credential = Credential::Defender {
        flag: manifest.public_key.clone(),
        secret,
        api: api.into(),
    };
    let mut created = Vec::new();
    let save = (|| -> Result<()> {
        write_new_json(defender_path, &credential)
            .context("choose an unused, writable path for the defender key with --defender-out")?;
        created.push(defender_path);
        write_new_json(flag_path, &flag)?;
        created.push(flag_path);
        if let Some(path) = manifest_path {
            write_new_json(path, &manifest)?;
        }
        Ok(())
    })();
    if let Err(error) = save {
        for path in created.into_iter().rev() {
            fs::remove_file(path)
                .with_context(|| format!("{error:#}; could not remove {}", path.display()))?;
        }
        return Err(error);
    }
    eprintln!(
        "Keep {} private. Plant only {}.",
        defender_path.display(),
        flag_path.display()
    );
    if manifest_path.is_none() {
        print_json(&manifest)?;
    }
    Ok(())
}

pub(super) fn publication(key: &Path, listing: Option<Listing>) -> Result<()> {
    let credential: Credential = super::read_json(key)?;
    let Credential::Defender { flag, secret, .. } = &credential else {
        bail!("publication requires a defender key");
    };
    validate_public_key(flag)?;
    let api = credential.api()?;
    let path = format!("hunts/{flag}/publication");
    let current: PublicationState = get(&api, &path)?;
    let change = publication::sign(secret, flag, &current, listing)?;
    let accepted: PublicationState = post(&api, &path, &change)?;
    ensure!(
        accepted == change.state,
        "API acknowledged a different publication"
    );
    print_json(&accepted)
}

pub(super) fn report(
    flag: &Key,
    manifest: &Manifest,
    message: &str,
    dossier_key_out: Option<PathBuf>,
    hunt: &str,
) -> Result<()> {
    let secret = dossiers::fresh_secret();
    let opening = dossiers::open(flag, manifest, &secret, message)?;
    let path = dossier_key_out
        .unwrap_or_else(|| format!("dossier-key-{}.json", opening.participants.finder).into());
    let credential = Credential::Finder {
        secret,
        opening: Box::new(opening),
        hunt: hunt.into(),
    };
    write_new_json(&path, &credential)?;
    resend(&credential, &path)
}

pub(super) fn resend(credential: &Credential, path: &Path) -> Result<()> {
    let Credential::Finder { opening, .. } = credential else {
        bail!("report requires a flag or a saved dossier key");
    };
    dossiers::verify_opening(opening, &credential.manifest()?)?;
    let acknowledgement = post::<AcceptedOpening>(&credential.api()?, "report", opening)
        .and_then(|ack| {
            ensure!(
                ack.opening == **opening
                    && ack.receipt.dossier_id == opening.participants.finder
                    && ack.receipt.sequence > 0,
                "API acknowledged a different opening"
            );
            Ok(ack)
        })
        .with_context(|| {
            format!(
                "dossier key saved at {}; retry with report and that file",
                path.display()
            )
        })?;
    print_json(&json!({
        "receipt": acknowledgement.receipt,
        "dossier_key_file": path,
    }))
}

pub(super) fn unlock(credential: &Credential, dossier: Option<&str>, after: i64) -> Result<()> {
    let api = credential.api()?;
    ensure!(after >= 0, "invalid page cursor");
    if dossier.is_none() && matches!(credential, Credential::Defender { .. }) {
        let manifest = credential.manifest()?;
        let page: Page<CaptureReceipt> = get_page(
            &api,
            &format!("hunts/{}/dossiers", manifest.public_key),
            after,
        )?;
        let mut previous = after;
        for receipt in &page.items {
            validate_public_key(&receipt.dossier_id)?;
            ensure!(receipt.sequence > previous, "reports are out of order");
            previous = receipt.sequence;
        }
        return print_json(&json!({
            "receipts": page.items, "next_after": page.next_after,
        }));
    }
    let opening = credential.opening(dossier, &api)?;
    let participants = &opening.participants;
    let page: Page<Value> = get_page(
        &api,
        &format!("dossiers/{}/messages", participants.finder),
        after,
    )?;
    let mut messages = Vec::new();
    if after == 0 {
        messages.push(read_message(
            participants,
            credential.secret(),
            &opening.first,
        ));
    }
    for item in page.items {
        messages.push(match serde_json::from_value(item) {
            Ok(entry) => read_message(participants, credential.secret(), &entry),
            Err(_) => json!({"error": "invalid message"}),
        });
    }
    print_json(&json!({
        "dossier_id": participants.finder,
        "messages": messages, "next_after": page.next_after,
    }))
}

fn read_message(p: &Participants, secret: &str, entry: &DossierMessage) -> Value {
    let sender = if entry.sender == p.finder {
        "finder"
    } else {
        "defender"
    };
    match dossiers::decrypt(p, secret, entry) {
        Ok(text) => json!({"sender": sender, "text": text}),
        Err(_) if dossiers::verify_entry(p, entry).is_err() => json!({"error": "invalid message"}),
        Err(_) => json!({"sender": sender, "error": "unreadable message"}),
    }
}

pub(super) fn attach(credential: &Credential, dossier: Option<&str>, message: &str) -> Result<()> {
    let api = credential.api()?;
    let opening = credential.opening(dossier, &api)?;
    let participants = &opening.participants;
    let entry = dossiers::encrypt(participants, credential.secret(), message)?;
    let acknowledgement: DossierMessage = post(
        &api,
        &format!("dossiers/{}/messages", participants.finder),
        &entry,
    )?;
    ensure!(
        acknowledgement == entry,
        "API acknowledged a different message"
    );
    print_json(&entry)
}

fn get<T: DeserializeOwned>(api: &str, path: &str) -> Result<T> {
    let response = client()?.get(registry_endpoint(api, path)?).send()?;
    response_json_bound(response, MAX_RESPONSE_BYTES)
}

fn get_page<T: DeserializeOwned>(api: &str, path: &str, after: i64) -> Result<Page<T>> {
    let page: Page<T> = get(api, &format!("{path}?after={after}"))?;
    ensure!(
        page.next_after
            .is_none_or(|next| next > after && !page.items.is_empty()),
        "invalid continuation from facilitator"
    );
    Ok(page)
}

#[cfg(test)]
mod tests {
    use super::*;
    use schnorrkel::{ExpansionMode, MiniSecretKey};

    #[test]
    fn transcript_attributes_only_verified_entries_and_preserves_readable_neighbors() {
        let (flag, manifest, defender) = kompromat::generate(Map::new());
        let finder = dossiers::fresh_secret();
        let opening = dossiers::open(&flag, &manifest, &finder, "first").unwrap();
        let p = &opening.participants;

        // A finder can sign arbitrary bytes, including an invalid AEAD tag.
        let mut corrupt = dossiers::encrypt(p, &finder, "second").unwrap();
        corrupt.ciphertext = "00".repeat(16);
        let mut wire = Vec::new();
        for part in [
            &p.flag,
            &p.defender,
            &p.finder,
            &corrupt.sender,
            &corrupt.nonce,
            &corrupt.ciphertext,
        ] {
            wire.extend(hex::decode(part).unwrap());
        }
        let signer = MiniSecretKey::from_bytes(&hex::decode(&finder).unwrap())
            .unwrap()
            .expand_to_keypair(ExpansionMode::Ed25519);
        corrupt.signature = hex::encode(
            signer
                .sign_simple(b"kompromat:finder-dossier:message:v1", &wire)
                .to_bytes(),
        );
        let mut forged = corrupt.clone();
        forged.sender = p.defender.clone();
        let reply = dossiers::encrypt(p, &defender, "last").unwrap();

        let transcript = [opening.first, corrupt, forged, reply]
            .iter()
            .map(|entry| read_message(p, &defender, entry))
            .collect::<Vec<_>>();
        assert_eq!(
            json!(transcript),
            json!([
                {"sender": "finder", "text": "first"},
                {"sender": "finder", "error": "unreadable message"},
                {"error": "invalid message"},
                {"sender": "defender", "text": "last"},
            ])
        );
    }
}
