use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use kompromat::{
    Key, Manifest, generate_private_for_api,
    threads::{self, AcceptedOpening, CaptureReceipt, Opening, Page, Participants, ThreadMessage},
    validate_public_key,
};
use reqwest::Url;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};

use super::{client, hunt_api, hunt_base, post, print_json, response_json_bound, write_secret};

// A full page holds up to 50 messages of 16 KiB each, encoded as hex.
const MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;

// Local files. Only the public Opening or a signed ThreadMessage goes on the wire.
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
        api: String,
        #[serde(default)]
        hunt: Option<String>,
    },
}

impl Credential {
    fn secret(&self) -> &str {
        match self {
            Self::Defender { secret, .. } | Self::Finder { secret, .. } => secret,
        }
    }

    fn api(&self, requested: Option<&str>, hunt: Option<&Url>) -> Result<String> {
        let base = match self {
            Self::Defender { api, .. } => {
                ensure!(hunt.is_none(), "the defender key already selects its hunt");
                api.clone()
            }
            Self::Finder {
                opening,
                hunt: saved,
                ..
            } => {
                let p = &opening.participants;
                if let Some(link) = hunt {
                    ensure!(
                        saved.as_deref().is_none_or(|url| url == link.as_str()),
                        "hunt differs from the one saved in this dossier key"
                    );
                    hunt_api(link, &p.flag, Some(&p.defender))?
                } else {
                    let link = saved.as_deref().context("this older dossier key requires --hunt with the hunt URL from the registry")?;
                    hunt_base(&Url::parse(link)?, &p.flag)?
                }
            }
        };
        ensure!(
            requested.is_none_or(|url| url.trim_end_matches('/') == base.trim_end_matches('/')),
            "API differs from the selected facilitator"
        );
        Ok(base)
    }

    fn manifest(&self) -> Result<Manifest> {
        let my_public = threads::participant_public(self.secret())?;
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
            defender_public_key: Some(defender),
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
                let opening: Opening = get(api, &format!("threads/{id}"))?;
                ensure!(
                    opening.participants.finder == id,
                    "API returned a different dossier"
                );
                opening
            }
        };
        threads::verify_opening(&opening, &manifest)?;
        Ok(opening)
    }
}

pub(super) fn generate(
    flag_path: &Path,
    defender_path: &Path,
    metadata: Map<String, Value>,
    api: &str,
) -> Result<()> {
    let (flag, manifest, secret) = generate_private_for_api(metadata, api)?;
    let credential = Credential::Defender {
        flag: manifest.public_key.clone(),
        secret,
        api: api.into(),
    };
    write_secret(defender_path, &credential)?;
    if let Err(error) = write_secret(flag_path, &flag) {
        fs::remove_file(defender_path)
            .context("could not roll back newly created defender file")?;
        return Err(error);
    }
    print_json(&manifest)
}

pub(super) fn report(
    flag: &Key,
    defender: &str,
    message: &str,
    dossier_key_out: Option<PathBuf>,
    api: &str,
    hunt: &str,
) -> Result<()> {
    let secret = threads::fresh_secret();
    let opening = threads::open(flag, defender, &secret, message)?;
    let path = dossier_key_out
        .unwrap_or_else(|| format!("dossier-key-{}.json", opening.participants.finder).into());
    let credential = Credential::Finder {
        secret,
        opening: Box::new(opening),
        api: api.into(),
        hunt: Some(hunt.into()),
    };
    write_secret(&path, &credential)?;
    resend(&credential, &path, None, None)
}

pub(super) fn resend(
    credential: &Credential,
    path: &Path,
    api: Option<&str>,
    hunt: Option<&Url>,
) -> Result<()> {
    let Credential::Finder { opening, .. } = credential else {
        bail!("report requires a flag or a saved dossier key");
    };
    threads::verify_opening(opening, &credential.manifest()?)?;
    let acknowledgement: AcceptedOpening = post(&credential.api(api, hunt)?, "report", opening)
        .with_context(|| {
            format!(
                "dossier key saved at {}; retry with report and that file",
                path.display()
            )
        })?;
    ensure!(
        acknowledgement.opening == **opening
            && acknowledgement.receipt.dossier_id == opening.participants.finder
            && acknowledgement.receipt.sequence > 0,
        "API acknowledged a different opening"
    );
    print_json(&json!({
        "receipt": acknowledgement.receipt,
        "dossier_key_file": path,
        "thread": opening.participants.finder,
        "finder_file": path,
    }))
}

pub(super) fn unlock(
    credential: &Credential,
    dossier: Option<&str>,
    api: Option<&str>,
    after: Option<i64>,
    hunt: Option<&Url>,
) -> Result<()> {
    let api = credential.api(api, hunt)?;
    let after = after.unwrap_or(0);
    ensure!(after >= 0, "invalid page cursor");
    if dossier.is_none() && matches!(credential, Credential::Defender { .. }) {
        let manifest = credential.manifest()?;
        let page: Page<CaptureReceipt> = get_page(
            &api,
            &format!("dossiers/{}/threads", manifest.public_key),
            after,
        )?;
        let mut ids = Vec::with_capacity(page.items.len());
        let mut previous = after;
        for receipt in &page.items {
            validate_public_key(&receipt.dossier_id)?;
            ensure!(receipt.sequence > previous, "reports are out of order");
            previous = receipt.sequence;
            ids.push(&receipt.dossier_id);
        }
        return print_json(&json!({
            "receipts": page.items, "threads": ids, "next_after": page.next_after,
        }));
    }
    let opening = credential.opening(dossier, &api)?;
    let participants = &opening.participants;
    let page: Page<Value> = get_page(
        &api,
        &format!("threads/{}/messages", participants.finder),
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
        "dossier_id": participants.finder, "thread": participants.finder,
        "messages": messages, "next_after": page.next_after,
    }))
}

fn read_message(p: &Participants, secret: &str, entry: &ThreadMessage) -> Value {
    let sender = if entry.sender == p.finder {
        "finder"
    } else {
        "defender"
    };
    match threads::decrypt(p, secret, entry) {
        Ok(text) => json!({"sender": sender, "text": text}),
        Err(_) if threads::verify_entry(p, entry).is_err() => json!({"error": "invalid message"}),
        Err(_) => json!({"sender": sender, "error": "unreadable message"}),
    }
}

pub(super) fn attach(
    credential: &Credential,
    dossier: Option<&str>,
    message: &str,
    api: Option<&str>,
    hunt: Option<&Url>,
) -> Result<()> {
    let api = credential.api(api, hunt)?;
    let opening = credential.opening(dossier, &api)?;
    let participants = &opening.participants;
    let entry = threads::encrypt(participants, credential.secret(), message)?;
    let acknowledgement: ThreadMessage = post(
        &api,
        &format!("threads/{}/messages", participants.finder),
        &entry,
    )?;
    ensure!(
        acknowledgement == entry,
        "API acknowledged a different message"
    );
    print_json(&entry)
}

fn get<T: DeserializeOwned>(api: &str, path: &str) -> Result<T> {
    let response = client()?
        .get(format!("{}/{path}", api.trim_end_matches('/')))
        .send()?;
    Ok(serde_json::from_value(response_json_bound(
        response,
        MAX_RESPONSE_BYTES,
    )?)?)
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
        let (flag, manifest, defender) = generate_private_for_api(Map::new(), "unused").unwrap();
        let finder = threads::fresh_secret();
        let opening = threads::open(
            &flag,
            manifest.defender_public_key.as_deref().unwrap(),
            &finder,
            "first",
        )
        .unwrap();
        let p = &opening.participants;

        // A finder can sign arbitrary bytes, including an invalid AEAD tag.
        let mut corrupt = threads::encrypt(p, &finder, "second").unwrap();
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
        let reply = threads::encrypt(p, &defender, "last").unwrap();

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
