use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use kompromat::{
    Key, Manifest, generate_private_for_api,
    threads::{self, AcceptedOpening, Opening, ThreadMessage},
    validate_public_key,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};

use super::{client, post, print_json, response_json, write_secret};

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
    },
}

impl Credential {
    fn secret(&self) -> &str {
        match self {
            Self::Defender { secret, .. } | Self::Finder { secret, .. } => secret,
        }
    }

    fn api(&self) -> &str {
        match self {
            Self::Defender { api, .. } | Self::Finder { api, .. } => api,
        }
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
) -> Result<()> {
    let secret = threads::fresh_secret();
    let opening = threads::open(flag, defender, &secret, message)?;
    let path = dossier_key_out
        .unwrap_or_else(|| format!("dossier-key-{}.json", opening.participants.finder).into());
    let credential = Credential::Finder {
        secret,
        opening: Box::new(opening),
        api: api.into(),
    };
    write_secret(&path, &credential)?;
    resend(&credential, &path, None)
}

pub(super) fn resend(credential: &Credential, path: &Path, api: Option<&str>) -> Result<()> {
    let Credential::Finder { opening, .. } = credential else {
        bail!("report requires a flag or a saved dossier key");
    };
    threads::verify_opening(opening, &credential.manifest()?)?;
    let response = post(
        api.unwrap_or(credential.api()),
        "threads?receipt=true",
        opening,
    )
    .with_context(|| {
        format!(
            "dossier key saved at {}; retry with report and that file",
            path.display()
        )
    })?;
    let acknowledgement: AcceptedOpening = serde_json::from_value(response)
        .with_context(|| format!("invalid capture receipt for dossier key {}", path.display()))?;
    ensure!(
        acknowledgement.opening == **opening,
        "API acknowledged a different opening"
    );
    check_receipt(&acknowledgement)?;
    print_json(&json!({
        "receipt": acknowledgement.receipt,
        "dossier_key_file": path,
        "thread": opening.participants.finder,
        "finder_file": path,
    }))
}

fn check_receipt(accepted: &AcceptedOpening) -> Result<()> {
    ensure!(
        accepted.receipt.dossier_id == accepted.opening.participants.finder
            && accepted.receipt.sequence > 0,
        "invalid capture receipt for this dossier"
    );
    Ok(())
}

pub(super) fn unlock(
    credential: &Credential,
    dossier: Option<&str>,
    api: Option<&str>,
) -> Result<()> {
    let api = api.unwrap_or(credential.api());
    if dossier.is_none() && matches!(credential, Credential::Defender { .. }) {
        let manifest = credential.manifest()?;
        let openings: Vec<AcceptedOpening> = get(
            api,
            &format!("dossiers/{}/threads?receipt=true", manifest.public_key),
        )?;
        let mut ids = Vec::with_capacity(openings.len());
        let mut receipts = Vec::with_capacity(openings.len());
        for accepted in openings {
            threads::verify_opening(&accepted.opening, &manifest)?;
            check_receipt(&accepted)?;
            ids.push(accepted.opening.participants.finder);
            receipts.push(accepted.receipt);
        }
        return print_json(&json!({"receipts": receipts, "threads": ids}));
    }
    let opening = credential.opening(dossier, api)?;
    let participants = &opening.participants;
    let entries: Vec<ThreadMessage> =
        get(api, &format!("threads/{}/messages", participants.finder))?;
    let messages = std::iter::once(&opening.first)
        .chain(&entries)
        .map(|entry| threads::decrypt(participants, credential.secret(), entry))
        .collect::<Result<Vec<_>>>()?;
    print_json(
        &json!({"dossier_id": participants.finder, "thread": participants.finder, "messages": messages}),
    )
}

pub(super) fn attach(
    credential: &Credential,
    dossier: Option<&str>,
    message: &str,
    api: Option<&str>,
) -> Result<()> {
    let api = api.unwrap_or(credential.api());
    let opening = credential.opening(dossier, api)?;
    let participants = &opening.participants;
    let entry = threads::encrypt(participants, credential.secret(), message)?;
    let acknowledgement: ThreadMessage = serde_json::from_value(post(
        api,
        &format!("threads/{}/messages", participants.finder),
        &entry,
    )?)?;
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
    Ok(serde_json::from_value(response_json(response)?)?)
}
