use anyhow::{Context, Result, ensure};
use kompromat::{
    EncryptedMessage, Key, Proof, decrypt_message, encrypt_message, threads::Page, verify_message,
};
use reqwest::Url;
use serde_json::{Value, json};

use super::{client, hunt_url, post, post_url, print_json, registered_hunt, response_json_bound};

pub(super) fn report(secret: &Key, api: Option<&str>, proof: &Proof) -> Result<()> {
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
    submit_proof(&url, proof)
}

pub(super) fn submit_proof(url: &str, proof: &Proof) -> Result<()> {
    let stored: Proof = post_url(url, proof)?;
    ensure!(&stored == proof, "API acknowledged a different proof");
    print_json(&stored)
}

pub(super) fn attach(
    flag: &Key,
    message: &str,
    hunt: Option<Url>,
    api: Option<&str>,
) -> Result<()> {
    ensure!(
        flag.defender_public_key.is_none(),
        "use the dossier key or defender key to attach"
    );
    let id = flag.public_key()?;
    let link = match hunt {
        Some(link) => link,
        None => hunt_url(
            api.context("supply --hunt or --api from the registry")?,
            &id,
        )?,
    };
    let api = registered_hunt(&link, &id, None)?.api;
    let entry = encrypt_message(flag, message)?;
    let stored: EncryptedMessage = post(&api, "messages", &entry)?;
    ensure!(
        stored.nonce == entry.nonce && stored.ciphertext == entry.ciphertext,
        "API acknowledged a different message"
    );
    verify_message(&stored, &entry.public_key)?;
    print_json(&stored)
}

pub(super) fn unlock(flag: &Key, hunt: Option<Url>, api: Option<String>, after: i64) -> Result<()> {
    ensure!(
        flag.defender_public_key.is_none(),
        "use the dossier key or defender key to unlock"
    );
    let public_key = flag.public_key()?;
    let api = if let Some(link) = hunt {
        registered_hunt(&link, &public_key, None)?.api
    } else {
        api.unwrap_or_else(|| flag.api.clone())
    };
    let response = client()?
        .get(format!(
            "{}/dossiers/{public_key}/messages?after={after}",
            api.trim_end_matches('/')
        ))
        .send()?;
    let value: Value = response_json_bound(response, 2 * 1024 * 1024)?;
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
                .and_then(|entry| decrypt_message(flag, &entry).ok())
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
    print_json(&transcript)
}
