//! Defender authorization for publishing or withdrawing a hunt brief.

use anyhow::{Context, Result, anyhow, ensure};
use reqwest::Url;
use schnorrkel::Signature;
use serde::{Deserialize, Serialize};

use crate::{decode, public_key, threads::keypair};

const CONTEXT: &[u8] = b"kompromat:hunt-publication:v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listing {
    pub title: String,
    pub brief_url: String,
}

impl Listing {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.title.is_empty()
                && self.title.trim() == self.title
                && self.title.len() <= 160
                && !self.title.chars().any(char::is_control),
            "expected a hunt title of 1 to 160 bytes without surrounding space or control characters"
        );
        let url = Url::parse(&self.brief_url).context("invalid brief URL")?;
        ensure!(
            self.brief_url.starts_with("https://")
                && self.brief_url.len() <= 2048
                && !self
                    .brief_url
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none(),
            "expected an absolute HTTPS brief URL without credentials, up to 2048 bytes"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationState {
    pub registry_id: String,
    pub revision: i64,
    pub listing: Option<Listing>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPublication {
    pub state: PublicationState,
    pub signature: String,
}

fn signed_bytes(flag: &str, state: &PublicationState) -> Result<Vec<u8>> {
    ensure!(
        state.revision > 0,
        "expected a positive publication revision"
    );
    let mut bytes = decode::<32>(&state.registry_id)?.to_vec();
    bytes.extend_from_slice(&public_key(flag)?.to_bytes());
    bytes.extend_from_slice(&state.revision.to_be_bytes());
    if let Some(listing) = &state.listing {
        listing.validate()?;
        bytes.push(1);
        bytes.extend_from_slice(&(listing.title.len() as u32).to_be_bytes());
        bytes.extend_from_slice(listing.title.as_bytes());
        bytes.extend_from_slice(listing.brief_url.as_bytes());
    } else {
        bytes.push(0);
    }
    Ok(bytes)
}

/// Sign the immediate successor of the observed state for this registry and flag.
pub fn sign(
    secret: &str,
    flag: &str,
    current: &PublicationState,
    listing: Option<Listing>,
) -> Result<SignedPublication> {
    let state = PublicationState {
        registry_id: current.registry_id.clone(),
        revision: current
            .revision
            .checked_add(1)
            .context("publication revision exhausted")?,
        listing,
    };
    let signature = keypair(secret)?.sign_simple(CONTEXT, &signed_bytes(flag, &state)?);
    Ok(SignedPublication {
        state,
        signature: hex::encode(signature.to_bytes()),
    })
}

impl SignedPublication {
    pub(crate) fn verify(&self, defender: &str, flag: &str) -> Result<()> {
        let signature =
            Signature::from_bytes(&decode::<64>(&self.signature)?).map_err(|e| anyhow!("{e}"))?;
        public_key(defender)?
            .verify_simple(CONTEXT, &signed_bytes(flag, &self.state)?, &signature)
            .map_err(|e| anyhow!("{e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_fields_require_a_title_and_an_https_brief() {
        let mut listing = Listing {
            title: "Export preview".into(),
            brief_url: "https://def.example/scope".into(),
        };
        assert!(listing.validate().is_ok());
        for title in ["", "  ", "Export\npreview", &"x".repeat(161)] {
            listing.title = title.into();
            assert!(listing.validate().is_err());
        }
        listing.title = "Export preview".into();
        for url in [
            "/scope",
            "http://def.example/scope",
            "https://user:password@def.example/scope",
            "https://def.example/\nscope",
            "javascript:alert(1)",
        ] {
            listing.brief_url = url.into();
            assert!(listing.validate().is_err());
        }
    }
}
