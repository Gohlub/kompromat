//! Per-finder dossiers. A flag authorizes the opening; only the finder and the
//! defender have the keys for the conversation, starting with its first note.

use anyhow::{Result, anyhow, bail, ensure};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, AeadCore, OsRng, Payload},
};
use schnorrkel::{ExpansionMode, Keypair, MiniSecretKey, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Key, Manifest, Proof, decode, prove, public_key, verify};

const CIPHER_CONTEXT: &[u8] = b"kompromat:finder-dossier:kex:v1";
const SIGNING_CONTEXT: &[u8] = b"kompromat:finder-dossier:message:v1";
const MAX_MESSAGE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Participants {
    pub flag: String,
    pub defender: String,
    pub finder: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadMessage {
    pub sender: String,
    pub nonce: String,
    pub ciphertext: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Opening {
    pub participants: Participants,
    pub first: ThreadMessage,
    pub proof: Proof,
}

/// The facilitator's durable acceptance record for a single private report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureReceipt {
    pub dossier_id: String,
    /// First accepted report for this flag is 1. Retries preserve this value.
    pub sequence: i64,
    /// Server UTC time. Older reports predate timestamp collection.
    pub accepted_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AcceptedOpening {
    pub opening: Opening,
    pub receipt: CaptureReceipt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_after: Option<i64>,
}

pub fn fresh_secret() -> String {
    hex::encode(MiniSecretKey::generate().to_bytes())
}

fn keypair(secret: &str) -> Result<Keypair> {
    let seed = MiniSecretKey::from_bytes(&decode::<32>(secret)?).map_err(|e| anyhow!("{e}"))?;
    Ok(seed.expand_to_keypair(ExpansionMode::Ed25519))
}

pub fn participant_public(secret: &str) -> Result<String> {
    Ok(hex::encode(keypair(secret)?.public.to_bytes()))
}

impl Participants {
    fn peer(&self, own: &str) -> Result<&str> {
        if own == self.finder {
            Ok(&self.defender)
        } else if own == self.defender {
            Ok(&self.finder)
        } else {
            bail!("key is not a participant in this finder dossier")
        }
    }

    // Four fixed-width, ordered public keys. Validate every key before using
    // the same context as AEAD associated data and as part of the signature.
    fn header(&self, sender: &str) -> Result<Vec<u8>> {
        self.peer(sender)?;
        ensure!(
            self.flag != self.defender && self.flag != self.finder && self.finder != self.defender,
            "flag, defender, and finder must use distinct keys"
        );
        let mut header = Vec::with_capacity(4 * 32);
        for key in [self.flag.as_str(), &self.defender, &self.finder, sender] {
            header.extend_from_slice(&public_key(key)?.to_bytes());
        }
        Ok(header)
    }

    fn cipher(&self, own: &Keypair) -> Result<XChaCha20Poly1305> {
        let own_public = hex::encode(own.public.to_bytes());
        let peer = public_key(self.peer(&own_public)?)?;
        Ok(own.aead_unauthenticated(CIPHER_CONTEXT, &peer))
    }
}

pub fn encrypt(p: &Participants, secret: &str, text: &str) -> Result<ThreadMessage> {
    ensure!(text.len() <= MAX_MESSAGE_BYTES, "message exceeds 16 KiB");
    let own = keypair(secret)?;
    let sender = hex::encode(own.public.to_bytes());
    let mut signed = p.header(&sender)?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = p
        .cipher(&own)?
        .encrypt(
            &nonce,
            Payload {
                msg: text.as_bytes(),
                aad: &signed,
            },
        )
        .map_err(|_| anyhow!("finder dossier encryption failed"))?;
    signed.extend_from_slice(&nonce);
    signed.extend_from_slice(&ciphertext);
    Ok(ThreadMessage {
        sender,
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
        signature: hex::encode(own.sign_simple(SIGNING_CONTEXT, &signed).to_bytes()),
    })
}

fn signed_bytes(p: &Participants, entry: &ThreadMessage) -> Result<Vec<u8>> {
    ensure!(
        (32..=(MAX_MESSAGE_BYTES + 16) * 2).contains(&entry.ciphertext.len())
            && entry
                .ciphertext
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid finder dossier ciphertext length or encoding"
    );
    let mut signed = p.header(&entry.sender)?;
    signed.extend_from_slice(&decode::<24>(&entry.nonce)?);
    signed.extend_from_slice(&hex::decode(&entry.ciphertext)?);
    Ok(signed)
}

pub fn verify_entry(p: &Participants, entry: &ThreadMessage) -> Result<()> {
    let signed = signed_bytes(p, entry)?;
    let signature =
        Signature::from_bytes(&decode::<64>(&entry.signature)?).map_err(|e| anyhow!("{e}"))?;
    public_key(&entry.sender)?
        .verify_simple(SIGNING_CONTEXT, &signed, &signature)
        .map_err(|e| anyhow!("{e}"))
}

pub fn decrypt(p: &Participants, secret: &str, entry: &ThreadMessage) -> Result<String> {
    verify_entry(p, entry)?;
    let nonce = decode::<24>(&entry.nonce)?;
    let plaintext = p
        .cipher(&keypair(secret)?)?
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: &hex::decode(&entry.ciphertext)?,
                aad: &p.header(&entry.sender)?,
            },
        )
        .map_err(|_| anyhow!("finder dossier decryption failed"))?;
    Ok(String::from_utf8(plaintext)?)
}

fn opening_claim(p: &Participants, first: &ThreadMessage) -> Result<String> {
    // The signature at the end is fixed width, so the ciphertext boundary
    // remains unambiguous. The flag proof itself uses the existing Proof format.
    let digest = Sha256::new()
        .chain_update(signed_bytes(p, first)?)
        .chain_update(decode::<64>(&first.signature)?)
        .finalize();
    Ok(format!(
        "kompromat:finder-dossier:open:v1:{}",
        hex::encode(digest)
    ))
}

pub fn open(flag: &Key, defender: &str, finder_secret: &str, text: &str) -> Result<Opening> {
    if let Some(pinned) = &flag.defender_public_key {
        ensure!(
            pinned == defender,
            "defender key differs from the planted flag"
        );
    }
    let participants = Participants {
        flag: flag.public_key()?,
        defender: defender.to_owned(),
        finder: participant_public(finder_secret)?,
    };
    let first = encrypt(&participants, finder_secret, text)?;
    let proof = prove(flag, opening_claim(&participants, &first)?)?;
    Ok(Opening {
        participants,
        first,
        proof,
    })
}

pub fn verify_opening(opening: &Opening, manifest: &Manifest) -> Result<()> {
    let p = &opening.participants;
    ensure!(
        p.flag == manifest.public_key,
        "opening belongs to another flag"
    );
    ensure!(
        manifest.defender_public_key.as_deref() == Some(p.defender.as_str()),
        "defender key differs from the manifest"
    );
    ensure!(
        opening.first.sender == p.finder,
        "finder must sign the opening"
    );
    verify_entry(p, &opening.first)?;
    ensure!(
        opening.proof.reply.is_none() && opening.proof.message == opening_claim(p, &opening.first)?,
        "opening proof does not bind this finder dossier"
    );
    verify(&opening.proof, manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Map;

    #[test]
    fn each_finder_and_defender_can_read_only_their_exchange() {
        let defender = fresh_secret();
        let recipient = participant_public(&defender).unwrap();
        let (mut flag, mut manifest) = crate::generate(Map::new());
        flag.defender_public_key = Some(recipient.clone());
        manifest.defender_public_key = Some(recipient.clone());

        let alice = fresh_secret();
        let bob = fresh_secret();
        let a = open(&flag, &recipient, &alice, "Alice's private report").unwrap();
        let b = open(&flag, &recipient, &bob, "Bob's private report").unwrap();
        for opening in [&a, &b] {
            verify_opening(opening, &manifest).unwrap();
        }
        assert_eq!(
            decrypt(&a.participants, &defender, &a.first).unwrap(),
            "Alice's private report"
        );
        assert!(decrypt(&a.participants, &bob, &a.first).is_err());
        assert!(decrypt(&a.participants, &flag.secret_key, &a.first).is_err());
        let reply = encrypt(&a.participants, &defender, "Details?").unwrap();
        assert_eq!(
            decrypt(&a.participants, &alice, &reply).unwrap(),
            "Details?"
        );
        assert!(verify_entry(&b.participants, &reply).is_err());
        assert!(encrypt(&a.participants, &bob, "pretend to be Alice").is_err());
        assert!(
            !serde_json::to_string(&a)
                .unwrap()
                .contains("Alice's private report")
        );

        let mut splice = a.clone();
        splice.first = encrypt(&a.participants, &alice, "another signed entry").unwrap();
        assert!(verify_opening(&splice, &manifest).is_err());
        splice.first = a.first.clone();
        splice.first.sender = recipient;
        assert!(verify_entry(&a.participants, &splice.first).is_err());
        assert!(verify_opening(&splice, &manifest).is_err());

        assert!(open(&flag, &b.participants.finder, &alice, "wrong defender").is_err());
        manifest.defender_public_key = Some(b.participants.finder);
        assert!(verify_opening(&a, &manifest).is_err());
    }

    #[test]
    fn reject_keys_which_collapse_roles_and_invalid_encodings() {
        let (flag, _) = crate::generate(Map::new());
        let defender = fresh_secret();
        let recipient = participant_public(&defender).unwrap();
        let finder = fresh_secret();
        assert!(open(&flag, &recipient, &defender, "").is_err());
        assert!(open(&flag, &recipient, &flag.secret_key, "").is_err());
        assert!(open(&flag, &flag.public_key().unwrap(), &finder, "").is_err());
        assert!(open(&flag, &"00".repeat(32), &finder, "").is_err());
        let too_long = "a".repeat(MAX_MESSAGE_BYTES + 1);
        assert!(open(&flag, &recipient, &finder, &too_long).is_err());
    }
}
