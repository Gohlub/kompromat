//! Local key generation and Schnorr proofs of possession.

pub mod api;
mod messages;
pub mod publication;
pub mod threads;

pub use messages::{EncryptedMessage, decrypt_message, encrypt_message, verify_message};

use anyhow::{Result, anyhow, ensure};
use schnorrkel::{ExpansionMode, Keypair, MiniSecretKey, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Changing this changes the protocol. The library also binds the public key.
const CONTEXT: &[u8] = b"kompromat:proof:v1";
const REPLY_CONTEXT: &[u8] = b"kompromat:proof-reply:v1";
pub const DEFAULT_API: &str = "http://127.0.0.1:3000";
/// Maximum UTF-8 plaintext size for an encrypted note.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
const PRIVATE_REPORTING_INSTRUCTIONS: &str = "Keep this file and its secret local. Use the registry's hunt URL with `kompromat report PATH_TO_THIS_FILE --hunt HUNT_URL --message-stdin < writeup.txt`. Save the dossier key to read and reply.";

fn default_api() -> String {
    DEFAULT_API.into()
}

fn reporting_instructions() -> String {
    "Report access with: kompromat report PATH_TO_THIS_FILE. To include a shared note, add --hunt HUNT_URL --message 'your note'. Use the hunt URL from the registry. Never upload this file.".into()
}

/// Public, self-contained directions for submitting proof of access.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub url: String,
    pub method: String,
    pub content_type: String,
    pub cli: String,
    pub http: String,
    pub proof_format: String,
    pub body: Value,
}

impl Submission {
    fn new(api: &str, public_key: &str) -> Self {
        let url = format!("{}/proofs", api.trim_end_matches('/'));
        // Quote the URL as a shell literal in the optional curl example.
        let quoted_url = format!("'{}'", url.replace('\'', "'\\''"));
        Self {
            http: format!("curl --request POST --url {quoted_url} --header 'Content-Type: application/json' --data-binary @proof.json"),
            url,
            method: "POST".into(),
            content_type: "application/json".into(),
            cli: "kompromat report PATH_TO_THIS_FILE".into(),
            proof_format: "kompromat prove PATH_TO_THIS_FILE > proof.json. For a shared note add --manifest TRUSTED_MANIFEST --message 'your note'. Bare proof: expand the 32-byte Schnorrkel MiniSecretKey with ExpansionMode::Ed25519 and sign the empty message under kompromat:proof:v1. Use lowercase hex for the public key and signature. Never send secret_key.".into(),
            body: serde_json::json!({"public_key": public_key, "message": "", "signature": "<locally generated Schnorr signature>"}),
        }
    }
}

/// The secret key file, including public reporting instructions. Never uploaded.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Key {
    pub secret_key: String,
    /// Pins the defender who receives private reports. Shared-format flags omit this key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defender_public_key: Option<String>,
    #[serde(default = "default_api")]
    pub api: String,
    #[serde(default = "reporting_instructions")]
    pub instructions: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submission: Option<Submission>,
}

impl Key {
    pub fn public_key(&self) -> Result<String> {
        Ok(hex::encode(self.keypair()?.public.to_bytes()))
    }

    pub(crate) fn keypair(&self) -> Result<Keypair> {
        let secret = MiniSecretKey::from_bytes(&decode::<32>(&self.secret_key)?)
            .map_err(|e| anyhow!("{e}"))?;
        Ok(secret.expand_to_keypair(ExpansionMode::Ed25519))
    }
}

/// Public registration manifest containing a public key and descriptive metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defender_public_key: Option<String>,
    #[serde(default)]
    pub metadata: Map<String, Value>,
}

impl Manifest {
    /// Match a found flag to an independently obtained hunt manifest.
    pub fn verify_flag(&self, public_key: &str, defender: Option<&str>) -> Result<()> {
        ensure!(
            self.public_key == public_key && self.defender_public_key.as_deref() == defender,
            "flag does not match the registered hunt"
        );
        Ok(())
    }
}

// Compatibility with callers of the original Rust API.
#[doc(hidden)]
pub use Manifest as Dossier;

/// A Schnorr proof over a public message and, optionally, an encrypted reply.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub public_key: String,
    pub message: String,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply: Option<EncryptedMessage>,
}

/// Generate a flag, its public manifest, and the defender key for reading reports.
pub fn generate(metadata: Map<String, Value>) -> Result<(Key, Manifest, String)> {
    generate_for_api(metadata, DEFAULT_API)
}

/// Generate the same keys and manifest with the supplied registry URL.
pub fn generate_for_api(
    metadata: Map<String, Value>,
    api: &str,
) -> Result<(Key, Manifest, String)> {
    ensure!(
        !metadata.contains_key("submission"),
        "private reports use the registered hunt's /report endpoint"
    );
    let (secret, public) = generate_keypair();
    let (flag, manifest) = generate_flag(metadata, api, Some(public));
    Ok((flag, manifest, secret))
}

/// Generate a shared dossier readable by everyone who holds its flag.
pub fn generate_shared(metadata: Map<String, Value>) -> (Key, Manifest) {
    generate_shared_for_api(metadata, DEFAULT_API)
}

pub fn generate_shared_for_api(metadata: Map<String, Value>, api: &str) -> (Key, Manifest) {
    generate_flag(metadata, api, None)
}

fn generate_keypair() -> (String, String) {
    let secret = MiniSecretKey::generate();
    let keypair = secret.expand_to_keypair(ExpansionMode::Ed25519);
    (
        hex::encode(secret.to_bytes()),
        hex::encode(keypair.public.to_bytes()),
    )
}

fn generate_flag(
    mut metadata: Map<String, Value>,
    api: &str,
    defender_public_key: Option<String>,
) -> (Key, Manifest) {
    let (secret_key, public_key) = generate_keypair();
    let (instructions, submission) = if defender_public_key.is_some() {
        (PRIVATE_REPORTING_INSTRUCTIONS.into(), None)
    } else {
        let submission = Submission::new(api, &public_key);
        metadata
            .entry("submission")
            .or_insert_with(|| serde_json::json!(submission));
        (reporting_instructions(), Some(submission))
    };
    metadata
        .entry("instructions")
        .or_insert_with(|| Value::String(instructions.clone()));
    (
        Key {
            secret_key,
            defender_public_key: defender_public_key.clone(),
            api: api.into(),
            instructions,
            submission,
        },
        Manifest {
            public_key,
            defender_public_key,
            metadata,
        },
    )
}

pub fn prove(key: &Key, message: String) -> Result<Proof> {
    sign_proof(key, message, None)
}

/// Encrypt a reply locally and bind it to the public proof.
pub fn prove_with_reply(key: &Key, message: String, reply: &str) -> Result<Proof> {
    sign_proof(key, message, Some(encrypt_message(key, reply)?))
}

pub(crate) fn sign_proof(
    key: &Key,
    message: String,
    reply: Option<EncryptedMessage>,
) -> Result<Proof> {
    let keypair = key.keypair()?;
    let mut proof = Proof {
        public_key: hex::encode(keypair.public.to_bytes()),
        message,
        signature: String::new(),
        reply,
    };
    let (context, bytes) = proof_message(&proof)?;
    proof.signature = hex::encode(keypair.sign_simple(context, &bytes).to_bytes());
    Ok(proof)
}

pub fn validate_public_key(encoded: &str) -> Result<()> {
    public_key(encoded).map(|_| ())
}

/// Verify against an independently obtained public manifest, not just the key
/// supplied by the proof's author. Metadata is not part of the signed claim.
pub fn verify(proof: &Proof, expected: &Manifest) -> Result<()> {
    ensure!(
        proof.public_key == expected.public_key,
        "key public key mismatch"
    );
    let public = public_key(&expected.public_key)?;
    let signature =
        Signature::from_bytes(&decode::<64>(&proof.signature)?).map_err(|e| anyhow!("{e}"))?;
    if let Some(reply) = &proof.reply {
        verify_message(reply, &expected.public_key)?;
    }
    let (context, bytes) = proof_message(proof)?;
    public
        .verify_simple(context, &bytes, &signature)
        .map_err(|e| anyhow!("{e}"))?;
    Ok(())
}

fn proof_message(proof: &Proof) -> Result<(&'static [u8], Vec<u8>)> {
    let Some(reply) = &proof.reply else {
        return Ok((CONTEXT, proof.message.as_bytes().to_vec()));
    };
    // Length-prefix the public message; the reply has fixed-size key/nonce and
    // ends with a fixed-size signature. A separate context prevents stripping it.
    let mut bytes = (proof.message.len() as u64).to_be_bytes().to_vec();
    bytes.extend_from_slice(proof.message.as_bytes());
    bytes.extend_from_slice(&messages::signed_bytes(reply)?);
    bytes.extend_from_slice(&decode::<64>(&reply.signature)?);
    Ok((REPLY_CONTEXT, bytes))
}

fn public_key(encoded: &str) -> Result<PublicKey> {
    let bytes = decode::<32>(encoded)?;
    ensure!(bytes != [0; 32], "identity public key is not allowed");
    PublicKey::from_bytes(&bytes).map_err(|e| anyhow!("{e}"))
}

fn decode<const N: usize>(encoded: &str) -> Result<[u8; N]> {
    ensure!(
        encoded.len() == N * 2
            && encoded
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "expected {} lowercase hex characters",
        N * 2
    );
    let mut bytes = [0; N];
    hex::decode_to_slice(encoded, &mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_manifest_preserves_the_brief_and_omits_shared_submission() {
        let mut metadata = Map::new();
        metadata.insert("instructions".into(), Value::String("hunt brief".into()));
        let (flag, manifest, defender_secret) = generate(metadata).unwrap();
        let defender = threads::participant_public(&defender_secret).unwrap();
        assert_eq!(flag.defender_public_key.as_ref(), Some(&defender));
        assert_eq!(manifest.defender_public_key.as_ref(), Some(&defender));
        assert_eq!(manifest.metadata["instructions"], "hunt brief");
        assert_eq!(flag.instructions, PRIVATE_REPORTING_INSTRUCTIONS);
        assert!(!manifest.metadata.contains_key("submission"));
        assert!(flag.submission.is_none());
    }

    #[test]
    fn proof_roundtrip_keeps_secret_local() {
        let (key, public, _) = generate(Map::new()).unwrap();
        let proof = prove(&key, "found in the archive".into()).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let restored: Proof = serde_json::from_str(&json).unwrap();
        verify(&restored, &public).unwrap();
        assert!(!json.contains(&key.secret_key));
        assert!(
            !serde_json::to_string(&public)
                .unwrap()
                .contains(&key.secret_key)
        );
        // Repeated proving delegates nonce generation to Schnorrkel.
        let another = prove(&key, proof.message.clone()).unwrap();
        verify(&another, &public).unwrap();
        assert_ne!(proof.signature, another.signature);
    }

    #[test]
    fn tampering_and_wrong_manifests_fail() {
        let (key, public, _) = generate(Map::new()).unwrap();
        let proof = prove(&key, "original".into()).unwrap();
        let mut changed = proof.clone();
        changed.message.push('!');
        assert!(verify(&changed, &public).is_err());
        changed = proof.clone();
        changed.signature.replace_range(
            ..2,
            if &proof.signature[..2] == "00" {
                "01"
            } else {
                "00"
            },
        );
        assert!(verify(&changed, &public).is_err());
        let (_, other, _) = generate(Map::new()).unwrap();
        assert!(verify(&proof, &other).is_err());
        changed = proof;
        changed.public_key = other.public_key.clone();
        assert!(verify(&changed, &other).is_err());
    }

    #[test]
    fn invalid_encodings_and_identity_are_rejected() {
        for key in ["".into(), "00".repeat(32), "ff".repeat(32), "AB".repeat(32)] {
            assert!(validate_public_key(&key).is_err());
        }
        assert!(
            prove(
                &Key {
                    secret_key: "bad".into(),
                    defender_public_key: None,
                    api: default_api(),
                    instructions: reporting_instructions(),
                    submission: None,
                },
                String::new()
            )
            .is_err()
        );
    }

    #[test]
    fn signatures_from_other_protocols_fail() {
        let secret = MiniSecretKey::generate();
        let keypair = secret.expand_to_keypair(ExpansionMode::Ed25519);
        let public = Manifest {
            public_key: hex::encode(keypair.public.to_bytes()),
            defender_public_key: None,
            metadata: Map::new(),
        };
        let proof = Proof {
            public_key: public.public_key.clone(),
            message: "hello".into(),
            signature: hex::encode(keypair.sign_simple(b"another-app", b"hello").to_bytes()),
            reply: None,
        };
        assert!(verify(&proof, &public).is_err());
    }

    #[test]
    fn shared_reply_is_bound_to_the_proof_and_stays_encrypted() {
        let (key, public) = generate_shared(Map::new());
        let proof = prove_with_reply(&key, "I found it".into(), "The private details").unwrap();
        verify(&proof, &public).unwrap();
        assert_eq!(
            decrypt_message(&key, proof.reply.as_ref().unwrap()).unwrap(),
            "The private details"
        );
        let json = serde_json::to_string(&proof).unwrap();
        assert!(!json.contains("The private details"));
        assert!(!json.contains(&key.secret_key));
        verify(&serde_json::from_str(&json).unwrap(), &public).unwrap();

        let mut changed = proof.clone();
        changed.reply = None;
        assert!(verify(&changed, &public).is_err());
        changed = proof.clone();
        changed.reply = Some(encrypt_message(&key, "a different valid reply").unwrap());
        assert!(verify(&changed, &public).is_err());
        changed = proof.clone();
        changed.message.push('!');
        assert!(verify(&changed, &public).is_err());
        let mut legacy = prove(&key, "I found it".into()).unwrap();
        assert!(!serde_json::to_string(&legacy).unwrap().contains("reply"));
        legacy.reply = proof.reply.clone();
        assert!(verify(&legacy, &public).is_err());

        // Even a valid outer signature cannot authorize a reply for another key.
        let (other, _) = generate_shared(Map::new());
        let wrong_key = sign_proof(
            &key,
            String::new(),
            Some(encrypt_message(&other, "wrong").unwrap()),
        )
        .unwrap();
        assert!(verify(&wrong_key, &public).is_err());
    }
}
