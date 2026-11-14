//! Local key generation and Schnorr proofs of possession.

pub mod api;
mod messages;
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

fn default_api() -> String {
    DEFAULT_API.into()
}

fn reporting_instructions() -> String {
    "Found this key? Install the CLI: curl -fsSL https://kompromat.sh/cli | sh. Report access with: kompromat report PATH_TO_THIS_FILE. Or generate a proof locally and use the HTTP instructions in submission. Never upload this key file or secret_key. Optionally add --reply \"your message\" for an encrypted response.".into()
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
            proof_format: "Generate proof.json locally: kompromat prove PATH_TO_THIS_FILE > proof.json. To include an encrypted note, add --reply to the prove command with the note as its argument. For a proof without a note, an independent client can decode secret_key as a 32-byte Schnorrkel MiniSecretKey, expand with ExpansionMode::Ed25519, and sign the empty byte string using context kompromat:proof:v1. Keep the template's message field empty. Encode the public key (32 bytes) and signature (64 bytes) as lowercase hex. Do not send secret_key.".into(),
            body: serde_json::json!({"public_key": public_key, "message": "", "signature": "<locally generated Schnorr signature>"}),
        }
    }
}

/// The secret key file, including public reporting instructions. Never uploaded.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Key {
    pub secret_key: String,
    /// Recipient pinned in a planted flag when private finder dossiers are enabled.
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

pub fn generate(metadata: Map<String, Value>) -> (Key, Manifest) {
    generate_for_api(metadata, DEFAULT_API)
}

pub fn generate_for_api(mut metadata: Map<String, Value>, api: &str) -> (Key, Manifest) {
    let secret = MiniSecretKey::generate();
    let keypair = secret.expand_to_keypair(ExpansionMode::Ed25519);
    let public_key = hex::encode(keypair.public.to_bytes());
    let submission = Submission::new(api, &public_key);
    let instructions = reporting_instructions();
    metadata
        .entry("instructions")
        .or_insert_with(|| Value::String(instructions.clone()));
    metadata
        .entry("submission")
        .or_insert_with(|| serde_json::json!(submission));
    (
        Key {
            secret_key: hex::encode(secret.to_bytes()),
            defender_public_key: None,
            api: api.into(),
            instructions,
            submission: Some(submission),
        },
        Manifest {
            public_key,
            defender_public_key: None,
            metadata,
        },
    )
}

/// Generate a planted flag and a separate, defender-only credential.
pub fn generate_private_for_api(
    mut metadata: Map<String, Value>,
    api: &str,
) -> Result<(Key, Manifest, String)> {
    let instructions = metadata.remove("instructions");
    ensure!(
        !metadata.contains_key("submission"),
        "private finder reports use the /threads endpoint"
    );
    let (mut flag, mut manifest) = generate_for_api(metadata, api);
    let defender_secret = threads::fresh_secret();
    let defender_public = threads::participant_public(&defender_secret)?;
    flag.defender_public_key = Some(defender_public.clone());
    manifest.defender_public_key = Some(defender_public);

    flag.instructions = "Found this flag? Run kompromat report PATH_TO_THIS_FILE --message 'your note'. Keep the finder receipt to read replies. Never upload the flag or the receipt.".into();
    // The legacy curl template describes a different endpoint and message format.
    flag.submission = None;
    manifest.metadata.remove("submission");
    manifest.metadata.insert(
        "instructions".into(),
        instructions.unwrap_or_else(|| Value::String(flag.instructions.clone())),
    );
    Ok((flag, manifest, defender_secret))
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
    fn proof_roundtrip_keeps_secret_local() {
        let (key, public) = generate(Map::new());
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
        let (key, public) = generate(Map::new());
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
        let (_, other) = generate(Map::new());
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
    fn private_reply_is_bound_to_the_proof_and_stays_encrypted() {
        let (key, public) = generate(Map::new());
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
        let (other, _) = generate(Map::new());
        let wrong_key = sign_proof(
            &key,
            String::new(),
            Some(encrypt_message(&other, "wrong").unwrap()),
        )
        .unwrap();
        assert!(verify(&wrong_key, &public).is_err());
    }
}
