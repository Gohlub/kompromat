//! Local key generation and Schnorr proofs of possession.

pub mod api;
pub mod publication;
pub mod threads;

use anyhow::{Result, anyhow, ensure};
use schnorrkel::{ExpansionMode, Keypair, MiniSecretKey, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Changing this changes the protocol. The library also binds the public key.
const CONTEXT: &[u8] = b"kompromat:proof:v1";
pub const DEFAULT_API: &str = "http://127.0.0.1:3000";
/// Maximum UTF-8 plaintext size for an encrypted note.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
const PRIVATE_REPORTING_INSTRUCTIONS: &str = "Keep this file and its secret local. Use the registry's hunt URL with `kompromat report PATH_TO_THIS_FILE --hunt HUNT_URL --message-stdin < writeup.txt`. Save the dossier key to read and reply.";

/// The flag secret and pinned recipient. Never uploaded.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Key {
    pub secret_key: String,
    pub defender_public_key: String,
    pub instructions: String,
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
    pub defender_public_key: String,
    #[serde(default)]
    pub metadata: Map<String, Value>,
}

impl Manifest {
    /// Match a found flag to an independently obtained hunt manifest.
    pub fn verify_flag(&self, public_key: &str, defender: &str) -> Result<()> {
        ensure!(
            self.public_key == public_key && self.defender_public_key == defender,
            "flag does not match the registered hunt"
        );
        Ok(())
    }
}

/// A Schnorr proof over a public message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub public_key: String,
    pub message: String,
    pub signature: String,
}

/// Generate a flag, its public manifest, and the defender key for reading reports.
pub fn generate(metadata: Map<String, Value>) -> (Key, Manifest, String) {
    let (secret_key, public_key) = generate_keypair();
    let (defender_secret, defender_public_key) = generate_keypair();
    (
        Key {
            secret_key,
            defender_public_key: defender_public_key.clone(),
            instructions: PRIVATE_REPORTING_INSTRUCTIONS.into(),
        },
        Manifest {
            public_key,
            defender_public_key,
            metadata,
        },
        defender_secret,
    )
}

fn generate_keypair() -> (String, String) {
    let secret = MiniSecretKey::generate();
    let keypair = secret.expand_to_keypair(ExpansionMode::Ed25519);
    (
        hex::encode(secret.to_bytes()),
        hex::encode(keypair.public.to_bytes()),
    )
}

pub fn prove(key: &Key, message: String) -> Result<Proof> {
    let keypair = key.keypair()?;
    let signature = hex::encode(keypair.sign_simple(CONTEXT, message.as_bytes()).to_bytes());
    Ok(Proof {
        public_key: hex::encode(keypair.public.to_bytes()),
        message,
        signature,
    })
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
    public
        .verify_simple(CONTEXT, proof.message.as_bytes(), &signature)
        .map_err(|e| anyhow!("{e}"))?;
    Ok(())
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
    fn private_manifest_preserves_the_brief_and_pins_the_defender() {
        let mut metadata = Map::new();
        metadata.insert("instructions".into(), Value::String("hunt brief".into()));
        let (flag, manifest, defender_secret) = generate(metadata);
        let defender = threads::participant_public(&defender_secret).unwrap();
        assert_eq!(flag.defender_public_key, defender);
        assert_eq!(manifest.defender_public_key, defender);
        assert_eq!(manifest.metadata["instructions"], "hunt brief");
        assert_eq!(flag.instructions, PRIVATE_REPORTING_INSTRUCTIONS);
    }

    #[test]
    fn proof_roundtrip_keeps_secret_local() {
        let (key, public, _) = generate(Map::new());
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
        let (key, public, _) = generate(Map::new());
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
        let (_, other, _) = generate(Map::new());
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
                    defender_public_key: String::new(),
                    instructions: String::new(),
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
            defender_public_key: threads::participant_public(&threads::fresh_secret()).unwrap(),
            metadata: Map::new(),
        };
        let proof = Proof {
            public_key: public.public_key.clone(),
            message: "hello".into(),
            signature: hex::encode(keypair.sign_simple(b"another-app", b"hello").to_bytes()),
        };
        assert!(verify(&proof, &public).is_err());
    }
}
