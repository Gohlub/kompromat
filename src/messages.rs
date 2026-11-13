//! Signed, end-to-end encrypted messages for holders of the same key file.

use anyhow::{Result, anyhow, ensure};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use hkdf::Hkdf;
use schnorrkel::Signature;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{Key, decode, public_key};

pub(crate) const CONTEXT: &[u8] = b"kompromat:record:v1";
const KEY_CONTEXT: &[u8] = b"kompromat:record:encryption:v1";
const MAX_MESSAGE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedMessage {
    pub public_key: String,
    pub nonce: String,
    pub ciphertext: String,
    pub signature: String,
}

pub fn encrypt_message(key: &Key, message: &str) -> Result<EncryptedMessage> {
    ensure!(message.len() <= MAX_MESSAGE_BYTES, "message exceeds 16 KiB");
    let keypair = key.keypair()?;
    let public = keypair.public.to_bytes();
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher(key)?
        .encrypt(
            &nonce,
            Payload {
                msg: message.as_bytes(),
                aad: &aad(&public),
            },
        )
        .map_err(|_| anyhow!("message encryption failed"))?;
    let mut entry = EncryptedMessage {
        public_key: hex::encode(public),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
        signature: String::new(),
    };
    entry.signature = hex::encode(
        keypair
            .sign_simple(CONTEXT, &signed_bytes(&entry)?)
            .to_bytes(),
    );
    Ok(entry)
}

/// The server verifies authorization without knowing the encryption key.
pub fn verify_message(entry: &EncryptedMessage, expected_public_key: &str) -> Result<()> {
    ensure!(
        entry.public_key == expected_public_key,
        "key public key mismatch"
    );
    let public = public_key(expected_public_key)?;
    let signature =
        Signature::from_bytes(&decode::<64>(&entry.signature)?).map_err(|e| anyhow!("{e}"))?;
    public
        .verify_simple(CONTEXT, &signed_bytes(entry)?, &signature)
        .map_err(|e| anyhow!("{e}"))?;
    Ok(())
}

/// Verify against the key derived from the local secret before decrypting.
pub fn decrypt_message(key: &Key, entry: &EncryptedMessage) -> Result<String> {
    let expected = key.public_key()?;
    verify_message(entry, &expected)?;
    let nonce = decode::<24>(&entry.nonce)?;
    let ciphertext = hex::decode(&entry.ciphertext)?;
    let plaintext = cipher(key)?
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: &ciphertext,
                aad: &aad(&decode::<32>(&expected)?),
            },
        )
        .map_err(|_| anyhow!("message decryption failed"))?;
    Ok(String::from_utf8(plaintext)?)
}

fn cipher(key: &Key) -> Result<XChaCha20Poly1305> {
    let seed = decode::<32>(&key.secret_key)?;
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(None, &seed)
        .expand(KEY_CONTEXT, &mut key)
        .map_err(|_| anyhow!("encryption key derivation failed"))?;
    Ok(XChaCha20Poly1305::new((&key).into()))
}

fn aad(public: &[u8; 32]) -> Vec<u8> {
    [CONTEXT, public.as_slice()].concat()
}

/// Fixed-size public key and nonce precede the ciphertext, so framing is unambiguous.
pub(crate) fn signed_bytes(entry: &EncryptedMessage) -> Result<Vec<u8>> {
    ensure!(
        (32..=(MAX_MESSAGE_BYTES + 16) * 2).contains(&entry.ciphertext.len())
            && entry.ciphertext.len().is_multiple_of(2)
            && entry
                .ciphertext
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "expected lowercase hex ciphertext with a 16-byte tag and at most 16 KiB of content"
    );
    Ok([
        decode::<32>(&entry.public_key)?.as_slice(),
        decode::<24>(&entry.nonce)?.as_slice(),
        hex::decode(&entry.ciphertext)?.as_slice(),
    ]
    .concat())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Manifest, Proof, generate, prove, verify};
    use serde_json::Map;

    #[test]
    fn same_key_file_unlocks_randomized_messages() {
        let (key, public) = generate(Map::new());
        let copy: Key = serde_json::from_str(&serde_json::to_string(&key).unwrap()).unwrap();
        for message in ["", "Follow the instructions here.\n🦀"] {
            let entry = encrypt_message(&key, message).unwrap();
            verify_message(&entry, &public.public_key).unwrap();
            assert_eq!(decrypt_message(&copy, &entry).unwrap(), message);
            let other = encrypt_message(&key, message).unwrap();
            assert_ne!(entry.nonce, other.nonce);
            assert_ne!(entry.ciphertext, other.ciphertext);
        }
        assert!(encrypt_message(&key, &"x".repeat(MAX_MESSAGE_BYTES + 1)).is_err());
    }

    #[test]
    fn wrong_key_tampering_and_invalid_aead_fail() {
        let (key, public) = generate(Map::new());
        let (other, _) = generate(Map::new());
        let entry = encrypt_message(&key, "private instructions").unwrap();
        assert!(decrypt_message(&other, &entry).is_err());
        let mut changed = entry.clone();
        changed.nonce = "00".repeat(24);
        assert!(verify_message(&changed, &public.public_key).is_err());
        changed = entry;
        changed.ciphertext = "00".repeat(32);
        assert!(decrypt_message(&key, &changed).is_err());
        // Even an authorized signer cannot cause unauthenticated AEAD output.
        changed.signature = hex::encode(
            key.keypair()
                .unwrap()
                .sign_simple(CONTEXT, &signed_bytes(&changed).unwrap())
                .to_bytes(),
        );
        verify_message(&changed, &public.public_key).unwrap();
        assert!(decrypt_message(&key, &changed).is_err());
        changed.nonce = "AB".repeat(24);
        assert!(verify_message(&changed, &public.public_key).is_err());
    }

    #[test]
    fn public_proofs_and_message_writes_are_separate_protocols() {
        let (key, public) = generate(Map::new());
        let mut entry = encrypt_message(&key, "private").unwrap();
        let public_proof = prove(&key, hex::encode(signed_bytes(&entry).unwrap())).unwrap();
        let original_signature = entry.signature.clone();
        entry.signature = public_proof.signature;
        assert!(verify_message(&entry, &public.public_key).is_err());
        // Test the exact same bytes in the wrong signing context as well.
        entry.signature = hex::encode(
            key.keypair()
                .unwrap()
                .sign_simple(crate::CONTEXT, &signed_bytes(&entry).unwrap())
                .to_bytes(),
        );
        assert!(verify_message(&entry, &public.public_key).is_err());
        let proof = Proof {
            public_key: entry.public_key,
            message: "private".into(),
            signature: original_signature,
            reply: None,
        };
        assert!(
            verify(
                &proof,
                &Manifest {
                    public_key: public.public_key,
                    metadata: Map::new()
                }
            )
            .is_err()
        );
    }
}
