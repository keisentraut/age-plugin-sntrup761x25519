use crate::{IDENTITY_PREFIX, RECIPIENT_PREFIX};
use bech32::{ToBase32, Variant};
use pqcrypto::kem::sntrup761;
use pqcrypto_traits::kem::{PublicKey, SecretKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::fmt;
use x25519_dalek;
use x25519_dalek::EphemeralSecret;

#[derive(Clone)]
pub(crate) struct Recipient {
    x25519pk: x25519_dalek::PublicKey,
    sntrup761pk: sntrup761::PublicKey,
}

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Recipient({:?}, {:?})",
            self.x25519pk.to_bytes(),
            self.sntrup761pk.as_bytes()
        )
    }
}
impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let concattedpk = [
            self.x25519pk.to_bytes().to_vec(),
            self.sntrup761pk.as_bytes().to_vec(),
        ]
        .concat();
        f.write_str(
            bech32::encode(RECIPIENT_PREFIX, &concattedpk.to_base32(), Variant::Bech32)
                .expect("HRP is invalid")
                .as_str(),
        )
    }
}

impl Recipient {
    // pub fn gen_test() -> Self {
    //     let (sntrup761pk, _) = sntrup761::keypair();
    //     let x25519pk = x25519_dalek::PublicKey::from(&EphemeralSecret::new(OsRng));
    //     Self {
    //         sntrup761pk: sntrup761pk,
    //         x25519pk: x25519pk,
    //     }
    // }
    /// Attempts to parse a valid recipient.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 32 + sntrup761::public_key_bytes() {
            let x25519pk = bytes[..32].to_vec();
            let sntrup761pk = &bytes[32..32 + sntrup761::public_key_bytes()];
            let x25519pk = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(x25519pk).unwrap());
            let sntrup761pk = sntrup761::PublicKey::from_bytes(sntrup761pk).unwrap();
            Some(Self {
                x25519pk: x25519pk,
                sntrup761pk: sntrup761pk,
            })
        } else {
            None
        }
    }
}

#[derive(Clone)]
pub(crate) struct Identity {
    x25519sk: x25519_dalek::StaticSecret,
    sntrup761sk: sntrup761::SecretKey,
}
impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Identity({:?}, {:?})",
            self.x25519sk.to_bytes(),
            self.sntrup761sk.as_bytes()
        )
    }
}
impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let concattedsk = [
            self.x25519sk.to_bytes().to_vec(),
            self.sntrup761sk.as_bytes().to_vec(),
        ]
        .concat();
        f.write_str(
            bech32::encode(IDENTITY_PREFIX, &concattedsk.to_base32(), Variant::Bech32)
                .expect("HRP is invalid")
                .as_str(),
        )
    }
}

impl Identity {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 32 + sntrup761::secret_key_bytes() {
            let x25519sk = bytes[..32].to_vec();
            let sntrup761sk = &bytes[32..32 + sntrup761::secret_key_bytes()];
            let x25519sk =
                x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(x25519sk).unwrap());
            let sntrup761sk = sntrup761::SecretKey::from_bytes(sntrup761sk).unwrap();
            Some(Identity {
                x25519sk: x25519sk,
                sntrup761sk: sntrup761sk,
            })
        } else {
            None
        }
    }
}
