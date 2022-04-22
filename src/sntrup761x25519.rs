use crate::RECIPIENT_PREFIX;
use bech32::{ToBase32, Variant};
use pqcrypto::kem::sntrup761;
use pqcrypto_traits::kem::PublicKey;
use sha2::{Digest, Sha256};
use std::fmt;
use x25519_dalek;
use  rand_core::OsRng;
#[derive(Clone)]
pub(crate) struct Recipient {
    x25519pk: x25519_dalek::StaticSecret,
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
                .expect("HRP is valid")
                .as_str(),
        )
    }
}

impl Recipient {
    pub fn gen_test() -> Self {
        let (p, _) = sntrup761::keypair();
        Self {
            sntrup761pk : p,
            x25519pk : x25519_dalek::StaticSecret::new(OsRng),
        }
    }
    /// Attempts to parse a valid YubiKey recipient from its compressed SEC-1 byte encoding.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 32 + sntrup761::public_key_bytes() {
            let x25519pk  = bytes[..32].to_vec();
            let sntrup761pk = &bytes[32..32 + sntrup761::public_key_bytes()];
            let x25519pk =  x25519_dalek::StaticSecret::from(<[u8;32]>::try_from(x25519pk).unwrap());
            let sntrup761pk = sntrup761::PublicKey::from_bytes(sntrup761pk).unwrap();
            Some(Self { x25519pk: x25519pk, sntrup761pk: sntrup761pk })
        } else {
            None
        }
    }
}

