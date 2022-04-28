use std::fmt;

use bech32::{ToBase32, Variant};
use pqcrypto::kem::sntrup761;
use pqcrypto_traits::kem::{PublicKey, SecretKey};
use x25519_dalek;

use crate::{IDENTITY_PREFIX, RECIPIENT_PREFIX};

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

    pub(crate) fn new(
        x25519pk: x25519_dalek::PublicKey,
        sntrup761pk: sntrup761::PublicKey,
    ) -> Self {
        Recipient {
            x25519pk: x25519pk,
            sntrup761pk: sntrup761pk,
        }
    }
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
    pub(crate) fn get_x25519pk(self: &Self) -> &x25519_dalek::PublicKey {
        &self.x25519pk
    }
    pub(crate) fn get_sntrup761pk(self: &Self) -> &sntrup761::PublicKey {
        &self.sntrup761pk
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
                .to_ascii_uppercase()
                .as_str(),
        )
    }
}

impl Identity {
    pub(crate) fn new(
        x25519sk: x25519_dalek::StaticSecret,
        sntrup761sk: sntrup761::SecretKey,
    ) -> Self {
        Identity {
            x25519sk: x25519sk,
            sntrup761sk: sntrup761sk,
        }
    }
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

    pub(crate) fn get_x25519sk(self: &Self) -> &x25519_dalek::StaticSecret {
        &self.x25519sk
    }
    pub(crate) fn get_sntrup761sk(self: &Self) -> &sntrup761::SecretKey {
        &self.sntrup761sk
    }
}
