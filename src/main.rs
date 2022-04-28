use std::collections::HashMap;
use std::io;

use age_core::format::{FileKey, Stanza};
use age_core::primitives::{aead_decrypt, aead_encrypt, hkdf};
use age_core::secrecy::ExposeSecret;
// use age_plugin::identity::Error::Identity;
// use age_plugin::recipient::Error::Recipient;
use age_plugin::{
    identity::{self, IdentityPluginV1},
    // print_new_identity,
    recipient::{self, RecipientPluginV1},
    run_state_machine,
    Callbacks,
};
use pqcrypto::kem::sntrup761;
use pqcrypto_traits::kem::{Ciphertext, SharedSecret};
use rand_core::OsRng;
use structopt::StructOpt;
use x25519_dalek::EphemeralSecret;

use crate::sntrup761::decapsulate;
use crate::sntrup761::encapsulate;

mod sntrup761x25519;

const PLUGIN_NAME: &str = "sntrup761x25519";
// const BINARY_NAME: &str = "age-plugin-sntrup761x25519";
const RECIPIENT_PREFIX: &str = "age1sntrup761x25519";
const IDENTITY_PREFIX: &str = "age-plugin-sntrup761x25519-";
const STANZA_TAG: &str = "sntrup761x25519";

#[derive(Default)]
pub(crate) struct RecipientPlugin {
    recipients: Vec<sntrup761x25519::Recipient>,
    identities: Vec<sntrup761x25519::Identity>,
}

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipient(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        // eprintln!("age-plugin-unencrypted: RecipientPluginV1::add_recipient called");
        if plugin_name == PLUGIN_NAME {
            // parse and store (if success) recipient
            match sntrup761x25519::Recipient::from_bytes(bytes) {
                Some(r) => {
                    self.recipients.push(r);
                    Ok(())
                }
                None => Err(recipient::Error::Recipient {
                    index,
                    message: "Invalid recipient".to_owned(),
                }),
            }
        } else {
            Err(recipient::Error::Recipient {
                index,
                message: "invalid recipient".to_owned(),
            })
        }
    }

    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        // eprintln!("age-plugin-unencrypted: RecipientPluginV1::add_identity called");
        if plugin_name == PLUGIN_NAME {
            match sntrup761x25519::Identity::from_bytes(bytes) {
                Some(i) => {
                    self.identities.push(i);
                    Ok(())
                }
                None => Err(recipient::Error::Identity {
                    index,
                    message: "Invalid identity".to_owned(),
                }),
            }
        } else {
            Err(recipient::Error::Identity {
                index,
                message: "Invalid identity".to_owned(),
            })
        }
    }

    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        _callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        // callbacks.message(&format!("age-plugin-unencrypted: RecipientPluginV1::wrap_file_keys called with {} file_keys", file_keys.len()))?;
        let mut ret: Vec<Vec<Stanza>> = vec![];
        for fk in &file_keys {
            let mut stanzas: Vec<Stanza> = vec![];
            for r in &self.recipients {
                // create an epheremal X25519 secret and public key
                let x25519_esk = EphemeralSecret::new(OsRng);
                let x25519_epk = x25519_dalek::PublicKey::from(&x25519_esk);
                let x25519_ss = x25519_esk.diffie_hellman(&r.get_x25519pk());

                // pass X25519 shared secret to HKDF to derive encryption key
                let mut x25519_salt = vec![];
                x25519_salt.extend_from_slice(x25519_epk.as_bytes());
                x25519_salt.extend_from_slice(r.get_x25519pk().as_bytes());
                let x25519_enc_key = hkdf(
                    &x25519_salt,
                    b"x25519sntrup761-x25519",
                    x25519_ss.as_bytes(),
                );

                // get shared secret and ciphertext of sntrup761
                let (sntrup761_ss, sntrup761_ciphertext) = encapsulate(&r.get_sntrup761pk());

                // pass sntrup761 shared secret to HKDF to derive encryption key
                let sntrup761_enc_key = hkdf(
                    b"x25519sntrup761-sntrup761",
                    b"x25519sntrup761-sntrup761",
                    sntrup761_ss.as_bytes(),
                );

                // now combine both enc_keys to one final key
                // TODO: would it be better to not pass x25519_enc_key as salt?
                let enc_key_combined =
                    hkdf(&x25519_enc_key, b"x25519sntrup761", &sntrup761_enc_key);

                // encrypt final key
                let encrypted_file_key = aead_encrypt(&enc_key_combined, fk.expose_secret());

                // finally, create stanza
                let sntrup761_arg = base64::encode(sntrup761_ciphertext.as_bytes());
                let x25519_arg = base64::encode(x25519_epk.as_bytes());
                stanzas.push(Stanza {
                    tag: STANZA_TAG.to_string(),
                    args: vec![x25519_arg, sntrup761_arg],
                    body: encrypted_file_key,
                })
            }
            ret.push(stanzas);
        }
        Ok(Ok(ret))
    }
}

#[derive(Debug, Default, Clone)]
struct IdentityPlugin {
    identities: Vec<sntrup761x25519::Identity>,
}

impl IdentityPlugin {
    fn try_decrypt(
        self: &Self,
        x25519_epk: &Vec<u8>,
        sntrup761_ciphertext: &Vec<u8>,
        stanza_body: &Vec<u8>,
    ) -> Option<FileKey> {
        // first, try to convert to the correct rust types
        if let (Ok(x25519_epk), Ok(sntrup761_ciphertext), Ok(encrypted_file_key)) = (
            <[u8; 32]>::try_from(x25519_epk.as_slice()),
            sntrup761::Ciphertext::from_bytes(sntrup761_ciphertext.as_slice()),
            <[u8; 32]>::try_from(stanza_body.as_slice()),
        ) {
            let x25519_epk = x25519_dalek::PublicKey::from(x25519_epk);
            // now we try to decrypt it with any identity we have
            for i in &self.identities {
                let x25519_ss = i.get_x25519sk().diffie_hellman(&x25519_epk);
                let x25519_pk = x25519_dalek::PublicKey::from(i.get_x25519sk());

                // pass X25519 shared secret to HKDF to derive encryption key
                let mut x25519_salt = vec![];
                x25519_salt.extend_from_slice(x25519_epk.as_bytes());
                x25519_salt.extend_from_slice(x25519_pk.as_bytes());
                let x25519_enc_key = hkdf(
                    &x25519_salt,
                    b"x25519sntrup761-x25519",
                    x25519_ss.as_bytes(),
                );

                // get shared secret and ciphertext of sntrup761
                let sntrup761_ss = decapsulate(&sntrup761_ciphertext, &i.get_sntrup761sk());

                // pass sntrup761 shared secret to HKDF to derive encryption key
                let sntrup761_enc_key = hkdf(
                    b"x25519sntrup761-sntrup761",
                    b"x25519sntrup761-sntrup761",
                    sntrup761_ss.as_bytes(),
                );

                // now combine both enc_keys to one final key
                // TODO: would it be better to not pass x25519_enc_key as salt?
                let enc_key_combined =
                    hkdf(&x25519_enc_key, b"x25519sntrup761", &sntrup761_enc_key);

                // encrypt final key
                let decrypted_file_key = aead_decrypt(&enc_key_combined, 16, &encrypted_file_key);
                if let Ok(dfk) = decrypted_file_key {
                    return Some(FileKey::from(
                        <[u8; 16]>::try_from(dfk).expect("This cannot happen"),
                    ));
                }
            }
        };
        None
    }
}

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        // eprintln!("age-plugin-unencrypted: IdentityPluginV1::add_identity called");
        if plugin_name == PLUGIN_NAME {
            match sntrup761x25519::Identity::from_bytes(bytes) {
                Some(i) => {
                    self.identities.push(i);
                    Ok(())
                }
                None => Err(identity::Error::Identity {
                    index,
                    message: "Invalid identity".to_owned(),
                }),
            }
        } else {
            Err(identity::Error::Identity {
                index,
                message: "Invalid identity".to_owned(),
            })
        }
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        _callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        // callbacks.message("age-plugin-unencrypted: IdentityPluginV1::unwrap_file_keys called")?;
        let mut file_keys = HashMap::with_capacity(files.len());

        for file_index in 0..files.len() {
            let mut current_file_key: Option<FileKey> = None;
            let mut current_errors: Vec<identity::Error> = vec![];

            for stanza_index in 0..files[file_index].len() {
                let current_stanza = &files[file_index][stanza_index];
                if current_stanza.tag == STANZA_TAG {
                    if let [x25519_arg, sntrup761_arg] = &current_stanza.args[..] {
                        if let (Ok(x25519_epk), Ok(sntrup761_ciphertext)) =
                            (base64::decode(x25519_arg), base64::decode(sntrup761_arg))
                        {
                            // stanza parsing is now done, now we start decrypting
                            if let Some(fk) = self.try_decrypt(
                                &x25519_epk,
                                &sntrup761_ciphertext,
                                &current_stanza.body,
                            ) {
                                current_file_key = Some(fk);
                                break;
                            } else {
                                current_errors.push(identity::Error::Stanza {
                                    file_index: file_index,
                                    stanza_index: stanza_index,
                                    message: "Stanza decryption failed".to_string(),
                                });
                            }
                        } else {
                            current_errors.push(identity::Error::Stanza {
                                file_index: file_index,
                                stanza_index: stanza_index,
                                message: "Stanza argument is not valid base64".to_string(),
                            });
                        }
                    } else {
                        current_errors.push(identity::Error::Stanza {
                            file_index: file_index,
                            stanza_index: stanza_index,
                            message: "Stanza has not exactly two arguments".to_string(),
                        });
                    }
                } else {
                    // ignore this stanza, it is encrypted with an unsupported format
                    // this is not considered an error!
                }
            }

            match current_file_key {
                Some(fk) => file_keys.insert(file_index, Ok(fk)),
                None => file_keys.insert(file_index, Err(current_errors)),
            };
        }
        Ok(file_keys)
    }
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "age-plugin-sntrup761x25519",
    about = "age plugin for post-quantum safe algorithm sntrup761x25519 support",
    author = "Klaus Eisentraut",
    version = "0.1"
)]
struct PluginOptions {
    /// this will be used by main age binary, no need to call this manually
    #[structopt(long)]
    age_plugin: Option<String>,
}

fn main() -> io::Result<()> {
    let opts = PluginOptions::from_args();

    if let Some(state_machine) = opts.age_plugin {
        // The plugin was started by an age client; run the state machine.
        run_state_machine(
            &state_machine,
            RecipientPlugin::default,
            IdentityPlugin::default,
        )?;
        return Ok(());
    }

    // Here you can assume the binary is being run directly by a user,
    // and perform administrative tasks like generating keys.
    let (sntrup761pk, sntrup761sk) = pqcrypto::kem::sntrup761::keypair();
    let x25519sk = x25519_dalek::StaticSecret::new(OsRng);
    let x25519pk = x25519_dalek::PublicKey::from(&x25519sk);
    println!(
        "# created: {}",
        chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    println!(
        "# public key: {}",
        sntrup761x25519::Recipient::new(x25519pk, sntrup761pk)
    );
    println!("{}", sntrup761x25519::Identity::new(x25519sk, sntrup761sk));
    Ok(())
}
