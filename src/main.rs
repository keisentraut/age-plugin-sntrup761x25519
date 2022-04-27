use age_core::format::{FileKey, Stanza};
use age_plugin::recipient::Error::Recipient;
use age_plugin::{
    identity::{self, IdentityPluginV1},
    print_new_identity,
    recipient::{self, RecipientPluginV1},
    run_state_machine, Callbacks,
};
use rand_core::OsRng;
use std::collections::HashMap;
use std::io;
use structopt::StructOpt;
use x25519_dalek::{EphemeralSecret, StaticSecret};

use pqcrypto::kem::sntrup761;

mod sntrup761x25519;
use crate::sntrup761x25519::Recipient as sntrup761x25519Recipient;

const PLUGIN_NAME: &str = "sntrup761x25519";
const BINARY_NAME: &str = "age-plugin-sntrup761x25519";
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
        eprintln!("age-plugin-unencrypted: RecipientPluginV1::add_recipient called");
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
        eprintln!("age-plugin-unencrypted: RecipientPluginV1::add_identity called");
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
        mut callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        eprintln!("age-plugin-unencrypted: RecipientPluginV1::wrap_file_keys called");

        // for fk in file_keys {
        //     for i in self.identities {
        //         let esk = EphemeralSecret::new(OsRng);
        //     }
        // }
        todo!();
    }
}

#[derive(Debug, Default, Clone)]
struct IdentityPlugin {
    identities: Vec<sntrup761x25519::Identity>,
}

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        eprintln!("age-plugin-unencrypted: IdentityPluginV1::add_identity called");
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
        mut callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        eprintln!("age-plugin-unencrypted: IdentityPluginV1::unwrap_file_keys called");
        todo!()
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
use pqcrypto_traits::kem::PublicKey;
use pqcrypto_traits::kem::SecretKey;

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
    // let (mut pk, mut sk) = pqcrypto::kem::sntrup761::keypair();
    // let (ss1, ct) = pqcrypto::kem::sntrup761::encapsulate(&pk);
    // let ss2 = pqcrypto::kem::sntrup761::decapsulate(&ct, &sk);
    // assert!(ss1 == ss2);
    // println!("Public Key {:?}", pk.as_bytes());
    // println!("Secret Key {:?}", sk.as_bytes());
    // println!("");
    // println!("");
    // println!("");
    // println!("{:?}", sntrup761x25519Recipient::gen_test());
    // println!("{:}", sntrup761x25519Recipient::gen_test());

    let (mut sntrup761pk, mut sntrup761sk) = pqcrypto::kem::sntrup761::keypair();
    let x25519sk = x25519_dalek::StaticSecret::new(OsRng);
    println!(
        "# created: {}",
        chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    todo!();
}
