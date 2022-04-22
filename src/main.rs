use age_core::format::{FileKey, Stanza};
use age_plugin::{
    identity::{self, IdentityPluginV1},
    print_new_identity,
    recipient::{self, RecipientPluginV1},
    run_state_machine, Callbacks,
};
use std::collections::HashMap;
use std::io;
use age_plugin::recipient::Error::Recipient;
use structopt::StructOpt;

use pqcrypto::kem::sntrup761;

mod sntrup761x25519;
use crate::sntrup761x25519::Recipient as sntrup761x25519Recipient;

const PLUGIN_NAME: &str = "sntrup761x25519";
const BINARY_NAME: &str = "age-plugin-sntrup761x25519";
const RECIPIENT_PREFIX: &str = "age1sntrup761x25519";
const IDENTITY_PREFIX: &str = "age-plugin-sntrup761x25519-";
const STANZA_TAG: &str = "sntrup761x25519";

#[derive(Default, Debug)]
pub(crate) struct RecipientPlugin {
    recipients: Vec<sntrup761x25519::Recipient>,
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
            // A real plugin would store the recipient here.
            Ok(())
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
        todo!()
    }

    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        mut callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        todo!()
    }
}

#[derive(Debug, Default)]
struct IdentityPlugin;

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        todo!()
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        mut callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
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
    let (mut pk, mut sk) = pqcrypto::kem::sntrup761::keypair();
    let (ss1, ct) = pqcrypto::kem::sntrup761::encapsulate(&pk);
    let ss2 = pqcrypto::kem::sntrup761::decapsulate(&ct, &sk);
    assert!(ss1 == ss2);
    println!("Public Key {:?}", pk.as_bytes());
    println!("Secret Key {:?}", sk.as_bytes());
    println!("");
    println!("");
    println!("");
    println!("{:?}", sntrup761x25519Recipient::gen_test());
    println!("{:}", sntrup761x25519Recipient::gen_test());
    Ok(())
}
