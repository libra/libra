// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

// The config holds the options that define the testing environment.
// A config entry starts with "//!", differentiating it from a directive.

use crate::{config::strip, errors::*, genesis_accounts::make_genesis_accounts};
use language_e2e_tests::account::{Account, AccountData};
use libra_config::trusted_peers::ConfigHelpers;
use libra_crypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use libra_crypto::{HashValue, SigningKey};
use libra_types::account_address::AccountAddress;
use libra_types::validator_set::ValidatorSet;
use std::{
    collections::{btree_map, BTreeMap},
    str::FromStr,
};

// unit: microlibra
const DEFAULT_BALANCE: u64 = 1_000_000;

#[derive(Debug)]
pub enum Role {
    /// Means that the account is a current validator; its address is in the on-chain validator set
    Validator,
}

/// Struct that specifies the initial setup of an account.
#[derive(Debug)]
pub struct AccountDefinition {
    /// Name of the account. The name is case insensitive.
    pub name: String,
    /// The initial balance of the account.
    pub balance: Option<u64>,
    /// The initial sequence number of the account.
    pub sequence_number: Option<u64>,
    /// Special role this account has in the system (if any)
    pub role: Option<Role>,
}

impl FromStr for Role {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "validator" => Ok(Role::Validator),
            other => Err(ErrorKind::Other(format!("Invalid account role {:?}", other)).into()),
        }
    }
}

#[derive(Debug)]
pub struct ChannelDefinition {
    pub name: String,
    /// Channel participant.
    pub participants: Vec<String>,
    pub channel_sequence_number: Option<u64>,
}

/// A raw entry extracted from the input. Used to build the global config table.
#[derive(Debug)]
pub enum Entry {
    /// Defines an account that can be used in tests.
    AccountDefinition(AccountDefinition),
    ChannelDefinition(ChannelDefinition),
}

impl Entry {
    pub fn is_validator(&self) -> bool {
        match self {
            Entry::AccountDefinition(AccountDefinition {
                role: Some(Role::Validator),
                ..
            }) => true,
            _ => false,
        }
    }
}

impl FromStr for Entry {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.split_whitespace().collect::<String>();
        let s = strip(&s, "//!")
            .ok_or_else(|| ErrorKind::Other("txn config entry must start with //!".to_string()))?
            .trim_start();

        if let Some(s) = strip(s, "account:") {
            let v: Vec<_> = s
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|s| !s.is_empty())
                .collect();
            if v.is_empty() || v.len() > 4 {
                return Err(ErrorKind::Other(
                    "config 'account' takes 1 to 4 parameters".to_string(),
                )
                .into());
            }
            let balance = v.get(1).and_then(|s| s.parse::<u64>().ok());
            let sequence_number = v.get(2).and_then(|s| s.parse::<u64>().ok());
            let role = v.get(3).and_then(|s| s.parse::<Role>().ok());
            return Ok(Entry::AccountDefinition(AccountDefinition {
                name: v[0].to_string(),
                balance,
                sequence_number,
                role,
            }));
        }
        if let Some(s) = strip(s, "channel:") {
            let v: Vec<_> = s
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|s| !s.is_empty())
                .collect();
            if v.len() < 2 || v.len() > 4 {
                return Err(ErrorKind::Other(
                    "config 'channel' takes 2 to 4 parameters".to_string(),
                )
                .into());
            }
            let participants_args: &str = v
                .get(1)
                .expect("channel config must contains participants.");
            let participants = participants_args
                .split('|')
                .map(|s| s.to_string())
                .collect();

            let channel_sequence_number = v.get(2).and_then(|s| s.parse::<u64>().ok());
            return Ok(Entry::ChannelDefinition(ChannelDefinition {
                name: v[0].to_string(),
                participants,
                channel_sequence_number,
            }));
        }
        Err(ErrorKind::Other(format!("failed to parse '{}' as global config entry", s)).into())
    }
}

#[derive(Debug)]
pub struct ChannelParticipant<'a> {
    pub address: AccountAddress,
    pub account: &'a Account,
}

#[derive(Debug)]
pub struct ChannelConfig {
    pub channel_address: AccountAddress,
    pub participants: Vec<AccountAddress>,
}

#[derive(Debug)]
pub struct ChannelData<'a> {
    pub channel_address: AccountAddress,
    pub participants: Vec<ChannelParticipant<'a>>,
}

impl<'a> ChannelData<'a> {
    pub fn get_participant_public_keys(&self) -> Vec<Ed25519PublicKey> {
        self.participants
            .iter()
            .map(|participant| participant.account.pubkey.clone())
            .collect()
    }

    pub fn sign_by_participants(&self, msg: &HashValue) -> Vec<Ed25519Signature> {
        self.sign(msg, |_| true)
            .iter()
            .map(|s| s.as_ref().cloned().unwrap())
            .collect()
    }

    pub fn sign<F>(&self, msg: &HashValue, mut filter: F) -> Vec<Option<Ed25519Signature>>
    where
        F: FnMut(&ChannelParticipant) -> bool,
    {
        self.participants
            .iter()
            .map(|participant| {
                if filter(participant) {
                    Some(participant.account.privkey.sign_message(msg))
                } else {
                    None
                }
            })
            .collect()
    }
}

/// A table of options either shared by all transactions or used to define the testing environment.
#[derive(Debug)]
pub struct Config {
    /// A map from account names to account data
    pub accounts: BTreeMap<String, AccountData>,
    pub genesis_accounts: BTreeMap<String, Account>,
    /// The validator set after genesis
    pub validator_set: ValidatorSet,
    pub channels: BTreeMap<String, ChannelConfig>,
}

impl Config {
    pub fn build(entries: &[Entry]) -> Result<Self> {
        let mut accounts = BTreeMap::new();
        let mut validator_accounts = entries.iter().filter(|entry| entry.is_validator()).count();

        // generate a validator set with |validator_accounts| validators
        let (validator_keys, consensus_config, network_config) =
            ConfigHelpers::gen_validator_nodes(validator_accounts, None);
        let validator_set = consensus_config.get_validator_set(&network_config);

        let mut channels = BTreeMap::new();
        // initialize the keys of validator entries with the validator set
        // enhance type of config to contain a validator set, use it to initialize genesis
        for entry in entries {
            match entry {
                Entry::AccountDefinition(def) => {
                    let account_data = if entry.is_validator() {
                        validator_accounts -= 1;
                        let validator_public_keys =
                            validator_set.payload()[validator_accounts].clone();
                        let validator_pubkey = validator_public_keys.consensus_public_key();
                        let (validator_privkey, _) =
                            &validator_keys[validator_public_keys.account_address()];
                        AccountData::with_keypair(
                            validator_privkey.consensus_private_key.clone(),
                            validator_pubkey.clone(),
                            def.balance.unwrap_or(DEFAULT_BALANCE),
                            def.sequence_number.unwrap_or(0),
                        )
                    } else {
                        AccountData::new(
                            def.balance.unwrap_or(DEFAULT_BALANCE),
                            def.sequence_number.unwrap_or(0),
                        )
                    };
                    let name = def.name.to_ascii_lowercase();
                    let entry = accounts.entry(name);
                    match entry {
                        btree_map::Entry::Vacant(entry) => {
                            entry.insert(account_data);
                        }
                        btree_map::Entry::Occupied(_) => {
                            return Err(ErrorKind::Other(format!(
                                "already has account '{}'",
                                def.name,
                            ))
                            .into());
                        }
                    }
                }
                Entry::ChannelDefinition(def) => {
                    let mut participants: Vec<AccountAddress> = def
                        .participants
                        .iter()
                        .map(|name| {
                            accounts
                                .get(name)
                                .and_then(|account| Some(*account.address()))
                                //TODO use error to replace expect
                                .expect(
                                    format!("Can not find account by name: {:?}", name).as_str(),
                                )
                        })
                        .collect();
                    participants.sort();
                    let channel_address = AccountAddress::channel_address(participants.as_slice());
                    let channel_data = ChannelConfig {
                        channel_address,
                        participants,
                    };
                    let name = def.name.to_ascii_lowercase();
                    let entry = channels.entry(name);
                    match entry {
                        btree_map::Entry::Vacant(entry) => {
                            entry.insert(channel_data);
                        }
                        btree_map::Entry::Occupied(_) => {
                            return Err(ErrorKind::Other(format!(
                                "already has channel '{}'",
                                def.name,
                            ))
                            .into());
                        }
                    }
                }
            }
        }

        if let btree_map::Entry::Vacant(entry) = accounts.entry("default".to_string()) {
            entry.insert(AccountData::new(
                DEFAULT_BALANCE,
                /* sequence_number */ 0,
            ));
        }
        Ok(Config {
            accounts,
            genesis_accounts: make_genesis_accounts(),
            validator_set,
            channels,
        })
    }

    pub fn get_account_for_name(&self, name: &str) -> Result<&Account> {
        self.accounts
            .get(name)
            .map(|account_data| account_data.account())
            .or_else(|| self.genesis_accounts.get(name))
            .ok_or_else(|| ErrorKind::Other(format!("account '{}' does not exist", name)).into())
    }

    pub fn get_account_for_address(&self, addr: &AccountAddress) -> Result<&Account> {
        self.accounts
            .iter()
            .find(|(_, a)| a.address() == addr)
            .map(|(_, a)| a.account())
            .ok_or_else(|| ErrorKind::Other(format!("account '{}' does not exist", addr)).into())
    }

    pub fn get_channel_for_name(&self, name: &str) -> Result<&ChannelConfig> {
        self.channels
            .get(name)
            .ok_or_else(|| ErrorKind::Other(format!("channel '{}' does not exist", name)).into())
    }
}
