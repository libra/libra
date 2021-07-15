// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result};
use diem_types::{transaction::Version, trusted_state::TrustedState, waypoint::Waypoint};
use std::{collections::HashMap, fmt::Debug};

mod private {
    pub trait Sealed {}

    impl Sealed for super::InMemoryStorage {}
}

// TODO(philiphayes): unseal `Storage` trait once verifying client stabilizes.
pub trait Storage: private::Sealed + Debug {
    fn get(&self, key: &str) -> Result<Vec<u8>>;
    fn set(&mut self, key: &str, value: Vec<u8>) -> Result<()>;
}

#[derive(Debug, Default)]
pub struct InMemoryStorage {
    data: HashMap<String, Vec<u8>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }
}

impl Storage for InMemoryStorage {
    fn get(&self, key: &str) -> Result<Vec<u8>> {
        self.data
            .get(key)
            .map(Clone::clone)
            .ok_or_else(|| Error::unknown("key not set"))
    }

    fn set(&mut self, key: &str, value: Vec<u8>) -> Result<()> {
        self.data.insert(key.to_owned(), value);
        Ok(())
    }
}

pub const TRUSTED_STATE_KEY: &str = "trusted_state";

#[derive(Debug)]
pub(crate) struct TrustedStateStore<S> {
    trusted_state: TrustedState,
    storage: S,
}

impl<S: Storage> TrustedStateStore<S> {
    pub(crate) fn new(storage: S) -> Result<Self> {
        let trusted_state = storage
            .get(TRUSTED_STATE_KEY)
            .and_then(|bytes| bcs::from_bytes(&bytes).map_err(Error::decode))?;

        Ok(Self {
            trusted_state,
            storage,
        })
    }

    pub(crate) fn new_with_state(trusted_state: TrustedState, storage: S) -> Self {
        let maybe_stored_state: Result<TrustedState> = storage
            .get(TRUSTED_STATE_KEY)
            .and_then(|bytes| bcs::from_bytes(&bytes).map_err(Error::decode));

        let trusted_state = if let Ok(stored_state) = maybe_stored_state {
            if trusted_state.version() > stored_state.version() {
                trusted_state
            } else {
                stored_state
            }
        } else {
            trusted_state
        };

        Self {
            trusted_state,
            storage,
        }
    }

    pub(crate) fn version(&self) -> Version {
        self.trusted_state.version()
    }

    pub(crate) fn waypoint(&self) -> Waypoint {
        self.trusted_state.waypoint()
    }

    pub(crate) fn trusted_state(&self) -> &TrustedState {
        &self.trusted_state
    }

    pub(crate) fn ratchet(&mut self, new_state: TrustedState) -> Result<()> {
        // We only need to store the potential new trusted state if it's actually
        // ahead of what we have stored locally.
        if new_state.version() > self.version() {
            self.trusted_state = new_state;
            let trusted_state_bytes = bcs::to_bytes(&self.trusted_state).map_err(Error::decode)?;
            self.storage.set(TRUSTED_STATE_KEY, trusted_state_bytes)?;
        }
        Ok(())
    }
}
