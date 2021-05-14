// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{data_cache::MoveStorage, runtime::VMRuntime, session::Session};
use move_core_types::{account_address::AccountAddress, identifier::Identifier};
use move_vm_types::natives::function::NativeFunction;

pub struct MoveVM<N> {
    runtime: VMRuntime<N>,
}

impl<N: NativeFunction> MoveVM<N> {
    pub fn new<I>(natives: I) -> Self
    where
        I: IntoIterator<Item = (AccountAddress, Identifier, Identifier, N)>,
    {
        Self {
            runtime: VMRuntime::new(natives),
        }
    }

    /// Create a new Session backed by the given storage.
    ///
    /// Right now it is the caller's responsibility to ensure cache coherence of the Move VM Loader
    ///   - When a module gets published in a Move VM Session, and then gets used by another
    ///     transaction, it will be loaded into the code cache and stay there even if the resulted
    ///     effects do not get commited back to the storage when the Session ends.
    ///   - As a result, if one wants to have multiple sessions at a time, one needs to make sure
    ///     none of them will try to publish a module. In other words, if there is a module publishing
    ///     Session it must be the only Session existing.
    ///   - In general, a new Move VM needs to be created whenever the storage gets modified by an
    ///     outer envrionment, or otherwise the states may be out of sync. There are a few exceptional
    ///     cases where this may not be necessary, with the most notable one being the common module
    ///     publishing flow: you can keep using the same Move VM if you publish some modules in a Session
    ///     and apply the effects to the storage when the Session ends.
    pub fn new_session<'r, S: MoveStorage>(&self, remote: &'r S) -> Session<'r, '_, S, N> {
        self.runtime.new_session(remote)
    }
}
