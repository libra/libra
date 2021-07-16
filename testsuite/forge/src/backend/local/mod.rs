// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{Factory, Result, Swarm, Version};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

mod cargo;
mod node;
mod swarm;
pub use node::LocalNode;
pub use swarm::{LocalSwarm, LocalSwarmBuilder, SwarmDirectory};

#[derive(Clone, Debug)]
pub struct LocalVersion {
    revision: String,
    bin: PathBuf,
    version: Version,
}

impl LocalVersion {
    fn bin(&self) -> &Path {
        &self.bin
    }

    fn version(&self) -> Version {
        self.version.clone()
    }
}

pub struct LocalFactory {
    versions: Arc<HashMap<Version, LocalVersion>>,
}

impl LocalFactory {
    pub fn new(versions: HashMap<Version, LocalVersion>) -> Self {
        Self {
            versions: Arc::new(versions),
        }
    }

    pub fn from_workspace() -> Result<Self> {
        let mut versions = HashMap::new();
        let new_version =
            cargo::get_diem_node_binary_from_worktree().map(|(revision, bin)| LocalVersion {
                revision,
                bin,
                version: Version::new(usize::max_value()),
            })?;

        versions.insert(new_version.version.clone(), new_version);
        Ok(Self::new(versions))
    }

    pub fn from_revision(revision: &str) -> Result<Self> {
        let mut versions = HashMap::new();
        let new_version =
            cargo::get_diem_node_binary_at_revision(revision).map(|(revision, bin)| {
                LocalVersion {
                    revision,
                    bin,
                    version: Version::new(usize::max_value()),
                }
            })?;

        versions.insert(new_version.version.clone(), new_version);
        Ok(Self::new(versions))
    }
}

impl Factory for LocalFactory {
    fn launch_swarm(&self, node_num: usize) -> Box<dyn Swarm> {
        let mut swarm = LocalSwarm::builder(self.versions.clone())
            .number_of_validators(node_num)
            .build()
            .unwrap();
        swarm.launch().unwrap();

        Box::new(swarm)
    }
}
