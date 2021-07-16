// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{Factory, Result, Swarm, Version};
use anyhow::{bail, Context};
use std::{
    collections::HashMap,
    env,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

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
        let new_version = head_version().map(|(revision, bin)| LocalVersion {
            revision,
            bin,
            version: Version::new(usize::max_value()),
        })?;

        versions.insert(new_version.version.clone(), new_version);
        Ok(Self::new(versions))
    }
}

fn head_version() -> Result<(String, PathBuf)> {
    let output = Command::new("git")
        .args(&["rev-parse", "HEAD"])
        .output()
        .context("Failed to get git revision")?;
    let mut revision = String::from_utf8(output.stdout)?;

    // Determine if the worktree is dirty
    if !Command::new("git")
        .args(&["diff-index", "--name-only", "HEAD", "--"])
        .output()
        .context("Failed to determine if the worktree is dirty")?
        .stdout
        .is_empty()
    {
        revision.push_str("-dirty");
    }

    let bin = get_diem_node()?;

    Ok((revision, bin))
}

fn get_diem_node() -> Result<PathBuf> {
    let output = Command::new("cargo")
        .current_dir(workspace_root()?)
        .args(&["build", "--bin=diem-node"])
        .output()
        .context("Failed to build diem-node")?;

    if output.status.success() {
        let bin_path = build_dir()?.join(format!("{}{}", "diem-node", env::consts::EXE_SUFFIX));
        if !bin_path.exists() {
            bail!(
                "Can't find binary diem-node in expected path {:?}",
                bin_path
            );
        }

        Ok(bin_path)
    } else {
        bail!("Faild to build diem-node");
    }
}

// Path to top level workspace
fn workspace_root() -> Result<PathBuf> {
    let mut path = build_dir()?;
    while !path.ends_with("target") {
        path.pop();
    }
    path.pop();
    Ok(path)
}

// Path to the directory where build artifacts live.
fn build_dir() -> Result<PathBuf> {
    env::current_exe()
        .ok()
        .map(|mut path| {
            path.pop();
            if path.ends_with("deps") {
                path.pop();
            }
            path
        })
        .context("Can't find the build directory. Cannot continue running tests")
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
