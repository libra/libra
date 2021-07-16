// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::Result;
use anyhow::{bail, Context};
use serde::Deserialize;
use std::{
    env,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::NamedTempFile;

#[derive(Deserialize)]
pub struct Metadata {
    pub target_directory: PathBuf,
    pub workspace_root: PathBuf,
}

pub fn metadata() -> Result<Metadata> {
    let output = Command::new("cargo")
        .arg("metadata")
        .arg("--no-deps")
        .arg("--format-version=1")
        .output()
        .context("Failed to query cargo metadata")?;

    serde_json::from_slice(&output.stdout).map_err(Into::into)
}

/// Get the diem node binary from the current working directory
pub fn get_diem_node_binary_from_worktree() -> Result<(String, PathBuf)> {
    let metadata = metadata()?;
    let mut revision = git_rev_parse(&metadata, "HEAD")?;
    if git_is_worktree_dirty()? {
        revision.push_str("-dirty");
    }

    let bin_path = cargo_build_diem_node(&metadata.workspace_root, &metadata.target_directory)?;

    Ok((revision, bin_path))
}

/// This function will attempt to build the diem-node binary at an arbitrary revision.
/// Using the `target/forge` as a working directory it will do the following:
///     1. Look for a binary named `diem-node--<revision>`, if it already exists return it
///     2. If the binary doesn't exist check out the revision to `target/forge/revision` by doing
///        `git archive --format=tar <revision> | tar x`
///     3. Using the `target/forge/target` directory as a cargo artifact directory, build the
///        binary and then move it to `target/forge/diem-node--<revision>`
pub fn get_diem_node_binary_at_revision(revision: &str) -> Result<(String, PathBuf)> {
    let metadata = metadata()?;
    let forge_directory = metadata.target_directory.join("forge");
    let revision = git_rev_parse(&metadata, format!("{}^{{commit}}", revision))?;
    let checkout_dir = forge_directory.join(&revision);
    let forge_target_directory = forge_directory.join("target");
    let diem_node_bin = forge_directory.join(format!(
        "diem-node--{}{}",
        revision,
        env::consts::EXE_SUFFIX
    ));

    if diem_node_bin.exists() {
        return Ok((revision, diem_node_bin));
    }

    fs::create_dir_all(&forge_target_directory)?;

    checkout_revision(&metadata, &revision, &checkout_dir)?;

    fs::rename(
        cargo_build_diem_node(&checkout_dir, &forge_target_directory)?,
        &diem_node_bin,
    )?;

    let _ = fs::remove_dir_all(&checkout_dir);

    Ok((revision, diem_node_bin))
}

fn git_rev_parse<R: AsRef<OsStr>>(metadata: &Metadata, rev: R) -> Result<String> {
    let output = Command::new("git")
        .current_dir(&metadata.workspace_root)
        .arg("rev-parse")
        .arg(rev)
        .output()
        .context("Failed to parse revision")?;
    if output.status.success() {
        String::from_utf8(output.stdout)
            .map(|s| s.trim().to_owned())
            .map_err(Into::into)
    } else {
        bail!("Failed to parse revision");
    }
}

// Determine if the worktree is dirty
fn git_is_worktree_dirty() -> Result<bool> {
    Command::new("git")
        .args(&["diff-index", "--name-only", "HEAD", "--"])
        .output()
        .context("Failed to determine if the worktree is dirty")
        .map(|output| !output.stdout.is_empty())
}

fn cargo_build_diem_node<D, T>(directory: D, target_directory: T) -> Result<PathBuf>
where
    D: AsRef<Path>,
    T: AsRef<Path>,
{
    let target_directory = target_directory.as_ref();
    let output = Command::new("cargo")
        .current_dir(directory)
        .env("CARGO_TARGET_DIR", target_directory)
        .args(&["build", "--bin=diem-node"])
        .output()
        .context("Failed to build diem-node")?;

    if output.status.success() {
        let bin_path =
            target_directory.join(format!("debug/{}{}", "diem-node", env::consts::EXE_SUFFIX));
        if !bin_path.exists() {
            bail!(
                "Can't find binary diem-node at expected path {:?}",
                bin_path
            );
        }

        Ok(bin_path)
    } else {
        bail!("Faild to build diem-node");
    }
}

fn checkout_revision(metadata: &Metadata, revision: &str, to: &Path) -> Result<()> {
    fs::create_dir_all(to)?;

    let archive_file = NamedTempFile::new()?.into_temp_path();

    let output = Command::new("git")
        .current_dir(&metadata.workspace_root)
        .arg("archive")
        .arg("--format=tar")
        .arg("--output")
        .arg(&archive_file)
        .arg(&revision)
        .output()
        .context("Failed to run git archive")?;
    if !output.status.success() {
        bail!("Failed to run git archive");
    }

    let output = Command::new("tar")
        .current_dir(to)
        .arg("xf")
        .arg(&archive_file)
        .output()
        .context("Failed to run tar")?;

    if !output.status.success() {
        bail!("Failed to run tar");
    }

    Ok(())
}
