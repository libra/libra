// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::source_package::parsed_manifest as PM;
use anyhow::{bail, format_err, Context, Result};
use move_core_types::{account_address::AccountAddress, identifier::Identifier};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};
use toml::Value as TV;

const EMPTY_ADDR_STR: &str = "_";

const PACKAGE_NAME: &str = "package";
const BUILD_NAME: &str = "build";
const ADDRESSES_NAME: &str = "addresses";
const DEV_ADDRESSES_NAME: &str = "dev-addresses";
const DEPENDENCY_NAME: &str = "dependencies";
const DEV_DEPENDENCY_NAME: &str = "dev-dependencies";

const KNOWN_NAMES: &[&str] = &[
    PACKAGE_NAME,
    BUILD_NAME,
    ADDRESSES_NAME,
    DEV_ADDRESSES_NAME,
    DEPENDENCY_NAME,
    DEV_DEPENDENCY_NAME,
];

const REQUIRED_FIELDS: &[&str] = &[PACKAGE_NAME];

pub fn parse_move_manifest_string(manifest_string: String) -> Result<TV> {
    toml::from_str::<TV>(&manifest_string).context("Unable to parse Move package manifest")
}

pub fn parse_source_manifest(tval: TV) -> Result<PM::SourceManifest> {
    match tval {
        TV::Table(mut table) => {
            check_for_required_field_names(&table, REQUIRED_FIELDS)
                .context("Error parsing package manifest")?;
            warn_if_unknown_field_names(&table, KNOWN_NAMES);
            let addresses = table
                .remove(ADDRESSES_NAME)
                .map(parse_addresses)
                .transpose()
                .context("Error parsing '[addresses]' section of manifest")?;
            let dev_address_assignments = table
                .remove(DEV_ADDRESSES_NAME)
                .map(parse_dev_addresses)
                .transpose()
                .context("Error parsing '[dev-addresses]' section of manifest")?;
            let package = table
                .remove(PACKAGE_NAME)
                .map(parse_package_info)
                .transpose()
                .context("Error parsing '[package]' section of manifest")?
                .unwrap();
            let build = table
                .remove(BUILD_NAME)
                .map(parse_build_info)
                .transpose()
                .context("Error parsing '[build]' section of manifest")?;
            let dependencies = table
                .remove(DEPENDENCY_NAME)
                .map(parse_dependencies)
                .transpose()
                .context("Error parsing '[dependencies]' section of manifest")?
                .unwrap_or_else(BTreeMap::new);
            let dev_dependencies = table
                .remove(DEV_DEPENDENCY_NAME)
                .map(parse_dependencies)
                .transpose()
                .context("Error parsing '[dev-dependencies]' section of manifest")?
                .unwrap_or_else(BTreeMap::new);
            Ok(PM::SourceManifest {
                package,
                addresses,
                dev_address_assignments,
                build,
                dependencies,
                dev_dependencies,
            })
        }
        x => {
            bail!(
                "Malformed package manifest {}. Expected a table at top level, but encountered a {}",
                x,
                x.type_str()
            )
        }
    }
}

pub fn parse_package_info(tval: TV) -> Result<PM::PackageInfo> {
    match tval {
        TV::Table(mut table) => {
            check_for_required_field_names(&table, &["name", "version"])?;
            warn_if_unknown_field_names(&table, &["name", "version", "authors", "license"]);
            let name = table
                .remove("name")
                .ok_or_else(|| format_err!("'name' is a required field but was not found",))?;
            let version = table
                .remove("version")
                .ok_or_else(|| format_err!("'version' is a required field but was not found",))?;
            let name = name
                .as_str()
                .ok_or_else(|| format_err!("Package name must be a string"))?;
            let name = Identifier::new(name).context("Invalid package name")?;
            let version = parse_version(version)?;
            let license = table.remove("license").map(|x| x.to_string());
            let authors = match table.remove("authors") {
                None => Vec::new(),
                Some(arr) => {
                    let unparsed_vec = arr
                        .as_array()
                        .ok_or_else(|| format_err!("Invalid author(s) list"))?;
                    unparsed_vec
                        .iter()
                        .map(|tval| {
                            tval.as_str().map(|x| x.to_string()).ok_or_else(|| {
                                format_err!(
                                    "Invalid author '{}' of type {} found. Expected a string.",
                                    tval.to_string(),
                                    tval.type_str()
                                )
                            })
                        })
                        .collect::<Result<_>>()?
                }
            };

            Ok(PM::PackageInfo {
                name,
                version,
                authors,
                license,
            })
        }
        x => bail!(
            "Malformed section in manifest {}. Expected a table, but encountered a {}",
            x,
            x.type_str()
        ),
    }
}

pub fn parse_dependencies(tval: TV) -> Result<PM::Dependencies> {
    match tval {
        TV::Table(table) => {
            let mut deps = BTreeMap::new();
            for (dep_name, dep) in table.into_iter() {
                let dep_name_ident =
                    Identifier::new(dep_name).context("Invalid dependency name")?;
                let dep = parse_dependency(dep)?;
                deps.insert(dep_name_ident, dep);
            }
            Ok(deps)
        }
        x => bail!(
            "Malformed section in manifest {}. Expected a table, but encountered a {}",
            x,
            x.type_str()
        ),
    }
}

pub fn parse_build_info(tval: TV) -> Result<PM::BuildInfo> {
    match tval {
        TV::Table(mut table) => {
            warn_if_unknown_field_names(&table, &["source_version"]);
            Ok(PM::BuildInfo {
                source_version: table
                    .remove("source_version")
                    .map(parse_version)
                    .transpose()?,
            })
        }
        x => bail!(
            "Malformed section in manifest {}. Expected a table, but encountered a {}",
            x,
            x.type_str()
        ),
    }
}

pub fn parse_addresses(tval: TV) -> Result<PM::AddressDeclarations> {
    match tval {
        TV::Table(table) => {
            let mut addresses = BTreeMap::new();
            for (addr_name, entry) in table.into_iter() {
                let ident = Identifier::new(addr_name).context("Invalid address name")?;
                match entry.as_str() {
                    Some(entry_str) => {
                        if entry_str == EMPTY_ADDR_STR {
                            if addresses.insert(ident.clone(), None).is_some() {
                                bail!("Duplicate address name '{}' found.", ident);
                            }
                        } else if addresses
                            .insert(
                                ident.clone(),
                                Some(
                                    AccountAddress::from_hex_literal(entry_str)
                                        .context("Invalid address")?,
                                ),
                            )
                            .is_some()
                        {
                            bail!("Duplicate address name '{}' found.", ident);
                        }
                    }
                    None => bail!(
                        "Invalid address name {} encountered. Expected a string but found a {}",
                        entry,
                        entry.type_str()
                    ),
                }
            }
            Ok(addresses)
        }
        x => bail!(
            "Malformed section in manifest {}. Expected a table, but encountered a {}",
            x,
            x.type_str()
        ),
    }
}

pub fn parse_dev_addresses(tval: TV) -> Result<PM::DevAddressDeclarations> {
    match tval {
        TV::Table(table) => {
            let mut addresses = BTreeMap::new();
            for (addr_name, entry) in table.into_iter() {
                let ident = Identifier::new(addr_name).context("Invalid address name")?;
                match entry.as_str() {
                    Some(entry_str) => {
                        if entry_str == EMPTY_ADDR_STR {
                            bail!("Found uninstantiated named address '{}'. All addresses in the '{}' field must be instantiated.",
                            ident, DEV_ADDRESSES_NAME);
                        } else if addresses
                            .insert(
                                ident.clone(),
                                AccountAddress::from_hex_literal(entry_str)
                                    .context("Invalid address")?,
                            )
                            .is_some()
                        {
                            bail!("Duplicate address name '{}' found.", ident);
                        }
                    }
                    None => bail!(
                        "Invalid address name {} encountered. Expected a string but found a {}",
                        entry,
                        entry.type_str()
                    ),
                }
            }
            Ok(addresses)
        }
        x => bail!(
            "Malformed section in manifest {}. Expected a table, but encountered a {}",
            x,
            x.type_str()
        ),
    }
}

fn parse_dependency(tval: TV) -> Result<PM::Dependency> {
    match tval {
        TV::Table(mut table) => {
            warn_if_unknown_field_names(&table, &["addr_subst", "version", "local", "digest"]);
            let subst = table
                .remove("addr_subst")
                .map(parse_substitution)
                .transpose()?;
            let version = table.remove("version").map(parse_version).transpose()?;
            let digest = table.remove("digest").map(parse_digest).transpose()?;
            match table.remove("local") {
                Some(local) => {
                    let local_str = local
                        .as_str()
                        .ok_or_else(|| format_err!("Local source path not a string"))?;
                    let local_path = PathBuf::from(local_str);
                    Ok(PM::Dependency {
                        subst,
                        version,
                        digest,
                        local: Some(local_path),
                    })
                }
                None => {
                    bail!("'local' path not specified for dependency.")
                }
            }
        }
        x => bail!("Malformed dependency {}", x),
    }
}

fn parse_substitution(tval: TV) -> Result<PM::Substitution> {
    match tval {
        TV::Table(table) => {
            let mut subst = BTreeMap::new();
            for (addr_name, tval) in table.into_iter() {
                let addr_ident =
                    Identifier::new(addr_name.as_str()).context("Invalid address name")?;
                match tval {
                    TV::String(addr_or_name) => {
                        if let Ok(addr) = AccountAddress::from_hex_literal(&addr_or_name) {
                            subst.insert(addr_ident, PM::SubstOrRename::Assign(addr));
                        } else {
                            let rename_from = Identifier::new(addr_or_name.as_str()).context("Invalid address name")?;
                            subst.insert(addr_ident, PM::SubstOrRename::RenameFrom(rename_from));
                        }
                    }
                    x => bail!(
                        "Malformed dependency substitution {}. Expected a string, but encountered a {}",
                        x,
                        x.type_str()
                    ),
                }
            }
            Ok(subst)
        }
        x => bail!(
            "Malformed dependency substitution {}. Expected a table, but encountered a {}",
            x,
            x.type_str()
        ),
    }
}

fn parse_version(tval: TV) -> Result<PM::Version> {
    let version_str = tval.as_str().unwrap();
    let version_parts = version_str.split('.').collect::<Vec<_>>();
    if version_parts.len() != 3 {
        bail!(
            "Version is malformed. Versions must be of the form <u64>.<u64>.<u64>, but found '{}'",
            version_str
        );
    }

    Ok((
        version_parts[0]
            .parse::<u64>()
            .context("Invalid major version")?,
        version_parts[1]
            .parse::<u64>()
            .context("Invalid minor version")?,
        version_parts[2]
            .parse::<u64>()
            .context("Invalid bugfix version")?,
    ))
}

fn parse_digest(tval: TV) -> Result<Vec<u8>> {
    let digest_str = tval
        .as_str()
        .ok_or_else(|| format_err!("Invalid package digest"))?;
    Ok(digest_str.as_bytes().to_vec())
}

// check that only recognized names are provided at the top-level
fn warn_if_unknown_field_names(table: &toml::map::Map<String, TV>, known_names: &[&str]) {
    let mut unknown_names = BTreeSet::new();
    for key in table.keys() {
        if !known_names.contains(&key.as_str()) {
            unknown_names.insert(key.to_string());
        }
    }

    if !unknown_names.is_empty() {
        eprintln!(
            "Warning: unknown field name{} found. Expected one of [{}], but found {}",
            if unknown_names.len() > 1 { "s" } else { "" },
            known_names.join(", "),
            unknown_names
                .into_iter()
                .map(|x| format!("'{}'", x))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}

fn check_for_required_field_names(
    table: &toml::map::Map<String, TV>,
    required_fields: &[&str],
) -> Result<()> {
    let mut missing_fields = BTreeSet::new();

    for field_name in required_fields {
        if !table.contains_key(*field_name) {
            missing_fields.insert(field_name.to_string());
        }
    }

    if !missing_fields.is_empty() {
        bail!(
            "Required field name{} {} not found",
            if missing_fields.len() > 1 { "s" } else { "" },
            missing_fields
                .into_iter()
                .map(|x| format!("'{}'", x))
                .collect::<Vec<_>>()
                .join(", "),
        )
    }

    Ok(())
}
