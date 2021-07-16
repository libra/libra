// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use move_build::source_package::{layout, manifest_parser};

// TODO: This currently only parses the "Move.toml" under the current directory
fn main() {
    let current_dir = std::env::current_dir().unwrap();
    let manifest_string =
        std::fs::read_to_string(current_dir.join(layout::SourcePackageLayout::Manifest.path()))
            .unwrap();
    let toml_manifest = manifest_parser::parse_move_manifest_string(manifest_string).unwrap();
    manifest_parser::parse_source_manifest(toml_manifest).unwrap();
}
