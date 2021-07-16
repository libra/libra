// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SourcePackageLayout {
    Sources,
    Specifications,
    Tests,
    Scripts,
    Examples,
    Manifest,
}

impl SourcePackageLayout {
    /// A Move source package is laid out on-disk as
    /// a_move_package
    /// ├── examples       (optional)
    /// ├── Move.toml      (required)
    /// ├── scripts        (optional)
    /// ├── sources        (required)
    /// ├── specifications (optional)
    /// └── tests          (optional)
    pub fn path(&self) -> &Path {
        let path = match self {
            Self::Sources => "sources",
            Self::Manifest => "Move.toml",
            Self::Tests => "tests",
            Self::Scripts => "scripts",
            Self::Examples => "examples",
            Self::Specifications => "specifications",
        };
        &Path::new(path)
    }

    pub fn is_optional(&self) -> bool {
        match self {
            Self::Sources | Self::Manifest => false,
            Self::Tests | Self::Scripts | Self::Examples | Self::Specifications => true,
        }
    }
}
