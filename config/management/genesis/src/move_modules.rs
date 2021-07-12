// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::builder::GenesisBuilder;
use diem_management::{config::ConfigPath, error::Error, secure_backend::SharedBackend};
use diem_secure_storage::Storage;
use std::{fs, path::PathBuf};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct SetMoveModules {
    #[structopt(flatten)]
    config: ConfigPath,
    // Directory containing Move bytecode (.mv) files to use in genesis
    #[structopt(long)]
    dir: PathBuf,
    #[structopt(flatten)]
    backend: SharedBackend,
}

impl SetMoveModules {
    pub fn execute(self) -> Result<Vec<Vec<u8>>, Error> {
        let mut move_modules = vec![];
        // collect all Move bytecode files located immediately under self.dir
        for dir_entry in
            fs::read_dir(self.dir.clone()).map_err(|e| Error::UnexpectedError(e.to_string()))?
        {
            let path = dir_entry
                .map_err(|e| Error::UnexpectedError(e.to_string()))?
                .path();
            if path.is_dir() {
                return Err(Error::UnexpectedError(format!(
                    "Subdirectory {:?} found under Move bytecode modules directory. All bytecode files must be located directly under the modules directory {:?}", path, self.dir)));
            }
            move_modules.push(fs::read(path).map_err(|e| Error::UnexpectedError(e.to_string()))?)
        }
        let config = self
            .config
            .load()?
            .override_shared_backend(&self.backend.shared_backend)?;

        // In order to not break cli compatibility we need to clear the namespace set via cli since
        // it was previously ignored.
        let mut shared_backend = config.shared_backend;
        shared_backend.clear_namespace();

        let storage = Storage::from(&shared_backend);
        GenesisBuilder::new(storage)
            .set_move_modules(move_modules.clone())
            .map_err(|e| Error::StorageWriteError("shared", "move_modules", e.to_string()))?;

        Ok(move_modules)
    }
}
