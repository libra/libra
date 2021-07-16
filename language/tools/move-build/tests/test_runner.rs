// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use move_build::source_package::manifest_parser as MP;
use move_command_line_common::testing::{format_diff, read_env_update_baseline, EXP_EXT};
use std::{fs, path::Path};

pub fn run_test(path: &Path) -> datatest_stable::Result<()> {
    let update_baseline = read_env_update_baseline();
    let exp_path = path.with_extension(EXP_EXT);

    let exp_exists = exp_path.is_file();

    let contents = fs::read_to_string(path)?;
    let output = match MP::parse_move_manifest_string(contents).and_then(MP::parse_source_manifest)
    {
        Ok(parsed_package) => format!("{:#?}", parsed_package),
        Err(error) => format!("{:#}", error),
    };

    if update_baseline {
        fs::write(&exp_path, &output)?;
        return Ok(());
    }

    if exp_exists {
        let expected = fs::read_to_string(&exp_path)?;
        if expected != output {
            return Err(anyhow::format_err!(
                "Expected outputs differ for {:?}:\n{}",
                exp_path,
                format_diff(expected, output)
            )
            .into());
        }
    } else {
        return Err(anyhow::format_err!(
            "No expected output found for {:?}.\
                    You probably want to rerun with `env UPDATE_BASELINE=1`",
            path
        )
        .into());
    }
    Ok(())
}

datatest_stable::harness!(run_test, "tests/test_sources", r".*\.toml$");
