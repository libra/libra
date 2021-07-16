// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use codespan_reporting::term::termcolor::Buffer;

use anyhow::anyhow;
use itertools::Itertools;
use move_command_line_common::{env::read_env_var, testing::EXP_EXT};
use move_prover::{cli::Options, run_move_prover};
use move_prover_test_utils::{baseline_test::verify_or_update_baseline, extract_test_directives};
use tempfile::TempDir;

use datatest_stable::Requirements;
#[allow(unused_imports)]
use log::{debug, info, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use walkdir::WalkDir;

use once_cell::sync::OnceCell;

const ENV_FLAGS: &str = "MVP_TEST_FLAGS";
const ENV_TEST_EXTENDED: &str = "MVP_TEST_X";
const ENV_TEST_INCONSISTENCY: &str = "MVP_TEST_INCONSISTENCY";
const ENV_TEST_FEATURE: &str = "MVP_TEST_FEATURE";
const ENV_TEST_ON_CI: &str = "MVP_TEST_ON_CI";
const INCONSISTENCY_TEST_FLAGS: &[&str] = &[
    "--dependency=../move-stdlib/modules",
    "--dependency=../diem-framework/modules",
    "--check-inconsistency",
];
const REGULAR_TEST_FLAGS: &[&str] = &[
    "--dependency=../move-stdlib/modules",
    "--dependency=../diem-framework/modules",
];

static NOT_CONFIGURED_WARNED: AtomicBool = AtomicBool::new(false);

/// A struct to describe a feature to test.
struct Feature {
    /// Name of this feature.
    name: &'static str,
    /// Flags specific to this feature.
    flags: &'static [&'static str],
    /// Inclusion mode.
    inclusion_mode: InclusionMode,
    /// True if the tests should only be run if requested by MVP_TEST_FEATURE
    only_if_requested: bool,
    /// Whether this feature will be tested in CI.
    enable_in_ci: bool,
    /// Whether this feature has as a separate baseline file.
    separate_baseline: bool,
    /// A static function pointer to the runner to be used for datatest. Since datatest
    /// does not support function values and closures, we need to have a different runner for
    /// each feature
    runner: fn(&Path) -> datatest_stable::Result<()>,
    /// A predicate to be called on the path determining whether the feature is enabled.
    /// The first name is the name of the test group, the second the path to the test
    /// source.
    enabling_condition: fn(&str, &str) -> bool,
}

/// An inclusion mode. A feature may be run in one of these modes.
#[derive(Clone, Copy)]
enum InclusionMode {
    /// Only a test which has the comment `// also_include_for: <feature>` will be included.
    #[allow(dead_code)]
    Explicit,
    /// Every test will be included unless it has the comment `// exclude_for: <feature>`.
    Implicit,
}

fn get_features() -> &'static [Feature] {
    static TESTED_FEATURES: OnceCell<Vec<Feature>> = OnceCell::new();
    TESTED_FEATURES.get_or_init(|| {
        // Tests the default configuration.
        vec![
            Feature {
                name: "default",
                flags: &[],
                inclusion_mode: InclusionMode::Implicit,
                enable_in_ci: true,
                only_if_requested: false,
                separate_baseline: false,
                runner: |p| test_runner_for_feature(p, get_feature_by_name("default")),
                enabling_condition: |_, _| true,
            },
            // Tests with cvc4 as a backend for boogie.
            Feature {
                name: "cvc4",
                flags: &["--use-cvc4"],
                inclusion_mode: InclusionMode::Implicit,
                enable_in_ci: false, // Do not enable in CI until we have more data about stability
                only_if_requested: false,
                separate_baseline: false,
                runner: |p| test_runner_for_feature(p, get_feature_by_name("cvc4")),
                enabling_condition: |group, _| group == "unit",
            },
        ]
    })
}

fn get_feature_by_name(name: &str) -> &'static Feature {
    for feature in get_features() {
        if feature.name == name {
            return feature;
        }
    }
    panic!("feature not found")
}

/// Test runner for a given feature.
fn test_runner_for_feature(path: &Path, feature: &Feature) -> datatest_stable::Result<()> {
    // Use the below + `cargo test -- --test-threads=1` to identify a long running test
    // println!(">>> testing {}", path.to_string_lossy().to_string());

    info!(
        "testing {} with feature `{}` (flags = `{}`)",
        path.display(),
        feature.name,
        feature.flags.iter().map(|s| s.to_string()).join(" ")
    );

    let temp_dir = TempDir::new()?;
    std::fs::create_dir_all(temp_dir.path())?;
    let (mut args, baseline_path) = get_flags_and_baseline(temp_dir.path(), path, feature)?;

    args.insert(0, "mvp_test".to_owned());
    args.push("--verbose=warn".to_owned());
    // TODO: timeouts aren't handled correctly by the boogie wrapper but lead to hang. Determine
    //   reasons and reactivate.
    // args.push("--num-instances=2".to_owned()); // run two Boogie instances with different seeds
    // args.push("--sequential".to_owned());

    // Move source.
    args.push(path.to_string_lossy().to_string());

    let mut options = Options::create_from_args(&args)?;
    options.setup_logging_for_test();
    let no_tools = read_env_var("BOOGIE_EXE").is_empty()
        || !options.backend.use_cvc4 && read_env_var("Z3_EXE").is_empty()
        || options.backend.use_cvc4 && read_env_var("CVC4_EXE").is_empty();
    let baseline_valid =
        !no_tools || !extract_test_directives(path, "// no-boogie-test")?.is_empty();

    if no_tools {
        options.prover.generate_only = true;
        if NOT_CONFIGURED_WARNED
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            warn!(
                "Prover tools are not configured, verification tests will be skipped. \
        See https://github.com/diem/diem/tree/main/language/move-prover/doc/user/install.md \
        for instructions."
            );
        }
    }
    options.backend.check_tool_versions()?;
    options.prover.stable_test_output = true;
    options.backend.stable_test_output = true;

    let mut error_writer = Buffer::no_color();
    let mut diags = match run_move_prover(&mut error_writer, options) {
        Ok(()) => "".to_string(),
        Err(err) => format!("Move prover returns: {}\n", err),
    };
    if baseline_valid {
        if let Some(ref path) = baseline_path {
            diags += &String::from_utf8_lossy(&error_writer.into_inner()).to_string();
            verify_or_update_baseline(path.as_path(), &diags)?
        } else if !diags.is_empty() {
            return Err(anyhow!(
                "Unexpected prover output (expected none): {}{}",
                diags,
                String::from_utf8_lossy(&error_writer.into_inner())
            )
            .into());
        }
    }

    Ok(())
}

/// Returns flags and baseline file for this test run
fn get_flags_and_baseline(
    temp_dir: &Path,
    path: &Path,
    feature: &Feature,
) -> anyhow::Result<(Vec<String>, Option<PathBuf>)> {
    // Determine the way how to configure tests based on directory of the path.
    let path_str = path.to_string_lossy();

    let stdlib_test_flags = if read_env_var(ENV_TEST_INCONSISTENCY).is_empty() {
        REGULAR_TEST_FLAGS
    } else {
        INCONSISTENCY_TEST_FLAGS
    };

    let (base_flags, baseline_path) =
        if path_str.contains("diem-framework/") || path_str.contains("move-stdlib/") {
            (stdlib_test_flags, None)
        } else {
            let feature_name = feature.name.to_string();
            let separate_baseline = feature.separate_baseline
                || extract_test_directives(path, "// separate_baseline: ")?.contains(&feature_name);
            (
                REGULAR_TEST_FLAGS,
                Some(path.with_extension(if separate_baseline {
                    format!("{}_exp", feature.name)
                } else {
                    EXP_EXT.to_string()
                })),
            )
        };
    let mut flags = base_flags.iter().map(|s| (*s).to_string()).collect_vec();

    // Add flags specific to the feature.
    flags.extend(feature.flags.iter().map(|f| f.to_string()));

    // Add flags specified in the source.
    flags.extend(extract_test_directives(path, "// flag:")?);

    // Add flags specified via environment variable.
    flags.extend(shell_words::split(&read_env_var(ENV_FLAGS))?);

    // Create a temporary file for output. We inject the modifier to potentially prevent
    // any races between similar named files in different directories, as it appears TempPath
    // isn't working always.
    let base_name = format!("{}.bpl", path.file_stem().unwrap().to_str().unwrap());
    let output = temp_dir.join(base_name).to_str().unwrap().to_string();
    flags.push(format!("--output={}", output));
    Ok((flags, baseline_path))
}

/// Collects the enabled tests, accumulating them as datatest requirements.
/// We collect the test data sources ourselves instead of letting datatest
/// do it because we want to select them based on enabled feature as indicated
/// in the source. We still use datatest to finally run the tests to utilize its
/// execution engine.
fn collect_enabled_tests(reqs: &mut Vec<Requirements>, group: &str, feature: &Feature, path: &str) {
    let mut p = PathBuf::new();
    p.push(path);
    for entry in WalkDir::new(p.clone()).min_depth(1).into_iter().flatten() {
        if !entry.file_name().to_string_lossy().ends_with(".move") {
            continue;
        }
        let path = entry.path();
        let mut included = match feature.inclusion_mode {
            InclusionMode::Implicit => !extract_test_directives(path, "// exclude_for: ")
                .unwrap_or_default()
                .iter()
                .any(|s| s.as_str() == feature.name),
            InclusionMode::Explicit => extract_test_directives(path, "// also_include_for: ")
                .unwrap_or_default()
                .iter()
                .any(|s| s.as_str() == feature.name),
        };
        if included && read_env_var(ENV_TEST_ON_CI) == "1" {
            included = feature.enable_in_ci
                && extract_test_directives(path, "// no_ci:")
                    .unwrap_or_default()
                    .is_empty();
        }
        let root_str = p.to_string_lossy().to_string();
        let path_str = path.to_string_lossy().to_string();
        if included {
            included = (feature.enabling_condition)(group, &path_str);
        }
        if included {
            reqs.push(Requirements::new(
                feature.runner,
                format!("prover {}[{}]", group, feature.name),
                root_str,
                path_str,
            ));
        }
    }
}

// Test entry point based on datatest runner.
fn main() {
    let mut reqs = vec![];
    for feature in get_features() {
        // Evaluate whether the user narrowed which feature to test.
        let feature_narrow = read_env_var(ENV_TEST_FEATURE);
        if !feature_narrow.is_empty() && feature.name != feature_narrow {
            continue;
        }
        if feature_narrow.is_empty() && feature.only_if_requested {
            continue;
        }
        // Check whether we are running extended tests
        if read_env_var(ENV_TEST_EXTENDED) == "1" {
            collect_enabled_tests(&mut reqs, "extended", feature, "tests/xsources");
        } else {
            collect_enabled_tests(&mut reqs, "unit", feature, "tests/sources");
            collect_enabled_tests(&mut reqs, "stdlib", feature, "../move-stdlib");
            collect_enabled_tests(&mut reqs, "diem", feature, "../diem-framework");
        }
    }
    datatest_stable::runner(&reqs);
}
