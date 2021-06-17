// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

pub mod base;
pub mod experimental;
pub mod sandbox;

/// Default directory where saved Move resources live
pub const DEFAULT_STORAGE_DIR: &str = "storage";

/// Default directory where Move modules live
pub const DEFAULT_SOURCE_DIR: &str = "src";

/// Default directory where Move packages live under build_dir
pub const DEFAULT_PACKAGE_DIR: &str = "package";

/// Default dependency inclusion mode
pub const DEFAULT_DEP_MODE: &str = "stdlib";

/// Default directory for build output
pub use move_lang::command_line::DEFAULT_OUTPUT_DIR as DEFAULT_BUILD_DIR;

/// Extension for resource and event files, which are in BCS format
const BCS_EXTENSION: &str = "bcs";

use anyhow::Result;
use move_core_types::{
    account_address::AccountAddress, errmap::ErrorMapping, identifier::Identifier,
    language_storage::TypeTag, parser, transaction_argument::TransactionArgument,
};
use move_vm_runtime::native_functions::NativeFunction;
use sandbox::utils::mode::{Mode, ModeType};
use std::{fs, path::Path};
use structopt::StructOpt;

type NativeFunctionRecord = (AccountAddress, Identifier, Identifier, NativeFunction);

#[derive(StructOpt)]
#[structopt(
    name = "move",
    about = "CLI frontend for Move compiler and VM",
    rename_all = "kebab-case"
)]
pub struct Move {
    /// Directory storing Move resources, events, and module bytecodes produced by module publishing
    /// and script execution.
    #[structopt(long, default_value = DEFAULT_STORAGE_DIR, global = true)]
    storage_dir: String,
    /// Directory storing build artifacts produced by compilation
    #[structopt(long, short = "d", default_value = DEFAULT_BUILD_DIR, global = true)]
    build_dir: String,
    /// Dependency inclusion mode
    #[structopt(
        long,
        default_value = DEFAULT_DEP_MODE,
        global = true,
    )]
    mode: ModeType,
    /// Print additional diagnostics
    #[structopt(short = "v", global = true)]
    verbose: bool,
    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(StructOpt)]
pub enum Command {
    /// Compile and emit Move bytecode for the specified scripts and/or modules
    #[structopt(name = "compile")]
    Compile {
        /// The source files to check
        #[structopt(
            name = "PATH_TO_SOURCE_FILE",
            default_value = DEFAULT_SOURCE_DIR,
        )]
        source_files: Vec<String>,
        /// Do not emit source map information along with the compiled bytecode
        #[structopt(long = "no-source-maps")]
        no_source_maps: bool,
        /// Type check and verify the specified scripts and/or modules. Does not emit bytecode.
        #[structopt(long = "check")]
        check: bool,
    },
    /// Execute a sandbox command
    #[structopt(name = "sandbox")]
    Sandbox {
        #[structopt(subcommand)]
        cmd: SandboxCommand,
    },
    /// (Experimental) Run static analyses on Move source or bytecode
    #[structopt(name = "experimental")]
    Experimental {
        #[structopt(subcommand)]
        cmd: ExperimentalCommand,
    },
}

#[derive(StructOpt)]
pub enum SandboxCommand {
    /// Compile the specified modules and publish the resulting bytecodes in global storage
    #[structopt(name = "publish")]
    Publish {
        /// The source files containing modules to publish
        #[structopt(
            name = "PATH_TO_SOURCE_FILE",
            default_value = DEFAULT_SOURCE_DIR,
        )]
        source_files: Vec<String>,
        /// If set, fail during compilation when attempting to publish a module that already
        /// exists in global storage
        #[structopt(long = "no-republish")]
        no_republish: bool,
        /// By default, code that might cause breaking changes for bytecode
        /// linking or data layout compatibility checks will not be published.
        /// Set this flag to ignore breaking changes checks and publish anyway
        #[structopt(long = "ignore-breaking-changes")]
        ignore_breaking_changes: bool,
        /// fix publishing order
        #[structopt(short = "m", long = "override-ordering")]
        override_ordering: Option<Vec<String>>,
    },
    /// Compile/run a Move script that reads/writes resources stored on disk in `storage`.
    /// This command compiles the script first before running it.
    #[structopt(name = "run")]
    Run {
        /// Path to .mv file containing either script or module bytecodes. If the file is a module, the
        /// `script_name` parameter must be set.
        #[structopt(name = "script")]
        script_file: String,
        /// Name of the script function inside `script_file` to call. Should only be set if `script_file`
        /// points to a module.
        #[structopt(name = "name")]
        script_name: Option<String>,
        /// Possibly-empty list of signers for the current transaction (e.g., `account` in
        /// `main(&account: signer)`). Must match the number of signers expected by `script_file`.
        #[structopt(long = "signers")]
        signers: Vec<String>,
        /// Possibly-empty list of arguments passed to the transaction (e.g., `i` in
        /// `main(i: u64)`). Must match the arguments types expected by `script_file`.
        /// Supported argument types are
        /// bool literals (true, false),
        /// u64 literals (e.g., 10, 58),
        /// address literals (e.g., 0x12, 0x0000000000000000000000000000000f),
        /// hexadecimal strings (e.g., x"0012" will parse as the vector<u8> value [00, 12]), and
        /// ASCII strings (e.g., 'b"hi" will parse as the vector<u8> value [68, 69])
        #[structopt(long = "args", parse(try_from_str = parser::parse_transaction_argument))]
        args: Vec<TransactionArgument>,
        /// Possibly-empty list of type arguments passed to the transaction (e.g., `T` in
        /// `main<T>()`). Must match the type arguments kinds expected by `script_file`.
        #[structopt(long = "type-args", parse(try_from_str = parser::parse_type_tag))]
        type_args: Vec<TypeTag>,
        /// Maximum number of gas units to be consumed by execution.
        /// When the budget is exhaused, execution will abort.
        /// By default, no `gas-budget` is specified and gas metering is disabled.
        #[structopt(long = "gas-budget", short = "g")]
        gas_budget: Option<u64>,
        /// If set, the effects of executing `script_file` (i.e., published, updated, and
        /// deleted resources) will NOT be committed to disk.
        #[structopt(long = "dry-run", short = "n")]
        dry_run: bool,
    },
    /// Run expected value tests using the given batch file
    #[structopt(name = "test")]
    Test {
        /// a directory path in which all the tests will be executed
        #[structopt(name = "path")]
        path: String,
        /// Show coverage information after tests are done.
        /// By default, coverage will not be tracked nor shown.
        #[structopt(long = "track-cov")]
        track_cov: bool,
        /// Create a new test directory scaffold with the specified <path>
        #[structopt(long = "create")]
        create: bool,
    },
    /// View Move resources, events files, and modules stored on disk
    #[structopt(name = "view")]
    View {
        /// Path to a resource, events file, or module stored on disk.
        #[structopt(name = "file")]
        file: String,
    },
    /// Delete all resources, events, and modules stored on disk under `storage`.
    /// Does *not* delete anything in `src`.
    Clean {},
    /// Run well-formedness checks on the `storage` and `build` directories.
    #[structopt(name = "doctor")]
    Doctor {},
    /// Typecheck and verify the scripts and/or modules under `src`.
    #[structopt(name = "link")]
    Link {
        /// If set, fail when attempting to typecheck a module that already exists in global storage
        #[structopt(long = "no-republish")]
        no_republish: bool,
    },
}

#[derive(StructOpt)]
pub enum ExperimentalCommand {
    /// Perform a read/write set analysis and print the results for
    /// `module_file`::`script_name`
    #[structopt(name = "read-write-set")]
    ReadWriteSet {
        /// Path to .mv file containing module bytecode.
        #[structopt(name = "module")]
        module_file: String,
        /// A function inside `module_file`.
        #[structopt(name = "function")]
        fun_name: String,
        #[structopt(long = "signers")]
        signers: Vec<String>,
        #[structopt(long = "args", parse(try_from_str = parser::parse_transaction_argument))]
        args: Vec<TransactionArgument>,
        #[structopt(long = "type-args", parse(try_from_str = parser::parse_type_tag))]
        type_args: Vec<TypeTag>,
        #[structopt(long = "concretize")]
        concretize: bool,
    },
}

fn handle_experimental_commands(
    move_args: &Move,
    mode: &Mode,
    experimental_command: &ExperimentalCommand,
) -> Result<()> {
    match experimental_command {
        ExperimentalCommand::ReadWriteSet {
            module_file,
            fun_name,
            signers,
            args,
            type_args,
            concretize,
        } => {
            let state = mode.prepare_state(&move_args.build_dir, &move_args.storage_dir)?;
            experimental::commands::analyze_read_write_set(
                &state,
                module_file,
                fun_name,
                signers,
                args,
                type_args,
                *concretize,
                move_args.verbose,
            )
        }
    }
}

fn handle_sandbox_commands(
    natives: Vec<NativeFunctionRecord>,
    error_descriptions: &ErrorMapping,
    move_args: &Move,
    mode: &Mode,
    sandbox_command: &SandboxCommand,
) -> Result<()> {
    match sandbox_command {
        SandboxCommand::Link { no_republish } => {
            let state = mode.prepare_state(&move_args.build_dir, &move_args.storage_dir)?;
            base::commands::check(
                &[state.interface_files_dir()?],
                !*no_republish,
                &[DEFAULT_SOURCE_DIR.to_string()],
                move_args.verbose,
            )
        }
        SandboxCommand::Publish {
            source_files,
            no_republish,
            ignore_breaking_changes,
            override_ordering,
        } => {
            let state = mode.prepare_state(&move_args.build_dir, &move_args.storage_dir)?;
            sandbox::commands::publish(
                natives,
                &state,
                source_files,
                !*no_republish,
                *ignore_breaking_changes,
                override_ordering.as_ref().map(|o| o.as_slice()),
                move_args.verbose,
            )
        }
        SandboxCommand::Run {
            script_file,
            script_name,
            signers,
            args,
            type_args,
            gas_budget,
            dry_run,
        } => {
            let state = mode.prepare_state(&move_args.build_dir, &move_args.storage_dir)?;
            sandbox::commands::run(
                natives,
                error_descriptions,
                &state,
                script_file,
                script_name,
                signers,
                args,
                type_args.to_vec(),
                *gas_budget,
                *dry_run,
                move_args.verbose,
            )
        }
        SandboxCommand::Test {
            path,
            track_cov: _,
            create: true,
        } => sandbox::commands::create_test_scaffold(path),
        SandboxCommand::Test {
            path,
            track_cov,
            create: false,
        } => sandbox::commands::run_all(
            path,
            &std::env::current_exe()?.to_string_lossy(),
            *track_cov,
        ),
        SandboxCommand::View { file } => {
            let state = mode.prepare_state(&move_args.build_dir, &move_args.storage_dir)?;
            sandbox::commands::view(&state, file)
        }
        SandboxCommand::Clean {} => {
            // delete storage
            let storage_dir = Path::new(&move_args.storage_dir);
            if storage_dir.exists() {
                fs::remove_dir_all(&storage_dir)?;
            }

            // delete build
            let build_dir = Path::new(&move_args.build_dir);
            if build_dir.exists() {
                fs::remove_dir_all(&build_dir)?;
            }
            Ok(())
        }
        SandboxCommand::Doctor {} => {
            let state = mode.prepare_state(&move_args.build_dir, &move_args.storage_dir)?;
            sandbox::commands::doctor(&state)
        }
    }
}

pub fn move_cli(
    natives: Vec<NativeFunctionRecord>,
    error_descriptions: &ErrorMapping,
) -> Result<()> {
    let move_args = Move::from_args();
    let mode = Mode::new(move_args.mode);

    match &move_args.cmd {
        Command::Compile {
            source_files,
            no_source_maps,
            check,
        } => {
            let mode_interface_dir = mode
                .prepare_state(&move_args.build_dir, &move_args.storage_dir)?
                .interface_files_dir()?;
            if *check {
                base::commands::check(
                    &[mode_interface_dir],
                    false,
                    &source_files,
                    move_args.verbose,
                )
            } else {
                base::commands::compile(
                    &[mode_interface_dir],
                    &move_args.build_dir,
                    false,
                    &source_files,
                    !*no_source_maps,
                    move_args.verbose,
                )
            }
        }
        Command::Sandbox { cmd } => {
            handle_sandbox_commands(natives, error_descriptions, &move_args, &mode, cmd)
        }
        Command::Experimental { cmd } => handle_experimental_commands(&move_args, &mode, cmd),
    }
}
