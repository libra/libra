// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! The purpose of this crate is to offer a single source of truth for the definitions of shared
//! constants within the Diem codebase. This is useful because many different components within
//! Diem often require access to global constant definitions (e.g., Diem Safety Rules,
//! the Key Manager, and Secure Storage). To avoid duplicating these definitions across crates
//! (and better allow these constants to be updated in a single location), we define them here.
#![forbid(unsafe_code)]

/// Definitions of global cryptographic keys (e.g., as held in secure storage)
pub const CONSENSUS_KEY: &str = "consensus";
pub const EXECUTION_KEY: &str = "execution";
pub const FULLNODE_NETWORK_KEY: &str = "fullnode_network";
pub const DIEM_ROOT_KEY: &str = "diem_root";
pub const TREASURY_COMPLIANCE_KEY: &str = "treasury_compliance";
pub const OPERATOR_ACCOUNT: &str = "operator_account";
pub const OPERATOR_KEY: &str = "operator";
pub const OWNER_ACCOUNT: &str = "owner_account";
pub const OWNER_KEY: &str = "owner";
pub const VALIDATOR_NETWORK_ADDRESS_KEYS: &str = "validator_network_address_keys";
pub const VALIDATOR_NETWORK_KEY: &str = "validator_network";

/// Definitions of global data items (e.g., as held in secure storage)
pub const SAFETY_DATA: &str = "safety_data";
pub const WAYPOINT: &str = "waypoint";
pub const GENESIS_WAYPOINT: &str = "genesis-waypoint";
pub const MOVE_MODULES: &str = "move-modules";
