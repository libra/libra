// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

// [Decoupled Execution]
//
//                 Execution
//  Consensus      Phase          Commit Phase
// ┌─────────┐    ┌─────────┐    ┌─────────────┐
// │ Ordered ├───►│ Execute ├───►│ Send Commit │
// │ Blocks  │    │         │    │ Proposal    │
// └─────────┘    └─────────┘    └─────────────┘
//                                     ▼
//                               ┌─────────────┐    ┌──────────┐
//                               │ Signature   ├───►│ Commit   │
//                               │ Aggregation │    │ Blocks   │
//                               └─────────────┘    └──────────┘
//                                     ▼
//                               ┌─────────────┐
//                               │ Send Commit │
//                               │ Decision    │ (Asynchronously)
//                               └─────────────┘

pub mod commit_phase;
pub mod execution_phase;
pub mod ordering_state_computer;

#[cfg(test)]
mod tests;