// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

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

#![allow(dead_code)]
pub mod execution_phase;
pub mod ordering_state_computer;
