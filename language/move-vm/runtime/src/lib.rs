// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! The core Move VM logic.
//!
//! It is a design goal for the Move VM to be independent of the Diem blockchain, so that
//! other blockchains can use it as well. The VM isn't there yet, but hopefully will be there
//! soon.

#[macro_use]
extern crate mirai_annotations;

pub mod data_cache;
mod interpreter;
pub mod loader;
pub mod logging;
pub mod move_vm;
pub mod native_functions;
mod runtime;
pub mod session;
#[macro_use]
mod tracing;

// Only include debugging functionality in debug builds
#[cfg(debug_assertions)]
mod debug;

#[cfg(test)]
mod unit_tests;
