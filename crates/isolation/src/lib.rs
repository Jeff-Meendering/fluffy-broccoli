//! Parser fault containment. Separate processes are not an operating-system sandbox.
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

mod client;
mod protocol;
mod worker;

pub use client::{WorkerPool, default_worker};
pub use worker::run_worker;

pub const ISOLATION_DESCRIPTION: &str = "Bounded extraction IPC and enforced process deadlines; Unix process-group cleanup; Linux address-space limit. No filesystem/network sandbox. Windows descendant and memory limits are not established.";
