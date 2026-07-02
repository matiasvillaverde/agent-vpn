//! `vpn` — an agent-first, provider-agnostic WireGuard tunnel manager.
//!
//! The library exposes the full command logic so it can be driven in-process
//! with any command runner, including a mock — which is how the crate reaches
//! full test coverage without root privileges or real network interfaces.

#![deny(missing_docs)]

pub mod backend;
pub mod cli;
pub mod config;
pub mod error;
pub mod output;
pub mod probe;
pub mod runner;
pub mod settings;
pub mod status;

#[cfg(test)]
pub(crate) mod testutil;
