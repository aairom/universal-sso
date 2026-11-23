//! Rust client for the Universal SSO gateway (`ssod`), used here with the
//! generic OAuth 2.0 provider.
//!
//! The gateway performs the OAuth 2.0 authorization-code flow with PKCE and a
//! signed `state`, and keeps the client secret and tokens server-side. This
//! crate starts a login, checks the redirect, and reads the resulting profile.

pub mod client;
pub mod config;
pub mod error;
pub mod policy;

pub use client::{Client, Login, Profile, User};
pub use config::Config;
pub use error::Error;
