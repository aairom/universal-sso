//! Error type for the gateway client.

use thiserror::Error;

/// Everything that can go wrong while talking to the gateway.
#[derive(Debug, Error)]
pub enum Error {
    /// A configuration value is missing or invalid.
    #[error("configuration error: {0}")]
    Config(String),
    /// The gateway or network could not be reached, or the reply was unusable.
    #[error("request failed: {0}")]
    Transport(String),
    /// The gateway answered with its structured error body.
    #[error("gateway error {status} [{code}]: {message}")]
    Api {
        /// HTTP status code.
        status: u16,
        /// Machine-readable code such as `PROVIDER_NOT_FOUND`.
        code: String,
        /// Human-readable message.
        message: String,
    },
    /// The login redirect failed the client-side safety policy.
    #[error("unsafe authorization redirect: {0}")]
    Policy(String),
    /// The flow needs a browser because a redirect leaves the gateway host.
    #[error("redirect leaves the gateway host: open the URL in a browser")]
    LeavesGateway,
}
