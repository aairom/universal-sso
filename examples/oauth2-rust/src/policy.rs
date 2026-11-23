//! Client-side safety policy for the authorization redirect.
//!
//! The gateway owns the signed state, the PKCE verifier and the client
//! secret. This client only checks that the redirect it is about to hand to a
//! browser is sane for an OAuth 2.0 authorization-code flow.

use url::Url;

use crate::error::Error;

fn policy(msg: impl Into<String>) -> Error {
    Error::Policy(msg.into())
}

/// Verifies `redirect` and returns the `state` value it carries.
///
/// Rules:
/// * the scheme is `http` or `https`, and `https` is required unless the
///   redirect stays on the gateway's own host (the mock provider);
/// * when `expected_host` is set, the host equals it or is a subdomain of it;
/// * `state` is present and non-empty;
/// * PKCE is in use: `code_challenge` is present and
///   `code_challenge_method` is `S256`.
pub fn check_authorize_url(
    redirect: &Url,
    gateway: &Url,
    expected_host: Option<&str>,
) -> Result<String, Error> {
    if !matches!(redirect.scheme(), "http" | "https") {
        return Err(policy(format!(
            "scheme {:?} is not http or https",
            redirect.scheme()
        )));
    }
    let same_host = redirect.host_str() == gateway.host_str()
        && redirect.port_or_known_default() == gateway.port_or_known_default();
    if !same_host && redirect.scheme() != "https" {
        return Err(policy("external identity provider must use https"));
    }
    if let Some(expected) = expected_host {
        let host = redirect.host_str().unwrap_or("").to_ascii_lowercase();
        if host != expected && !host.ends_with(&format!(".{expected}")) {
            return Err(policy(format!(
                "host {host:?} is not {expected:?} or a subdomain"
            )));
        }
    }
    let param = |name: &str| {
        redirect
            .query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default()
    };
    let state = param("state");
    if state.is_empty() {
        return Err(policy("redirect has no state parameter"));
    }
    if param("code_challenge").is_empty() || param("code_challenge_method") != "S256" {
        return Err(policy("redirect does not use PKCE with S256"));
    }
    Ok(state)
}
