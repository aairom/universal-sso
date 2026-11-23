//! Configuration read from the environment (see `.env.example`).

use std::time::Duration;
use url::Url;

use crate::error::Error;

/// Gateway URL used when `SSO_GATEWAY_URL` is not set.
pub const DEFAULT_GATEWAY_URL: &str = "http://localhost:8080";

/// Settings for talking to the Universal SSO gateway (`ssod`).
#[derive(Debug, Clone)]
pub struct Config {
    /// Base URL of `ssod`. Plain `http` is accepted only for loopback hosts.
    pub gateway_url: Url,
    /// Provider id registered in the gateway, `oauth2` by default.
    pub provider: String,
    /// When set, the login redirect must go to this host or a subdomain of it.
    pub expected_idp_host: Option<String>,
    /// Bound for every HTTP request.
    pub timeout: Duration,
}

fn is_loopback(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

impl Config {
    /// Builds a `Config` from `getenv`, which makes it testable without
    /// touching the process environment.
    pub fn from_lookup<F>(getenv: F, default_provider: &str) -> Result<Config, Error>
    where
        F: Fn(&str) -> Option<String>,
    {
        let get = |k: &str| {
            getenv(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };

        let raw = get("SSO_GATEWAY_URL").unwrap_or_else(|| DEFAULT_GATEWAY_URL.to_string());
        let mut gateway_url = Url::parse(&raw).map_err(|_| {
            Error::Config("SSO_GATEWAY_URL must be an http(s) URL with a host".into())
        })?;
        if !matches!(gateway_url.scheme(), "http" | "https") || gateway_url.host_str().is_none() {
            return Err(Error::Config(
                "SSO_GATEWAY_URL must be an http(s) URL with a host".into(),
            ));
        }
        if gateway_url.scheme() == "http" && !is_loopback(gateway_url.host_str().unwrap_or("")) {
            return Err(Error::Config(
                "SSO_GATEWAY_URL uses plain http for a non-loopback host: use https".into(),
            ));
        }
        gateway_url.set_query(None);
        gateway_url.set_fragment(None);
        let trimmed = gateway_url.path().trim_end_matches('/').to_string();
        gateway_url.set_path(&trimmed);

        let provider = get("SSO_PROVIDER").unwrap_or_else(|| default_provider.to_string());
        let valid = !provider.is_empty()
            && provider.len() <= 64
            && provider
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
        if !valid {
            return Err(Error::Config(format!(
                "SSO_PROVIDER {provider:?} must match [a-z0-9_-]{{1,64}}"
            )));
        }

        let timeout = match get("SSO_HTTP_TIMEOUT_SECONDS") {
            None => Duration::from_secs(10),
            Some(s) => match s.parse::<u64>() {
                Ok(n) if (1..=300).contains(&n) => Duration::from_secs(n),
                _ => {
                    return Err(Error::Config(
                        "SSO_HTTP_TIMEOUT_SECONDS must be an integer from 1 to 300".into(),
                    ))
                }
            },
        };

        Ok(Config {
            gateway_url,
            provider,
            expected_idp_host: get("SSO_EXPECTED_IDP_HOST").map(|h| h.to_ascii_lowercase()),
            timeout,
        })
    }

    /// Reads the real process environment.
    pub fn from_env(default_provider: &str) -> Result<Config, Error> {
        Config::from_lookup(|k| std::env::var(k).ok(), default_provider)
    }

    /// Absolute URL for a gateway path such as `/healthz`.
    pub fn endpoint(&self, path: &str) -> String {
        format!(
            "{}{}",
            self.gateway_url.as_str().trim_end_matches('/'),
            path
        )
    }
}
