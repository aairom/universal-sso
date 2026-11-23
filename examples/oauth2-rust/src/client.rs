//! Blocking HTTP client for the Universal SSO gateway.
//!
//! Contract (see `cmd/ssod/handler.go`):
//!
//! | Request | Success | Failure |
//! |---|---|---|
//! | `GET /healthz` | 200 `{"status":"ok"}` | |
//! | `GET /providers` | 200 `{"providers":[...]}` | |
//! | `GET /auth/{provider}/login` | 302 to the IdP | `{"code","message"}` |
//! | `GET /auth/{provider}/callback` | 200 `{"provider_id","user"}` | `{"code","message"}` |

use std::io::Read;

use serde::Deserialize;
use url::Url;

use crate::config::Config;
use crate::error::Error;
use crate::policy::check_authorize_url;

/// Upper bound for response bodies read from the gateway.
const MAX_BODY: u64 = 1 << 20;
/// Upper bound for redirects followed by [`Client::follow_local`].
const MAX_HOPS: usize = 5;

/// Normalized user profile returned by the gateway callback.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct User {
    /// Provider-specific stable user id.
    pub id: String,
    /// E-mail address, when the provider shares it.
    #[serde(default)]
    pub email: String,
    /// Whether the provider verified the address.
    #[serde(default)]
    pub email_verified: bool,
    /// Display name, when available.
    #[serde(default)]
    pub display_name: String,
    /// Roles granted by the provider.
    #[serde(default)]
    pub roles: Vec<String>,
}

/// Body of a successful callback.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Profile {
    /// Provider id that authenticated the user.
    pub provider_id: String,
    /// The user profile.
    pub user: User,
}

/// A started sign-in.
#[derive(Debug, Clone)]
pub struct Login {
    /// Where the user's browser must go. It passed the redirect policy.
    pub authorize_url: Url,
    /// Signed state the gateway issued for this attempt.
    pub state: String,
}

/// Gateway client. Redirects are never followed automatically so every hop can
/// be checked against the policy.
pub struct Client {
    cfg: Config,
    agent: ureq::Agent,
}

#[derive(Deserialize)]
struct ApiBody {
    #[serde(default)]
    code: String,
    #[serde(default)]
    message: String,
}

struct Reply {
    status: u16,
    location: Option<String>,
    body: Vec<u8>,
}

impl Client {
    /// Builds a client for `cfg`.
    pub fn new(cfg: Config) -> Client {
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout(cfg.timeout)
            .build();
        Client { cfg, agent }
    }

    /// The configuration in use.
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    fn get(&self, url: &str) -> Result<Reply, Error> {
        let resp = match self.agent.get(url).set("Accept", "application/json").call() {
            Ok(r) => r,
            // ureq reports 4xx/5xx as Err(Status); the body still carries the gateway error.
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(Error::Transport(e.to_string())),
        };
        let status = resp.status();
        let location = resp.header("Location").map(str::to_string);
        let mut body = Vec::new();
        resp.into_reader()
            .take(MAX_BODY)
            .read_to_end(&mut body)
            .map_err(|e| Error::Transport(e.to_string()))?;
        Ok(Reply {
            status,
            location,
            body,
        })
    }

    fn api_error(reply: &Reply) -> Error {
        let parsed: ApiBody = serde_json::from_slice(&reply.body).unwrap_or(ApiBody {
            code: String::new(),
            message: String::new(),
        });
        let (code, message) = if parsed.code.is_empty() {
            let text = String::from_utf8_lossy(&reply.body);
            (
                "UNKNOWN".to_string(),
                text.trim().chars().take(200).collect(),
            )
        } else {
            (parsed.code, parsed.message)
        };
        Error::Api {
            status: reply.status,
            code,
            message,
        }
    }

    /// Succeeds when the gateway reports `{"status":"ok"}`.
    pub fn health(&self) -> Result<(), Error> {
        let reply = self.get(&self.cfg.endpoint("/healthz"))?;
        let ok = reply.status == 200
            && serde_json::from_slice::<serde_json::Value>(&reply.body)
                .ok()
                .and_then(|v| v.get("status").and_then(|s| s.as_str().map(str::to_string)))
                .as_deref()
                == Some("ok");
        if ok {
            Ok(())
        } else {
            Err(Error::Transport(format!(
                "gateway not healthy: HTTP {}",
                reply.status
            )))
        }
    }

    /// Lists the provider ids registered in the gateway.
    pub fn providers(&self) -> Result<Vec<String>, Error> {
        #[derive(Deserialize)]
        struct P {
            providers: Vec<String>,
        }
        let reply = self.get(&self.cfg.endpoint("/providers"))?;
        if reply.status != 200 {
            return Err(Self::api_error(&reply));
        }
        serde_json::from_slice::<P>(&reply.body)
            .map(|p| p.providers)
            .map_err(|e| Error::Transport(format!("decode providers: {e}")))
    }

    /// Asks the gateway to begin a sign-in and validates the redirect.
    ///
    /// Returns [`Error::Api`] when the gateway refuses, for example
    /// `PROVIDER_NOT_FOUND` for a provider that is not registered.
    pub fn start_login(&self) -> Result<Login, Error> {
        let path = format!("/auth/{}/login", self.cfg.provider);
        let reply = self.get(&self.cfg.endpoint(&path))?;
        if reply.status != 302 && reply.status != 303 {
            return Err(Self::api_error(&reply));
        }
        let loc = reply
            .location
            .ok_or_else(|| Error::Transport("gateway redirect has no Location header".into()))?;
        let authorize_url = self
            .cfg
            .gateway_url
            .join(&loc)
            .map_err(|e| Error::Transport(format!("bad Location header: {e}")))?;
        let state = check_authorize_url(
            &authorize_url,
            &self.cfg.gateway_url,
            self.cfg.expected_idp_host.as_deref(),
        )?;
        Ok(Login {
            authorize_url,
            state,
        })
    }

    fn same_host(&self, u: &Url) -> bool {
        u.host_str() == self.cfg.gateway_url.host_str()
            && u.port_or_known_default() == self.cfg.gateway_url.port_or_known_default()
    }

    /// Completes a sign-in without a browser, but only while every redirect
    /// stays on the gateway's own host. That is true for the mock provider,
    /// which is why it is used for tests and demos. Real identity providers need
    /// a person at a browser and yield [`Error::LeavesGateway`].
    pub fn follow_local(&self, login: &Login) -> Result<Profile, Error> {
        let mut next = login.authorize_url.clone();
        if !self.same_host(&next) {
            return Err(Error::LeavesGateway);
        }
        for _ in 0..MAX_HOPS {
            let reply = self.get(next.as_str())?;
            match reply.status {
                200 => {
                    let p: Profile = serde_json::from_slice(&reply.body).map_err(|_| {
                        Error::Transport("callback response is not a profile".into())
                    })?;
                    if p.user.id.is_empty() {
                        return Err(Error::Transport(
                            "callback response is not a profile".into(),
                        ));
                    }
                    return Ok(p);
                }
                302 => {
                    let loc = reply.location.ok_or_else(|| {
                        Error::Transport("redirect has no Location header".into())
                    })?;
                    let target = next
                        .join(&loc)
                        .map_err(|e| Error::Transport(e.to_string()))?;
                    if !self.same_host(&target) {
                        return Err(Error::LeavesGateway);
                    }
                    next = target;
                }
                _ => return Err(Self::api_error(&reply)),
            }
        }
        Err(Error::Transport("too many redirects".into()))
    }
}
