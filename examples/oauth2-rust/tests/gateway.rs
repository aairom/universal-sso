//! Integration tests against an in-process fake gateway that mimics `ssod`.

use std::collections::HashMap;
use std::thread;

use oauth2_rust::policy::check_authorize_url;
use oauth2_rust::{Client, Config, Error};
use tiny_http::{Header, Response, Server};
use url::Url;

fn cfg(base: &str, provider: &str) -> Config {
    let m: HashMap<&str, String> = [
        ("SSO_GATEWAY_URL", base.to_string()),
        ("SSO_PROVIDER", provider.to_string()),
    ]
    .into();
    Config::from_lookup(|k| m.get(k).cloned(), "oauth2").unwrap()
}

/// Starts a fake gateway on a random loopback port and returns its base URL.
fn fake_gateway() -> String {
    let server = Server::http("127.0.0.1:0").unwrap();
    let base = format!("http://{}", server.server_addr().to_ip().unwrap());
    thread::spawn(move || {
        for req in server.incoming_requests() {
            let url = req.url().to_string();
            let path = url.split('?').next().unwrap_or("").to_string();
            let json = |code: u16, body: &str| {
                Response::from_string(body.to_string())
                    .with_status_code(code)
                    .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
            };
            let redirect = |to: &str| {
                Response::from_string("")
                    .with_status_code(302)
                    .with_header(Header::from_bytes("Location", to).unwrap())
            };
            match path.as_str() {
                "/healthz" => req.respond(json(200, r#"{"status":"ok"}"#)),
                "/providers" => req.respond(json(200, r#"{"providers":["mock","oauth2"]}"#)),
                "/auth/mock/login" => req.respond(redirect("/mock/authorize?state=s1&code_challenge=c&code_challenge_method=S256")),
                "/mock/authorize" => req.respond(redirect("/auth/mock/callback?code=mock-code&state=s1")),
                "/auth/mock/callback" => req.respond(json(
                    200,
                    r#"{"provider_id":"mock","user":{"id":"u1","email":"a@b.test","display_name":"Mock User"}}"#,
                )),
                "/auth/oauth2/login" => req.respond(redirect(
                    "https://idp.example.test/authorize?state=s2&code_challenge=c&code_challenge_method=S256",
                )),
                "/auth/missing/login" => req.respond(json(404, r#"{"code":"PROVIDER_NOT_FOUND","message":"missing"}"#)),
                "/auth/weak/login" => req.respond(redirect("https://idp.example.test/authorize?state=s3")),
                _ => req.respond(json(500, "boom")),
            }
            .unwrap();
        }
    });
    base
}

#[test]
fn health_and_providers() {
    let base = fake_gateway();
    let c = Client::new(cfg(&base, "mock"));
    c.health().unwrap();
    assert_eq!(c.providers().unwrap(), vec!["mock", "oauth2"]);
}

#[test]
fn mock_flow_completes_without_browser() {
    let base = fake_gateway();
    let c = Client::new(cfg(&base, "mock"));
    let login = c.start_login().unwrap();
    assert_eq!(login.state, "s1");
    let profile = c.follow_local(&login).unwrap();
    assert_eq!(profile.provider_id, "mock");
    assert_eq!(profile.user.email, "a@b.test");
}

#[test]
fn external_idp_needs_a_browser() {
    let base = fake_gateway();
    let c = Client::new(cfg(&base, "oauth2"));
    let login = c.start_login().unwrap();
    assert_eq!(login.state, "s2");
    assert!(matches!(c.follow_local(&login), Err(Error::LeavesGateway)));
}

#[test]
fn missing_provider_is_a_structured_error() {
    let base = fake_gateway();
    match Client::new(cfg(&base, "missing")).start_login() {
        Err(Error::Api {
            status: 404, code, ..
        }) => assert_eq!(code, "PROVIDER_NOT_FOUND"),
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn redirect_without_pkce_is_refused() {
    let base = fake_gateway();
    assert!(matches!(
        Client::new(cfg(&base, "weak")).start_login(),
        Err(Error::Policy(_))
    ));
}

#[test]
fn non_json_error_body_is_reported() {
    let base = fake_gateway();
    match Client::new(cfg(&base, "other")).start_login() {
        Err(Error::Api {
            status: 500,
            code,
            message,
        }) => {
            assert_eq!(code, "UNKNOWN");
            assert_eq!(message, "boom");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn unreachable_gateway() {
    let c = Client::new(cfg("http://127.0.0.1:1", "mock"));
    assert!(matches!(c.health(), Err(Error::Transport(_))));
}

#[test]
fn config_validation() {
    let lookup = |pairs: Vec<(&'static str, &'static str)>| {
        let m: HashMap<&str, &str> = pairs.into_iter().collect();
        Config::from_lookup(move |k| m.get(k).map(|v| v.to_string()), "oauth2")
    };
    assert!(lookup(vec![]).is_ok());
    assert!(lookup(vec![("SSO_GATEWAY_URL", "ftp://x")]).is_err());
    assert!(lookup(vec![("SSO_GATEWAY_URL", "http://gateway.example.test")]).is_err());
    assert!(lookup(vec![("SSO_PROVIDER", "Bad Provider")]).is_err());
    assert!(lookup(vec![("SSO_HTTP_TIMEOUT_SECONDS", "0")]).is_err());
    assert!(lookup(vec![("SSO_HTTP_TIMEOUT_SECONDS", "abc")]).is_err());
    let c = lookup(vec![
        ("SSO_GATEWAY_URL", "https://sso.example.test/base/"),
        ("SSO_EXPECTED_IDP_HOST", " IdP.Example.Test "),
    ])
    .unwrap();
    assert_eq!(
        c.endpoint("/healthz"),
        "https://sso.example.test/base/healthz"
    );
    assert_eq!(c.expected_idp_host.as_deref(), Some("idp.example.test"));
}

#[test]
fn policy_rules() {
    let gw = Url::parse("http://localhost:8080").unwrap();
    let ok = Url::parse(
        "https://idp.example.test/authorize?state=abc&code_challenge=x&code_challenge_method=S256",
    )
    .unwrap();
    assert_eq!(
        check_authorize_url(&ok, &gw, Some("example.test")).unwrap(),
        "abc"
    );
    for bad in [
        "javascript:alert(1)",
        "http://idp.example.test/a?state=a&code_challenge=x&code_challenge_method=S256",
        "https://evil.test/a?state=a&code_challenge=x&code_challenge_method=S256",
        "https://notexample.test/a?state=a&code_challenge=x&code_challenge_method=S256",
        "https://idp.example.test/a?code_challenge=x&code_challenge_method=S256",
        "https://idp.example.test/a?state=a",
        "https://idp.example.test/a?state=a&code_challenge=x&code_challenge_method=plain",
    ] {
        let u = Url::parse(bad).unwrap();
        assert!(
            check_authorize_url(&u, &gw, Some("example.test")).is_err(),
            "should refuse {bad}"
        );
    }
    let local = Url::parse(
        "http://localhost:8080/mock/authorize?state=a&code_challenge=x&code_challenge_method=S256",
    )
    .unwrap();
    assert!(check_authorize_url(&local, &gw, None).is_ok());
}
