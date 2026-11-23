//! `oauth2-rust` command line.
//!
//! ```text
//! oauth2-rust check            gateway reachable, provider registered
//! oauth2-rust login            print the URL to open in a browser
//! oauth2-rust login --follow   finish the sign-in without a browser (mock provider only)
//! ```

use std::io::Write;
use std::process::ExitCode;

use oauth2_rust::{Client, Config, Error};

/// Gateway provider id used when `SSO_PROVIDER` is unset.
const DEFAULT_PROVIDER: &str = "oauth2";

/// Runs one command and returns the exit code. Output goes to the given writers.
pub fn run<F>(args: &[String], getenv: F, out: &mut dyn Write, err: &mut dyn Write) -> u8
where
    F: Fn(&str) -> Option<String>,
{
    let Some(cmd) = args.first() else {
        let _ = writeln!(err, "usage: oauth2-rust check | login [--follow]");
        return 2;
    };
    let cfg = match Config::from_lookup(&getenv, DEFAULT_PROVIDER) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            return 2;
        }
    };
    let client = Client::new(cfg);
    match cmd.as_str() {
        "check" => cmd_check(&client, out, err),
        "login" => {
            let mut follow = false;
            for a in &args[1..] {
                match a.as_str() {
                    "--follow" => follow = true,
                    other => {
                        let _ = writeln!(err, "unknown option {other:?}");
                        return 2;
                    }
                }
            }
            cmd_login(&client, follow, out, err)
        }
        other => {
            let _ = writeln!(err, "unknown command {other:?}");
            2
        }
    }
}

fn cmd_check(client: &Client, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    if let Err(e) = client.health() {
        let _ = writeln!(err, "gateway check failed: {e}");
        return 1;
    }
    let ids = match client.providers() {
        Ok(ids) => ids,
        Err(e) => {
            let _ = writeln!(err, "listing providers failed: {e}");
            return 1;
        }
    };
    let _ = writeln!(out, "gateway ok, providers: {}", ids.join(", "));
    if ids.iter().any(|id| *id == client.config().provider) {
        0
    } else {
        let _ = writeln!(
            err,
            "provider {:?} is not registered in the gateway",
            client.config().provider
        );
        1
    }
}

fn cmd_login(client: &Client, follow: bool, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let login = match client.start_login() {
        Ok(l) => l,
        Err(e) => return report(&e, err),
    };
    if !follow {
        let _ = writeln!(out, "Open this URL in a browser to sign in:");
        let _ = writeln!(out, "{}", login.authorize_url);
        let _ = writeln!(out, "The identity provider returns the browser to the gateway callback, which completes the login.");
        return 0;
    }
    match client.follow_local(&login) {
        Ok(p) => {
            let _ = writeln!(
                out,
                "signed in via {} as {} ({})",
                p.provider_id, p.user.display_name, p.user.email
            );
            0
        }
        Err(e) => report(&e, err),
    }
}

fn report(e: &Error, err: &mut dyn Write) -> u8 {
    match e {
        Error::Api { code, message, .. } if code == "PROVIDER_NOT_FOUND" => {
            let _ = writeln!(err, "the gateway has no such provider ({message}). Its adapter may not be implemented yet: see Docs/Architecture.md");
        }
        Error::Policy(_) => {
            let _ = writeln!(err, "refused to continue: {e}");
        }
        _ => {
            let _ = writeln!(err, "login failed: {e}");
        }
    }
    1
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = run(
        &args,
        |k| std::env::var(k).ok(),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    );
    ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| m.get(k).cloned()
    }

    fn call(args: &[&str], pairs: &[(&str, &str)]) -> (u8, String, String) {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let code = run(&args, env(pairs), &mut o, &mut e);
        (
            code,
            String::from_utf8(o).unwrap(),
            String::from_utf8(e).unwrap(),
        )
    }

    #[test]
    fn usage_and_bad_input() {
        assert_eq!(call(&[], &[]).0, 2);
        assert_eq!(call(&["bogus"], &[]).0, 2);
        assert_eq!(call(&["check"], &[("SSO_GATEWAY_URL", "ftp://x")]).0, 2);
        assert_eq!(call(&["login", "--nope"], &[]).0, 2);
    }

    #[test]
    fn unreachable_gateway_exits_1() {
        let (code, _, err) = call(&["check"], &[("SSO_GATEWAY_URL", "http://127.0.0.1:1")]);
        assert_eq!(code, 1);
        assert!(err.contains("gateway check failed"));
    }
}
