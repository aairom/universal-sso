// Command ssoctl helps configure and verify provider setup without exposing secrets.
//
//	ssoctl google check    [--env FILE] [--offline]   validate the Google values in .env
//	ssoctl google url      [--env FILE]               print a browser URL (PKCE) for a manual sign-in
//	ssoctl google exchange [--env FILE] <code|URL>    exchange the code and verify the ID token claims
//
// Secret values are never printed. ID token signatures are NOT verified here;
// this tool is a setup diagnostic, not a login path.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const pkceFile = ".run/google-pkce.json"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, http.DefaultClient))
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: ssoctl google <check|url|exchange> [--env FILE] [--offline] [code-or-redirect-URL]")
}

func run(args []string, out, errw io.Writer, client *http.Client) int {
	if len(args) < 2 || args[0] != "google" {
		usage(errw)
		return 2
	}
	cmd := args[1]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(errw)
	envPath := fs.String("env", ".env", "path to the .env file")
	offline := fs.Bool("offline", false, "skip network checks (check only)")
	if err := fs.Parse(args[2:]); err != nil {
		return 2
	}

	env, err := loadEnvFile(*envPath)
	if err != nil {
		fmt.Fprintf(errw, "cannot read %s: %v\nCreate it with: cp .env.example .env\n", *envPath, err)
		return 1
	}

	switch cmd {
	case "check":
		return doCheck(out, env, *envPath, *offline, client)
	case "url":
		return doURL(out, errw, env)
	case "exchange":
		return doExchange(out, errw, env, fs.Args(), client)
	}
	usage(errw)
	return 2
}

func printFindings(w io.Writer, fs []Finding) (fails int) {
	for _, f := range fs {
		fmt.Fprintf(w, "[%-4s] %s\n", f.Level, f.Msg)
		if f.Level != OK && f.Fix != "" {
			fmt.Fprintf(w, "       fix: %s\n", f.Fix)
		}
		if f.Level == Fail {
			fails++
		}
	}
	return fails
}

func doCheck(out io.Writer, env map[string]string, path string, offline bool, c *http.Client) int {
	var findings []Finding
	if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 {
		findings = append(findings, Finding{Warn, fmt.Sprintf("%s is readable by other users (mode %o)", path, st.Mode().Perm()),
			"chmod 600 " + path})
	}
	findings = append(findings, checkGoogleEnv(env)...)
	if !offline {
		findings = append(findings, checkDiscovery(context.Background(), c))
	}
	fails := printFindings(out, findings)
	if fails > 0 {
		fmt.Fprintf(out, "\n%d problem(s) must be fixed. Re-run: make google-check\n", fails)
		return 1
	}
	fmt.Fprintln(out, "\nConfiguration looks consistent.")
	fmt.Fprintf(out, "Register this exact redirect URI in Google Cloud Console (Clients > your client):\n  %s\n", env[envRedirect])
	fmt.Fprintln(out, "Next: make google-url")
	return 0
}

func doURL(out, errw io.Writer, env map[string]string) int {
	if fails := countFails(checkGoogleEnv(env)); fails > 0 {
		fmt.Fprintln(errw, "Fix the configuration first: make google-check")
		return 1
	}
	s, err := newPKCESession()
	if err != nil {
		fmt.Fprintln(errw, "random generation failed:", err)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(pkceFile), 0o700); err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	data, _ := json.Marshal(s)
	if err := os.WriteFile(pkceFile, data, 0o600); err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	fmt.Fprintln(out, "1. Open this URL in your browser and sign in:")
	fmt.Fprintf(out, "\n%s\n\n", buildAuthURL(env, s))
	fmt.Fprintln(out, "2. Google redirects to your redirect URI. If nothing is listening there, the browser shows")
	fmt.Fprintln(out, "   a connection error; that is expected. Copy the FULL address-bar URL (it contains ?code=...).")
	fmt.Fprintln(out, "3. Run: make google-exchange CODE='<paste the full URL>'")
	fmt.Fprintln(out, "\nThe code is single use and expires within minutes.")
	return 0
}

func countFails(fs []Finding) int {
	n := 0
	for _, f := range fs {
		if f.Level == Fail {
			n++
		}
	}
	return n
}

func doExchange(out, errw io.Writer, env map[string]string, args []string, c *http.Client) int {
	if len(args) != 1 {
		fmt.Fprintln(errw, "usage: ssoctl google exchange [--env FILE] <code-or-redirect-URL>")
		return 2
	}
	if countFails(checkGoogleEnv(env)) > 0 {
		fmt.Fprintln(errw, "Fix the configuration first: make google-check")
		return 1
	}
	raw, err := os.ReadFile(pkceFile)
	if err != nil {
		fmt.Fprintln(errw, "no pending login found; run `make google-url` first")
		return 1
	}
	var s pkceSession
	if err := json.Unmarshal(raw, &s); err != nil {
		fmt.Fprintln(errw, "corrupt", pkceFile, "- run `make google-url` again")
		return 1
	}
	code, state, err := extractCode(args[0])
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	if code == "" {
		fmt.Fprintln(errw, "no code found in the input; paste the full redirected URL")
		return 1
	}
	if state != "" && state != s.State {
		fmt.Fprintln(errw, "state in the URL does not match the pending login (STATE_MISMATCH); run `make google-url` again")
		return 1
	}

	res, err := exchangeCode(context.Background(), c, env, code, s.Verifier)
	if err != nil {
		fmt.Fprintln(errw, "exchange failed:", err)
		fmt.Fprintln(errw, hintFor(err))
		return 1
	}
	_ = os.Remove(pkceFile) // single use

	fmt.Fprintf(out, "Token exchange succeeded (scope: %s, access token lifetime: %ds)\n\n", res.Scope, res.ExpiresIn)
	fails := printFindings(out, verifyClaims(res.Claims, env[envClientID], s.Nonce, time.Now()))
	fmt.Fprintln(out, "\nClaims (informational):")
	for _, k := range []string{"sub", "email_verified", "hd"} {
		if v, ok := res.Claims[k]; ok {
			fmt.Fprintf(out, "  %-15s %v\n", k, v)
		}
	}
	fmt.Fprintln(out, "\nNote: the signature was not verified here; the adapter must check it against Google's JWKS.")
	if fails > 0 {
		return 1
	}
	fmt.Fprintln(out, "The Google side is configured correctly.")
	return 0
}

// hintFor maps Google token endpoint errors to the troubleshooting section.
func hintFor(err error) string {
	msg := err.Error()
	switch {
	case strings.HasPrefix(msg, "invalid_client"):
		return "hint: wrong Client ID or secret (Docs/Google-SSO-Setup.md, 7.2)"
	case strings.HasPrefix(msg, "invalid_grant"):
		return "hint: code already used or expired, redirect_uri differs, or PKCE verifier mismatch (7.4); run `make google-url` for a fresh code"
	case strings.HasPrefix(msg, "redirect_uri_mismatch"):
		return "hint: redirect URI not registered on this client (7.1)"
	case errors.Is(err, context.DeadlineExceeded):
		return "hint: network timeout; check connectivity"
	}
	return "hint: see Docs/Google-SSO-Setup.md, section 7"
}
