package main

import (
	"bytes"
	"html/template"
	"net/http"
)

// providerView describes how a provider is shown on the landing page.
type providerView struct {
	ID    string
	Label string
	Hint  string
	Icon  string // key into the icon set in landingTmpl
}

// providerViews are display details for known providers. Unknown IDs get a generic entry.
var providerViews = map[string]providerView{
	"google": {Label: "Continue with Google", Hint: "OpenID Connect with PKCE", Icon: "google"},
	"mock":   {Label: "Continue with Mock", Hint: "Local test identity, no real account", Icon: "mock"},
}

func viewFor(id string) providerView {
	v, ok := providerViews[id]
	if !ok {
		v = providerView{Label: "Continue with " + id, Hint: "Single sign-on", Icon: "key"}
	}
	v.ID = id
	return v
}

const landingHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Universal SSO</title>
<style>
:root{
  --bg:#f4f6fb;--card:#ffffff;--text:#161b2e;--muted:#5b6478;--line:#e3e7f1;
  --accent:#4f6df5;--accent2:#8b5cf6;--ok:#16a34a;--shadow:0 10px 40px rgba(31,45,95,.12);
}
@media (prefers-color-scheme:dark){
  :root{--bg:#0d1020;--card:#161a2f;--text:#eef1fb;--muted:#9aa4c0;--line:#272d4a;--shadow:0 10px 40px rgba(0,0,0,.45)}
}
*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0;display:flex;align-items:center;justify-content:center;padding:24px;color:var(--text);
  font:16px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  background:
    radial-gradient(900px 500px at 12% -10%,rgba(79,109,245,.22),transparent 60%),
    radial-gradient(800px 500px at 100% 110%,rgba(139,92,246,.20),transparent 60%),
    var(--bg);
}
.card{width:100%;max-width:420px;background:var(--card);border:1px solid var(--line);border-radius:20px;box-shadow:var(--shadow);padding:36px 32px 24px}
.logo{width:56px;height:56px;border-radius:16px;display:grid;place-items:center;margin:0 auto 18px;
  background:linear-gradient(135deg,var(--accent),var(--accent2));box-shadow:0 8px 20px rgba(79,109,245,.35)}
.logo svg{width:30px;height:30px;fill:none;stroke:#fff;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
h1{margin:0;text-align:center;font-size:1.65rem;letter-spacing:-.02em;font-weight:750}
.sub{margin:6px 0 26px;text-align:center;color:var(--muted);font-size:.95rem}
ul{list-style:none;margin:0;padding:0;display:grid;gap:12px}
.btn{display:flex;align-items:center;gap:14px;text-decoration:none;color:inherit;padding:14px 16px;border:1px solid var(--line);
  border-radius:14px;background:var(--card);transition:transform .12s ease,border-color .12s ease,box-shadow .12s ease}
.btn:hover,.btn:focus-visible{transform:translateY(-1px);border-color:var(--accent);box-shadow:0 6px 18px rgba(79,109,245,.18);outline:none}
.btn:focus-visible{box-shadow:0 0 0 3px rgba(79,109,245,.35)}
.ico{flex:none;width:40px;height:40px;border-radius:10px;display:grid;place-items:center;background:var(--bg);border:1px solid var(--line)}
.ico svg{width:22px;height:22px}
.txt{flex:1;min-width:0}
.txt b{display:block;font-weight:650}
.txt span{display:block;color:var(--muted);font-size:.82rem}
.arrow{flex:none;width:18px;height:18px;stroke:var(--muted);fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.empty{padding:16px;border:1px dashed var(--line);border-radius:14px;color:var(--muted);text-align:center}
.foot{margin-top:26px;padding-top:16px;border-top:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;
  gap:12px;flex-wrap:wrap;font-size:.82rem;color:var(--muted)}
.foot a{color:var(--muted);text-decoration:none;border-bottom:1px dotted var(--muted)}
.foot a:hover{color:var(--accent);border-color:var(--accent)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--ok);margin-right:6px;box-shadow:0 0 0 3px rgba(22,163,74,.2)}
.links{display:flex;gap:14px}
@media (prefers-reduced-motion:reduce){.btn{transition:none}}
</style>
</head>
<body>
<main class="card">
  <div class="logo" aria-hidden="true">
    <svg viewBox="0 0 24 24"><path d="M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6l7-3z"/><path d="M9 12l2.2 2.2L15.5 10"/></svg>
  </div>
  <h1>Universal SSO</h1>
  <p class="sub">One secure sign-in for every identity provider</p>

  {{if .Providers}}
  <ul>
  {{range .Providers}}
    <li>
      <a class="btn" href="/auth/{{.ID}}/login">
        <span class="ico" aria-hidden="true">
        {{if eq .Icon "google"}}
          <svg viewBox="0 0 24 24"><path fill="#4285F4" d="M23 12.27c0-.8-.07-1.56-.2-2.3H12v4.35h6.17a5.28 5.28 0 0 1-2.29 3.46v2.87h3.7C21.74 18.65 23 15.7 23 12.27z"/><path fill="#34A853" d="M12 23.5c3.1 0 5.7-1.03 7.6-2.8l-3.7-2.87c-1.03.69-2.35 1.1-3.9 1.1-3 0-5.54-2.02-6.45-4.74H1.73v2.97A11.5 11.5 0 0 0 12 23.5z"/><path fill="#FBBC05" d="M5.55 14.19a6.9 6.9 0 0 1 0-4.38V6.84H1.73a11.5 11.5 0 0 0 0 10.32l3.82-2.97z"/><path fill="#EA4335" d="M12 5.07c1.69 0 3.2.58 4.4 1.72l3.28-3.28C17.7 1.65 15.1.5 12 .5A11.5 11.5 0 0 0 1.73 6.84l3.82 2.97C6.46 7.09 9 5.07 12 5.07z"/></svg>
        {{else if eq .Icon "mock"}}
          <svg viewBox="0 0 24 24" fill="none" stroke="#8b5cf6" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="3.5"/><path d="M5 20c0-3.6 3.1-6 7-6s7 2.4 7 6"/></svg>
        {{else}}
          <svg viewBox="0 0 24 24" fill="none" stroke="#4f6df5" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3"/></svg>
        {{end}}
        </span>
        <span class="txt"><b>{{.Label}}</b><span>{{.Hint}}</span></span>
        <svg class="arrow" viewBox="0 0 24 24" aria-hidden="true"><path d="M9 6l6 6-6 6"/></svg>
      </a>
    </li>
  {{end}}
  </ul>
  {{else}}
  <div class="empty">No identity providers are configured.</div>
  {{end}}

  <div class="foot">
    <span><span class="dot" aria-hidden="true"></span>Server online</span>
    <span class="links"><a href="/providers">Providers</a><a href="/healthz">Health</a></span>
  </div>
</main>
</body>
</html>
`

var landingTmpl = template.Must(template.New("landing").Parse(landingHTML))

// renderLanding renders the landing page for the given provider IDs.
func renderLanding(ids []string) ([]byte, error) {
	views := make([]providerView, 0, len(ids))
	for _, id := range ids {
		views = append(views, viewFor(id))
	}
	var buf bytes.Buffer
	if err := landingTmpl.Execute(&buf, struct{ Providers []providerView }{views}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// landingHandler serves the landing page with a restrictive CSP: inline CSS
// only, no scripts, no external resources, no framing.
func landingHandler(providers func() []string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		page, err := renderLanding(providers())
		if err != nil {
			writeError(w, err)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		_, _ = w.Write(page)
	}
}
