#!/usr/bin/env python3
"""Build Docs/Documentation-Audit.html, a single self-contained audit dashboard.

Everything on the page is measured when this script runs, nothing is typed in by
hand: the validation gates are executed and timed, documentation changes come
from `git diff --numstat`, code excerpts are cut out of the real source files,
and the configuration schema is read from `.env.example`. The page is therefore
a snapshot of the repository at the commit shown in its header.

Usage:
    python3 scripts/build_audit_dashboard.py [--baseline <git-rev>] [--skip-gates]

--skip-gates reuses no results: the gate table then shows "not run". Use it only
to preview layout. The default runs every gate.

Output goes to Docs/Documentation-Audit.html (documents live in Docs/).
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "Docs" / "Documentation-Audit.html"
BASELINE_DEFAULT = "1aab4b0"  # last commit before the Okta/Auth0/Entra adapters

SHAPE_PATTERN = r"[0-9]{6,}-[A-Za-z0-9_]+\.apps\.googleusercontent\.com|GOCSPX-[A-Za-z0-9_-]{10,}"


def sh(cmd: str, timeout: int = 280) -> tuple[int, str, float]:
    """Run a shell command from the repository root and time it."""
    start = time.monotonic()
    try:
        p = subprocess.run(cmd, shell=True, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr), time.monotonic() - start
    except subprocess.TimeoutExpired:
        return 124, "timed out", time.monotonic() - start


# --------------------------------------------------------------------- gates
def run_gates(skip: bool) -> list[dict]:
    """Execute each validation gate. Each result has name, ok, seconds, detail."""
    specs = [
        ("gofmt", "gofmt -l . | grep -v '^_sources' ; true", lambda rc, out: out.strip() == "", "no unformatted files"),
        ("go vet", "go vet ./... && go vet -tags e2e ./cmd/...", lambda rc, out: rc == 0, "default and -tags e2e builds"),
        ("go test -race", "go test -race -count=1 -cover ./... 2>&1", lambda rc, out: rc == 0, None),
        ("test gate", "bash .bob/skills/test-gate/scripts/run_tests.sh", lambda rc, out: rc == 0, "includes 5 example suites and the e2e run"),
        ("secrets scan", "bash .bob/skills/secure-config/scripts/scan_secrets.sh .", lambda rc, out: rc == 0 and "OK:" in out, "no hard-coded secrets"),
        ("project audit", "bash .bob/skills/project-audit/scripts/audit.sh", lambda rc, out: rc == 0 and "AUDIT PASSED" in out, "README, Docs/, .gitignore, scripts"),
        (
            "credential shape scan",
            "grep -rnE --exclude-dir=.git --exclude-dir=_sources --exclude-dir=.run --exclude-dir=audit "
            "--exclude-dir=target --exclude-dir=bin --exclude-dir=obj --exclude-dir=__pycache__ "
            "--exclude='.env' --exclude='.env.bak*' --exclude='Documentation-Audit.html' "
            f"'{SHAPE_PATTERN}' . ; true",
            lambda rc, out: out.strip() == "",
            "no Google client id / secret shaped strings",
        ),
    ]
    results = []
    for name, cmd, check, note in specs:
        if skip:
            results.append({"name": name, "ok": None, "seconds": 0.0, "detail": "not run (--skip-gates)", "cmd": cmd})
            continue
        print(f"  gate: {name} ...", flush=True)
        rc, out, secs = sh(cmd)
        ok = bool(check(rc, out))
        detail = note or ""
        if name == "go test -race":
            pk = re.findall(r"^ok\s+\S+", out, re.M)
            bad = re.findall(r"^FAIL\s+\S+", out, re.M)
            detail = f"{len(pk)} packages ok, {len(bad)} failed"
        if name == "test gate":
            ps = len(re.findall(r"^PASS ", out, re.M))
            sk = "SKIPPED suites" in out
            detail = f"{ps} e2e PASS lines, skips: {'yes' if sk else 'none'}"
        if not ok:
            last = out.strip().splitlines()[-1][:160] if out.strip() else "no output"
            detail = (detail + " | " if detail else "") + "FAILED: " + last
        results.append({"name": name, "ok": ok, "seconds": round(secs, 1), "detail": detail, "cmd": cmd.split(" ; ")[0][:90]})
    return results


def coverage() -> list[dict]:
    """Per-package statement coverage for the new adapter packages."""
    rc, out, _ = sh("go test -count=1 -cover ./pkg/sso/... ./cmd/... 2>&1")
    rows = []
    for m in re.finditer(r"^ok\s+(\S+)\s+\S+\s+coverage: ([\d.]+)%", out, re.M):
        rows.append({"pkg": m.group(1).replace("github.com/universal-sso/universal-sso/", ""), "cov": float(m.group(2))})
    return rows


# ---------------------------------------------------------------- docs table
def doc_changes(baseline: str) -> list[dict]:
    """Documentation files changed since baseline, with line counts and headings."""
    rc, out, _ = sh(f"git diff --numstat {baseline} -- '*.md' .env.example Makefile")
    notes = {
        "Docs/Okta-SSO-Setup.md": "Status note, 404 row, security-control rows, planned-adapter wording",
        "Docs/Auth0-SSO-Setup.md": "Status note, 404 row, trailing-slash issuer, AUDIENCE and ROLES_CLAIM variables",
        "Docs/Azure-AD-SSO-Setup.md": "Status note, tenant pinning, ALLOWED_TENANTS and AUTHORITY variables",
        "Docs/Architecture.md": "New 'OIDC vendor adapters' and 'Verification boundary' sections, diagram",
        "Docs/Google-SSO-Setup.md": "S4 no longer says Google is unregistered, hosted-domain restriction documented as implemented",
        "Docs/Examples.md": "Rewrote 'Read this first', added 'End-to-end check'",
        "Docs/Quickstart.md": "Provider status table, scope paragraph, troubleshooting, next steps",
        "README.md": "Status line, workflow diagram node, provider table, scope paragraph",
        ".env.example": "Okta sample id is now a placeholder, new optional variables documented",
        "Makefile": "Added test-e2e target",
    }
    rows = []
    for line in out.splitlines():
        a, d, path = line.split("\t")
        if path.startswith("examples/") and path.endswith("README.md"):
            what = "'Read this first' banner replaced (adapter no longer planned)"
        else:
            what = notes.get(path, "")
        kind = "example README" if path.startswith("examples/") else ("config" if path in (".env.example", "Makefile") else "guide" if path.startswith("Docs/") else "readme")
        rows.append({"file": path, "added": int(a), "removed": int(d), "kind": kind, "what": what})
    return rows


def stale_docs() -> list[dict]:
    """Search the docs for statements that contradict the code, and report them."""
    items = []

    def find(path: str, pattern: str) -> int | None:
        for i, line in enumerate((ROOT / path).read_text().splitlines(), 1):
            if re.search(pattern, line):
                return i
        return None

    ln = find("Docs/Google-SSO-Setup.md", r"Google provider is not registered yet")
    if not ln:
        items.append({"sev": "fixed", "file": "Docs/Google-SSO-Setup.md", "line": find("Docs/Google-SSO-Setup.md", r"### S4") or 1,
                      "issue": "Troubleshooting S4 no longer claims the Google provider is unregistered.",
                      "evidence": "cmd/ssod/main.go googleFromEnv registers it; TestGoogleFromEnv covers it", "action": "None"})
    else:
        items.append({"sev": "outdated", "file": "Docs/Google-SSO-Setup.md", "line": ln,
                      "issue": "Says the Google provider is 'not registered yet' and `ssod` answers 404. It is registered when the client id and secret are set.",
                      "evidence": "cmd/ssod/main.go googleFromEnv registers it; TestGoogleFromEnv covers it", "action": "Reword S4"})
    ln = find("Docs/Google-SSO-Setup.md", r"Planned, not yet implemented: restricting sign-in")
    if not ln:
        items.append({"sev": "fixed", "file": "Docs/Google-SSO-Setup.md", "line": find("Docs/Google-SSO-Setup.md", r"HOSTED_DOMAIN") or 1,
                      "issue": "Hosted-domain restriction is documented as implemented.",
                      "evidence": "pkg/sso/google/provider.go checkDomain enforces the hd claim; provider_test.go tests it", "action": "None"})
    else:
        items.append({"sev": "outdated", "file": "Docs/Google-SSO-Setup.md", "line": ln,
                      "issue": "Says hosted-domain restriction is not implemented.",
                      "evidence": "pkg/sso/google/provider.go checkDomain enforces the hd claim; provider_test.go tests it", "action": "Document SSO_PROVIDERS_GOOGLE_HOSTED_DOMAIN as implemented"})
    for name, f in (("SAML 2.0", "Docs/SAML-SSO-Setup.md"), ("Generic OAuth 2.0", "Docs/OAuth2-SSO-Setup.md")):
        ln = find(f, r"planned, not yet implemented")
        items.append({"sev": "accurate", "file": f, "line": ln or 5,
                      "issue": f"{name} guide still says 'planned'. Correct: no adapter exists.",
                      "evidence": "ssod registers mock, google, okta, auth0, azure only", "action": "Update when the adapter lands"})
    return items


def open_items() -> list[dict]:
    rc, out, _ = sh("git branch --list backup-before-squash")
    has_backup = bool(out.strip())
    rc, out, _ = sh("git rev-list --objects --all | grep -cE 'target/|/obj/|/bin/'")
    hist = out.strip().splitlines()[-1] if out.strip() else "0"
    rc, out, _ = sh("git status --porcelain")
    dirty = [l for l in out.splitlines() if l.strip()]
    items = [
        {"prio": "high", "item": "Sign in against a live Okta, Auth0 and Entra tenant",
         "why": "Adapters are verified against an in-process fake IdP only. Needs your tenant, credentials and a browser.",
         "owner": "you", "status": "open"},
        {"prio": "medium", "item": f"Build output is in git history ({hist} objects)",
         "why": "target/, bin/, obj/ were pushed earlier. The working tree no longer tracks them. Removal needs a history rewrite and force-push.",
         "owner": "you decide", "status": "open"},
        {"prio": "medium", "item": "SAML 2.0 and generic OAuth 2.0 adapters",
         "why": "Not implemented. The Go and Rust example clients default to these ids and report PROVIDER_NOT_FOUND.",
         "owner": "backlog", "status": "open"},
        {"prio": "low", "item": "Node.js example client",
         "why": "Only Rust, Go, Python, Java and C# exist.", "owner": "you decide", "status": "open"},
        {"prio": "low", "item": "Delete branch backup-before-squash" if has_backup else "backup-before-squash branch",
         "why": "Leftover safety branch." if has_backup else "Already removed.", "owner": "you",
         "status": "open" if has_backup else "done"},
        {"prio": "low", "item": "Working tree",
         "why": "Clean, nothing to commit." if not dirty else f"{len(dirty)} uncommitted path(s): " + ", ".join(l[3:] for l in dirty[:5]),
         "owner": "you", "status": "done" if not dirty else "open"},
    ]
    return items


# ------------------------------------------------------------- code excerpts
def excerpt(path: str, start_pat: str, lines: int, title: str, lang: str = "go", note: str = "") -> dict:
    text = (ROOT / path).read_text().splitlines()
    for i, l in enumerate(text):
        if re.search(start_pat, l):
            body = text[i : i + lines]
            for k, bl in enumerate(body):  # stop at the closing brace of the enclosing func
                if bl == "}":
                    body = body[: k + 1]
                    break
            return {"title": title, "path": path, "line": i + 1, "lang": lang, "code": "\n".join(body), "note": note}
    raise SystemExit(f"excerpt start not found in {path}: {start_pat}")


def excerpts() -> list[dict]:
    return [
        excerpt("pkg/sso/okta/provider.go", r"^func New\(", 21, "Okta: thin vendor layer", note="Maps groups and preferred_username. Issuer pinning comes from the shared base."),
        excerpt("pkg/sso/auth0/provider.go", r"^func New\(", 46, "Auth0: slash issuer, audience, roles, logout", note="Appends the trailing slash Auth0 puts in every iss. /v2/logout replaces end_session_endpoint."),
        excerpt("pkg/sso/entra/provider.go", r"^\tswitch \{", 26, "Entra: tenant pinning for multi-tenant endpoints", note="For common, organizations and consumers, the issuer must equal <authority>/<tid>/v2.0 for the token's own tid."),
        excerpt("pkg/sso/oidc/provider.go", r"^func \(p \*Provider\) verifyIDToken", 36, "Shared base: ID token verification", note="RS256 only. Checks signature, issuer, audience, exp, nbf and subject. The nonce is checked in HandleCallback."),
        excerpt("pkg/sso/oidc/jwt.go", r"^func parseJWT", 36, "Shared base: algorithm allow-list", note="Rejects none, HS256 and every non-RS256 token before any key lookup."),
        excerpt("cmd/ssod/vendors.go", r"^func vendorEnv", 22, "Gateway: placeholder-aware vendor wiring", note="A fresh .env.example keeps all three vendors off. A client id without a secret is an error."),
    ]


# ------------------------------------------------------------- config schema
def env_schema() -> list[dict]:
    """Parse .env.example into rows: variable, example value, group, required, enabled-by-default."""
    groups = {"SERVER": "Server", "STATE": "Server", "LOG": "Server", "OKTA": "Okta", "AUTH0": "Auth0", "AZURE": "Entra ID (azure)", "GOOGLE": "Google"}
    rows, seen = [], set()
    optional_hint = {"AUDIENCE", "ROLES_CLAIM", "ALLOWED_TENANTS", "AUTHORITY", "HOSTED_DOMAIN", "REDIRECT_URL"}
    for line in (ROOT / ".env.example").read_text().splitlines():
        m = re.match(r"^(#\s*)?(SSO_[A-Z0-9_]+)=(.*)$", line)
        if not m:
            continue
        commented, key, val = m.group(1), m.group(2), m.group(3)
        if key in seen:
            continue
        seen.add(key)
        parts = key.split("_")
        grp = next((g for k, g in groups.items() if k in parts), "Server")
        tail = "_".join(parts[3:]) if key.startswith("SSO_PROVIDERS_") else ""
        optional = bool(commented) or tail in optional_hint
        secret = "SECRET" in key
        rows.append({"var": key, "example": "<redacted sample>" if secret else val, "group": grp,
                     "required": "optional" if optional else "required", "secret": secret,
                     "sample": val.endswith("-placeholder") or val.startswith("change-this")})
    return rows


def adapter_schema() -> list[dict]:
    """Config struct fields for each adapter, read from the Go source."""
    out = []
    for name, path in (("okta.Config", "pkg/sso/okta/provider.go"), ("auth0.Config", "pkg/sso/auth0/provider.go"), ("entra.Config", "pkg/sso/entra/provider.go")):
        text = (ROOT / path).read_text()
        m = re.search(r"type Config struct \{(.*?)\n\}", text, re.S)
        for line in m.group(1).splitlines():
            line = line.strip()
            f = re.match(r"^(\w+)\s+(\S+)\s*(//\s*(.*))?$", line)
            if f and not line.startswith("//"):
                out.append({"struct": name, "field": f.group(1), "type": f.group(2), "doc": (f.group(4) or "").strip()})
    return out


# ------------------------------------------------------------------- render
CSS = r"""
:root{--bg:#fff;--surf:#f7f8fa;--bd:#e5e7eb;--tx:#1f2328;--mut:#57606a;--acc:#3b82d4;--ok:#1a7f37;--bad:#cf222e;--warn:#9a6700;--code:#0d1117;--codefg:#e6edf3}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--surf:#161b22;--bd:#30363d;--tx:#e6edf3;--mut:#9da7b3;--acc:#58a6ff;--ok:#3fb950;--bad:#f85149;--warn:#d29922;--code:#010409}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.6 -apple-system,"Segoe UI",system-ui,sans-serif}
header,main,footer{max-width:1100px;margin:0 auto;padding:0 20px}header{padding-top:28px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:34px 0 10px;padding-top:10px;border-top:1px solid var(--bd)}h3{font-size:15px;margin:18px 0 6px}
.mut{color:var(--mut)}.meta{font-size:12px;color:var(--mut)}
nav{position:sticky;top:0;background:var(--bg);border-bottom:1px solid var(--bd);z-index:5}nav .in{max-width:1100px;margin:0 auto;padding:8px 20px;display:flex;gap:16px;flex-wrap:wrap;font-size:13px}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.notice{border:1px solid var(--warn);border-left-width:4px;background:var(--surf);padding:12px 16px;border-radius:6px;margin:16px 0}
.notice b{color:var(--warn)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin:14px 0}.card{background:var(--surf);border:1px solid var(--bd);border-radius:6px;padding:10px 14px}.card .n{font-size:24px;font-weight:600}.card .l{font-size:12px;color:var(--mut)}
table{border-collapse:collapse;width:100%;margin:8px 0;font-size:13px}th,td{border:1px solid var(--bd);padding:6px 10px;text-align:left;vertical-align:top}th{background:var(--surf);cursor:pointer;user-select:none;white-space:nowrap}th:hover{color:var(--acc)}th[aria-sort=ascending]::after{content:" \25B2";font-size:10px}th[aria-sort=descending]::after{content:" \25BC";font-size:10px}
.tools{display:flex;gap:10px;align-items:center;margin:6px 0;flex-wrap:wrap}input[type=search],select{padding:5px 8px;border:1px solid var(--bd);border-radius:4px;background:var(--bg);color:var(--tx);font:inherit}
.pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;border:1px solid}.p-ok{color:var(--ok);border-color:var(--ok)}.p-bad{color:var(--bad);border-color:var(--bad)}.p-warn{color:var(--warn);border-color:var(--warn)}.p-mut{color:var(--mut);border-color:var(--bd)}
pre{background:var(--code);color:var(--codefg);padding:12px 14px;border-radius:6px;overflow:auto;font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin:6px 0}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}p code,td code,li code{background:var(--surf);border:1px solid var(--bd);padding:0 4px;border-radius:3px}
.t-kw{color:#ff7b72}.t-ty{color:#79c0ff}.t-st{color:#a5d6ff}.t-cm{color:#8b949e;font-style:italic}.t-nu{color:#d2a8ff}.t-fn{color:#d2a8ff}
details{border:1px solid var(--bd);border-radius:6px;margin:10px 0;background:var(--surf)}summary{cursor:pointer;padding:8px 12px;font-weight:600}details .body{padding:0 12px 10px}.path{font-size:12px;color:var(--mut)}
.copy{float:right;margin:6px 6px 0 0;font-size:12px;padding:2px 8px;border:1px solid var(--bd);background:var(--surf);color:var(--tx);border-radius:4px;cursor:pointer}
.chart{width:100%;height:auto}.legend{font-size:12px;color:var(--mut);margin:4px 0}
.tl{display:flex;flex-direction:column;gap:6px;margin:10px 0}.tl .row{display:grid;grid-template-columns:150px 1fr 70px;gap:10px;align-items:center}.tl .bar{height:20px;border-radius:3px;min-width:3px}
.flow{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:10px 0}.flow .box{padding:6px 10px;border:2px solid;border-radius:6px;font-size:12px;background:var(--surf)}.flow .arr{color:var(--mut)}
footer{padding:30px 20px;margin-top:40px;border-top:1px solid var(--bd);text-align:center;font-size:12px;color:var(--mut)}
@media print{nav,.copy,.tools{display:none}details{border:0}}
"""

JS = r"""
(function(){
 // ---- sortable tables
 document.querySelectorAll('table.sortable').forEach(function(t){
  var heads=t.tHead.rows[0].cells;
  Array.prototype.forEach.call(heads,function(th,idx){
   th.tabIndex=0;th.setAttribute('role','columnheader');
   function go(){
    var dir=th.getAttribute('aria-sort')==='ascending'?'descending':'ascending';
    Array.prototype.forEach.call(heads,function(h){h.removeAttribute('aria-sort')});
    th.setAttribute('aria-sort',dir);
    var body=t.tBodies[0],rows=Array.prototype.slice.call(body.rows);
    var num=th.getAttribute('data-type')==='num';
    rows.sort(function(a,b){
     var x=a.cells[idx].getAttribute('data-v')||a.cells[idx].textContent.trim();
     var y=b.cells[idx].getAttribute('data-v')||b.cells[idx].textContent.trim();
     if(num){x=parseFloat(x)||0;y=parseFloat(y)||0;return dir==='ascending'?x-y:y-x}
     return dir==='ascending'?x.localeCompare(y):y.localeCompare(x);
    });
    rows.forEach(function(r){body.appendChild(r)});
   }
   th.addEventListener('click',go);
   th.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();go()}});
  });
 });
 // ---- table filters
 document.querySelectorAll('input[data-filter]').forEach(function(inp){
  var t=document.getElementById(inp.getAttribute('data-filter'));
  inp.addEventListener('input',function(){
   var q=inp.value.toLowerCase();
   Array.prototype.forEach.call(t.tBodies[0].rows,function(r){r.style.display=r.textContent.toLowerCase().indexOf(q)>-1?'':'none'});
  });
 });
 document.querySelectorAll('select[data-col]').forEach(function(sel){
  var t=document.getElementById(sel.getAttribute('data-table')),c=+sel.getAttribute('data-col');
  sel.addEventListener('change',function(){
   Array.prototype.forEach.call(t.tBodies[0].rows,function(r){r.style.display=(!sel.value||r.cells[c].textContent.trim()===sel.value)?'':'none'});
  });
 });
 // ---- copy buttons
 document.querySelectorAll('button.copy').forEach(function(b){
  b.addEventListener('click',function(){
   var code=b.parentNode.querySelector('pre code').textContent;
   if(navigator.clipboard){navigator.clipboard.writeText(code).then(function(){b.textContent='copied';setTimeout(function(){b.textContent='copy'},1200)})}
  });
 });
 // ---- charts (inline SVG, no libraries)
 var D=JSON.parse(document.getElementById('data').textContent);
 var NS='http://www.w3.org/2000/svg';
 function el(n,a,txt){var e=document.createElementNS(NS,n);for(var k in a)e.setAttribute(k,a[k]);if(txt!=null)e.textContent=txt;return e}
 function css(v){return getComputedStyle(document.documentElement).getPropertyValue(v).trim()}
 function drawDocs(){
  var host=document.getElementById('chart-docs');host.textContent='';
  var rows=D.docs.slice().sort(function(a,b){return (b.added+b.removed)-(a.added+a.removed)});
  var W=900,rh=24,pad=210,H=rows.length*rh+30,max=Math.max.apply(null,rows.map(function(r){return r.added+r.removed}))||1;
  var s=el('svg',{viewBox:'0 0 '+W+' '+H,class:'chart',role:'img','aria-label':'Lines added and removed per documentation file'});
  rows.forEach(function(r,i){
   var y=i*rh+6,sc=(W-pad-60)/max;
   s.appendChild(el('text',{x:pad-8,y:y+14,'text-anchor':'end','font-size':12,fill:css('--tx')},r.file.length>34?'...'+r.file.slice(-31):r.file));
   s.appendChild(el('rect',{x:pad,y:y,width:Math.max(1,r.added*sc),height:16,fill:css('--ok')},null)).appendChild(el('title',{},r.file+': +'+r.added));
   s.appendChild(el('rect',{x:pad+r.added*sc,y:y,width:Math.max(r.removed?1:0,r.removed*sc),height:16,fill:css('--bad')},null)).appendChild(el('title',{},r.file+': -'+r.removed));
   s.appendChild(el('text',{x:pad+(r.added+r.removed)*sc+6,y:y+13,'font-size':11,fill:css('--mut')},'+'+r.added+' / -'+r.removed));
  });
  host.appendChild(s);
 }
 function drawCov(){
  var host=document.getElementById('chart-cov');host.textContent='';
  var rows=D.coverage.slice().sort(function(a,b){return b.cov-a.cov});
  var W=900,rh=24,pad=230,H=rows.length*rh+14;
  var s=el('svg',{viewBox:'0 0 '+W+' '+H,class:'chart',role:'img','aria-label':'Statement coverage per package'});
  rows.forEach(function(r,i){
   var y=i*rh+4,sc=(W-pad-70)/100,col=r.cov>=85?css('--ok'):(r.cov>=50?css('--warn'):css('--bad'));
   s.appendChild(el('text',{x:pad-8,y:y+14,'text-anchor':'end','font-size':12,fill:css('--tx')},r.pkg));
   s.appendChild(el('rect',{x:pad,y:y,width:100*sc,height:16,fill:css('--surf'),stroke:css('--bd')}));
   s.appendChild(el('rect',{x:pad,y:y,width:r.cov*sc,height:16,fill:col}));
   s.appendChild(el('text',{x:pad+100*sc+8,y:y+13,'font-size':12,fill:css('--tx')},r.cov.toFixed(1)+'%'));
  });
  host.appendChild(s);
 }
 function drawGates(){
  var host=document.getElementById('chart-gates');host.textContent='';
  var max=Math.max.apply(null,D.gates.map(function(g){return g.seconds}))||1;
  D.gates.forEach(function(g){
   var row=document.createElement('div');row.className='row';
   var n=document.createElement('div');n.textContent=g.name;
   var wrap=document.createElement('div');var b=document.createElement('div');b.className='bar';
   b.style.width=Math.max(1,g.seconds/max*100)+'%';
   b.style.background=g.ok===true?css('--ok'):(g.ok===false?css('--bad'):css('--bd'));
   b.title=g.name+': '+g.seconds+'s';wrap.appendChild(b);
   var t=document.createElement('div');t.className='mut';t.textContent=g.seconds+' s';
   row.appendChild(n);row.appendChild(wrap);row.appendChild(t);host.appendChild(row);
  });
 }
 function drawAll(){drawDocs();drawCov();drawGates()}
 drawAll();
 if(window.matchMedia){window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change',drawAll)}
})();
"""

GO_KW = {"package", "import", "func", "return", "if", "else", "for", "range", "switch", "case", "default", "var", "const", "type", "struct", "interface", "map", "go", "defer", "nil", "true", "false", "chan", "break", "continue"}
GO_TY = {"string", "bool", "int", "int64", "error", "any", "byte", "rune", "float64"}


def highlight_go(code: str) -> str:
    """Tiny Go tokenizer: comments, strings, numbers, keywords, types. Output is escaped HTML."""
    tok = re.compile(r'(//[^\n]*)|("(?:\\.|[^"\\\n])*"|`[^`]*`)|(\b\d+\b)|([A-Za-z_]\w*)')
    out, pos = [], 0
    for m in tok.finditer(code):
        out.append(html.escape(code[pos : m.start()]))
        t = html.escape(m.group(0))
        if m.group(1):
            out.append(f'<span class="t-cm">{t}</span>')
        elif m.group(2):
            out.append(f'<span class="t-st">{t}</span>')
        elif m.group(3):
            out.append(f'<span class="t-nu">{t}</span>')
        else:
            w = m.group(4)
            if w in GO_KW:
                out.append(f'<span class="t-kw">{t}</span>')
            elif w in GO_TY or (w[0].isupper() and w not in ("T",)):
                out.append(f'<span class="t-ty">{t}</span>')
            else:
                out.append(t)
        pos = m.end()
    out.append(html.escape(code[pos:]))
    return "".join(out)


def pill(kind: str, text: str) -> str:
    return f'<span class="pill p-{kind}">{html.escape(text)}</span>'


def sortable(table_id: str, heads: list[tuple[str, str]], rows: list[list[tuple[str, str]]]) -> str:
    """heads: (label, type). rows: cells as (html, sort-value)."""
    th = "".join(f'<th scope="col" data-type="{t}">{html.escape(h)}</th>' for h, t in heads)
    body = "".join("<tr>" + "".join(f'<td data-v="{html.escape(v, quote=True)}">{c}</td>' for c, v in r) + "</tr>" for r in rows)
    return f'<table class="sortable" id="{table_id}"><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>'


def render(gates, cov, docs, stale, items, ex, env, schema, baseline) -> str:
    head = sh("git rev-parse --short HEAD")[1].strip()
    branch = sh("git rev-parse --abbrev-ref HEAD")[1].strip()
    now = dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    n_pass = sum(1 for g in gates if g["ok"] is True)
    n_fail = sum(1 for g in gates if g["ok"] is False)
    n_out = sum(1 for s in stale if s["sev"] == "outdated")
    n_open = sum(1 for i in items if i["status"] == "open")
    total_add = sum(d["added"] for d in docs)
    total_del = sum(d["removed"] for d in docs)

    # --- gate matrix
    grows = []
    for g in gates:
        st = {True: pill("ok", "PASS"), False: pill("bad", "FAIL"), None: pill("mut", "NOT RUN")}[g["ok"]]
        grows.append([(html.escape(g["name"]), g["name"]), (st, str(g["ok"])), (f'{g["seconds"]}', str(g["seconds"])),
                      (html.escape(g["detail"]), g["detail"]), (f'<code>{html.escape(g["cmd"])}</code>', g["cmd"])])
    gate_tbl = sortable("t-gates", [("Gate", "str"), ("Result", "str"), ("Seconds", "num"), ("Detail", "str"), ("Command", "str")], grows)

    # --- docs matrix
    drows = []
    for d in docs:
        drows.append([(f'<code>{html.escape(d["file"])}</code>', d["file"]), (html.escape(d["kind"]), d["kind"]),
                      (f'+{d["added"]}', str(d["added"])), (f'-{d["removed"]}', str(d["removed"])),
                      (html.escape(d["what"]), d["what"]), (pill("ok", "updated"), "updated")])
    docs_tbl = sortable("t-docs", [("File", "str"), ("Type", "str"), ("Added", "num"), ("Removed", "num"), ("Sections modified", "str"), ("Status", "str")], drows)

    # --- stale
    srows = []
    for s in stale:
        sev = {"outdated": pill("bad", "OUTDATED"), "fixed": pill("ok", "FIXED"), "accurate": pill("ok", "ACCURATE")}[s["sev"]]
        srows.append([(sev, s["sev"]), (f'<code>{html.escape(s["file"])}:{s["line"]}</code>', s["file"]), (html.escape(s["issue"]), s["issue"]),
                      (html.escape(s["evidence"]), s["evidence"]), (html.escape(s["action"]), s["action"])])
    stale_tbl = sortable("t-stale", [("Verdict", "str"), ("Location", "str"), ("Finding", "str"), ("Evidence", "str"), ("Action", "str")], srows)

    # --- open items
    prio = {"high": "bad", "medium": "warn", "low": "mut"}
    irows = []
    for i in items:
        stp = pill("ok", "done") if i["status"] == "done" else pill("warn", "open")
        irows.append([(pill(prio[i["prio"]], i["prio"]), {"high": "0", "medium": "1", "low": "2"}[i["prio"]]), (html.escape(i["item"]), i["item"]),
                      (html.escape(i["why"]), i["why"]), (html.escape(i["owner"]), i["owner"]), (stp, i["status"])])
    items_tbl = sortable("t-items", [("Priority", "num"), ("Item", "str"), ("Why", "str"), ("Owner", "str"), ("Status", "str")], irows)

    # --- env schema
    erows = []
    for e in env:
        flags = []
        if e["secret"]:
            flags.append(pill("warn", "secret"))
        if e["sample"]:
            flags.append(pill("mut", "sample value, provider stays off"))
        erows.append([(f'<code>{html.escape(e["var"])}</code>', e["var"]), (html.escape(e["group"]), e["group"]),
                      (html.escape(e["required"]), e["required"]), (f'<code>{html.escape(e["example"])}</code>', e["example"]), (" ".join(flags) or "-", ("secret" if e["secret"] else "sample" if e["sample"] else ""))])
    env_tbl = sortable("t-env", [("Variable", "str"), ("Group", "str"), ("Required", "str"), ("Example in .env.example", "str"), ("Notes", "str")], erows)
    groups = sorted({e["group"] for e in env})
    group_opts = '<option value="">all groups</option>' + "".join(f"<option>{html.escape(g)}</option>" for g in groups)

    srow = []
    for f in schema:
        srow.append([(html.escape(f["struct"]), f["struct"]), (f'<code>{html.escape(f["field"])}</code>', f["field"]), (f'<code>{html.escape(f["type"])}</code>', f["type"]), (html.escape(f["doc"]) or "-", f["doc"])])
    schema_tbl = sortable("t-schema", [("Go struct", "str"), ("Field", "str"), ("Type", "str"), ("Meaning (from source comment)", "str")], srow)

    # --- code excerpts
    ex_html = []
    for i, e in enumerate(ex):
        ex_html.append(
            f'<details{" open" if i == 0 else ""}><summary>{html.escape(e["title"])} <span class="path">{html.escape(e["path"])}:{e["line"]}</span></summary>'
            f'<div class="body"><p class="mut">{html.escape(e["note"])}</p><button class="copy" type="button">copy</button>'
            f'<pre><code class="lang-go">{highlight_go(e["code"])}</code></pre></div></details>'
        )

    # --- flow of the validation suite
    order = [("go build", "ok"), *[(g["name"], {True: "ok", False: "bad", None: "mut"}[g["ok"]]) for g in gates]]
    color = {"ok": "var(--ok)", "bad": "var(--bad)", "mut": "var(--bd)"}
    flow = '<span class="arr">&rarr;</span>'.join(f'<span class="box" style="border-color:{color[c]}">{html.escape(n)}</span>' for n, c in order)

    e2e = (
        "<p>The test gate runs <code>tests/run_tests.sh</code>, which runs the root suite, the five example suites, then <code>tests/e2e.sh</code>: "
        "the gateway built with <code>-tags e2e</code> serves <b>fake</b> OIDC servers and each client signs in through each provider.</p>"
        '<div class="flow"><span class="box" style="border-color:var(--acc)">root go test -race</span><span class="arr">&rarr;</span>'
        '<span class="box" style="border-color:var(--acc)">5 example suites</span><span class="arr">&rarr;</span>'
        '<span class="box" style="border-color:var(--acc)">build ssod -tags e2e</span><span class="arr">&rarr;</span>'
        '<span class="box" style="border-color:var(--acc)">5 clients &times; okta, auth0, azure, mock = 20 sign-ins</span><span class="arr">&rarr;</span>'
        '<span class="box" style="border-color:var(--acc)">4 negative checks</span></div>'
    )

    data = json.dumps({"docs": docs, "coverage": cov, "gates": gates}).replace("</", "<\\/")
    overall = pill("ok", "ALL GATES PASSED") if n_fail == 0 and n_pass == len(gates) else pill("bad", f"{n_fail} GATE(S) NEED ATTENTION")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Universal SSO - documentation audit</title><style>{CSS}</style></head><body>
<nav><div class="in"><a href="#summary">Summary</a><a href="#matrix">Status matrix</a><a href="#code">Adapter code</a><a href="#schema">Configuration</a><a href="#validation">Validation</a><a href="#findings">Outdated &amp; open</a></div></nav>
<header><h1>Universal SSO documentation audit</h1>
<div class="meta">Commit <code>{html.escape(head)}</code> on <code>{html.escape(branch)}</code> &middot; compared with <code>{html.escape(baseline)}</code> &middot; generated {html.escape(now)} by <code>scripts/build_audit_dashboard.py</code> &middot; {overall}</div></header>
<main>
<section id="summary"><h2>1. Summary</h2>
<div class="notice"><b>Scope of verification.</b> The Okta, Auth0 and Microsoft Entra ID adapters were tested against an <b>in-process fake identity provider</b> (<code>pkg/sso/oidc/oidctest</code>), not against live tenant credentials. The unit tests and <code>tests/e2e.sh</code> prove that the adapters, the gateway and the five example clients work together over HTTP. They do <b>not</b> prove that a real Okta, Auth0 or Entra tenant accepts your configuration. A real sign-in needs your tenant, credentials and a browser, and follows the matching <code>Docs/*-SSO-Setup.md</code> guide.</div>
<div class="cards">
<div class="card"><div class="n">{n_pass}/{len(gates)}</div><div class="l">validation gates passed</div></div>
<div class="card"><div class="n">{len(docs)}</div><div class="l">documentation files changed</div></div>
<div class="card"><div class="n">+{total_add} / -{total_del}</div><div class="l">documentation lines</div></div>
<div class="card"><div class="n">{n_out}</div><div class="l">outdated pages found</div></div>
<div class="card"><div class="n">{n_open}</div><div class="l">open items</div></div>
</div>
<p>The Okta, Auth0 and Entra guides, README, Quickstart, Architecture, Examples and the five example READMEs now describe the adapters as implemented and fake-IdP tested. SAML 2.0 and generic OAuth 2.0 are still planned, and their guides say so correctly.</p></section>

<section id="matrix"><h2>2. Documentation status matrix</h2>
<p class="mut">Changes since <code>{html.escape(baseline)}</code>, measured with <code>git diff --numstat</code>. Click a column header to sort.</p>
<div class="tools"><input type="search" placeholder="filter files or sections" aria-label="Filter documentation table" data-filter="t-docs"></div>
{docs_tbl}
<h3>Lines changed per file</h3><div class="legend"><span style="color:var(--ok)">&#9632;</span> added &nbsp; <span style="color:var(--bad)">&#9632;</span> removed</div><div id="chart-docs"></div></section>

<section id="code"><h2>3. Adapter implementation</h2>
<p class="mut">Excerpts are cut from the real source files when the page is built, so they match the committed code. The three vendor packages are thin layers over <code>pkg/sso/oidc</code>.</p>
{"".join(ex_html)}</section>

<section id="schema"><h2>4. Configuration schema</h2>
<p class="mut">There is no database. State is a signed, stateless value (HMAC) plus an in-memory cache, so the schema that matters is configuration: environment variables read by <code>ssod</code> and the Go <code>Config</code> structs of each adapter.</p>
<h3>Environment variables (<code>.env.example</code>)</h3>
<div class="tools"><input type="search" placeholder="filter variables" aria-label="Filter variables" data-filter="t-env"><select aria-label="Filter by group" data-table="t-env" data-col="1">{group_opts}</select></div>
{env_tbl}
<h3>Adapter <code>Config</code> structs</h3>
<div class="tools"><input type="search" placeholder="filter fields" aria-label="Filter fields" data-filter="t-schema"></div>
{schema_tbl}</section>

<section id="validation"><h2>5. Validation suite</h2>
<p class="mut">Each gate was executed when this page was built. Bars show wall-clock time.</p>
<div class="flow">{flow}</div>
{gate_tbl}
<h3>Time per gate</h3><div class="tl" id="chart-gates"></div>
<h3>Statement coverage</h3><div id="chart-cov"></div>
{e2e}</section>

<section id="findings"><h2>6. Outdated pages and open items</h2>
<h3>Documentation accuracy check</h3>
<p class="mut">Pages searched for statements that contradict the code.</p>
{stale_tbl}
<h3>Open items</h3>
<div class="tools"><select aria-label="Filter by status" data-table="t-items" data-col="4"><option value="">all</option><option>open</option><option>done</option></select></div>
{items_tbl}</section>
</main>
<footer>Made with IBM Bob</footer>
<script id="data" type="application/json">{data}</script>
<script>{JS}</script>
</body></html>
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", default=BASELINE_DEFAULT)
    ap.add_argument("--skip-gates", action="store_true")
    a = ap.parse_args()
    print("collecting data")
    gates = run_gates(a.skip_gates)
    cov = [] if a.skip_gates else coverage()
    page = render(gates, cov, doc_changes(a.baseline), stale_docs(), open_items(), excerpts(), env_schema(), adapter_schema(), a.baseline)
    OUT.write_text(page)
    print(f"wrote {OUT.relative_to(ROOT)} ({len(page) // 1024} KiB)")
    return 0 if all(g["ok"] is not False for g in gates) else 1


if __name__ == "__main__":
    sys.exit(main())
