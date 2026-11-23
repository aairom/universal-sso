"""Unit tests for scripts/build_audit_dashboard.py. Run: python3 -m unittest discover scripts"""
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_audit_dashboard as b  # noqa: E402


class HighlightTest(unittest.TestCase):
    def test_keywords_strings_comments(self):
        out = b.highlight_go('func f() string { return "a<b" } // note <x>')
        self.assertIn('<span class="t-kw">func</span>', out)
        self.assertIn('<span class="t-ty">string</span>', out)
        self.assertIn('<span class="t-st">&quot;a&lt;b&quot;</span>', out)
        self.assertIn('<span class="t-cm">// note &lt;x&gt;</span>', out)

    def test_escapes_plain_text(self):
        self.assertNotIn("<x>", b.highlight_go("a := <x>"))


class SortableTest(unittest.TestCase):
    def test_table_shape(self):
        t = b.sortable("t1", [("A", "str"), ("N", "num")], [[("x", "x"), ("5", "5")], [("y", "y"), ("7", "7")]])
        self.assertIn('id="t1"', t)
        self.assertEqual(t.count("<tr>"), 3)
        self.assertIn('data-type="num"', t)
        self.assertIn('data-v="7"', t)

    def test_sort_value_is_escaped(self):
        t = b.sortable("t2", [("A", "str")], [[("c", 'a"b')]])
        self.assertIn("a&quot;b", t)


class SchemaTest(unittest.TestCase):
    def test_env_schema_marks_secrets_and_placeholders(self):
        rows = b.env_schema()
        self.assertTrue(rows)
        names = [r["var"] for r in rows]
        self.assertEqual(len(names), len(set(names)))
        for r in rows:
            if "SECRET" in r["var"]:
                self.assertTrue(r["secret"])
                self.assertEqual(r["example"], "<redacted sample>")

    def test_adapter_schema_covers_three_structs(self):
        structs = {r["struct"] for r in b.adapter_schema()}
        self.assertEqual(structs, {"okta.Config", "auth0.Config", "entra.Config"})


class ExcerptTest(unittest.TestCase):
    def test_excerpts_end_at_function_end_and_are_real_code(self):
        for e in b.excerpts():
            self.assertEqual(e["code"].splitlines()[-1], "}", e["title"])
            self.assertGreater(e["line"], 0)

    def test_missing_start_pattern_fails_loudly(self):
        with self.assertRaises(SystemExit):
            b.excerpt("README.md", r"^THIS_DOES_NOT_EXIST$", 3, "x")


class StaleDocsTest(unittest.TestCase):
    def test_saml_and_oauth2_are_not_reported_planned(self):
        items = b.stale_docs()
        saml = [i for i in items if i["file"] == "Docs/SAML-SSO-Setup.md"]
        self.assertTrue(saml)
        self.assertTrue(all(i["sev"] == "fixed" for i in saml), saml)
        self.assertFalse([i for i in items if i["sev"] == "outdated" and "planned" in i["issue"]])

    def test_open_items_state_the_saml_limits(self):
        text = " ".join(i["why"] for i in b.open_items())
        self.assertIn("Only the Go client", text)
        self.assertNotIn("Not implemented", text)


class GateAndRenderTest(unittest.TestCase):
    def test_skip_gates_marks_not_run(self):
        gates = b.run_gates(True)
        self.assertEqual(len(gates), 7)
        self.assertTrue(all(g["ok"] is None for g in gates))

    def test_shape_pattern_does_not_match_itself(self):
        self.assertIsNone(re.search(b.SHAPE_PATTERN, b.SHAPE_PATTERN))

    def test_render_contains_required_parts(self):
        gates = b.run_gates(True)
        page = b.render(gates, [{"pkg": "pkg/x", "cov": 90.0}], b.doc_changes(b.BASELINE_DEFAULT), b.stale_docs(),
                        b.open_items(), b.excerpts(), b.env_schema(), b.adapter_schema(), b.BASELINE_DEFAULT)
        self.assertIn("in-process fake identity provider", page)
        self.assertIn("not against live tenant credentials", page)
        self.assertIn("Made with IBM Bob", page)
        # every filter / select points at an existing table id
        for tid in re.findall(r'data-(?:filter|table)="([^"]+)"', page):
            self.assertIn(f'id="{tid}"', page)
        data = re.search(r'<script id="data" type="application/json">(.*?)</script>', page, re.S).group(1)
        self.assertEqual(set(json.loads(data)), {"docs", "coverage", "gates"})
        self.assertNotRegex(page, b.SHAPE_PATTERN)


if __name__ == "__main__":
    unittest.main()
