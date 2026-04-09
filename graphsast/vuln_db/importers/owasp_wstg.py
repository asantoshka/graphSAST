"""OWASP Web Security Testing Guide (WSTG) importer.

Seeds vuln_classes and taint_signatures from the OWASP WSTG v4.2 test case
catalogue.  Each WSTG test ID (e.g. WSTG-INPV-05) becomes one vuln_class row;
the associated sink patterns become taint_signature rows of type SINK.

The data is embedded directly — no network access needed — so the importer
works offline and is reproducible.

Reference: https://owasp.org/www-project-web-security-testing-guide/
"""

from __future__ import annotations

import logging
from typing import Any

from graphsast.vuln_db.store import VulnStore

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# WSTG test catalogue
#
# Each entry:
#   wstg_id      WSTG-XXXX-NN  (canonical test identifier)
#   cwe_id       Primary CWE mapping
#   owasp_cat    OWASP Top-10 2021 A-code
#   name         Short human name
#   description  One-line description
#   severity     CRITICAL | HIGH | MEDIUM | LOW
#   language     "any" unless language-specific
#   sinks        List of qualified_pattern strings mapped to SINK taint sigs
#   sources      List of qualified_pattern strings mapped to SOURCE taint sigs
# ──────────────────────────────────────────────────────────────────────────────

_WSTG_CATALOGUE: list[dict[str, Any]] = [

    # ── INPV: Input Validation ────────────────────────────────────────────────

    {
        "wstg_id": "WSTG-INPV-01",
        "cwe_id": "CWE-79",
        "owasp_cat": "A03",
        "name": "Reflected XSS",
        "description": "Unsanitised user input reflected into HTML output.",
        "severity": "HIGH",
        "sinks": [
            "flask.Response", "django.http.HttpResponse",
            "render_template", "render_template_string",
            "Markup", "jinja2.Markup",
            "bottle.template", "fastapi.responses.HTMLResponse",
        ],
        "sources": [
            "flask.request.args", "flask.request.form", "flask.request.values",
            "django.http.HttpRequest.GET", "django.http.HttpRequest.POST",
            "request.GET", "request.POST", "request.body",
        ],
    },
    {
        "wstg_id": "WSTG-INPV-02",
        "cwe_id": "CWE-79",
        "owasp_cat": "A03",
        "name": "Stored XSS",
        "description": "User input stored then later output without sanitisation.",
        "severity": "HIGH",
        "sinks": [
            "flask.Response", "django.http.HttpResponse",
            "render_template", "render_template_string",
            "Markup", "jinja2.Markup",
        ],
        "sources": [
            "sqlite3.Cursor.fetchone", "sqlite3.Cursor.fetchall",
            "django.db.models.QuerySet", "sqlalchemy.orm.Query.first",
            "sqlalchemy.orm.Query.all",
        ],
    },
    {
        "wstg_id": "WSTG-INPV-05",
        "cwe_id": "CWE-89",
        "owasp_cat": "A03",
        "name": "SQL Injection",
        "description": "Untrusted data interpolated directly into an SQL statement.",
        "severity": "CRITICAL",
        "sinks": [
            "sqlite3.Connection.execute",
            "sqlite3.Cursor.execute",
            "sqlite3.Connection.executemany",
            "sqlite3.Cursor.executemany",
            "MySQLdb.cursors.Cursor.execute",
            "pymysql.cursors.Cursor.execute",
            "psycopg2.extensions.cursor.execute",
            "psycopg2.extensions.cursor.executemany",
            "django.db.connection.cursor",
            "sqlalchemy.engine.Connection.execute",
            "sqlalchemy.orm.Session.execute",
            "cx_Oracle.Cursor.execute",
        ],
        "sources": [
            "flask.request.args", "flask.request.form", "flask.request.json",
            "flask.request.values", "flask.request.data",
            "django.http.HttpRequest.GET", "django.http.HttpRequest.POST",
            "django.http.HttpRequest.body",
            "request.GET", "request.POST", "request.body",
            "fastapi.Request.query_params", "fastapi.Request.body",
        ],
    },
    {
        "wstg_id": "WSTG-INPV-06",
        "cwe_id": "CWE-89",
        "owasp_cat": "A03",
        "name": "LDAP Injection",
        "description": "Unsanitised input inserted into an LDAP filter or DN.",
        "severity": "HIGH",
        "sinks": [
            "ldap3.Connection.search",
            "ldap.ldapobject.LDAPObject.search",
            "ldap.ldapobject.LDAPObject.search_s",
            "ldap.ldapobject.LDAPObject.simple_bind_s",
        ],
        "sources": [
            "flask.request.args", "flask.request.form",
            "django.http.HttpRequest.GET", "django.http.HttpRequest.POST",
        ],
    },
    {
        "wstg_id": "WSTG-INPV-07",
        "cwe_id": "CWE-91",
        "owasp_cat": "A03",
        "name": "XML Injection",
        "description": "User input injected into an XML document or XPath query.",
        "severity": "HIGH",
        "sinks": [
            "xml.etree.ElementTree.fromstring",
            "xml.etree.ElementTree.parse",
            "lxml.etree.fromstring",
            "lxml.etree.parse",
            "defusedxml.ElementTree.fromstring",
        ],
        "sources": [
            "flask.request.data", "flask.request.get_data",
            "django.http.HttpRequest.body",
        ],
    },
    {
        "wstg_id": "WSTG-INPV-11",
        "cwe_id": "CWE-94",
        "owasp_cat": "A03",
        "name": "Code Injection",
        "description": "Arbitrary code execution via eval/exec with user-controlled input.",
        "severity": "CRITICAL",
        "sinks": [
            "eval", "exec", "compile",
            "builtins.eval", "builtins.exec",
            "__import__",
            "importlib.import_module",
        ],
        "sources": [
            "flask.request.args", "flask.request.form", "flask.request.json",
            "django.http.HttpRequest.GET", "django.http.HttpRequest.POST",
            "request.GET", "request.POST",
        ],
    },
    {
        "wstg_id": "WSTG-INPV-12",
        "cwe_id": "CWE-78",
        "owasp_cat": "A03",
        "name": "OS Command Injection",
        "description": "Unsanitised input passed to a system shell.",
        "severity": "CRITICAL",
        "sinks": [
            "os.system", "os.popen", "os.popen2", "os.popen3", "os.popen4",
            "subprocess.run", "subprocess.call", "subprocess.check_call",
            "subprocess.check_output", "subprocess.Popen",
            "commands.getstatusoutput", "commands.getoutput",
        ],
        "sources": [
            "flask.request.args", "flask.request.form", "flask.request.json",
            "flask.request.values",
            "django.http.HttpRequest.GET", "django.http.HttpRequest.POST",
            "request.GET", "request.POST",
        ],
    },
    {
        "wstg_id": "WSTG-INPV-13",
        "cwe_id": "CWE-134",
        "owasp_cat": "A03",
        "name": "Format String Injection",
        "description": "User-controlled format string passed to a format function.",
        "severity": "HIGH",
        "sinks": ["str.format", "logging.Logger.info", "logging.Logger.warning",
                   "logging.Logger.error", "logging.Logger.debug"],
        "sources": [
            "flask.request.args", "flask.request.form",
            "django.http.HttpRequest.GET", "django.http.HttpRequest.POST",
        ],
    },
    {
        "wstg_id": "WSTG-INPV-18",
        "cwe_id": "CWE-94",
        "owasp_cat": "A03",
        "name": "Server-Side Template Injection (SSTI)",
        "description": "User input embedded in a template string rendered server-side.",
        "severity": "CRITICAL",
        "sinks": [
            "jinja2.Environment.from_string",
            "jinja2.Template",
            "render_template_string",
            "mako.template.Template",
            "mako.lookup.TemplateLookup.get_template",
            "tornado.template.Template",
            "django.template.Template",
        ],
        "sources": [
            "flask.request.args", "flask.request.form", "flask.request.json",
            "django.http.HttpRequest.GET", "django.http.HttpRequest.POST",
        ],
    },
    {
        "wstg_id": "WSTG-INPV-19",
        "cwe_id": "CWE-918",
        "owasp_cat": "A10",
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "User-controlled URL causes the server to make unintended requests.",
        "severity": "HIGH",
        "sinks": [
            "requests.get", "requests.post", "requests.put", "requests.head",
            "requests.request", "requests.Session.get", "requests.Session.post",
            "urllib.request.urlopen", "urllib.request.urlretrieve",
            "urllib2.urlopen",
            "httpx.get", "httpx.post", "httpx.AsyncClient.get",
            "aiohttp.ClientSession.get", "aiohttp.ClientSession.post",
        ],
        "sources": [
            "flask.request.args", "flask.request.form", "flask.request.json",
            "django.http.HttpRequest.GET", "django.http.HttpRequest.POST",
        ],
    },

    # ── ATHN: Authentication ──────────────────────────────────────────────────

    {
        "wstg_id": "WSTG-ATHN-02",
        "cwe_id": "CWE-312",
        "owasp_cat": "A02",
        "name": "Credentials in Transport",
        "description": "Credentials or tokens stored/logged in cleartext.",
        "severity": "HIGH",
        "sinks": [
            "logging.Logger.info", "logging.Logger.debug",
            "logging.Logger.warning", "print",
            "open",
        ],
        "sources": [
            "flask.request.form", "django.http.HttpRequest.POST",
            "request.POST",
        ],
    },
    {
        "wstg_id": "WSTG-ATHN-03",
        "cwe_id": "CWE-640",
        "owasp_cat": "A07",
        "name": "Weak Password Reset",
        "description": "Password reset token is predictable or insufficiently random.",
        "severity": "MEDIUM",
        "sinks": [
            "random.random", "random.randint", "random.choice",
            "time.time",
        ],
        "sources": [],
    },

    # ── SESS: Session Management ──────────────────────────────────────────────

    {
        "wstg_id": "WSTG-SESS-02",
        "cwe_id": "CWE-330",
        "owasp_cat": "A02",
        "name": "Weak Session Token Generation",
        "description": "Session tokens generated with insufficient entropy.",
        "severity": "HIGH",
        "sinks": [
            "random.random", "random.randint", "random.randrange",
            "random.choice", "random.choices",
            "md5",
        ],
        "sources": [],
    },
    {
        "wstg_id": "WSTG-SESS-05",
        "cwe_id": "CWE-352",
        "owasp_cat": "A01",
        "name": "Cross-Site Request Forgery (CSRF)",
        "description": "State-changing endpoints lack CSRF token validation.",
        "severity": "HIGH",
        "sinks": [],   # Detected via missing-check (csrf_check), not taint
        "sources": [],
    },

    # ── ATHZ: Authorization ───────────────────────────────────────────────────

    {
        "wstg_id": "WSTG-ATHZ-01",
        "cwe_id": "CWE-639",
        "owasp_cat": "A01",
        "name": "Insecure Direct Object Reference (IDOR)",
        "description": "User-controlled resource identifier used without authorisation check.",
        "severity": "HIGH",
        "sinks": [
            "open", "pathlib.Path.open", "pathlib.Path.read_text",
            "sqlite3.Connection.execute", "sqlite3.Cursor.execute",
        ],
        "sources": [
            "flask.request.args", "flask.request.view_args",
            "django.http.HttpRequest.GET",
        ],
    },
    {
        "wstg_id": "WSTG-ATHZ-02",
        "cwe_id": "CWE-22",
        "owasp_cat": "A01",
        "name": "Path Traversal",
        "description": "User-supplied path allows access to files outside the web root.",
        "severity": "HIGH",
        "sinks": [
            "open", "pathlib.Path.open", "pathlib.Path.read_text",
            "pathlib.Path.read_bytes", "pathlib.Path.write_text",
            "os.path.join", "shutil.copy", "shutil.move",
            "send_file", "flask.send_file", "flask.send_from_directory",
        ],
        "sources": [
            "flask.request.args", "flask.request.form",
            "django.http.HttpRequest.GET", "django.http.HttpRequest.POST",
            "request.GET", "request.POST",
        ],
    },

    # ── CRYP: Cryptography ────────────────────────────────────────────────────

    {
        "wstg_id": "WSTG-CRYP-02",
        "cwe_id": "CWE-327",
        "owasp_cat": "A02",
        "name": "Weak Cryptographic Algorithm",
        "description": "Use of insecure hash or cipher (MD5, SHA1, DES, RC4).",
        "severity": "MEDIUM",
        "sinks": [
            "hashlib.md5", "hashlib.sha1",
            "Crypto.Cipher.DES.new", "Crypto.Cipher.ARC4.new",
            "cryptography.hazmat.primitives.ciphers.algorithms.TripleDES",
            "Cryptodome.Cipher.DES.new",
        ],
        "sources": [],
    },

    # ── ERRH: Error Handling ──────────────────────────────────────────────────

    {
        "wstg_id": "WSTG-ERRH-01",
        "cwe_id": "CWE-209",
        "owasp_cat": "A05",
        "name": "Information Disclosure via Error Messages",
        "description": "Full stack traces or sensitive info returned in HTTP error responses.",
        "severity": "LOW",
        "sinks": [
            "flask.jsonify", "django.http.JsonResponse",
            "traceback.format_exc", "traceback.print_exc",
        ],
        "sources": [],
    },

    # ── CONF: Configuration ───────────────────────────────────────────────────

    {
        "wstg_id": "WSTG-CONF-05",
        "cwe_id": "CWE-601",
        "owasp_cat": "A01",
        "name": "Open Redirect",
        "description": "User-controlled URL used in a redirect without allow-list validation.",
        "severity": "MEDIUM",
        "sinks": [
            "flask.redirect", "django.shortcuts.redirect",
            "django.http.HttpResponseRedirect",
            "fastapi.responses.RedirectResponse",
            "bottle.redirect",
        ],
        "sources": [
            "flask.request.args", "flask.request.form",
            "django.http.HttpRequest.GET", "django.http.HttpRequest.POST",
            "request.GET", "request.POST",
        ],
    },

    # ── BUSL: Business Logic ──────────────────────────────────────────────────

    {
        "wstg_id": "WSTG-BUSL-07",
        "cwe_id": "CWE-502",
        "owasp_cat": "A08",
        "name": "Insecure Deserialization",
        "description": "Untrusted data deserialised with an unsafe library.",
        "severity": "CRITICAL",
        "sinks": [
            "pickle.loads", "pickle.load",
            "cPickle.loads", "cPickle.load",
            "yaml.load",
            "marshal.loads",
            "jsonpickle.decode",
            "dill.loads",
        ],
        "sources": [
            "flask.request.data", "flask.request.get_data",
            "django.http.HttpRequest.body",
            "open",
        ],
    },
]


# ──────────────────────────────────────────────────────────────────────────────
# Public loader function
# ──────────────────────────────────────────────────────────────────────────────

def load_owasp_wstg(vuln_db: VulnStore) -> dict[str, int]:
    """Seed vuln_classes and taint_signatures from the WSTG catalogue.

    Safe to call multiple times — uses INSERT OR REPLACE so rows are
    idempotent.

    Returns a dict with ``vuln_classes`` and ``taint_signatures`` counts.
    """
    vc_count = 0
    sig_count = 0

    for entry in _WSTG_CATALOGUE:
        wstg_id  = entry["wstg_id"]
        vc_id    = f"wstg-{wstg_id.lower()}"
        language = entry.get("language", "any")

        # ── vuln_class ────────────────────────────────────────────────────────
        vuln_db.upsert_vuln_class({
            "id":          vc_id,
            "cwe_id":      entry["cwe_id"],
            "owasp_cat":   entry["owasp_cat"],
            "name":        entry["name"],
            "description": entry["description"],
            "severity":    entry["severity"],
            "language":    language,
            "source":      "owasp_wstg",
        })
        vc_count += 1

        # ── SINK taint signatures ─────────────────────────────────────────────
        for i, sink_pattern in enumerate(entry.get("sinks", [])):
            sig_id = f"{vc_id}-sink-{i:03d}"
            # Derive a friendly name from the pattern
            short_name = sink_pattern.split(".")[-1]
            vuln_db.upsert_taint_signature({
                "id":                sig_id,
                "name":              f"{short_name} ({wstg_id})",
                "qualified_pattern": sink_pattern,
                "language":          language,
                "sig_type":          "SINK",
                "cwe_ids":           [entry["cwe_id"]],
                "vuln_class_id":     vc_id,
                "description":       (
                    f"WSTG {wstg_id} sink — {entry['name']}: {sink_pattern}"
                ),
                "source":            "owasp_wstg",
            })
            sig_count += 1

        # ── SOURCE taint signatures ───────────────────────────────────────────
        for i, src_pattern in enumerate(entry.get("sources", [])):
            sig_id = f"{vc_id}-source-{i:03d}"
            short_name = src_pattern.split(".")[-1]
            vuln_db.upsert_taint_signature({
                "id":                sig_id,
                "name":              f"{short_name} ({wstg_id})",
                "qualified_pattern": src_pattern,
                "language":          language,
                "sig_type":          "SOURCE",
                "cwe_ids":           [entry["cwe_id"]],
                "vuln_class_id":     vc_id,
                "description":       (
                    f"WSTG {wstg_id} source — {entry['name']}: {src_pattern}"
                ),
                "source":            "owasp_wstg",
            })
            sig_count += 1

    vuln_db._conn.commit()

    logger.info(
        "OWASP WSTG: %d vuln_classes, %d taint_signatures loaded",
        vc_count, sig_count,
    )
    return {"vuln_classes": vc_count, "taint_signatures": sig_count}
