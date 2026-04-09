"""JavaScript/TypeScript (Node.js) and C# taint signatures.

Seeds taint_signatures for:
  - javascript  (Node.js / Express)
  - typescript  (NestJS / Express-TS)
  - csharp      (ASP.NET Core)

Each signature maps a (qualified) function/method name to a vuln_class_id
with the role it plays: SOURCE, SINK, or SANITIZER.

Adding new signatures:
  Follow the format in TAINT_SIGNATURES below.
  See docs/adding-language-support.md for the complete field reference.
"""

from __future__ import annotations

from graphsast.vuln_db.store import VulnStore

# ──────────────────────────────────────────────────────────────────────────────
# Helper
# ──────────────────────────────────────────────────────────────────────────────

def _sig(
    lang: str,
    name: str,
    role: str,
    vuln_class: str,
    arg_index: int | None = None,
    notes: str = "",
) -> dict:
    d: dict = {
        "language":     lang,
        "name":         name,
        "role":         role,
        "vuln_class_id": vuln_class,
    }
    if arg_index is not None:
        d["arg_index"] = arg_index
    if notes:
        d["notes"] = notes
    return d


# ──────────────────────────────────────────────────────────────────────────────
# JavaScript / TypeScript (Node.js / Express / NestJS)
# ──────────────────────────────────────────────────────────────────────────────

_JS_SOURCES: list[dict] = [
    # ── Express request object properties ─────────────────────────────────────
    _sig("javascript", "req.body",             "SOURCE", "sqli",           notes="POST body — user-controlled"),
    _sig("javascript", "req.query",            "SOURCE", "sqli",           notes="URL query string — user-controlled"),
    _sig("javascript", "req.params",           "SOURCE", "sqli",           notes="Route parameters — user-controlled"),
    _sig("javascript", "req.headers",          "SOURCE", "sqli",           notes="HTTP headers — user-controlled"),
    _sig("javascript", "req.cookies",          "SOURCE", "sqli",           notes="Cookie values — user-controlled"),
    _sig("javascript", "req.body",             "SOURCE", "cmdi",),
    _sig("javascript", "req.query",            "SOURCE", "cmdi",),
    _sig("javascript", "req.params",           "SOURCE", "cmdi",),
    _sig("javascript", "req.body",             "SOURCE", "xss",),
    _sig("javascript", "req.query",            "SOURCE", "xss",),
    _sig("javascript", "req.body",             "SOURCE", "path-traversal",),
    _sig("javascript", "req.query",            "SOURCE", "path-traversal",),
    _sig("javascript", "req.body",             "SOURCE", "ssrf",),
    _sig("javascript", "req.query",            "SOURCE", "ssrf",),
    _sig("javascript", "req.body",             "SOURCE", "ssti",),
    _sig("javascript", "req.body",             "SOURCE", "open-redirect",),
    _sig("javascript", "req.query",            "SOURCE", "open-redirect",),
    _sig("javascript", "req.body",             "SOURCE", "deserialization",),
    # process.env values passed to queries can be user-influenced in some flows
    _sig("javascript", "process.env",          "SOURCE", "sqli",           notes="Env vars — potentially user-influenced"),
]

_JS_SINKS: list[dict] = [
    # ── SQL ───────────────────────────────────────────────────────────────────
    _sig("javascript", "db.query",             "SINK",   "sqli",   arg_index=0, notes="Generic db.query(sql, params)"),
    _sig("javascript", "connection.query",     "SINK",   "sqli",   arg_index=0, notes="mysql/mysql2 connection.query"),
    _sig("javascript", "pool.query",           "SINK",   "sqli",   arg_index=0, notes="mysql2/pg pool.query"),
    _sig("javascript", "client.query",         "SINK",   "sqli",   arg_index=0, notes="pg Client.query"),
    _sig("javascript", "sequelize.query",      "SINK",   "sqli",   arg_index=0, notes="Sequelize raw query"),
    _sig("javascript", "knex.raw",             "SINK",   "sqli",   arg_index=0, notes="Knex raw SQL"),
    _sig("javascript", "mongoose.connection.db.collection", "SINK", "sqli", arg_index=0),
    # ── Command injection ─────────────────────────────────────────────────────
    _sig("javascript", "child_process.exec",   "SINK",   "cmdi",   arg_index=0, notes="Executes shell command"),
    _sig("javascript", "child_process.execSync", "SINK", "cmdi",   arg_index=0),
    _sig("javascript", "child_process.spawn",  "SINK",   "cmdi",   arg_index=0),
    _sig("javascript", "child_process.spawnSync", "SINK","cmdi",   arg_index=0),
    _sig("javascript", "exec",                 "SINK",   "cmdi",   arg_index=0, notes="destructured exec from child_process"),
    _sig("javascript", "execSync",             "SINK",   "cmdi",   arg_index=0),
    _sig("javascript", "spawn",                "SINK",   "cmdi",   arg_index=0),
    # ── Code execution ────────────────────────────────────────────────────────
    _sig("javascript", "eval",                 "SINK",   "cmdi",   arg_index=0, notes="eval(userInput) — arbitrary code execution"),
    _sig("javascript", "new Function",         "SINK",   "cmdi",   arg_index=0, notes="new Function(body) — dynamic code"),
    _sig("javascript", "vm.runInNewContext",    "SINK",   "cmdi",   arg_index=0),
    _sig("javascript", "vm.runInThisContext",   "SINK",   "cmdi",   arg_index=0),
    # ── XSS ───────────────────────────────────────────────────────────────────
    _sig("javascript", "res.send",             "SINK",   "xss",    arg_index=0, notes="Sends raw HTML/text response"),
    _sig("javascript", "res.write",            "SINK",   "xss",    arg_index=0),
    _sig("javascript", "res.end",              "SINK",   "xss",    arg_index=0),
    _sig("javascript", "document.write",       "SINK",   "xss",    arg_index=0, notes="DOM XSS (client-side)"),
    _sig("javascript", "innerHTML",            "SINK",   "xss",    arg_index=0, notes="DOM XSS via innerHTML assignment"),
    # ── Path traversal ────────────────────────────────────────────────────────
    _sig("javascript", "fs.readFile",          "SINK",   "path-traversal", arg_index=0),
    _sig("javascript", "fs.readFileSync",      "SINK",   "path-traversal", arg_index=0),
    _sig("javascript", "fs.writeFile",         "SINK",   "path-traversal", arg_index=0),
    _sig("javascript", "fs.writeFileSync",     "SINK",   "path-traversal", arg_index=0),
    _sig("javascript", "fs.unlink",            "SINK",   "path-traversal", arg_index=0),
    _sig("javascript", "fs.createReadStream",  "SINK",   "path-traversal", arg_index=0),
    _sig("javascript", "fs.createWriteStream", "SINK",   "path-traversal", arg_index=0),
    _sig("javascript", "path.join",            "SINK",   "path-traversal", arg_index=0, notes="unsafe join with user input"),
    _sig("javascript", "require",              "SINK",   "path-traversal", arg_index=0, notes="dynamic require(userInput)"),
    # ── SSRF ──────────────────────────────────────────────────────────────────
    _sig("javascript", "axios.get",            "SINK",   "ssrf",   arg_index=0),
    _sig("javascript", "axios.post",           "SINK",   "ssrf",   arg_index=0),
    _sig("javascript", "axios",                "SINK",   "ssrf",   arg_index=0),
    _sig("javascript", "fetch",                "SINK",   "ssrf",   arg_index=0, notes="Node.js 18+ global fetch"),
    _sig("javascript", "http.get",             "SINK",   "ssrf",   arg_index=0),
    _sig("javascript", "http.request",         "SINK",   "ssrf",   arg_index=0),
    _sig("javascript", "https.get",            "SINK",   "ssrf",   arg_index=0),
    _sig("javascript", "https.request",        "SINK",   "ssrf",   arg_index=0),
    _sig("javascript", "request",              "SINK",   "ssrf",   arg_index=0, notes="npm 'request' library"),
    _sig("javascript", "got",                  "SINK",   "ssrf",   arg_index=0, notes="npm 'got' library"),
    _sig("javascript", "superagent.get",       "SINK",   "ssrf",   arg_index=0),
    # ── Deserialization ───────────────────────────────────────────────────────
    _sig("javascript", "JSON.parse",           "SINK",   "deserialization", arg_index=0, notes="unsafe if input is from untrusted source"),
    _sig("javascript", "serialize-javascript", "SINK",   "deserialization", arg_index=0),
    _sig("javascript", "node-serialize.unserialize", "SINK", "deserialization", arg_index=0, notes="CVE-2017-5941"),
    _sig("javascript", "YAML.load",            "SINK",   "deserialization", arg_index=0, notes="js-yaml unsafe load"),
    # ── Open redirect ─────────────────────────────────────────────────────────
    _sig("javascript", "res.redirect",         "SINK",   "open-redirect", arg_index=0),
    # ── SSTI ──────────────────────────────────────────────────────────────────
    _sig("javascript", "ejs.render",           "SINK",   "ssti",   arg_index=0, notes="EJS template injection"),
    _sig("javascript", "pug.render",           "SINK",   "ssti",   arg_index=0),
    _sig("javascript", "handlebars.compile",   "SINK",   "ssti",   arg_index=0),
    _sig("javascript", "nunjucks.renderString","SINK",   "ssti",   arg_index=0),
    _sig("javascript", "lodash.template",      "SINK",   "ssti",   arg_index=0),
]

_JS_SANITIZERS: list[dict] = [
    _sig("javascript", "escape",               "SANITIZER", "xss",  notes="HTML escape"),
    _sig("javascript", "encodeURIComponent",   "SANITIZER", "xss",  notes="URL encode"),
    _sig("javascript", "validator.escape",     "SANITIZER", "xss"),
    _sig("javascript", "DOMPurify.sanitize",   "SANITIZER", "xss"),
    _sig("javascript", "xss",                  "SANITIZER", "xss",  notes="npm 'xss' package"),
    _sig("javascript", "mysql.escape",         "SANITIZER", "sqli"),
    _sig("javascript", "mysql2.escape",        "SANITIZER", "sqli"),
    _sig("javascript", "pg.escapeLiteral",     "SANITIZER", "sqli"),
    _sig("javascript", "path.resolve",         "SANITIZER", "path-traversal", notes="resolves to absolute path"),
    _sig("javascript", "path.normalize",       "SANITIZER", "path-traversal"),
]

# TypeScript shares Node.js signatures — just re-emit with language="typescript"
_TS_SOURCES = [dict(s, language="typescript") for s in _JS_SOURCES]
_TS_SINKS    = [dict(s, language="typescript") for s in _JS_SINKS]
_TS_SANITIZERS = [dict(s, language="typescript") for s in _JS_SANITIZERS]

# ──────────────────────────────────────────────────────────────────────────────
# C# / ASP.NET Core
# ──────────────────────────────────────────────────────────────────────────────

_CS_SOURCES: list[dict] = [
    # ── ASP.NET Core request inputs ───────────────────────────────────────────
    _sig("csharp", "Request.Query",          "SOURCE", "sqli",           notes="URL query string"),
    _sig("csharp", "Request.Form",           "SOURCE", "sqli",           notes="POST form body"),
    _sig("csharp", "Request.Headers",        "SOURCE", "sqli",           notes="HTTP headers"),
    _sig("csharp", "Request.Cookies",        "SOURCE", "sqli",           notes="Cookie values"),
    _sig("csharp", "Request.RouteValues",    "SOURCE", "sqli",           notes="Route template values"),
    _sig("csharp", "Request.Body",           "SOURCE", "sqli",           notes="Raw request body stream"),
    _sig("csharp", "Request.Query",          "SOURCE", "cmdi"),
    _sig("csharp", "Request.Form",           "SOURCE", "cmdi"),
    _sig("csharp", "Request.Query",          "SOURCE", "xss"),
    _sig("csharp", "Request.Form",           "SOURCE", "xss"),
    _sig("csharp", "Request.Query",          "SOURCE", "path-traversal"),
    _sig("csharp", "Request.Form",           "SOURCE", "path-traversal"),
    _sig("csharp", "Request.Query",          "SOURCE", "ssrf"),
    _sig("csharp", "Request.Form",           "SOURCE", "ssrf"),
    _sig("csharp", "Request.Form",           "SOURCE", "deserialization"),
    _sig("csharp", "Request.Body",           "SOURCE", "deserialization"),
    _sig("csharp", "Request.Query",          "SOURCE", "open-redirect"),
    _sig("csharp", "Request.Form",           "SOURCE", "open-redirect"),
    # Environment variables
    _sig("csharp", "Environment.GetEnvironmentVariable", "SOURCE", "sqli", notes="Env vars can be user-controlled"),
]

_CS_SINKS: list[dict] = [
    # ── SQL ───────────────────────────────────────────────────────────────────
    _sig("csharp", "SqlCommand",             "SINK",   "sqli",   arg_index=0, notes="ADO.NET SqlCommand constructor"),
    _sig("csharp", "SqlCommand.CommandText", "SINK",   "sqli",   arg_index=0, notes="CommandText property assignment"),
    _sig("csharp", "NpgsqlCommand",          "SINK",   "sqli",   arg_index=0, notes="PostgreSQL Npgsql"),
    _sig("csharp", "MySqlCommand",           "SINK",   "sqli",   arg_index=0, notes="MySql.Data"),
    _sig("csharp", "OracleCommand",          "SINK",   "sqli",   arg_index=0),
    _sig("csharp", "DbContext.Database.ExecuteSqlRaw",      "SINK", "sqli", arg_index=0, notes="EF Core raw SQL"),
    _sig("csharp", "DbContext.Database.ExecuteSqlRawAsync", "SINK", "sqli", arg_index=0),
    _sig("csharp", "DbContext.Database.SqlQuery",           "SINK", "sqli", arg_index=0, notes="EF Core SqlQuery"),
    _sig("csharp", "Dapper.Execute",         "SINK",   "sqli",   arg_index=0, notes="Dapper Execute"),
    _sig("csharp", "Dapper.Query",           "SINK",   "sqli",   arg_index=0),
    # ── Command injection ─────────────────────────────────────────────────────
    _sig("csharp", "Process.Start",          "SINK",   "cmdi",   arg_index=0, notes="System.Diagnostics.Process.Start"),
    _sig("csharp", "ProcessStartInfo.FileName",      "SINK", "cmdi", arg_index=0),
    _sig("csharp", "ProcessStartInfo.Arguments",     "SINK", "cmdi", arg_index=0),
    _sig("csharp", "ShellExecute",           "SINK",   "cmdi",   arg_index=0),
    # ── XSS ───────────────────────────────────────────────────────────────────
    _sig("csharp", "Response.Write",         "SINK",   "xss",    arg_index=0, notes="Raw HTML output"),
    _sig("csharp", "HtmlString",             "SINK",   "xss",    arg_index=0, notes="new HtmlString(userInput) — bypasses encoding"),
    _sig("csharp", "Html.Raw",               "SINK",   "xss",    arg_index=0, notes="Razor @Html.Raw(userInput)"),
    _sig("csharp", "MarkupString",           "SINK",   "xss",    arg_index=0, notes="Blazor MarkupString cast"),
    # ── Path traversal ────────────────────────────────────────────────────────
    _sig("csharp", "File.ReadAllText",       "SINK",   "path-traversal", arg_index=0),
    _sig("csharp", "File.ReadAllBytes",      "SINK",   "path-traversal", arg_index=0),
    _sig("csharp", "File.WriteAllText",      "SINK",   "path-traversal", arg_index=0),
    _sig("csharp", "File.WriteAllBytes",     "SINK",   "path-traversal", arg_index=0),
    _sig("csharp", "File.OpenRead",          "SINK",   "path-traversal", arg_index=0),
    _sig("csharp", "File.Open",              "SINK",   "path-traversal", arg_index=0),
    _sig("csharp", "File.Delete",            "SINK",   "path-traversal", arg_index=0),
    _sig("csharp", "Directory.GetFiles",     "SINK",   "path-traversal", arg_index=0),
    _sig("csharp", "Path.Combine",           "SINK",   "path-traversal", arg_index=0, notes="unsafe combine with user input"),
    _sig("csharp", "StreamReader",           "SINK",   "path-traversal", arg_index=0),
    _sig("csharp", "FileStream",             "SINK",   "path-traversal", arg_index=0),
    # ── SSRF ──────────────────────────────────────────────────────────────────
    _sig("csharp", "HttpClient.GetAsync",    "SINK",   "ssrf",   arg_index=0),
    _sig("csharp", "HttpClient.PostAsync",   "SINK",   "ssrf",   arg_index=0),
    _sig("csharp", "HttpClient.SendAsync",   "SINK",   "ssrf",   arg_index=0),
    _sig("csharp", "HttpClient.GetStringAsync", "SINK","ssrf",   arg_index=0),
    _sig("csharp", "WebClient.DownloadString",  "SINK","ssrf",   arg_index=0, notes="legacy WebClient"),
    _sig("csharp", "WebClient.DownloadFile",    "SINK","ssrf",   arg_index=0),
    _sig("csharp", "WebRequest.Create",      "SINK",   "ssrf",   arg_index=0, notes="legacy WebRequest"),
    _sig("csharp", "RestClient",             "SINK",   "ssrf",   arg_index=0, notes="RestSharp RestClient"),
    # ── Deserialization ───────────────────────────────────────────────────────
    _sig("csharp", "BinaryFormatter.Deserialize",  "SINK", "deserialization", arg_index=0, notes="Insecure BinaryFormatter — CVE class"),
    _sig("csharp", "XmlSerializer.Deserialize",    "SINK", "deserialization", arg_index=0, notes="XXE risk if DTD not disabled"),
    _sig("csharp", "XmlDocument.LoadXml",           "SINK", "deserialization", arg_index=0, notes="XXE risk"),
    _sig("csharp", "XmlDocument.Load",              "SINK", "deserialization", arg_index=0),
    _sig("csharp", "DataContractSerializer.ReadObject", "SINK", "deserialization", arg_index=0),
    _sig("csharp", "ObjectStateFormatter.Deserialize",  "SINK", "deserialization", arg_index=0),
    _sig("csharp", "NetDataContractSerializer.Deserialize", "SINK", "deserialization", arg_index=0),
    _sig("csharp", "JsonConvert.DeserializeObject", "SINK", "deserialization", arg_index=0, notes="Newtonsoft — TypeNameHandling=All is dangerous"),
    # ── Open redirect ─────────────────────────────────────────────────────────
    _sig("csharp", "Redirect",               "SINK",   "open-redirect", arg_index=0, notes="Controller.Redirect()"),
    _sig("csharp", "Response.Redirect",      "SINK",   "open-redirect", arg_index=0),
    # ── LDAP injection ────────────────────────────────────────────────────────
    _sig("csharp", "DirectorySearcher.Filter", "SINK", "ldap-injection", arg_index=0),
    _sig("csharp", "DirectoryEntry",          "SINK",   "ldap-injection", arg_index=0),
]

_CS_SANITIZERS: list[dict] = [
    _sig("csharp", "HtmlEncoder.Default.Encode",  "SANITIZER", "xss"),
    _sig("csharp", "WebUtility.HtmlEncode",        "SANITIZER", "xss"),
    _sig("csharp", "HttpUtility.HtmlEncode",       "SANITIZER", "xss"),
    _sig("csharp", "AntiXssEncoder.HtmlEncode",    "SANITIZER", "xss"),
    _sig("csharp", "SecurityElement.Escape",       "SANITIZER", "xss"),
    _sig("csharp", "Path.GetFileName",             "SANITIZER", "path-traversal", notes="strips directory components"),
    _sig("csharp", "Uri.EscapeDataString",         "SANITIZER", "ssrf"),
    _sig("csharp", "Uri.IsWellFormedUriString",    "SANITIZER", "ssrf"),
    _sig("csharp", "SqlParameter",                 "SANITIZER", "sqli",  notes="parameterised query — safe"),
    _sig("csharp", "NpgsqlParameter",              "SANITIZER", "sqli"),
    _sig("csharp", "DbParameter",                  "SANITIZER", "sqli"),
]


# ──────────────────────────────────────────────────────────────────────────────
# Combined list
# ──────────────────────────────────────────────────────────────────────────────

TAINT_SIGNATURES: list[dict] = (
    _JS_SOURCES + _JS_SINKS + _JS_SANITIZERS
    + _TS_SOURCES + _TS_SINKS + _TS_SANITIZERS
    + _CS_SOURCES + _CS_SINKS + _CS_SANITIZERS
)


def load_lang_sigs(vuln_db: VulnStore) -> dict[str, int]:
    """Seed JS/TS and C# taint signatures into vuln_db."""
    count = 0
    for sig in TAINT_SIGNATURES:
        vuln_db.upsert_taint_signature(sig)
        count += 1
    vuln_db.commit()
    return {"taint_signatures": count}
