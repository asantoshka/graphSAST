# GraphSAST — TODO

Items are grouped by theme and ordered roughly by priority within each group.
Status: `[ ]` pending · `[~]` in progress · `[x]` done

---

## Core correctness
- [x] Phase 1A / 1B result merging into final report
- [x] Phase 1A vs 1B conflict resolution (1A wins on CONFIRMED)
- [x] Phase 3 reachability severity scorer (test_file → LOW, auth_protected → downgrade, public → keep)

---

## Configuration & architecture
- [x] `config.py` — pydantic-settings loader (TOML + env vars + CLI flags)
- [x] Abstract LLM backend (`llm/base.py` + factory)
- [x] Ollama backend (`llm/ollama_client.py`) inherits `LLMClient`
- [x] Claude / Anthropic backend (`llm/claude_client.py`) with adaptive thinking
- [x] Phase 1 finding cache — `sha256(phase | qn | file_hash | model | vuln_class)` in `graph.db`

---

## Language support
- [x] Python — parsing, taint, entry-point detection, built-in signatures
- [x] JavaScript — parsing, taint, entry-point detection, lang_sigs (82 signatures)
- [x] TypeScript — parsing, taint, entry-point detection, lang_sigs (mirrors JS)
- [x] C# — parsing, taint, entry-point detection, lang_sigs (79 signatures)
- [x] `docs/adding-language-support.md` — guide for adding new languages without touching code
- [ ] **Java entry-point AST walker**
  - Walk `@GetMapping`, `@PostMapping`, `@RequestMapping` annotation nodes
  - Patterns are in DB; AST walk not yet wired in graph builder
- [ ] **Go entry-point AST walker**
  - Detect `http.HandleFunc`, `gin.GET/POST`, gorilla/mux `r.Handle` registrations
  - Currently `planned` in capabilities matrix

---

## LLM backends — additional
- [ ] **OpenAI backend** (`llm/openai_client.py`)
  - Implement `LLMClient` using the `openai` Python SDK
  - Support GPT-4o, GPT-4-turbo, o1, o3-mini
  - Config: `backend = "openai"`, `llm.openai_api_key`, `llm.openai_base_url` (for Azure / proxies)
  - Wire into `factory.py` and `config.py`

- [ ] **AWS Bedrock backend** (`llm/bedrock_client.py`)
  - Implement `LLMClient` using `boto3` (`bedrock-runtime`)
  - Support Claude on Bedrock (`anthropic.claude-opus-4-6-v1:0`, etc.) and Titan / Llama models
  - Config: `backend = "bedrock"`, `llm.bedrock_region`, `llm.bedrock_model_id`
  - Auth via standard AWS credential chain (env vars / `~/.aws/credentials` / IAM role)
  - Wire into `factory.py` and `config.py`

---

## MCP (Model Context Protocol) support
- [ ] **MCP server mode** — expose GraphSAST as an MCP server so Claude Desktop / other MCP clients can call it
  - Tools to expose: `scan_directory`, `get_findings`, `get_taint_paths`, `get_entry_points`, `get_missing_checks`
  - Implementation: `graphsast/mcp_server.py` using `fastmcp` (already a dependency)
  - CLI command: `graphsast mcp-serve [--port 8080]`

- [ ] **MCP client mode** — Phase 1A / 1B can call external MCP servers as additional tool providers
  - Config: `[mcp] servers = [{name="files", command="npx @modelcontextprotocol/server-filesystem"}]`
  - Factory injects MCP tools alongside the built-in graph tools

---

## Analysis quality
- [ ] **LLM context trimmer**
  - Focus on ±20 lines around each node in the taint path instead of top-60 lines
  - Strip comments and blank lines to fit more relevant code into the context window
  - Lives in `llm/tools.py::fetch_function_source`

- [ ] **Interprocedural taint propagation**
  - Currently taint BFS stops at call boundaries; trace tainted args into callee bodies
  - Increases true-positive rate for multi-hop injection chains

- [ ] **Semgrep autofix integration**
  - When a Semgrep rule has a `fix:` field, surface the suggested patch in the report
  - Add `--apply-fixes` flag to `scan` command

---

## Data sources
- [ ] **OWASP MASTG importer** (`vuln_db/importers/owasp_mastg.py`)
  - Mobile Security Testing Guide — iOS and Android
  - Same shape as `owasp_wstg.py`: vuln_classes + taint_signatures
  - Cover: insecure data storage, insecure crypto, improper platform usage, network security

- [ ] **CWE XML importer** (`vuln_db/importers/cwe_xml.py`)
  - Fetch MITRE CWE XML (`https://cwe.mitre.org/data/xml/cwec_latest.xml.zip`)
  - Enrich `vuln_classes` rows with official CWE descriptions, related-CWE links, mitigations
  - Cache locally in `~/.graphsast/cache/cwe/`

---

## Developer tooling
- [ ] **`graphsast review` command**
  - Mark a finding as TP / FP interactively
  - Persist verdict to `vulns.db` (`review_decisions` table: finding_id, verdict, note, reviewed_at)
  - Suppress FP findings on future scans of the same location
  - Output: `graphsast review --id <finding-id> --verdict fp --note "sanitised upstream"`

- [ ] **`graphsast eval` command**
  - Given a labelled ground-truth JSONL file, compare against current scan output
  - Compute precision, recall, F1 per severity and per vuln class
  - Output: table + optional JSON report
  - Format: `{"file": "...", "line": 42, "vuln_class": "sqli", "expected": "TP"}`

---

## Test plan

### What already exists
- [x] `tests/test_ingestion.py` — 9 tests: entry-point detection, sink annotation, arg concat/parameterised, taint paths, safe-route false-positive, missing checks
- [x] `tests/test_scan.py` — 10 tests: full scan pipeline, SQLi/CMDi/PT/auth findings, severity presence, JSON/SARIF/Markdown output
- [x] `tests/fixtures/vulnrez/app.py` — intentionally vulnerable Flask app (12 routes, 5 vuln categories)

### Unit tests — `tests/unit/`

**`test_config.py`**
- [ ] Default settings load without any config files
- [ ] TOML file is read from user-global path (`~/.graphsast/config.toml`)
- [ ] Project-local TOML overrides user-global values (deep merge)
- [ ] `GRAPHSAST_LLM__BACKEND=claude` env var overrides TOML
- [ ] `GRAPHSAST_LLM__MODEL` env var sets model correctly
- [ ] Unknown backend raises `ValueError` from factory
- [ ] `get_settings()` with `project_root=None` falls back gracefully

**`test_migrations.py`**
- [ ] Fresh DB gets migrated to `LATEST_VERSION` (v9)
- [ ] Migration is idempotent — running twice does not error or duplicate rows
- [ ] `get_graphsast_version()` returns correct version after each migration
- [ ] `phase1_cache` table exists after v9
- [ ] `phase1a_findings` and `phase1b_findings` tables exist after v8

**`test_cache.py`**
- [ ] `make_cache_key` is deterministic — same inputs produce same hash
- [ ] `make_cache_key` changes when `file_path` content changes (different file hash)
- [ ] `make_cache_key` changes when `model` changes
- [ ] `make_cache_key` changes when `vuln_class_id` changes
- [ ] `make_cache_key` is stable when `file_path` is empty string
- [ ] `get_cached` returns `None` on miss
- [ ] `get_cached` returns payload dict on hit
- [ ] `set_cached` then `get_cached` round-trips correctly
- [ ] `set_cached` overwrites existing entry (INSERT OR REPLACE)
- [ ] `get_cached` does not raise when `phase1_cache` table is missing (graceful)

**`test_vuln_db.py`**
- [ ] `VulnStore` creates schema on first open
- [ ] `load_all` populates `vuln_classes` and `taint_signatures` from `builtin` source
- [ ] `load_lang_sigs` adds JS/TS/C# signatures; count ≥ 200
- [ ] Same signature loaded twice does not duplicate (idempotent)
- [ ] `VulnStore.stats()` returns `{"vuln_classes": N, "taint_signatures": M}`
- [ ] Custom YAML rule is loaded from `.graphsast/custom/` directory
- [ ] Custom rule with unknown `vuln_class_id` is skipped with a warning (no crash)
- [ ] OWASP WSTG import: ≥ 20 vuln classes, ≥ 200 signatures

**`test_arg_inspector.py`**
- [ ] `f"SELECT ... {user_input}"` → `arg_type=f_string`, `is_concatenated=True`
- [ ] `"SELECT ... " + param` → `arg_type=binary_op`, `is_concatenated=True`
- [ ] `"SELECT ... %s" % val` → `arg_type=percent_format`, `is_concatenated=True`
- [ ] `("SELECT ... ?", (val,))` → `arg_type=tuple`, `is_parameterised=True`, `is_concatenated=False`
- [ ] `"literal string"` → `arg_type=string_literal`, `is_concatenated=False`
- [ ] `variable_name` → `arg_type=identifier`, `contains_var=True`

**`test_taint_markers.py`**
- [ ] SOURCE annotation added to nodes matching source patterns
- [ ] SINK annotation added to nodes matching sink patterns
- [ ] SANITIZER annotation added to nodes matching sanitizer patterns
- [ ] Annotation is NOT duplicated on second run (unique index respected)
- [ ] Node with no matching pattern gets no annotation

**`test_reachability.py`**
- [ ] File in `tests/fixtures/` → reachability `test_file` → severity forced to LOW
- [ ] Finding with no auth missing-check record → `auth_protected` → severity downgraded one level
- [ ] Finding with auth missing-check present → `public` → severity unchanged
- [ ] CRITICAL auth_protected → HIGH
- [ ] HIGH auth_protected → MEDIUM
- [ ] LOW auth_protected → stays LOW
- [ ] `unknown` reachability (no graph info) → severity unchanged

**`test_correlator.py`**
- [ ] Two findings within 5 lines with same CWE are merged into one
- [ ] Two findings more than 5 lines apart with same CWE remain separate
- [ ] Finding with both `graph_taint` and `semgrep` sources gets higher confidence than either alone
- [ ] `llm_1a` source raises finding weight; CONFIRMED LLM verdict preserved after merge
- [ ] FALSE_POSITIVE LLM verdict causes finding to be marked suppressed
- [ ] Dedup does not merge findings across different CWE IDs
- [ ] Source weight mapping: graph_taint=3 > semgrep=2 > structure=1

**`test_graph_tools.py`**
- [ ] `fetch_function_source` returns source snippet when QN is in graph
- [ ] `fetch_function_source` falls back to suffix match when full QN not found
- [ ] `fetch_function_source` returns error string (not exception) for unknown QN
- [ ] `fetch_call_context` lists callers and callees
- [ ] `fetch_taint_path` returns path when source→sink taint exists
- [ ] `fetch_taint_path` returns explanatory string (not exception) when no path
- [ ] `fetch_argument_structure` returns arg rows for known caller/callee pair
- [ ] `fetch_argument_structure` falls back to loose name match
- [ ] `fetch_missing_checks` returns missing types for entry point with known gaps
- [ ] `GraphTools.execute` returns "Unknown tool" string for unrecognised tool name
- [ ] `GraphTools.execute` returns "Tool error" string on exception (no propagation)

**`test_phase1b_layer1.py`**
- [ ] `arg_type=tuple` (parameterised query) → `FALSE_POSITIVE` HIGH confidence without LLM
- [ ] `is_concatenated=True` + CWE-89 + HIGH severity → `CONFIRMED` HIGH confidence without LLM
- [ ] `is_concatenated=True` + CWE-78 + HIGH severity → `CONFIRMED` without LLM
- [ ] `missing_check` source only (no graph_taint) → `CONFIRMED` MEDIUM confidence
- [ ] Finding with no matching Layer 1 rule → returns `None` (needs LLM)

**`test_output_json.py`**
- [ ] `to_json()` returns dict with `schema_version`, `summary`, `findings`, `suppressed`
- [ ] `summary.by_severity` keys cover all severity levels present
- [ ] Each finding dict has `id`, `cwe_id`, `severity`, `file`, `line`, `title`, `sources`
- [ ] `summary.active_total` equals `len(findings)` minus suppressed
- [ ] Empty findings list produces valid JSON with zero counts

**`test_output_sarif.py`**
- [ ] Output has `version: "2.1.0"` and `$schema` field
- [ ] Each finding maps to exactly one SARIF `result`
- [ ] `ruleId` in results matches a rule in `tool.driver.rules`
- [ ] `locations[0].physicalLocation.artifactLocation.uri` is a relative path
- [ ] Severity maps: CRITICAL→error, HIGH→error, MEDIUM→warning, LOW→note
- [ ] Empty findings list produces valid SARIF with empty `results` array

**`test_output_markdown.py`**
- [ ] Report contains `# GraphSAST Security Report` header
- [ ] Findings grouped by severity (CRITICAL section before HIGH section)
- [ ] Each finding shows CWE ID, file path, line number
- [ ] LLM reasoning block appears when `llm_verdict` is set
- [ ] Suppressed findings section present when suppressions exist
- [ ] Empty findings list renders "No findings" message

---

### Integration tests — `tests/integration/`

**`test_js_fixture.py`** _(new fixture needed: `tests/fixtures/vulnjs/`)_
- [ ] Express route handlers detected as entry points
- [ ] `req.query.*` and `req.body.*` annotated as SOURCE
- [ ] `db.query()` called with string concatenation → taint path found
- [ ] `res.send(userInput)` → XSS taint path found
- [ ] `child_process.exec(userInput)` → CMDi taint path found
- [ ] Parameterised query `db.query("SELECT ?", [val])` → NOT in taint paths

**`test_ts_fixture.py`** _(new fixture needed: `tests/fixtures/vulnts/`)_
- [ ] NestJS `@Get()` / `@Post()` handlers detected as entry points
- [ ] TypeScript-specific sources (`req.query`, `@Body()`) annotated correctly
- [ ] Taint paths work through typed functions

**`test_csharp_fixture.py`** _(new fixture needed: `tests/fixtures/vulncs/`)_
- [ ] ASP.NET Core `[HttpGet]` / `[HttpPost]` controllers detected as entry points
- [ ] `Request.Query["param"]` annotated as SOURCE
- [ ] `SqlCommand` called with string concatenation → CWE-89 taint path
- [ ] `Process.Start(userInput)` → CWE-78 taint path
- [ ] `SqlParameter` sanitizer suppresses taint path

**`test_incremental_build.py`**
- [ ] Graph built twice with no code change: second build is faster (no re-parse)
- [ ] After modifying one file, only that file's nodes are re-ingested
- [ ] Deleted file's nodes are removed from graph on next build

**`test_phase1_cache_integration.py`**
- [ ] First scan writes cache entries for each entry point analysed
- [ ] Second scan with unchanged code returns cache hits (mock LLM not called)
- [ ] Modifying source file invalidates its cache entry only
- [ ] Cache hit restores original `scan_run_id` correctly

**`test_cli_scan.py`** (subprocess / `typer.testing.CliRunner`)
- [ ] `graphsast scan <fixture> --format json` exits 0 with valid JSON to stdout
- [ ] `graphsast scan <fixture> --format sarif` produces `version: "2.1.0"`
- [ ] `graphsast scan <fixture> --output report.json` writes file to disk
- [ ] `graphsast scan <fixture>` with CRITICAL finding exits with code 1
- [ ] `graphsast scan <clean_fixture>` with no high findings exits with code 0
- [ ] `graphsast build-graph <fixture>` creates `graph.db` in `.graphsast/`
- [ ] `graphsast capabilities <fixture>` prints language table without error
- [ ] `graphsast query <fixture> --entry-points` lists entry points
- [ ] `graphsast scan --no-semgrep` completes without Semgrep on PATH

**`test_semgrep_runner.py`**
- [ ] Semgrep runner returns findings when Semgrep is installed
- [ ] Semgrep runner returns empty list (not crash) when Semgrep is not on PATH
- [ ] Semgrep finding CWE IDs are normalised (e.g. `CWE-089` → `CWE-89`)
- [ ] `--language python` flag limits rules to Python-only rules

---

### LLM backend contract tests — `tests/llm/`

These tests mock the actual API calls; they validate protocol correctness, not model quality.

**`test_ollama_client.py`**
- [ ] `is_available()` returns True when Ollama health endpoint responds 200
- [ ] `is_available()` returns False when connection refused
- [ ] `chat()` sends correct JSON body (`model`, `messages`, `stream=False`)
- [ ] `chat()` returns normalised response dict with `role: assistant`
- [ ] `run_loop()` stops after `max_turns` even if model keeps calling tools
- [ ] `run_loop()` calls tool executor and feeds result back as `tool` message
- [ ] `list_models()` parses Ollama `/api/tags` response correctly

**`test_claude_client.py`**
- [ ] `_openai_tool_to_anthropic()` converts function schema to Anthropic format
- [ ] `chat()` separates system message into top-level `system` param
- [ ] `chat()` with `thinking=True` sends `thinking: {type: "adaptive"}`
- [ ] `run_loop()` converts `tool_use` blocks back to OpenAI-compat format
- [ ] `run_loop()` sends `tool_result` as user-role content (not `"role":"tool"`)
- [ ] `run_loop()` stops at `max_turns`
- [ ] `is_available()` calls `count_tokens` as a cheap probe (not a full inference)
- [ ] Model auto-upgrades from `"llama3.1"` to `"claude-opus-4-6"` via factory

**`test_factory.py`**
- [ ] `backend="ollama"` → returns `OllamaClient` instance
- [ ] `backend="claude"` → returns `ClaudeClient` instance
- [ ] `backend="unknown"` → raises `ValueError`
- [ ] `backend="claude"` with model still `"llama3.1"` → auto-upgrades to `"claude-opus-4-6"`
- [ ] Factory passes `llm_url`, `timeout`, `temperature` from config to Ollama

---

### Regression / golden-file tests — `tests/regression/`

- [ ] **VulnRez golden set** — run scan, compare finding IDs to `tests/regression/vulnrez_expected.json`; assert no new false negatives (expected TPs all present)
- [ ] **False-positive check** — `get_user_safe` must never appear in active findings across any scan permutation
- [ ] **Severity stability** — same finding in two consecutive scans of unchanged code has identical severity
- [ ] **SARIF schema validation** — SARIF output passes the official SARIF 2.1.0 JSON Schema (`sarif-schema-2.1.0.json`)

---

### Performance / smoke tests — `tests/perf/`

- [ ] Scan of VulnRez completes in < 5 s (without Semgrep, without LLM) on CI hardware
- [ ] Graph build of a 500-file Python project completes in < 30 s
- [ ] Second build (incremental, no changes) completes in < 3 s

---

### Test fixtures needed
- [ ] `tests/fixtures/vulnjs/app.js` — Express app with SQLi, XSS, CMDi, safe parameterised query
- [ ] `tests/fixtures/vulnts/app.ts` — NestJS controller with equivalent vulns
- [ ] `tests/fixtures/vulncs/Controllers/UserController.cs` — ASP.NET Core controller with SQLi, CMDi, safe SqlParameter
- [ ] `tests/fixtures/clean_project/app.py` — Flask app with no vulnerabilities (false-positive baseline)
- [ ] `tests/regression/vulnrez_expected.json` — golden finding IDs for regression gate

---

## Distribution & onboarding
- [x] `requirements.txt` — core runtime dependencies
- [x] `requirements-claude.txt` — Anthropic SDK extra
- [x] `requirements-openai.txt` — OpenAI SDK extra (placeholder)
- [x] `requirements-bedrock.txt` — boto3 extra (placeholder)
- [x] `requirements-dev.txt` — pytest, ruff
- [x] `Dockerfile` — multi-stage build (builder + semgrep + slim runtime), non-root user
- [x] `.dockerignore`
- [x] `README.md` — quickstart, language table, LLM backends, config reference, CLI reference
- [x] `docs/config.toml.example` — fully commented sample config
- [ ] **PyPI publish workflow** (`.github/workflows/publish.yml`)
  - Build wheel on tag push, publish to PyPI via Trusted Publisher
- [ ] **GitHub Actions CI** (`.github/workflows/ci.yml`)
  - Run `ruff check`, `pytest` on Python 3.11 and 3.12
  - Matrix scan of fixture apps to catch regressions
