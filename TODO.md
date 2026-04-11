# GraphSAST — TODO

Status: `[ ]` pending · `[~]` in progress · `[x]` done

---

## Core pipeline (v0.2.0 architecture)

- [x] `code_review_graph` integration — `full_build()` builds nodes/edges graph
- [x] Post-processing: FTS5 index (`rebuild_fts_index`) after graph build
- [x] Post-processing: execution flow tracing (`trace_flows` + `store_flows`) after graph build
- [x] Semgrep runner — `run_semgrep()`, returns raw finding dicts
- [x] `Finding` model — `from_semgrep()`, `effective_severity`, `is_false_positive`
- [x] Per-finding LLM analyst — `analyse_finding()` with tool-use ReAct loop
- [x] `GraphClient` — 13 read-only tools over `code_review_graph` SQLite DB
- [x] In-process MCP tools — OpenAI function-call format, no server/transport
- [x] Verdict parsing — `VERDICT / SEVERITY / REASONING` from LLM final message
- [x] Report output — Markdown, JSON, SARIF
- [x] `graphsast scan` CLI command
- [x] `graphsast check-llm` CLI command

---

## GraphClient tools (13 total)

- [x] `get_function` — source code + metadata for a function
- [x] `get_callers` — who calls a function
- [x] `get_callees` — what a function calls
- [x] `search_nodes` — FTS5 + LIKE fallback search
- [x] `read_file` — file or line range
- [x] `get_file_summary` — all symbols in a file with line ranges
- [x] `get_nodes_by_file` — full node metadata for every symbol in a file
- [x] `list_entry_points` — functions with no callers (attack surface)
- [x] `get_edges_for_node` — all edge types (CALLS, IMPORTS_FROM, INHERITS…)
- [x] `get_impact_radius` — blast radius BFS from changed files
- [x] `get_flows` — pre-computed flows ranked by criticality
- [x] `get_flow_by_id` — step-by-step path of a specific flow
- [x] `trace_path` — BFS call path between two functions

---

## LLM backends

- [x] Ollama (`ollama_client.py`) — OpenAI-compat `/v1/chat/completions`
- [x] Claude / Anthropic (`claude_client.py`)
- [x] OpenAI (`openai_client.py`)
- [x] AWS Bedrock (`bedrock_client.py`)
- [x] Factory (`factory.py`) — selects backend from config

---

## Configuration

- [x] `config.py` — pydantic-settings, TOML + env vars + CLI flags
- [x] `num_ctx = 32768` default — enough for deep multi-turn investigation
- [x] `analyst_max_turns = 15` default — allows full 5-step investigation protocol

---

## Planned

### API route extraction
- [ ] **`graphsast/analysis/routes.py`** — extract HTTP route paths from source code
  - Language-specific: requires per-framework regex patterns
  - Python: Flask, FastAPI, aiohttp, Django, Tornado
  - JS/TS: Express, Fastify, NestJS, Next.js
  - Java: Spring Boot, JAX-RS
  - Go: Gin, Echo, Chi, net/http
  - Ruby: Sinatra, Rails
  - Store in `routes` table in graph DB
  - New tool: `get_api_routes(path_filter)` — LLM can look up "what URL hits this handler?"
  - Useful for: PoC generation, exploitation steps in confirmed findings
  - **Deferred** — framework-specific, implement per target stack as needed

### code-review-graph upstream fix
- [ ] **Decorator storage bug** — `parser.py` extracts decorators but never stores them in `node.extra`
  - `flows.py::_has_framework_decorator()` always returns `False` because `node.extra.get("decorators")` is always `None`
  - Fix: add `extra={"decorators": list(decorators)}` when `deco_list` is non-empty in `parser.py`
  - This would make `list_entry_points()` correctly identify framework-decorated handlers
  - **Upstream change** — needs PR to `code_review_graph`

### Analysis quality
- [x] **Finding deduplication** — groups by (file_path, overlapping line range, CWE); keeps highest-severity/most-specific rule per cluster (`analysis/dedup.py`)
- [x] **Persistent findings store** — `FindingStore` in `analysis/store.py`; findings, scan runs, and LLM verdicts stored in `graph.db`
  - Fingerprint = `sha256(rule_id + file_path + line_start)` — model-independent location identity
  - Staleness = file hash mismatch — verdict auto-invalidated when source file changes
  - Run comparison — new / fixed / recurring per scan
  - `graphsast findings <target>` CLI — list runs, show findings, diff two runs
- [x] **LLM finding enrichment** — CVSS score, CVSS vector, vulnerability description, and PoC exploit scenario added to every confirmed finding
  - Analyst and hunter prompts extended with CVSS / CVSS_VECTOR / DESCRIPTION / POC output fields
  - Verdict fallback retry: if LLM exhausts budget without a VERDICT block, sends one final message with no tools to force output
  - Stale-cache detection: findings analysed before enrichment was added (missing CVSS + description) are automatically re-analysed on next `--llm` scan
  - New fields stored in `findings` table with SQLite `ALTER TABLE` migrations for backward compatibility
- [x] **`graphsast findings --detail` flag** — full per-finding panel: description, syntax-highlighted code snippet, PoC, CVSS with vector, reasoning
- [x] **CVSS column in findings table** — compact table shows colour-coded CVSS score; table uses `expand=True` + `min_width` so columns never collapse in narrow terminals
- [ ] **Semgrep autofix surfacing** — when a rule has a `fix:` field, include the suggested patch in the report
- [ ] **Parallel LLM analysis** — optional `--llm-workers N` flag (default 1) for concurrent per-finding analysis
  - No hallucination risk — each finding is an independent conversation with no shared state
  - Useful for API backends (Claude, OpenAI) where calls are network-bound; keep at 1 for Ollama (GPU queues requests anyway)
  - Implementation: `ThreadPoolExecutor(max_workers=N)` in `scanner.py`
  - Thread safety: each worker gets its own `FindingStore` connection (separate SQLite connection per thread); `GraphClient` is read-only so shared is fine in WAL mode

### Autonomous hunt (`graphsast hunt`)
- [x] **`graphsast/analysis/hunter.py`** — LLM-driven security analysis independent of Semgrep
  - `hunt(graph, llm_client, max_entry_points, max_turns)` — main entry point
  - `hunt_one(entry, llm_client, graph, max_turns)` — per-entry-point ReAct loop
  - Starting points: `get_flows(limit=N)` first, then `list_entry_points()` to fill remaining slots
  - System prompt: 5-step audit protocol with FINDING_START/FINDING_END block output format
  - Multiple findings per entry point allowed; NO_FINDINGS also valid output
  - Hunter findings enriched with CVSS / CVSS_VECTOR / DESCRIPTION / POC (same as analyst)
- [x] **`graphsast hunt` CLI command** — separate command, does not touch `scan` or `findings`
  - Flags: `--max-entries N` (default 10), `--llm-backend`, `--llm-model`, `--llm-max-turns`, `--output`, `--format`
  - `--full-hunt` flag — no cap; audits all flows + entry points (`len(entry_points) + 200`)
  - Stores results in same `findings` table with `rule_id = "hunter.<vuln_type>"` and `source = "hunter"`
  - Requires graph DB to exist (run `graphsast scan` first to build graph)
- [x] **`--full-hunt` flag on `scan`** — implies `--hunt`; overrides `--hunt-max-entries` cap
- [x] **Schema migration** — `source TEXT DEFAULT 'semgrep'` column added to `findings` table
  - `upsert_finding()` gets optional `source=` param (default `'semgrep'`), backward compatible
- [x] **Non-breaking** — `scan`, `findings`, `_render.py`, `analyst.py`, all 13 MCP tools unchanged

### Codebase describe (`graphsast describe`)
- [x] **`graphsast describe` CLI command** — rich codebase explanation from graph stats + optional LLM narrative
  - Auto-builds graph if no DB exists (no need to run `scan` first)
  - Structured stats section: file count, node/edge counts, languages, top files, hub functions, entry points
  - `--llm` flag: sends context to LLM for 5-section narrative (Overview, Architecture, Data Flows, Dependencies, Security Observations)
  - `graphsast/analysis/describer.py` + `GraphClient.get_stats()` method

### Output
- [x] **PoC/exploitation hints** — LLM outputs PoC exploit scenario for each confirmed finding (via DESCRIPTION / POC fields)
- [x] **Markdown report** — shows CVSS badge + vector, vulnerability description, vulnerable code block, collapsed PoC and reasoning sections
- [x] **JSON report** — includes `llm_description`, `llm_poc`, `llm_cvss_score`, `llm_cvss_vector` fields
- [ ] **`graphsast review` command** — interactively mark a finding as TP/FP, suppress FP on future scans

### Tests
- [ ] Unit tests for `GraphClient` methods
- [ ] Unit tests for `analyse_finding` verdict parsing
- [ ] Integration test: scan dvpwa fixture, assert known SQLi/CMDi findings confirmed
- [ ] Integration test: scan clean fixture, assert no HIGH/CRITICAL findings

### CI
- [ ] GitHub Actions: `ruff check` + `pytest` on Python 3.11 and 3.12
- [ ] PyPI publish workflow on tag push
