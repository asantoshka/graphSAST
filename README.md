# GraphSAST

A security analysis tool that combines a **structural code graph**, a **vulnerability pattern database**, and an **agentic LLM layer** to find real exploitable vulnerabilities — not just pattern matches.

```
graphsast scan ./myapp --llm --format markdown
```

---

## How it works

```
Source code
    │
    ▼
┌─────────────────────────────────┐
│  Phase 0 — Graph Builder        │  tree-sitter AST → nodes / edges / call args
│  (build-graph)                  │  taint annotations, entry-point detection
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│  Phase 2 — Pattern Scanners     │  Pass A: Semgrep pattern matching
│  (scan)                         │  Pass B: Taint BFS (source → sink, no sanitizer)
│                                 │  Pass C: Structural checks (dangerous imports, etc.)
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│  Phase 1A — LLM Discovery       │  Autonomous LLM exploration per entry point
│  (optional, --llm)              │  LLM reads real code, finds novel bugs
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│  Phase 1B — LLM Validation      │  Validates Phase 2 findings: CONFIRMED / FALSE_POSITIVE
│  (optional, --llm)              │  3-layer: graph-only → single-shot → micro-task
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│  Phase 3 — Correlation          │  Dedup, merge LLM results, reachability scoring
│                                 │  test files → LOW, auth-protected → downgrade
└────────────────┬────────────────┘
                 │
                 ▼
         Report (Markdown / JSON / SARIF)
```

---

## Quickstart

### 1. Install

```bash
pip install graphsast
# or with uv:
uv add graphsast
```

### 2. Build the vulnerability database

Downloads Semgrep rules, loads OWASP WSTG signatures, and seeds built-in language rules:

```bash
graphsast update-vuln-db ./myapp
```

### 3. Build the code graph

Parses your source code and builds the security-annotated graph:

```bash
graphsast build-graph ./myapp
```

### 4. Scan

```bash
# Fast scan (graph + Semgrep, no LLM)
graphsast scan ./myapp

# Full scan with LLM analysis (Ollama)
graphsast scan ./myapp --llm

# Full scan with Claude
GRAPHSAST_LLM__BACKEND=claude graphsast scan ./myapp --llm

# Output as JSON for CI
graphsast scan ./myapp --format json --output report.json

# One-shot: build graph + scan
graphsast scan ./myapp --build-first
```

Exit code `1` if any CRITICAL or HIGH active findings are found — useful for CI gates.

---

## Supported languages

| Language | Parsing | Taint | Entry-point detection | Built-in signatures |
|----------|:-------:|:-----:|:---------------------:|:-------------------:|
| Python | ✓ | ✓ | ✓ Flask/FastAPI/Django/Click/Celery | ✓ SQLi, CMDi, SSRF, Path traversal, Deserialization |
| JavaScript | ✓ | ✓ | ✓ Express | ✓ SQLi, CMDi, XSS, Path traversal, SSRF, SSTI |
| TypeScript | ✓ | ✓ | ✓ NestJS, Express | ✓ (same as JS) |
| C# | ✓ | ✓ | ✓ ASP.NET Core, Minimal API | ✓ SQLi, CMDi, XSS, Path traversal, SSRF, Deserialization |
| Java | ✓ | ~ | ~ Spring MVC annotations | ○ planned |
| Go | ✓ | ~ | ○ planned | ○ planned |

`✓` = supported · `~` = partial · `○` = planned

```bash
# See full capability matrix
graphsast capabilities ./myapp
```

---

## LLM backends

GraphSAST supports multiple LLM backends. Configure via `config.toml` or env vars.

### Ollama (default)

```bash
# Install Ollama: https://ollama.ai
ollama pull llama3.1

graphsast scan ./myapp --llm
```

Recommended models: `llama3.1`, `qwen2.5-coder:14b`, `deepseek-r1:14b`

```bash
graphsast scan ./myapp --llm --llm-model qwen2.5-coder:14b
```

### Claude (Anthropic)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
GRAPHSAST_LLM__BACKEND=claude graphsast scan ./myapp --llm
```

Uses `claude-opus-4-6` with adaptive thinking by default — the best model for deep security reasoning.

### OpenAI _(coming soon)_

```toml
# .graphsast/config.toml
[llm]
backend = "openai"
model   = "gpt-4o"
```

### AWS Bedrock _(coming soon)_

```toml
[llm]
backend          = "bedrock"
bedrock_region   = "us-east-1"
bedrock_model_id = "anthropic.claude-opus-4-6-v1:0"
```

---

## Configuration

GraphSAST reads config from (highest priority last):

1. Built-in defaults
2. `~/.graphsast/config.toml` — user-global
3. `<project>/.graphsast/config.toml` — project-local
4. `GRAPHSAST_*` env vars
5. CLI flags

Copy the example config to get started:

```bash
cp docs/config.toml.example ~/.graphsast/config.toml
```

Key settings:

```toml
[llm]
backend   = "ollama"          # "ollama" | "claude" | "openai" | "bedrock"
model     = "llama3.1"
timeout   = 300.0

[output]
format = "markdown"           # "markdown" | "json" | "sarif"

[analysis]
taint_max_depth = 10
```

Full reference: [`docs/config.toml.example`](docs/config.toml.example)

---

## CLI reference

```
graphsast build-graph <target>   Parse source code and build the graph
graphsast update-vuln-db <target> Populate / refresh the vulnerability DB
graphsast scan <target>          Run a full security scan
graphsast query <target>         Query graph for entry points, taint paths, etc.
graphsast capabilities <target>  Show language support matrix
graphsast check-llm              Test LLM backend connectivity
```

### `scan` options

| Flag | Default | Description |
|------|---------|-------------|
| `--llm` | off | Enable LLM analysis (Phase 1A + 1B) |
| `--llm-model` | from config | Ollama model name |
| `--llm-url` | from config | Ollama base URL |
| `--llm-timeout` | 300s | Per-request timeout |
| `--llm-max-ep` | 0 (all) | Max entry points for Phase 1A |
| `--format` | markdown | Output format: `markdown` \| `json` \| `sarif` |
| `--output` | stdout | Write report to file |
| `--no-semgrep` | off | Skip Semgrep pass (faster) |
| `--build-first` | off | Run `build-graph` before scanning |
| `--language` | all | Filter Semgrep rules to one language |
| `--db-dir` | `<target>/.graphsast` | Custom DB directory |

---

## Vulnerability sources

| Source | Description |
|--------|-------------|
| `builtin` | Built-in language rules: arg node types, entry-point patterns, capabilities |
| `lang_sigs` | JS/TS (Node.js/Express) and C# taint signatures |
| `wstg` | OWASP Web Security Testing Guide v4.2 — 20 vuln classes, 219+ signatures |
| `semgrep` | Semgrep OSS rules registry (cloned locally) |
| `custom` | Project-local YAML overrides in `.graphsast/custom/` |

```bash
# Refresh all sources
graphsast update-vuln-db ./myapp

# Refresh only specific sources
graphsast update-vuln-db ./myapp --source wstg,lang_sigs
```

---

## Report output

### Markdown (default)

Human-readable report with severity grouping, reachability context, and LLM reasoning.

### JSON

Structured report for CI pipelines and tooling:

```json
{
  "schema_version": "1.1",
  "summary": {"active_total": 3, "by_severity": {"CRITICAL": 1, "HIGH": 2}},
  "findings": [...],
  "suppressed": [...]
}
```

### SARIF

[SARIF 2.1.0](https://sarifweb.azurewebsites.net/) for GitHub Advanced Security and IDE integrations.

---

## Reachability scoring

GraphSAST adjusts severity based on how reachable a finding is from an attacker:

| Reachability | Effect |
|---|---|
| `test_file` | Force **LOW** — test/fixture code is not production |
| `public` | Keep original severity — no auth check in call chain |
| `auth_protected` | Downgrade one level — requires valid session |
| `unknown` | Keep original severity — couldn't determine |

---

## Adding language support

Language support is data-driven — no code changes needed.
See [`docs/adding-language-support.md`](docs/adding-language-support.md) for the complete guide.

---

## Phase 1 LLM finding cache

LLM analysis results are cached by `sha256(phase + qn + file_hash + model)`.

If a file hasn't changed since the last scan, the cached verdict is used — no LLM call is made. The cache lives in `graph.db` and travels with the project.

---

## Development

```bash
# Install dev dependencies
uv sync --extra dev

# Run tests
uv run pytest

# Lint
uv run ruff check .
```

### Project structure

```
graphsast/
├── cli/            CLI commands (Typer)
├── graph_db/       SecurityGraphStore (SQLite), migrations
├── ingestion/      tree-sitter parsing pipeline
├── vuln_db/        Vulnerability pattern DB and importers
│   └── importers/  builtin_lang_rules, owasp_wstg, lang_sigs, semgrep, custom
├── analysis/       Scanners (Phase 2) and correlator (Phase 3)
│   ├── phase2/     Semgrep runner, taint BFS, structure analyser
│   └── phase3/     Correlator, LLM merge, reachability scorer
├── llm/            LLM backends, Phase 1A/1B, cache
│   ├── base.py     LLMClient ABC
│   ├── factory.py  Backend selector
│   ├── ollama_client.py
│   ├── claude_client.py
│   ├── cache.py    Phase 1 finding cache
│   ├── phase1a.py  Autonomous LLM discovery
│   └── phase1b.py  LLM validation (3-layer)
├── output/         Markdown, JSON, SARIF formatters
└── config.py       pydantic-settings loader
docs/
├── adding-language-support.md
└── config.toml.example
```

---

## License

MIT
