# GraphSAST

A security analysis tool that combines a **structural code graph**, **Semgrep pattern scanning**, and an **agentic LLM layer** to triage vulnerabilities — not just flag them.

```
graphsast scan ./myapp --llm --llm-model qwen3:8b
```

---

## How it works

```
Source code
    │
    ▼
┌──────────────────────────────────┐
│  Graph Builder                   │  code-review-graph: tree-sitter AST
│                                  │  → nodes, edges, call graph (SQLite)
│                                  │  → FTS5 index + execution flow tracing
└───────────────┬──────────────────┘
                │
                ▼
┌──────────────────────────────────┐
│  Semgrep Scanner                 │  semgrep --config auto
│                                  │  → structured findings (rule, file, line, snippet)
└───────────────┬──────────────────┘
                │
                ▼
┌──────────────────────────────────┐
│  LLM Analyst  (optional --llm)   │  One finding at a time
│                                  │  LLM investigates via 13 graph tools:
│                                  │  read code → trace callers → check sanitisers
│                                  │  → CONFIRMED / FALSE_POSITIVE / NEEDS_REVIEW
│                                  │  + CVSS score, PoC exploit scenario
└───────────────┬──────────────────┘
                │
                ▼
        Report (Markdown / JSON / SARIF)
```

The LLM is given a mandatory investigation protocol: it must read the flagged function, trace data sources (callers), check data sinks (callees), look for sanitisers, and confirm reachability from a user-controlled entry point — before it is allowed to make a verdict. Each confirmed finding is enriched with a CVSS score, CVSS vector, vulnerability description, and a PoC exploit scenario.

---

## Quickstart

### 1. Install

```bash
pip install graphsast
# or with uv:
uv add graphsast
```

Requires Python 3.11+. Semgrep must be on PATH:

```bash
pip install semgrep
```

### 2. Scan (no LLM)

Builds the graph and runs Semgrep. Fast, no model needed.

```bash
graphsast scan ./myapp
```

### 3. Scan with LLM triage

The LLM investigates each finding, reads the real source code, and returns a verdict with CVSS score and PoC exploit scenario.

```bash
# Ollama (local)
ollama pull qwen3:8b
graphsast scan ./myapp --llm --llm-model qwen3:8b

# Claude (API)
export ANTHROPIC_API_KEY=sk-ant-...
graphsast scan ./myapp --llm --llm-backend claude

# Output to file
graphsast scan ./myapp --llm --format json --output report.json
```

### 4. Autonomous security hunt

Drives the LLM from entry points and execution flows — finds issues Semgrep rules don't cover.

```bash
graphsast hunt ./myapp --llm-backend claude
graphsast hunt ./myapp --llm-backend claude --full-hunt   # no cap on entry points/flows
```

Exit code `1` if any CRITICAL or HIGH active findings are present — useful for CI gates.

---

## LLM backends

| Backend | Config key | Notes |
|---|---|---|
| **Ollama** (default) | `backend = "ollama"` | Local inference |
| **Claude** | `backend = "claude"` | Requires `ANTHROPIC_API_KEY` |
| **OpenAI** | `backend = "openai"` | Requires `OPENAI_API_KEY` |
| **AWS Bedrock** | `backend = "bedrock"` | Uses standard AWS credential chain |

---

## Configuration

Config is layered (highest priority last):

1. Built-in defaults
2. `~/.graphsast/config.toml` — user-global
3. `<project>/.graphsast/config.toml` — project-local
4. `GRAPHSAST_*` environment variables
5. CLI flags

```toml
# .graphsast/config.toml

[llm]
backend           = "ollama"
model             = "qwen3:8b"
num_ctx           = 32768       # context window; 32768 recommended for deep analysis
analyst_max_turns = 15          # tool-use turns per finding; more = deeper investigation
timeout           = 300.0
temperature       = 0.1

[output]
format = "markdown"             # markdown | json | sarif
```

---

## CLI reference

```
graphsast scan <target>      Build graph → run Semgrep → (optionally) analyse with LLM
graphsast hunt <target>      Autonomous LLM-driven security hunt from entry points/flows
graphsast findings <target>  List stored findings; diff between runs
graphsast describe <target>  Graph stats + optional LLM narrative
graphsast check-llm          Test LLM backend connectivity and list available models
graphsast mcp-serve          Expose the 13 graph tools over the MCP protocol
```

### `scan` options

| Flag | Default | Description |
|---|---|---|
| `--llm` | off | Enable LLM analysis of each finding |
| `--llm-backend` | from config | `ollama` \| `claude` \| `openai` \| `bedrock` |
| `--llm-model` | from config | Model name |
| `--llm-max-turns` | 15 | Max tool-use turns per finding (0 = use config) |
| `--full-hunt` | off | No cap on entry points / flows analysed |
| `--semgrep-config` | `auto` | Semgrep `--config` value or path to rules file |
| `--semgrep-timeout` | 300s | Semgrep CLI timeout |
| `--format` | `markdown` | Output format: `markdown` \| `json` \| `sarif` |
| `--output` | stdout | Write report to file |
| `--db-dir` | `<target>/.graphsast` | Custom directory for `graph.db` |
| `--verbose` | off | Debug logging |

### `findings` options

| Flag | Default | Description |
|---|---|---|
| `--detail` | off | Full per-finding panel with reasoning and PoC |
| `--diff` | — | Compare two scan runs |

---

## LLM investigation tools

The LLM has 13 tools to investigate each finding. It is instructed to use at least 5 before reaching a verdict.

| Tool | What it does |
|---|---|
| `get_function` | Read a function's source code and metadata |
| `get_callers` | Who calls this function (data sources) |
| `get_callees` | What this function calls (data sinks) |
| `search_nodes` | Find functions/classes by name pattern (FTS5) |
| `read_file` | Read a file or a specific line range |
| `get_file_summary` | All symbols in a file with line ranges |
| `get_nodes_by_file` | Full metadata for every symbol in a file |
| `list_entry_points` | Functions with no callers — attack surface |
| `get_edges_for_node` | All edges: CALLS, IMPORTS_FROM, INHERITS, CONTAINS… |
| `get_impact_radius` | Blast radius BFS from a file |
| `get_flows` | Pre-computed execution flows ranked by criticality |
| `get_flow_by_id` | Step-by-step path of a specific flow |
| `trace_path` | BFS call chain between two functions |

These same tools are available to external agents via `graphsast mcp-serve` (MCP protocol).

---

## Report output

### Markdown (default)

Human-readable, grouped by severity. Each confirmed finding includes LLM verdict, CVSS score, reasoning, and a PoC exploit scenario.

### JSON

```json
{
  "summary": {"semgrep_findings": 9, "confirmed": 4, "false_positives": 3},
  "findings": [
    {
      "rule_id": "python.django.security.injection.tainted-sql-string",
      "file_path": "app/views.py",
      "line_start": 42,
      "severity": "HIGH",
      "llm_verdict": "CONFIRMED",
      "cvss_score": 8.1,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
      "llm_reasoning": "User input from request.GET flows directly into cursor.execute() without parameterisation.",
      "poc_scenario": "Send GET /search?q=1' OR '1'='1 to dump all rows."
    }
  ]
}
```

### SARIF

[SARIF 2.1.0](https://sarifweb.azurewebsites.net/) for GitHub Advanced Security and IDE integrations.

---

## Project structure

```
graphsast/
├── cli/            CLI commands (scan, hunt, findings, describe, check-llm, mcp-serve)
├── analysis/       scanner.py, analyst.py, hunter.py, semgrep.py, models.py
├── graph/          client.py — GraphClient (13 read-only tools)
├── mcp/            tools.py — MCP server + OpenAI tool schemas + executor
├── llm/            base.py, factory.py, ollama/claude/openai/bedrock clients
├── output/         markdown.py, json_report.py, sarif.py
├── vuln_db/        Vulnerability DB (populated, not yet used in analysis)
└── config.py       pydantic-settings loader
code_review_graph/  Upstream graph builder (tree-sitter, not modified)
```

---

## Planned

- **Semgrep autofix surfacing** — surface `fix:` patches alongside findings in reports
- **Parallel LLM analysis** — `--llm-workers N` flag for concurrent finding analysis
- **`graphsast review`** — interactively mark findings as TP/FP, suppress FPs on future scans
- **API route extraction** — extract HTTP paths (`GET /api/users`) from framework code (Flask, Express, Spring, Gin…)

---

## License

MIT
