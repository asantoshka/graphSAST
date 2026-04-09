# GraphSAST — Full Project Plan

> Everything we discussed: architecture, databases, analysis pipeline,
> agentic loop, small model optimisation, and build sequence.
> Ask questions against any section.

---

## Table of contents

1. [What is GraphSAST](#1-what-is-graphsast)
2. [What we are building on top of](#2-what-we-are-building-on-top-of)
3. [Core concepts and glossary](#3-core-concepts-and-glossary)
4. [Full architecture overview](#4-full-architecture-overview)
5. [Ingestion phase — building the code graph](#5-ingestion-phase--building-the-code-graph)
6. [DB 1 — code graph schema](#6-db-1--code-graph-schema)
7. [DB 2 — vulnerability pattern database](#7-db-2--vulnerability-pattern-database)
8. [Analysis pipeline — three phases](#8-analysis-pipeline--three-phases)
9. [The three-layer resolution strategy](#9-the-three-layer-resolution-strategy)
10. [What the graph can find alone](#10-what-the-graph-can-find-alone)
11. [Project structure](#11-project-structure)
12. [Build sequence — six milestones](#12-build-sequence--six-milestones)
13. [CLI interface](#13-cli-interface)
14. [Known gaps and mitigations](#14-known-gaps-and-mitigations)
15. [Tech stack decisions](#15-tech-stack-decisions)
16. [Where to start tomorrow](#16-where-to-start-tomorrow)

---

## 1. What is GraphSAST

GraphSAST is a standalone security analysis tool that finds vulnerabilities
in source code by combining three things that no existing open source tool
does together:

- A **structural code graph** built by parsing — not by an LLM
- A **vulnerability pattern database** seeded from Semgrep, CWE, and OWASP
- An **agentic LLM layer** that validates findings by reading real code

The key insight is that the graph does structural reasoning (what calls what,
how data flows, what is missing) and the LLM does semantic reasoning (is
this sanitizer actually effective, does this logic make sense). Neither has
to do the other's job.

### What makes it different from just running Semgrep

Semgrep can tell you "this pattern matched." It cannot tell you:

- Whether the matched function is reachable from a public entry point
- Whether tainted data actually flows through three intermediate functions
  to reach this sink
- Whether a sanitizer four calls away actually addresses this specific
  vulnerability class
- Whether this is business logic that bypasses access control even though
  no individual line looks wrong

GraphSAST answers all of those. Semgrep becomes one input to a richer
analysis, not the final word.

---

## 2. What we are building on top of

We fork **code-review-graph** (MIT licensed) as the infrastructure layer.

Repository: `github.com/tirth8205/code-review-graph`

### What it already gives us (do not rebuild)

- Tree-sitter parser wired for 19 languages
- SQLite schema with nodes, edges, qualified name system
- SHA-256 incremental update logic (only re-parse changed files)
- BFS impact radius traversal
- FTS5 full-text search
- MCP server scaffolding
- Git hook integration for auto-update
- CLI skeleton (build, update, watch, status)
- Database migration system (v1–v6)

### What we add on top

| code-review-graph has | GraphSAST adds |
|---|---|
| Structural nodes and edges | Taint annotations on nodes |
| CALLS, IMPORTS edges | TAINT_FLOWS_TO edge type |
| Blast radius query | Source-to-sink path finder |
| No vuln pattern storage | DB 2 (patterns, CWE, sinks) |
| No Semgrep integration | Phase 2 pattern runner |
| No LLM analysis | Three-layer analysis pipeline |
| No correlation | Phase 3 merge and dedup |
| No SARIF output | Output formatters |

Everything we add is **additive**. We extend the schema and add new
modules. We do not rewrite existing functionality.

---

## 3. Core concepts and glossary

### Parsing

**AST (Abstract Syntax Tree)**
A tree-shaped data structure the parser builds from source code. Instead
of raw text, nodes represent language constructs: function definition,
if-statement, variable assignment, method call.
> Like a sentence diagram — "the dog ate the bone" becomes subject + verb
> + object. Code becomes structure, not text.

**Tree-sitter**
A fast parser library that generates an AST for 19+ languages including
Python, Java, JavaScript, Go, Swift, Kotlin, C. No LLM involved. It runs
the same way a compiler front-end does — deterministic and fast.
> The factory that reads your .py file and produces a structured tree
> you can interrogate programmatically.

**Qualified name**
A unique string identifier for any code entity. Format:
`file_path::ClassName.method_name`
Example: `src/auth.py::AuthManager.login`
> Like a full postal address. City alone is ambiguous, but country + city
> + street + number is unique.

### Graph concepts

**Node (graph)**
A vertex representing one code entity: File, Class, Function, Variable,
Parameter, ImportedModule. Every node has a qualified name, type, and
the file and line where it lives.

**Edge (graph)**
A directed relationship between two nodes. Types:
`CALLS`, `IMPORTS`, `INHERITS`, `ASSIGNS`, `PASSES_TO`,
`TAINT_FLOWS_TO`, `READS_FROM`, `WRITES_TO`

**BFS (Breadth-First Search)**
A graph traversal that explores all neighbours of a node before going
deeper. Used to compute blast radius — all functions reachable from a
target within N hops.
> Ripples spreading from a stone in water. Each ring is one hop away.

**Blast radius**
The set of all nodes that could be affected if a given node is vulnerable
or changes. Computed by BFS following CALLS and DEPENDS_ON edges.

**Call graph**
A graph showing which functions call which other functions. The foundation
of your CALLS edges. Used to trace paths from entry points to sinks.

### Security concepts

**Taint analysis**
Tracks untrusted user input (a source) as it moves through the program
to see if it reaches a dangerous function (a sink) without being cleaned
(a sanitizer). The core technique for finding injection vulnerabilities.
> Water marked with dye at the tap. You follow the pipes to check if
> the dye reaches the drinking glass without passing through a filter.

**Source (taint)**
Where untrusted data enters: HTTP request parameters, form fields, file
uploads, environment variables, database reads of user-provided values.
> The tap where potentially contaminated water enters.

**Sink (taint)**
A dangerous function that causes a vulnerability if it receives untrusted
data: SQL execution, shell commands, file writes, HTML rendering without
escaping.
> The drinking glass. Contaminated water reaching it is the problem.

**Sanitizer**
A function that cleans or validates untrusted data, breaking the taint
chain: SQL parameterisation, HTML entity encoding, input validation.
> The water filter between tap and glass.

**SAST (Static Application Security Testing)**
Analysing source code for vulnerabilities without running it. Semgrep,
CodeQL, and GraphSAST are all SAST tools.
> Reading a recipe for toxic ingredients rather than cooking and tasting.

**CWE (Common Weakness Enumeration)**
A numbered catalogue of vulnerability classes. CWE-89 is SQL Injection,
CWE-79 is XSS, CWE-22 is Path Traversal. Your pattern DB is keyed on
CWE IDs.

**False positive**
A scanner reports a vulnerability that does not exist. GraphSAST reduces
these via the three-layer resolution strategy and graph-based sanitizer
verification.

**False negative**
A real vulnerability exists but the scanner misses it. The LLM layer is
designed to catch what patterns miss.

**Entry point**
A function reachable directly from outside: HTTP route handler, CLI
command, message queue consumer, scheduled job. User-controlled data
enters here.

**AST argument structure**
The type of expression used as an argument to a function call, as seen
in the AST:
- `string_literal` → fixed string → safe
- `binary_op (+)` → string concatenation → flag
- `f_string` or `.format()` → interpolation → flag
- `tuple` or `list` → parameterised → safe
- `identifier` → variable → check taint

This is the key insight for detecting SQLi by concatenation vs
parameterised query — the graph stores which type each sink call uses.

**ReAct loop**
Reason, Act, Observe, repeat. The LLM reasons about what it sees, calls
a tool to fetch more information (real source code), observes the result,
reasons again. This is how it validates findings without reading the
entire codebase.

---

## 4. Full architecture overview

```
SOURCE CODE INPUT
(git repo / directory / CI trigger)
         │
         ▼ Tree-sitter parse — no LLM, deterministic
┌─────────────────────────────────────────────┐
│              INGESTION PHASE                │
│  1. Structural extraction                   │
│     nodes: File, Class, Function, Var...    │
│     edges: CALLS, IMPORTS, INHERITS...      │
│                                             │
│  2. AST argument structure pass  [NEW]      │
│     per sink call: is_concatenated?         │
│     is_parameterised? contains_var?         │
│                                             │
│  3. Taint annotation pass                   │
│     tag SOURCE / SINK / SANITIZER nodes     │
│     add TAINT_FLOWS_TO edges                │
│                                             │
│  4. Missing edge markers  [NEW]             │
│     which auth/rate-limit/CSRF checks       │
│     are absent from each entry point        │
└──────────────────┬──────────────────────────┘
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
  ┌─────────────┐     ┌─────────────┐
  │    DB 1     │     │    DB 2     │
  │ code graph  │     │vuln patterns│
  │  graph.db   │     │  vulns.db   │
  └──────┬──────┘     └──────┬──────┘
         │                   │
         └─────────┬─────────┘
                   │
         ▼─────────────────────────────────────
         │         PHASE 1                     │
         │   Three-layer LLM resolution        │
         │                                     │
         │  Layer 1: pattern + graph           │
         │    → resolves ~65% of findings      │
         │    → zero LLM calls                 │
         │                                     │
         │  Layer 2: LLM single-shot           │
         │    → one call, small focused prompt │
         │    → resolves most remaining cases  │
         │                                     │
         │  Layer 3: targeted micro-task       │
         │    → only the specific uncertainty  │
         │    → fires on ~10% of findings      │
         ▼─────────────────────────────────────
         │         PHASE 2                     │
         │   Pattern matching                  │
         │                                     │
         │  Pass A: Semgrep                    │
         │  Pass B: graph taint BFS queries    │
         │  Pass C: import + structure         │
         ▼─────────────────────────────────────
         │         PHASE 3                     │
         │   Correlate + deduplicate           │
         │   Confidence tiering                │
         │   Severity scoring                  │
         ▼─────────────────────────────────────
              OUTPUT REPORT
         SARIF 2.1 / JSON / Markdown
```

---

## 5. Ingestion phase — building the code graph

The ingestion phase runs Tree-sitter against the target codebase and
populates DB 1. **No LLM is involved at any point here.**

### Pass 1 — structural extraction

For every file, Tree-sitter produces an AST. We walk it and extract:

**Nodes:**
- `File` — one per source file
- `Class` — class and struct definitions
- `Function` — function and method definitions
- `Variable` — variable assignments at module/class level
- `Parameter` — function parameters
- `ImportedModule` — import statements

**Edges:**
- `CALLS` — function A calls function B
- `IMPORTS` — file A imports module B
- `INHERITS` — class A inherits from class B
- `ASSIGNS` — variable A is assigned value B
- `PASSES_TO` — value A is passed as argument to function B
- `CONTAINS` — class A contains function B
- `READS_FROM` — function reads from data store
- `WRITES_TO` — function writes to data store

Every node gets a qualified name: `src/auth.py::AuthManager.login`

### Pass 2 — AST argument structure (your insight)

For every call to a known sink function, we inspect the AST node type
of each argument:

```
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
                ─────────────────────────────────────────
                            AST node: binary_op
                            → is_concatenated = True

cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
               ────────────────────────────────────
                            AST node: string_literal
                            → is_parameterised = True
```

This is stored in the `call_arguments` table. The same graph that
knows `execute()` was called now also knows **how** it was called.
This is what makes the difference between detecting SQLi and missing it.

**Argument types we detect:**

| AST node type | Meaning | Action |
|---|---|---|
| `string_literal` | Fixed string | Safe — no flag |
| `binary_op` (+) | Concatenation | Flag — high risk |
| `f_string` | F-string interpolation | Flag — high risk |
| `.format()` call | String formatting | Flag — high risk |
| `% operator` | Old-style formatting | Flag — medium risk |
| `tuple` or `list` | Parameterised | Safe — no flag |
| `identifier` | Variable reference | Check taint chain |

### Pass 3 — taint annotation

We walk the taint signatures from DB 2 and annotate nodes:

- Any node matching a SOURCE signature → `is_user_controlled = True`
- Any node matching a SINK signature → record in `taint_annotations`
- Any node matching a SANITIZER signature → record in `taint_annotations`
- Add `TAINT_FLOWS_TO` edges between connected source/sink pairs

### Pass 4 — missing edge markers (new)

For every entry point node, we run a bounded BFS through its call chain
and record which security functions are **absent**:

```python
security_functions = [
    "auth_required", "login_required",   # authentication
    "permission_required", "check_perm", # authorisation
    "rate_limit", "throttle",            # rate limiting
    "csrf_protect", "verify_token",      # CSRF
    "validate", "schema.load",           # input validation
]
```

If an entry point's entire call chain never reaches any auth function,
that is recorded in the `missing_checks` table.

### Incremental updates

On subsequent runs, we only re-parse files whose SHA-256 hash has
changed since the last build. For a 2,900-file project this takes
under 2 seconds.

---

## 6. DB 1 — code graph schema

```sql
-- Every code entity
CREATE TABLE nodes (
    id                  TEXT PRIMARY KEY,
    qualified_name      TEXT UNIQUE,          -- src/auth.py::AuthManager.login
    type                TEXT,                 -- File|Class|Function|Variable|Parameter
    name                TEXT,
    file_path           TEXT,
    line_start          INTEGER,
    line_end            INTEGER,
    signature           TEXT,
    language            TEXT,
    is_entry_point      BOOLEAN DEFAULT 0,   -- HTTP route, CLI cmd, etc.
    is_user_controlled  BOOLEAN DEFAULT 0,   -- tainted source
    file_hash           TEXT                 -- SHA-256 for incremental
);

-- Every relationship
CREATE TABLE edges (
    id              TEXT PRIMARY KEY,
    source_qn       TEXT,                    -- qualified_name of source
    target_qn       TEXT,                    -- qualified_name of target
    edge_type       TEXT,                    -- CALLS|IMPORTS|TAINT_FLOWS_TO|...
    line_number     INTEGER,
    FOREIGN KEY (source_qn) REFERENCES nodes(qualified_name),
    FOREIGN KEY (target_qn) REFERENCES nodes(qualified_name)
);

-- AST argument structure per sink call
CREATE TABLE call_arguments (
    id                  TEXT PRIMARY KEY,
    call_edge_id        TEXT,               -- which CALLS edge this belongs to
    arg_position        INTEGER,            -- 0-indexed
    arg_type            TEXT,               -- string_literal|binary_op|f_string|tuple|identifier
    is_concatenated     BOOLEAN DEFAULT 0,
    is_parameterised    BOOLEAN DEFAULT 0,
    contains_var        BOOLEAN DEFAULT 0,
    raw_ast_node        TEXT                -- JSON of the AST node for debugging
);

-- SOURCE / SINK / SANITIZER tags per node
CREATE TABLE taint_annotations (
    node_qn         TEXT,
    annotation_type TEXT,                   -- SOURCE|SINK|SANITIZER
    vuln_class_id   TEXT,                   -- which vulnerability class
    source_ref      TEXT                    -- which DB 2 signature matched
);

-- Missing security checks per entry point
CREATE TABLE missing_checks (
    entry_point_qn      TEXT,
    missing_type        TEXT,               -- auth|rate_limit|csrf|validation
    check_patterns      TEXT                -- what we looked for (JSON array)
);

-- Phase 1 findings
CREATE TABLE phase1_findings (
    id              TEXT PRIMARY KEY,
    scan_run_id     TEXT,
    qualified_name  TEXT,
    vuln_class_id   TEXT,
    verdict         TEXT,                   -- CONFIRMED|FALSE_POSITIVE|UNCERTAIN
    confidence      TEXT,                   -- HIGH|MEDIUM-HIGH|MEDIUM|LOW
    method          TEXT,                   -- pattern+graph|llm-single|llm-microtask
    cwe_id          TEXT,
    severity        TEXT,
    reasoning       TEXT,                   -- LLM explanation
    source_seen     TEXT,                   -- actual code the LLM looked at
    turns_used      INTEGER,
    taint_path      TEXT                    -- JSON array of qualified_names
);

-- Scan run metadata (for versioning and reproducibility)
CREATE TABLE scan_runs (
    id              TEXT PRIMARY KEY,
    timestamp       TEXT,
    vuln_db_hash    TEXT,                   -- SHA-256 of vulns.db at scan time
    graphsast_ver   TEXT,
    target_path     TEXT
);

-- Indexes for performance
CREATE INDEX idx_edges_source ON edges(source_qn);
CREATE INDEX idx_edges_target ON edges(target_qn);
CREATE INDEX idx_edges_type   ON edges(edge_type);
CREATE INDEX idx_nodes_file   ON nodes(file_path);
CREATE INDEX idx_taint_node   ON taint_annotations(node_qn);
CREATE INDEX idx_missing_ep   ON missing_checks(entry_point_qn);
```

---

## 7. DB 2 — vulnerability pattern database

This is a **separate SQLite file** (`vulns.db`). It is the intelligence
layer — what GraphSAST knows about vulnerability classes and how to
detect them.

### Schema

```sql
-- The vulnerability class (what it is)
CREATE TABLE vuln_classes (
    id          TEXT PRIMARY KEY,           -- "sqli-concat-python"
    cwe_id      TEXT,                       -- "CWE-89"
    owasp_cat   TEXT,                       -- "A03"
    name        TEXT,
    description TEXT,
    severity    TEXT,                       -- CRITICAL|HIGH|MEDIUM|LOW
    language    TEXT,                       -- python|java|go|any
    source      TEXT                        -- semgrep|cwe|owasp|custom
);

-- The detection methods (how to find it) — multiple per class
CREATE TABLE detectors (
    id              TEXT PRIMARY KEY,
    vuln_class_id   TEXT REFERENCES vuln_classes(id),
    detector_type   TEXT,                   -- semgrep|taint_signature|ast_pattern|graph_query
    content         TEXT,                   -- the rule / query / pattern
    language        TEXT,
    confidence      TEXT                    -- HIGH|MEDIUM|LOW
);

-- Sources and sinks per language
CREATE TABLE taint_signatures (
    id                  TEXT PRIMARY KEY,
    name                TEXT,
    qualified_pattern   TEXT,               -- e.g. "cursor.execute"
    language            TEXT,
    sig_type            TEXT,               -- SOURCE|SINK|SANITIZER
    cwe_ids             TEXT,               -- JSON array ["CWE-89"]
    source              TEXT
);

-- Vector embeddings for semantic search (optional)
CREATE TABLE vuln_embeddings (
    id          TEXT PRIMARY KEY,
    pattern_id  TEXT,
    embedding   BLOB,
    model_name  TEXT
);
```

### How it stays up to date — the loader pipeline

You never edit vulns.db directly. You run loaders that feed from
upstream sources into the unified schema:

```bash
graphsast update-vuln-db
```

**Loader sources:**

1. **Semgrep registry** (`returntocorp/semgrep-rules`)
   Clone locally, walk all YAML files, extract rules that have CWE tags,
   insert into `vuln_classes` and `detectors`. This alone gives you
   3,000+ patterns on day one.

2. **CWE XML dump** (MITRE, `cwe.mitre.org`)
   Seeds `vuln_classes` with official descriptions, severity, and
   related weaknesses.

3. **Taint signature YAML** (your hand-curated file)
   Language-specific sources, sinks, and sanitizers:
   ```yaml
   - name: psycopg2_execute
     pattern: "cursor.execute"
     language: python
     type: SINK
     cwe_ids: ["CWE-89"]
   ```

4. **Custom rules** (`.semgrep/custom/*.yaml`)
   Your own rules for targets you encounter on engagements.
   These get tagged `source: custom` in the DB.

5. **OWASP MASTG** (for mobile targets)
   Mobile-specific sinks for Android and iOS.

**Upsert strategy:**
Every loader uses `INSERT OR REPLACE` keyed on the rule `id`. Running
the loader multiple times is idempotent — same output every time.
New rules are inserted, updated rules are replaced, nothing is lost.

### How you extend it for a new vulnerability

One YAML file in your custom rules directory:

```yaml
# .graphsast/custom/ssrf-redis-python.yaml
id: ssrf-redis-python
cwe_id: CWE-918
owasp_cat: A10
name: SSRF via Redis URL
language: python
severity: HIGH
description: >
  User-controlled input passed to Redis connection URL
  allows SSRF to internal services.
detectors:
  - type: taint_signature
    sink_pattern: "redis.Redis"
    arg_position: 0
    confidence: HIGH
  - type: semgrep
    rule: |
      rules:
        - id: ssrf-redis
          pattern: redis.Redis(host=$X)
          languages: [python]
          severity: ERROR
```

Run `graphsast update-vuln-db --source custom`.
Everything downstream picks it up automatically.

### Where patterns come from

| Source | URL | What you get |
|---|---|---|
| Semgrep registry | github.com/returntocorp/semgrep-rules | 3,000+ community rules |
| CodeQL sources | github.com/github/codeql | Source/sink reference lists |
| OWASP MASTG | github.com/OWASP/owasp-mastg | Mobile-specific patterns |
| CWE database | cwe.mitre.org/data/xml | Official weakness catalogue |
| Joern queries | github.com/joernio/joern | Taint query reference patterns |
| NVD CVE feed | nvd.nist.gov/feeds | Real-world vulnerability patterns |

---

## 8. Analysis pipeline — three phases

### Phase 1 — two completely separate LLM mechanisms

Phase 1 has two sub-phases. They are fundamentally different in
purpose, mechanism, and what they catch. They must not be conflated.

---

#### Phase 1A — autonomous LLM analysis (no DB 2, no patterns, no pre-identified paths)

**What it is:** The LLM acts as an independent security researcher.
It has no briefing on what to look for. It reads the graph and code
and thinks for itself.

**Trigger:** Every entry point in the codebase gets its own 1A session.

**What the LLM receives:**
- Graph summary of the entry point: call chain, argument structures,
  missing security checks
- A language-specific system prompt grounding it in the target
  language's security idioms
- Access to tools to fetch real source code on demand

**What the LLM does NOT receive:**
- Anything from DB 2 — no known sink lists, no CWE tags, no Semgrep
  rule descriptions, no pattern hints
- Any pre-identified suspect paths from graph taint analysis
- Any structured task or checklist

**Mechanism: free multi-turn conversation**

The LLM explores however it wants. It reads graph context, forms
impressions, fetches code it finds interesting, reasons, fetches more.
There is no fixed sequence of steps. The conversation ends when the
LLM says it is done or the turn limit is reached.

```
Turn 1 — LLM reads entry point graph summary
  "login() calls execute() and passes request.args directly.
   Also I notice there is no auth check before get_user_data().
   Let me look at both."
  → calls fetch_function_source("src/db.py::execute")
  → calls fetch_function_source("src/api.py::get_user_data")

Turn 2 — LLM reads both functions
  "execute() does direct concatenation — SQL injection.
   get_user_data() takes user_id from request but doesn't
   check if the requesting user owns that record — IDOR.
   These are two separate findings."
  → outputs finding JSON, ends session
```

The LLM found both issues from its own knowledge. No pattern told it
to look for IDOR. No taint analysis flagged the concatenation. It
reasoned from what it saw.

**What Phase 1A catches that nothing else does:**

```
Business logic flaws
  auth present but applied after sensitive operation executes
  permission check on wrong object (IDOR)
  price/quantity manipulation through parameter ordering
  multi-step flow that bypasses a check by skipping a step

Novel vulnerability chaining
  individually safe operations that combine dangerously
  e.g. open redirect + cookie set → session fixation chain

Design-level issues
  rate limiting present but bypassable via parameter variation
  encryption present but key derived from user-controlled input

Framework-specific misuse
  Django ORM .extra() vs .raw() subtleties
  Flask before_request hook that can be skipped
  Spring Security config that applies to wrong path pattern

Anything with no pattern written for it yet
```

**Tools available in Phase 1A:**

```python
fetch_function_source(qualified_name)    # read real code of a function
fetch_call_context(qualified_name)       # callers + callees from graph
fetch_taint_path(source_qn, sink_qn)    # path between two nodes
fetch_argument_structure(call_edge_id)  # how an argument is constructed
fetch_callers(qualified_name)            # who calls this function
```

The LLM calls these because it is **curious** — it decided it wants
to look at something. Not because a structured flow told it to.

**Output:**

```sql
CREATE TABLE phase1a_findings (
    id               TEXT PRIMARY KEY,
    scan_run_id      TEXT,
    entry_point_qn   TEXT,
    suspected_vuln   TEXT,      -- LLM's own description in its own words
    suggested_cwe    TEXT,      -- LLM's best guess at a CWE
    affected_nodes   TEXT,      -- JSON array of qualified_names it looked at
    reasoning        TEXT,      -- full reasoning chain, verbatim
    confidence       TEXT,      -- HIGH | MEDIUM | LOW
    source_code_seen TEXT,      -- all code the LLM fetched and read
    turns_used       INTEGER,
    db2_consulted    BOOLEAN DEFAULT 0  -- always False in 1A
);
```

Turn limit: 8 turns per entry point. If not finished, store what
was found and mark `incomplete = True`.

---

#### Phase 1B — ReAct validation loop (graph-identified paths, DB 2 consulted)

**What it is:** A structured confirmation mechanism. The graph already
identified a specific suspect path (source → sink, or missing check).
Phase 1B's job is to validate whether that specific path is a real
vulnerability or a false positive.

**Trigger:** Every suspect path produced by graph taint BFS (source →
sink with no sanitizer), plus every entry point in `missing_checks`.

**What is different from Phase 1A:**

```
Phase 1A                          Phase 1B
──────────────────────────────────────────────────────
LLM explores freely               LLM validates a specific claim
No pre-identified path            Graph already found the path
LLM decides what to look at       Orchestrator directs the LLM
DB 2 not consulted                DB 2 consulted via Layer 1
Creative, open-ended              Structured, bounded
Finds novel issues                Confirms or drops known suspects
```

**Mechanism: three-layer resolution (see Section 9 for full detail)**

The orchestrator (Python code, not the LLM) decides which layer to
use for each suspect path:

```
Layer 1 — pattern + graph alone, zero LLM calls
  Graph + DB 2 give a clean answer → finding confirmed or dropped
  Handles ~65% of suspect paths

Layer 2 — LLM single-shot with ReAct tools
  One focused call: "Graph suspects X at this location.
  Here is the evidence. Fetch code if needed. Confirm or drop."
  LLM calls tools because it is verifying a specific claim,
  not because it is curious
  Max 5 turns

Layer 3 — targeted micro-task (if Layer 2 still uncertain)
  Only the specific check that Layer 2 could not resolve
  e.g. "Is this sanitizer effective against SQLi?" — yes/no only
  Max 3 turns
```

**The critical difference in how tools are used:**

In Phase 1A the LLM calls `fetch_function_source()` because it wants
to investigate something it noticed. In Phase 1B the LLM calls
`fetch_function_source()` because the orchestrator said "the graph
found a taint path ending here — go check if the concatenation is
real." Same tool, completely different reason for calling it.

**Output:**

```sql
CREATE TABLE phase1b_findings (
    id             TEXT PRIMARY KEY,
    scan_run_id    TEXT,
    qualified_name TEXT,
    vuln_class_id  TEXT,       -- maps to DB 2 vuln_classes.id
    suspect_path   TEXT,       -- JSON: the specific path graph identified
    verdict        TEXT,       -- CONFIRMED | FALSE_POSITIVE | UNCERTAIN
    confidence     TEXT,
    method         TEXT,       -- pattern+graph | llm-single | llm-microtask
    cwe_id         TEXT,
    severity       TEXT,
    reasoning      TEXT,
    source_seen    TEXT,
    turns_used     INTEGER,
    taint_path     TEXT,
    db2_consulted  BOOLEAN DEFAULT 1  -- always True in 1B
);
```

---

#### Summary: the two mechanisms side by side

```
                    PHASE 1A                  PHASE 1B
                    ────────                  ────────
Purpose             Discover unknowns         Validate known suspects
Input               Entry point graph         Specific suspect path
DB 2 used           Never                     Always (Layer 1+)
LLM direction       Self-directed             Orchestrator-directed
Tool usage reason   Curiosity                 Verification
Turn limit          8                         5 (Layer 2), 3 (Layer 3)
Unique value        Finds novel issues        Eliminates false positives
Output table        phase1a_findings          phase1b_findings
```

---

#### How 1A and 1B findings flow into Phase 3

| Phase 1A | Phase 1B | Phase 2 | Confidence | Report label |
|---|---|---|---|---|
| Found | Found | Found | VERY HIGH | All signals agree |
| Found | Found | Not found | HIGH | LLM + pattern agree |
| Found | Not found | Found | HIGH | LLM + Semgrep/graph agree |
| Not found | Found | Found | HIGH | Pattern-guided + Semgrep |
| Found | Not found | Not found | MEDIUM-HIGH | Autonomous LLM only |
| Not found | Found | Not found | MEDIUM-HIGH | Pattern-guided confirmed |
| Not found | Not found | Found | MEDIUM | Pattern/graph only |
| Found uncertain | Not found | Not found | LOW | Human review needed |

The **"Found / Not found / Not found"** row (Phase 1A only) is the
most important addition. This is the LLM finding something using its
own intelligence that no pattern and no graph taint query caught.
These are labelled in the report: "Autonomous LLM finding — no
matching pattern in DB 2. Human review recommended."

### Phase 2 — pattern matching

Three passes run in parallel:

**Pass A — Semgrep**
- Build a temporary ruleset from DB 2 detectors of type `semgrep`
- Run: `semgrep --config .rules/ --json ./target`
- Parse JSON output
- Map each finding to a `qualified_name` via line number lookup in DB 1
- Record in `phase2_findings`

**Pass B — graph taint queries**
- For every (SOURCE, SINK) pair from `taint_signatures`
- Run BFS from SOURCE toward SINK
- Condition: no SANITIZER node in path
- Extra: if `call_arguments.is_concatenated = True` at sink → higher severity
- Also queries `missing_checks` table:
  - Entry points with no auth edge
  - Entry points with no rate_limit edge
  - Sensitive data flows with no encrypt edge

**Pass C — import and structure analysis**
- Dangerous imports: `pickle`, `marshal`, `yaml` unsafe_load, `eval`, `exec`
- Orphaned sensitive functions (no incoming CALLS edges)
- God functions (unusually high out-degree to sink nodes)
- Inheritance violations: child class overrides security method but
  removes auth check

**Optional: Phase 2 LLM validation**
- High-confidence Semgrep hits → pass straight to Phase 3
- Medium-confidence hits → optional single-shot LLM validation
- Same ReAct tool set available as Phase 1

### Phase 3 — correlate and deduplicate

**Merge strategy:**

Group all findings by `(file_path, line_range, cwe_id)`:

| Condition | Confidence | Action |
|---|---|---|
| Phase 1 + Phase 2 agree | HIGH | Boost severity, include |
| Phase 1 confirmed (LLM + code seen) | MEDIUM-HIGH | Include with reasoning |
| Phase 2 only (Semgrep/graph) | MEDIUM | Standard confidence |
| Phase 1 uncertain + Phase 2 miss | LOW | Flag for human review |

**False positive filter:**
If a taint path passes through a node annotated `SANITIZER` in DB 1
that is known effective for this CWE in DB 2 → suppress the finding.

**Dedup:**
Same qualified_name + same CWE reported by multiple passes → merged
into one finding, all evidence preserved.

**Severity scoring:**
```
final_severity = base_severity (from DB 2)
               × confidence_multiplier
               × reachability_multiplier
```

Reachability multipliers:
```
Public HTTP route       → 1.0 (full severity)
Authenticated route     → 0.8
CLI command             → 0.6
Internal scheduled job  → 0.4
Test file only          → 0.1
No entry point found    → 0.3
```

**Output per finding includes:**
- CWE ID + OWASP category
- Severity (CRITICAL / HIGH / MEDIUM / LOW)
- File + line range
- Qualified name of vulnerable function
- Full taint path (array of qualified names)
- Argument structure at sink (concatenated / parameterised)
- LLM reasoning text (if LLM was used)
- Actual source code the LLM examined
- Confidence level + method used (pattern+graph / llm-single / llm-microtask)
- Turns used in ReAct loop

---

## 9. The three-layer resolution strategy

This is the design that makes small models (7B–14B) work well.
The core principle: **let patterns answer what patterns can answer,
only escalate to the LLM what genuinely requires reasoning.**

### Layer 1 — pattern + graph (free, instant, no LLM)

The graph and DB 2 together answer these questions before any LLM call:

```
Question                              Answered by
──────────────────────────────────────────────────────────────────
Is this function a known sink?        DB 2 taint_signatures
Is this a known source?               DB 2 taint_signatures
Is arg concatenated?                  DB 1 call_arguments.is_concatenated
Is source user-controlled?            DB 1 nodes.is_user_controlled
Is there a sanitizer in path?         DB 1 SANITIZER edge
Is sanitizer known effective?         DB 2 taint_signatures
Is entry point public?                DB 1 nodes.is_entry_point
Does Semgrep rule match?              Phase 2 Pass A result
```

If all checks give clean answers → **HIGH confidence finding, zero LLM
calls.** Straight to Phase 3.

In practice this resolves ~65% of findings for common vulnerability
classes (SQLi, XSS, command injection).

```python
def try_pattern_resolution(suspect_path):
    checks = {
        "sink_known":       db2.is_known_sink(suspect_path.sink),
        "source_confirmed": db1.is_user_controlled(suspect_path.source),
        "arg_unsafe":       db1.is_concatenated(suspect_path.sink_call),
        "no_sanitizer":     not db1.has_effective_sanitizer(suspect_path),
        "public_entry":     db1.is_public_entry(suspect_path.entry_point),
    }
    if all(checks.values()):
        return Finding(verdict=CONFIRMED, confidence=HIGH, method="pattern+graph")
    if checks["sink_known"] and checks["source_confirmed"] and not checks["arg_unsafe"]:
        return Finding(verdict=FALSE_POSITIVE, method="pattern+graph")
    return None  # ambiguous — escalate to Layer 2
```

### Layer 2 — LLM single-shot

One LLM call with a small, focused prompt. The model only receives
what Layer 1 could not answer, plus just the relevant code snippet.

Example prompt (< 400 tokens total):

```
You are a security reviewer.

Graph analysis found:
  - Sink: db.query() — NOT in known sink list (custom ORM)
  - Source: request.form['id'] — confirmed user input
  - Sanitizer: clean_input() found in path — effectiveness UNKNOWN
  - Argument: binary_op (string concatenation detected)

Vulnerability being checked: SQL Injection (CWE-89)

Sanitizer source code:
  def clean_input(val):
      return re.sub(r'[^\w]', '', val)

Sink call:
  db.query("SELECT * FROM t WHERE id=" + clean_input(user_id))

Question: Is clean_input() effective against SQL injection as used here?

Respond only with JSON:
{"verdict": "CONFIRMED|FALSE_POSITIVE|UNCERTAIN", "reason": "one sentence"}
```

Outcomes:
- `CONFIRMED` → finding goes to Phase 3
- `FALSE_POSITIVE` → dropped, never reaches Phase 3
- `UNCERTAIN` → escalate to Layer 3

Layer 2 resolves most of what Layer 1 couldn't. Typical escalation to
Layer 3 is ~10–15% of findings.

### Layer 3 — targeted micro-task

Only fires for genuinely uncertain cases. Crucially: it does not run
all micro-tasks. It runs **only the task that resolves the specific
uncertainty Layer 2 flagged.**

```python
def escalate_to_microtasks(suspect_path, layer2_result):
    if layer2_result.uncertain_about == "sanitizer_effectiveness":
        return run_sanitizer_microtask(suspect_path)
    if layer2_result.uncertain_about == "taint_source":
        return run_source_microtask(suspect_path)
    if layer2_result.uncertain_about == "reachability":
        return run_reachability_microtask(suspect_path)
```

Each micro-task:
- Single question
- < 400 token input
- Structured output (YES / NO or short enum)
- Uses Ollama's `format` parameter to enforce JSON schema

### LLM tools available in Layers 2 and 3

```python
tools = [
    fetch_function_source(qualified_name),   # real code of a function
    fetch_call_context(qualified_name),      # callers + callees from graph
    fetch_taint_path(source_qn, sink_qn),   # full path between two nodes
    fetch_argument_structure(call_edge_id), # how arg is constructed
    fetch_callers(qualified_name),           # who calls this function
]
```

**Turn limit:** 5 turns maximum per finding. If not resolved by turn 5
→ `UNCERTAIN`, flag for human review.

**Context window management (critical for small models):**
Before sending source code to the LLM:
- Only send ±20 lines around the relevant taint path
- Strip comments, docstrings, blank lines
- If function > 100 lines, summarise irrelevant parts with graph data

Without this, a 7B model will overflow its context on real codebases.

### Phase 1 finding cache

Key: `sha256(qualified_name + file_hash + vuln_class_id)`

If the function has not changed (same file_hash) and you are checking
the same vulnerability class → return cached finding. Invalidate when
the function or any of its callees change (blast radius from DB 1).

This makes incremental scans dramatically faster.

---

## 10. What the graph can find alone

Before any LLM or Semgrep involvement, graph queries alone can detect:

### Category 1 — taint path exists (source → sink, no sanitizer)

```
SQL Injection        request.args → execute() / raw() / query()
Command Injection    request.args → os.system() / subprocess()
SSRF                 request.args → requests.get() / urllib.open()
Path Traversal       request.args → open() / os.path.join()
LDAP Injection       request.args → ldap.search()
XSS                  request.args → render_template() / innerHTML
Log Injection        request.args → logger.info()
```

Query: find all paths where `start.is_user_controlled = True`,
`end.qualified_name IN SINK_LIST`, no SANITIZER in path.

### Category 2 — missing edge (expected function absent)

```
Missing authentication    entry point → no auth_required() in call chain
Missing authorisation     DB read of user_id → no permission_check()
Missing rate limiting     HTTP route → no rate_limiter in call chain
Missing input validation  user input → business logic, no validate()
Missing CSRF check        POST handler → no csrf_verify() in call chain
Missing encryption        password field → DB write with no hash()
```

Query: find entry points where BFS through call chain never reaches
the expected security function.

### Category 3 — dangerous graph topology

```
Hardcoded secrets         string_literal assigned to auth/crypto variable
IDOR                      user_id parameter → DB query, no ownership_check()
Dead code with sinks      function node, no incoming CALLS edges, contains sinks
God function              single function has edges to 20+ sink nodes
```

### Category 4 — import graph

```
Dangerous import          file imports pickle / marshal / eval / exec
Unexpected import         auth.py imports subprocess (shell from auth code)
```

---

## 11. Project structure

```
graphsast/
├── ingestion/
│   ├── parser.py           # Tree-sitter, 19 languages, AST extraction
│   ├── arg_inspector.py    # AST argument structure pass (new)
│   ├── taint_markers.py    # SOURCE/SINK/SANITIZER annotation pass
│   ├── missing_edges.py    # missing security check detection
│   └── hasher.py           # SHA-256 per file for incremental
│
├── graph_db/
│   ├── store.py            # SQLite adapter (GraphStore class)
│   ├── schema.py           # CREATE TABLE statements, migrations
│   ├── query.py            # BFS, taint path finder, missing check query
│   └── cache.py            # Phase 1 result cache
│
├── vuln_db/
│   ├── store.py            # vulns.db adapter
│   ├── schema.py           # vuln_classes, detectors, taint_signatures
│   ├── loader.py           # orchestrates all importers
│   ├── importers/
│   │   ├── semgrep.py      # walk semgrep-rules repo, import YAML
│   │   ├── cwe_xml.py      # parse CWE XML dump
│   │   ├── owasp_mastg.py  # mobile patterns
│   │   └── custom.py       # .graphsast/custom/*.yaml
│   └── embeddings.py       # optional vector index (sentence-transformers)
│
├── analysis/
│   ├── orchestrator.py     # coordinates all phases
│   ├── phase1a/
│   │   ├── autonomous.py   # free LLM exploration per entry point
│   │   ├── session.py      # manages multi-turn conversation
│   │   └── tools.py        # fetch_function_source, fetch_call_context, etc.
│   ├── phase1b/
│   │   ├── validator.py    # orchestrates three-layer resolution
│   │   ├── layer1.py       # pattern + graph, zero LLM
│   │   ├── layer2.py       # LLM single-shot with ReAct tools
│   │   ├── layer3.py       # targeted micro-task (specific uncertainty only)
│   │   └── tools.py        # same tool set as 1A, different usage intent
│   ├── phase2/
│   │   ├── semgrep_runner.py
│   │   ├── taint_queries.py
│   │   └── structure.py
│   └── phase3/
│       ├── correlator.py   # merges 1A + 1B + Phase 2 findings
│       └── scorer.py       # severity + reachability scoring
│
├── llm/
│   ├── backend.py          # abstract LLMBackend interface
│   ├── ollama.py           # Ollama implementation
│   ├── claude.py           # Claude API implementation
│   └── prompts/
│       ├── python.yaml     # language-specific system prompts
│       ├── java.yaml
│       └── go.yaml
│
├── output/
│   ├── sarif.py            # SARIF 2.1 formatter
│   ├── json_report.py      # JSON formatter
│   └── markdown.py         # human-readable report
│
├── cli/
│   ├── scan.py             # graphsast scan <target>
│   ├── build_graph.py      # graphsast build-graph <target>
│   ├── update_vuln_db.py   # graphsast update-vuln-db
│   └── query.py            # graphsast query --taint-paths ...
│
├── models.py               # shared Pydantic models (Finding, Node, Edge...)
├── config.py               # pydantic-settings config loader
├── tests/
│   ├── fixtures/
│   │   └── vulnrez/        # intentionally vulnerable target for eval
│   ├── test_parser.py
│   ├── test_taint.py
│   ├── test_phase1.py
│   └── test_phase2.py
│
├── .graphsast/
│   └── custom/             # your custom vuln rules
├── pyproject.toml
├── Dockerfile
└── README.md
```

---

## 12. Build sequence — six milestones

### Milestone 1 — fork + skeleton + ingestion (week 1–2)

**Tasks:**
1. Fork code-review-graph
2. Create the new package structure above
3. Extend `parser.py` with the AST argument structure pass
4. Add `arg_inspector.py` for `call_arguments` table population
5. Verify: `graphsast build-graph ./vulnrez` produces a populated SQLite

**Done when:** You can inspect `graph.db` and see nodes, edges, and
`call_arguments` rows with `is_concatenated` populated correctly for
VulnRez's SQL sinks.

### Milestone 2 — extend graph schema for security (week 2–3)

**Tasks:**
1. Add new columns to nodes: `is_entry_point`, `is_user_controlled`
2. Add new tables: `call_arguments`, `taint_annotations`, `missing_checks`
3. Write and run the schema migration (they already have a migration system)
4. Implement `taint_markers.py` — annotate SOURCE/SINK/SANITIZER nodes
5. Implement `missing_edges.py` — detect absent security functions

**Done when:** After `build-graph`, the graph correctly shows
`request.args` nodes tagged SOURCE, `cursor.execute` nodes tagged SINK,
and VulnRez's unprotected routes flagged in `missing_checks`.

### Milestone 3 — DB 2 + loader pipeline (week 3–4)

**Tasks:**
1. Create `vulns.db` schema
2. Write `importers/custom.py` first — load your hand-curated YAML
3. Write 20–30 Python taint signatures for VulnRez's sinks/sources
4. Write `importers/semgrep.py` — clone semgrep-rules repo, walk YAML
5. Implement `graphsast update-vuln-db` CLI command

**Done when:** `vulns.db` contains your custom signatures plus 500+
Semgrep rules with CWE tags. Query it and get a Semgrep rule for
CWE-89 in Python.

### Milestone 4 — Phase 1 Layer 1 (week 4–5)

**Tasks:**
1. Implement `layer1.py` — pattern + graph resolution, no LLM
2. Implement the taint path BFS query in `graph_db/query.py`
3. Write the result cache in `graph_db/cache.py`
4. Test against VulnRez — measure precision and recall

**Done when:** Running Layer 1 against VulnRez catches all known SQLi
vulnerabilities that involve known sinks with concatenated arguments.
Measure false positives.

### Milestone 5 — Phase 1 Layers 2 and 3, Phase 2 (week 5–7)

**Tasks:**
1. Implement `llm/backend.py` + `llm/ollama.py`
2. Implement `layer2.py` with single-shot validation
3. Implement the LLM tools (fetch_function_source, etc.)
4. Add language-specific prompt templates in `llm/prompts/`
5. Implement `layer3.py` with targeted micro-tasks
6. Implement `phase2/semgrep_runner.py`
7. Implement `phase2/taint_queries.py`
8. Implement `phase2/structure.py`

**Done when:** Full Phase 1 and Phase 2 run against VulnRez. Compare
results to known vulnerabilities. Tune confidence thresholds.

### Milestone 6 — Phase 3 + output + CLI (week 7–8)

**Tasks:**
1. Implement `phase3/correlator.py` with confidence tiering
2. Implement `phase3/scorer.py` with reachability multipliers
3. Implement SARIF output
4. Implement markdown report
5. Wire up the full `graphsast scan` CLI command
6. Add ground truth feedback mechanism (human_verdict column)

**Done when:** `graphsast scan ./vulnrez --output report.sarif` produces
a complete SARIF file. Open it in VS Code's SARIF viewer. Verify all
known VulnRez vulnerabilities appear with correct CWE IDs and severities.

---

## 13. CLI interface

```bash
# Build/update the code graph for a target
graphsast build-graph ./target-repo/
graphsast build-graph ./target-repo/ --incremental   # only changed files

# Populate/update the vulnerability pattern DB
graphsast update-vuln-db                              # all sources
graphsast update-vuln-db --source semgrep             # Semgrep registry only
graphsast update-vuln-db --source custom              # custom YAML only

# Run a full scan
graphsast scan ./target-repo/
graphsast scan ./target-repo/ --output report.sarif
graphsast scan ./target-repo/ --output report.md --format markdown
graphsast scan ./target-repo/ --phase 2              # skip Phase 1 (no LLM)
graphsast scan ./target-repo/ --lang python          # single language

# Query the graph directly (debugging / exploration)
graphsast query --taint-paths src/api/auth.py::login
graphsast query --missing-checks                     # show all missing auth
graphsast query --entry-points                       # list all entry points
graphsast query --callers src/db/queries.py::execute

# Evaluate against known-vulnerable target
graphsast eval ./vulnrez/ --ground-truth vulnrez_findings.json

# Mark findings after human review (feedback loop)
graphsast review --finding-id abc123 --verdict confirmed
graphsast review --finding-id def456 --verdict false-positive
```

---

## 14. Known gaps and mitigations

### Critical gaps

**Dynamic dispatch resolution**
Tree-sitter sees `handler.process(user_input)` but cannot resolve which
`process()` implementation gets called at runtime.
Mitigation: add a call resolution pass that conservatively adds edges
to all implementations of an interface or base class method.

**Inter-procedural taint across files**
Edges may be missing between files if only within-file CALLS are
recorded during parsing.
Mitigation: a post-parse link resolution pass that walks all IMPORTS
edges and creates cross-file CALLS edges.

**Context window overflow for small models**
A 500-line function passed to a 7B model will produce garbage output.
Mitigation: relevance trimmer that sends only ±20 lines around the
taint path, strips comments and blank lines.

### Quality gaps

**Second-order taint**
User input stored to DB, retrieved later and used unsafely.
Mitigation: `storage_taint` table — when SOURCE flows to DB write,
mark that table/column as tainted. DB reads of tainted columns become
new sources.

**No confidence calibration feedback**
Without measuring precision/recall, you don't know if Phase 1 is
helping or adding noise.
Mitigation: the human_verdict feedback column + regular eval runs
against VulnRez where ground truth is known.

**Sanitizer bypass**
A function in the SANITIZER list may not actually sanitize for the
specific vulnerability being checked.
Mitigation: Layer 2 LLM prompt explicitly asks "does this sanitizer
prevent this specific vulnerability class?" Not just "is a sanitizer
present?"

### Efficiency gaps

**No parallelism in Phase 2**
The three passes (Semgrep, taint queries, structure) are independent
and should run concurrently.
Mitigation: `concurrent.futures.ProcessPoolExecutor` for Phase 2.

**No scan result caching across runs**
Re-running scan re-analyses unchanged functions.
Mitigation: Phase 1 cache keyed on `(qualified_name, file_hash,
vuln_class_id)`.

**Sequential BFS for each source-sink pair**
For large graphs, N × M BFS queries is slow.
Mitigation: batch all SOURCE nodes and run multi-source BFS in one
traversal.

---

## 15. Tech stack decisions

| Component | Choice | Reason |
|---|---|---|
| Language | Python 3.11+ | Tree-sitter bindings, Semgrep API, ecosystem |
| Parser | tree-sitter + tree-sitter-languages | 19 languages, fast, deterministic |
| Code graph DB | SQLite (WAL mode) | Zero infra, same as code-review-graph, swap to Neo4j later for Cypher |
| Vuln pattern DB | SQLite (separate file) | Same benefits, clean separation |
| Vector search | sentence-transformers + sqlite-vec | Zero extra infra, optional |
| Pattern runner | Semgrep CLI via subprocess | Battle-tested, 3000+ community rules |
| LLM (local) | Ollama | Already in your stack, model-agnostic |
| LLM (API) | Claude / OpenAI via abstract backend | Swappable via LLMBackend interface |
| CLI | Typer | Clean, type-safe, auto-generates help |
| Config | pydantic-settings + config.toml | Type-safe, environment overridable |
| Testing | pytest + fixture repos | VulnRez as ground truth target |
| Packaging | uv + pyproject.toml | Fast, modern Python tooling |

**Recommended local model for your 3070 Ti (8GB VRAM):**
Qwen2.5-Coder 14B at Q4 quantisation fits exactly and gives near-34B
quality on code-specific tasks. Use `ollama pull qwen2.5-coder:14b-instruct-q4_K_M`.

---

## 16. Where to start tomorrow

```bash
# 1. Fork code-review-graph
git clone https://github.com/tirth8205/code-review-graph graphsast
cd graphsast

# 2. Set up environment
pip install uv
uv init
uv add tree-sitter tree-sitter-languages semgrep httpx typer \
        pydantic-settings pytest sentence-transformers

# 3. First task: read GraphStore
# Understand graph.py / GraphStore class fully before touching anything.
# Everything reads and writes through it.
cat code_review_graph/graph.py

# 4. First code: extend the schema
# Add call_arguments, taint_annotations, missing_checks tables
# via a new migration in migrations.py

# 5. First real test: parse VulnRez
graphsast build-graph ./vulnrez/
# Open graph.db in a SQLite viewer
# Verify cursor.execute() appears as a node
# Verify the argument is tagged binary_op / is_concatenated
```

The first working milestone is: parse VulnRez, open the SQLite file,
and see `is_concatenated = True` on the argument to a SQL sink. That
single data point validates the entire ingestion architecture.

Everything else — the LLM layers, the pattern DB, the output formats —
can be built and tested incrementally once the foundation is solid.

---

*Document reflects the full GraphSAST design discussion.*
*Ask questions against any section number for deeper detail.*
