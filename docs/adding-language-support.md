# Adding Language Support to GraphSAST

GraphSAST language support is **data-driven** — adding a new language requires no code changes.
You add rows to four data tables (plus optional taint signatures) and the engine handles the rest.

---

## Overview of data files

| File | What it controls |
|------|-----------------|
| `graphsast/vuln_db/importers/builtin_lang_rules.py` | AST node types, entry-point patterns, **entry-point strategies**, capability declarations |
| `graphsast/vuln_db/importers/lang_sigs.py` | Taint sources, sinks, and sanitizers for JS/TS/C# |
| `graphsast/vuln_db/importers/owasp_wstg.py` | OWASP WSTG vuln classes + Python web-framework taint sigs |

Custom/project-level overrides live in `.graphsast/custom/` (YAML).

---

## Step 1 — ARG_NODE_TYPES in `builtin_lang_rules.py`

These tell the argument classifier how to treat each tree-sitter AST node.

```python
{
    "id":               "LANG-SHORT-DESCRIPTION",   # unique, kebab-case
    "language":         "python",                   # must match tree-sitter language name
    "node_type":        "string",                   # exact tree-sitter node type name
    "arg_type":         "string_literal",           # see arg_type values below
    "is_concatenated":  1,    # optional — 1 if node mixes literals + variables
    "is_parameterised": 0,    # optional — 1 if node represents a safe parameterised call
    "contains_var":     1,    # optional — 1 if node holds a variable reference
    "child_type_check": "string_start",  # optional — check a child node's type
    "child_text_prefix": "f", # optional — match child's text prefix (e.g. "f" for f-strings)
    "operator_text":    "+",  # optional — for binary_expression, which operator to match
    "notes":            "human-readable explanation",
}
```

### `arg_type` values

| Value | Meaning |
|-------|---------|
| `string_literal` | Plain safe string, no interpolation |
| `f_string` | Interpolated / template — always flag as potential injection |
| `binary_op` | String concatenation via `+` or `%` |
| `identifier` | Variable reference — follow taint chain |
| `tuple` | Multi-argument parameterised call (safe) |
| `none` | null / None literal — safe |

### How to find tree-sitter node type names

```bash
# Install the tree-sitter CLI
pip install tree-sitter-languages

# Parse a sample file and dump the AST
python - <<'EOF'
from tree_sitter_languages import get_parser
parser = get_parser("javascript")
tree = parser.parse(b'db.query("SELECT * FROM users WHERE id = " + userId)')
print(tree.root_node.sexp())
EOF
```

Look for the node wrapping the argument you care about — its `.type` property is what goes in `node_type`.

---

## Step 2 — ENTRY_POINT_PATTERNS in `builtin_lang_rules.py`

Entry-point patterns identify functions that are called by an external actor (HTTP handler, CLI command, message consumer, etc.).

```python
{
    "id":         "LANG-ep-NAME",       # unique, kebab-case
    "language":   "javascript",
    "pattern":    "@Get(",              # the text to search for in source
    "match_type": "substring",          # "substring" or "regex"
    "notes":      "NestJS GET decorator",
}
```

### `match_type` values

| Value | Behaviour |
|-------|-----------|
| `substring` | `pattern in decorator_text` — fastest, use when no wildcards needed |
| `regex` | `re.search(pattern, decorator_text)` — use for multi-method patterns |

### Common patterns by framework

| Framework | Pattern | Example |
|-----------|---------|---------|
| Express (JS) | `(app\|router)\.(get\|post\|...)` | `app.get('/users', handler)` |
| NestJS | `@Get(`, `@Post(` | `@Get(':id')` |
| ASP.NET Core MVC | `[HttpGet`, `[HttpPost` | `[HttpGet("users/{id}")]` |
| ASP.NET Minimal API | `app\.Map(Get\|Post\|...)` | `app.MapGet("/users", handler)` |
| Spring (Java) | `@GetMapping`, `@PostMapping` | `@GetMapping("/users")` |
| Flask (Python) | `.route(`, `.get(`, `.post(` | `@app.route('/users')` |
| Gin (Go) | `r.GET(`, `r.POST(` | `r.GET("/users", handler)` |

---

## Step 2b — ENTRY_POINT_STRATEGIES in `builtin_lang_rules.py`

This is the step that was previously missing and required code changes for each new language.
A strategy tells the engine **how to walk the AST** to find entry-point functions.
Without a strategy row the patterns in Step 2 are never consulted.

Three strategy types cover all known paradigms:

| Strategy | Paradigm | Examples |
|----------|----------|---------|
| `wrapped_decorator` | Function wrapped inside a container node alongside its decorators | Python `decorated_definition` |
| `annotated_function` | Method/function node has an annotation container child | Java `modifiers`, C# `attribute_list`, TypeScript `decorator` |
| `call_registration` | A call expression registers a handler function as a route | Go `http.HandleFunc`, Express `app.get`, C# `app.MapGet` |

### Strategy config reference

#### `wrapped_decorator`

```python
{
    "id":       "LANG-ep-strategy",
    "language": "ruby",
    "strategy": "wrapped_decorator",
    "config": {
        "container_node":  "<node wrapping decorator+function>",  # e.g. "decorated_definition"
        "decorator_type":  "<node type of the decorator child>",  # e.g. "decorator"
        "function_type":   "<node type of the function child>",   # e.g. "function_definition"
        "name_child_type": "<node type of the name identifier>",  # e.g. "identifier"
    },
}
```

#### `annotated_function`

```python
{
    "id":       "LANG-ep-strategy",
    "language": "kotlin",
    "strategy": "annotated_function",
    "config": {
        "function_node":         "<method declaration node type>",    # e.g. "function_declaration"
        "annotation_container":  "<child node grouping annotations>", # e.g. "modifiers" — set to null if annotations are direct children
        "annotation_types":      ["<annotation node type>", ...],     # e.g. ["annotation"]
        "name_field":            "<field name for the method name>",  # e.g. "name"
    },
}
```

#### `call_registration`

```python
{
    "id":       "LANG-ep-strategy",
    "language": "php",
    "strategy": "call_registration",
    "config": {
        "call_node":           "<call expression node type>",       # e.g. "call_expression"
        "callee_field":        "<field name of the callee>",        # e.g. "function"
        "args_field":          "<field name of the argument list>", # e.g. "arguments"
        "handler_types":          ["<handler arg node type>", ...],    # e.g. ["identifier"] — named refs
        "inline_handler_types":   ["<inline function node type>", ...], # e.g. ["arrow_function","function_expression"] — anonymous handlers; returns @line:N:M key
        "selector_name_field":    "<field for name in selector nodes>",  # e.g. "field" — omit if none
        "append_paren":           True,  # True if patterns include "(" (e.g. "r.GET(")
    },
}
```

### How to find tree-sitter field names

```bash
python - <<'EOF'
from tree_sitter_languages import get_parser
parser = get_parser("go")
tree = parser.parse(b'http.HandleFunc("/", myHandler)')
print(tree.root_node.sexp())
EOF
```

Look at the `field_name:` labels in the S-expression output — those are the field names to use in `callee_field`, `args_field`, `name_field`, etc.

---

## Step 3 — LANGUAGE_CAPABILITIES in `builtin_lang_rules.py`

Declares what GraphSAST supports for the language. Used for UI display and feature-gating.

```python
{
    "id":          "LANG-CAPABILITY-NAME",
    "language":    "javascript",
    "capability":  "structural_parsing",    # see capability names below
    "status":      "supported",             # "supported" | "partial" | "planned"
    "description": "Human-readable description of what is supported",
}
```

### Standard capability names

| Capability | Description |
|-----------|-------------|
| `structural_parsing` | Extracts File/Class/Function nodes and CALLS/IMPORTS/INHERITS edges |
| `arg_classification` | Classifies call arguments (safe literal, interpolated, identifier) |
| `entry_point_detection` | Identifies externally-reachable entry points |
| `taint_annotation` | Labels SOURCE / SINK / SANITIZER nodes from signatures |
| `missing_checks` | Detects absent security checks (auth, rate-limit, CSRF) in call chains |
| `taint_paths` | Finds source → sink BFS paths with no sanitizer |
| `builtin_signatures` | Ships with language-specific taint signatures |

---

## Step 4 — Taint signatures (sources, sinks, sanitizers)

For languages with rich taint coverage, add signatures in `lang_sigs.py` using the helper:

```python
_sig(
    lang        = "javascript",         # language name
    name        = "db.query",           # qualified name matched against call sites
    role        = "SINK",               # SOURCE | SINK | SANITIZER
    vuln_class  = "sqli",               # vuln_class_id from vuln_classes table
    arg_index   = 0,                    # optional: which arg position to check (0-based)
    notes       = "mysql2 raw query",   # optional: human description
)
```

Add to one of the `_LANG_SOURCES`, `_LANG_SINKS`, or `_LANG_SANITIZERS` lists, then include in `TAINT_SIGNATURES`.

### Finding the right vuln_class_id

Available vuln_class_ids are seeded by `owasp_wstg.py`. Common ones:

| ID | Vulnerability |
|----|--------------|
| `sqli` | SQL Injection (CWE-89) |
| `cmdi` | Command Injection (CWE-78) |
| `xss` | Cross-Site Scripting (CWE-79) |
| `path-traversal` | Path Traversal (CWE-22) |
| `ssrf` | Server-Side Request Forgery (CWE-918) |
| `ssti` | Server-Side Template Injection (CWE-94) |
| `deserialization` | Insecure Deserialization (CWE-502) |
| `open-redirect` | Open Redirect (CWE-601) |
| `ldap-injection` | LDAP Injection (CWE-90) |

---

## Step 5 — Wire into the loader (if adding a new file)

If you create a new importer file (e.g. `my_lang_sigs.py`), add it to `loader.py`:

```python
if "my_lang_sigs" in sources:
    from graphsast.vuln_db.importers.my_lang_sigs import load_my_lang_sigs
    counts = load_my_lang_sigs(vuln_db)
    results["my_lang_sigs"] = counts["taint_signatures"]
```

And add `"my_lang_sigs"` to the default `sources` list at the top of `load_all()`.

Also export from `graphsast/vuln_db/importers/__init__.py`:

```python
from .my_lang_sigs import load_my_lang_sigs
```

---

## Complete example — adding Ruby (Sinatra / Rails)

### 1. ARG_NODE_TYPES

```python
# Ruby uses string nodes similar to Python
{"id": "rb-string-literal",    "language": "ruby", "node_type": "string",               "arg_type": "string_literal"},
{"id": "rb-interp-string",     "language": "ruby", "node_type": "string",               "arg_type": "f_string", "child_type_check": "interpolation", "is_concatenated": 1, "contains_var": 1, "notes": "\"...#{var}...\" interpolated string"},
{"id": "rb-heredoc",           "language": "ruby", "node_type": "heredoc_body",          "arg_type": "string_literal"},
{"id": "rb-binop-plus",        "language": "ruby", "node_type": "binary",               "arg_type": "binary_op",      "is_concatenated": 1, "contains_var": 1, "operator_text": "+"},
{"id": "rb-identifier",        "language": "ruby", "node_type": "identifier",            "arg_type": "identifier",     "contains_var": 1},
{"id": "rb-method-call",       "language": "ruby", "node_type": "method_add_arg",        "arg_type": "identifier",     "contains_var": 1, "notes": "method call result as argument"},
{"id": "rb-array",             "language": "ruby", "node_type": "array",                 "arg_type": "tuple",          "is_parameterised": 1},
```

### 2. ENTRY_POINT_PATTERNS

```python
{"id": "rb-ep-sinatra-get",    "language": "ruby", "pattern": r"(get|post|put|delete|patch)\s+['\"]", "match_type": "regex"},
{"id": "rb-ep-rails-action",   "language": "ruby", "pattern": "def ",   "match_type": "substring", "notes": "Rails controller actions — all public methods"},
```

### 2b. ENTRY_POINT_STRATEGIES

```python
# Sinatra: route blocks are call registrations (get "/path" do ... end)
{
    "id": "ruby-ep-strategy-sinatra",
    "language": "ruby",
    "strategy": "call_registration",
    "config": {
        "call_node":    "method_add_block",  # Sinatra route block
        "callee_field": "method",
        "args_field":   "method_add_arg",
        "handler_types": [],                 # handler is the block itself — no name
        "append_paren": False,
    },
},
```

### 3. LANGUAGE_CAPABILITIES

```python
{"id": "rb-parse",   "language": "ruby", "capability": "structural_parsing",   "status": "supported", "description": "Extracts nodes/edges via tree-sitter-ruby"},
{"id": "rb-arg",     "language": "ruby", "capability": "arg_classification",   "status": "supported", "description": "Classifies string, interpolated string, binary +"},
{"id": "rb-entry",   "language": "ruby", "capability": "entry_point_detection","status": "partial",   "description": "Sinatra route blocks; Rails actions (all public methods)"},
{"id": "rb-taint",   "language": "ruby", "capability": "taint_annotation",     "status": "planned",   "description": "Ruby-specific signatures not yet added"},
```

---

## Checklist

- [ ] `ARG_NODE_TYPES` entries added (node types verified against tree-sitter output)
- [ ] `ENTRY_POINT_PATTERNS` entries added (patterns verified against real source files)
- [ ] `ENTRY_POINT_STRATEGIES` entry added (verify field names with tree-sitter S-expression dump)
- [ ] `LANGUAGE_CAPABILITIES` entries added with accurate `status`
- [ ] Taint signatures added (sources, sinks, sanitizers)
- [ ] Loader wired up (if new file)
- [ ] `__init__.py` export updated (if new file)
- [ ] `--source` help text in `cli/main.py` updated (if new source name)
- [ ] Smoke-tested on a small sample project in that language
