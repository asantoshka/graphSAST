"""Built-in language support rules.

Seeds arg_node_types, entry_point_patterns, entry_point_strategies, and
language_capabilities for supported languages. Custom rules can override
any row by using the same id (INSERT OR REPLACE).

Adding a new language:
  1. Add rows to ARG_NODE_TYPES for the language's tree-sitter node names
  2. Add rows to ENTRY_POINT_PATTERNS for its decorator/annotation patterns
  3. Add rows to ENTRY_POINT_STRATEGIES to describe how to walk the AST
  4. Add rows to LANGUAGE_CAPABILITIES describing what's supported
  No code changes needed.
"""

from __future__ import annotations

from graphsast.vuln_db.store import VulnStore

# ──────────────────────────────────────────────────────────────────────────────
# arg_node_types
# ──────────────────────────────────────────────────────────────────────────────
# Fields: id, language, node_type, arg_type, is_concatenated, is_parameterised,
#         contains_var, child_type_check, child_text_prefix, operator_text, notes

ARG_NODE_TYPES: list[dict] = [

    # ── Python ────────────────────────────────────────────────────────────────
    # 'string' is used for both plain strings and f-strings.
    # Distinguish by checking child 'string_start' text prefix.
    {
        "id": "py-string-fstring",
        "language": "python",
        "node_type": "string",
        "arg_type": "f_string",
        "is_concatenated": 1, "contains_var": 1,
        "child_type_check": "string_start",
        "child_text_prefix": "f",
        "notes": "f\"...\" or f'...' — interpolated, always flag",
    },
    {
        "id": "py-string-fstring-interp",
        "language": "python",
        "node_type": "string",
        "arg_type": "f_string",
        "is_concatenated": 1, "contains_var": 1,
        "child_type_check": "interpolation",
        "notes": "string node containing an interpolation child — f-string",
    },
    {
        "id": "py-string-literal",
        "language": "python",
        "node_type": "string",
        "arg_type": "string_literal",
        "notes": "plain string literal — safe fallback when no f-string child found",
    },
    {
        "id": "py-concat-string",
        "language": "python",
        "node_type": "concatenated_string",
        "arg_type": "string_literal",
        "notes": "adjacent string literals ('a' 'b') — safe",
    },
    {
        "id": "py-binop-plus",
        "language": "python",
        "node_type": "binary_operator",
        "arg_type": "binary_op",
        "is_concatenated": 1, "contains_var": 1,
        "operator_text": "+",
        "notes": "string + variable concatenation",
    },
    {
        "id": "py-binop-percent",
        "language": "python",
        "node_type": "binary_operator",
        "arg_type": "percent_format",
        "is_concatenated": 1, "contains_var": 1,
        "operator_text": "%",
        "notes": "'SELECT %s' % value — old-style format string",
    },
    {
        "id": "py-formatted-string",
        "language": "python",
        "node_type": "formatted_string",
        "arg_type": "f_string",
        "is_concatenated": 1, "contains_var": 1,
        "notes": "older tree-sitter-python versions use this type for f-strings",
    },
    {
        "id": "py-tuple",
        "language": "python",
        "node_type": "tuple",
        "arg_type": "tuple",
        "is_parameterised": 1,
        "notes": "('SELECT ... ?', (val,)) — parameterised, safe",
    },
    {
        "id": "py-list",
        "language": "python",
        "node_type": "list",
        "arg_type": "tuple",
        "is_parameterised": 1,
        "notes": "list argument — treated as parameterised",
    },
    {
        "id": "py-identifier",
        "language": "python",
        "node_type": "identifier",
        "arg_type": "identifier",
        "contains_var": 1,
        "notes": "variable — taint chain needed to determine safety",
    },
    {
        "id": "py-attribute",
        "language": "python",
        "node_type": "attribute",
        "arg_type": "identifier",
        "contains_var": 1,
        "notes": "obj.attr — treated as variable reference",
    },
    {
        "id": "py-subscript",
        "language": "python",
        "node_type": "subscript",
        "arg_type": "identifier",
        "contains_var": 1,
        "notes": "obj[key] — treated as variable reference",
    },

    # ── JavaScript / TypeScript ───────────────────────────────────────────────
    {
        "id": "js-template-literal",
        "language": "javascript",
        "node_type": "template_literal",
        "arg_type": "f_string",
        "is_concatenated": 1, "contains_var": 1,
        "notes": "`SELECT ... ${id}` — template literal, always flag",
    },
    {
        "id": "js-string",
        "language": "javascript",
        "node_type": "string",
        "arg_type": "string_literal",
        "notes": "plain string literal",
    },
    {
        "id": "js-binop-plus",
        "language": "javascript",
        "node_type": "binary_expression",
        "arg_type": "binary_op",
        "is_concatenated": 1, "contains_var": 1,
        "operator_text": "+",
        "notes": "'SELECT ' + id — string concatenation",
    },
    {
        "id": "js-identifier",
        "language": "javascript",
        "node_type": "identifier",
        "arg_type": "identifier",
        "contains_var": 1,
    },
    {
        "id": "js-member-expr",
        "language": "javascript",
        "node_type": "member_expression",
        "arg_type": "identifier",
        "contains_var": 1,
        "notes": "req.body, req.query, obj.prop — treat as variable",
    },
    {
        "id": "js-subscript-expr",
        "language": "javascript",
        "node_type": "subscript_expression",
        "arg_type": "identifier",
        "contains_var": 1,
        "notes": "req.query['id'] — subscript access",
    },
    {
        "id": "js-array",
        "language": "javascript",
        "node_type": "array",
        "arg_type": "tuple",
        "is_parameterised": 1,
        "notes": "[sql, [param]] — parameterised query array",
    },
    {
        "id": "js-object",
        "language": "javascript",
        "node_type": "object",
        "arg_type": "tuple",
        "is_parameterised": 1,
        "notes": "{ text: sql, values: [...] } — parameterised object",
    },
    {
        "id": "js-await",
        "language": "javascript",
        "node_type": "await_expression",
        "arg_type": "identifier",
        "contains_var": 1,
        "notes": "await expr — unwrap to inner expression type",
    },
    # TypeScript shares JS node types + adds its own
    {
        "id": "ts-template-literal",
        "language": "typescript",
        "node_type": "template_literal",
        "arg_type": "f_string",
        "is_concatenated": 1, "contains_var": 1,
    },
    {
        "id": "ts-string",
        "language": "typescript",
        "node_type": "string",
        "arg_type": "string_literal",
    },
    {
        "id": "ts-binop-plus",
        "language": "typescript",
        "node_type": "binary_expression",
        "arg_type": "binary_op",
        "is_concatenated": 1, "contains_var": 1,
        "operator_text": "+",
    },
    {
        "id": "ts-identifier",
        "language": "typescript",
        "node_type": "identifier",
        "arg_type": "identifier",
        "contains_var": 1,
    },
    {
        "id": "ts-member-expr",
        "language": "typescript",
        "node_type": "member_expression",
        "arg_type": "identifier",
        "contains_var": 1,
        "notes": "req.body, req.query — treat as variable",
    },
    {
        "id": "ts-subscript-expr",
        "language": "typescript",
        "node_type": "subscript_expression",
        "arg_type": "identifier",
        "contains_var": 1,
    },
    {
        "id": "ts-array",
        "language": "typescript",
        "node_type": "array",
        "arg_type": "tuple",
        "is_parameterised": 1,
    },
    {
        "id": "ts-object",
        "language": "typescript",
        "node_type": "object",
        "arg_type": "tuple",
        "is_parameterised": 1,
    },

    # ── C# ────────────────────────────────────────────────────────────────────
    # tree-sitter-c-sharp node types
    {
        "id": "cs-string-literal",
        "language": "csharp",
        "node_type": "string_literal",
        "arg_type": "string_literal",
        "notes": "\"plain string\" — safe",
    },
    {
        "id": "cs-verbatim-string",
        "language": "csharp",
        "node_type": "verbatim_string_literal",
        "arg_type": "string_literal",
        "notes": "@\"verbatim string\" — safe",
    },
    {
        "id": "cs-interpolated-string",
        "language": "csharp",
        "node_type": "interpolated_string_expression",
        "arg_type": "f_string",
        "is_concatenated": 1, "contains_var": 1,
        "notes": "$\"SELECT ... {id}\" — interpolated string, always flag",
    },
    {
        "id": "cs-interpolated-string-interp",
        "language": "csharp",
        "node_type": "interpolated_string_expression",
        "arg_type": "f_string",
        "is_concatenated": 1, "contains_var": 1,
        "child_type_check": "interpolation",
        "notes": "interpolated_string_expression containing interpolation child",
    },
    {
        "id": "cs-binop-plus",
        "language": "csharp",
        "node_type": "binary_expression",
        "arg_type": "binary_op",
        "is_concatenated": 1, "contains_var": 1,
        "operator_text": "+",
        "notes": "\"SELECT \" + id — string concatenation",
    },
    {
        "id": "cs-identifier",
        "language": "csharp",
        "node_type": "identifier",
        "arg_type": "identifier",
        "contains_var": 1,
    },
    {
        "id": "cs-member-access",
        "language": "csharp",
        "node_type": "member_access_expression",
        "arg_type": "identifier",
        "contains_var": 1,
        "notes": "Request.Query[\"id\"], obj.Property — treat as variable",
    },
    {
        "id": "cs-element-access",
        "language": "csharp",
        "node_type": "element_access_expression",
        "arg_type": "identifier",
        "contains_var": 1,
        "notes": "Request.Form[\"field\"] — subscript access",
    },
    {
        "id": "cs-null-literal",
        "language": "csharp",
        "node_type": "null_literal",
        "arg_type": "none",
        "notes": "null — safe",
    },
    {
        "id": "cs-array-creation",
        "language": "csharp",
        "node_type": "array_creation_expression",
        "arg_type": "tuple",
        "is_parameterised": 1,
        "notes": "new object[] { id } — parameterised array",
    },
    {
        "id": "cs-implicit-array",
        "language": "csharp",
        "node_type": "implicit_array_creation_expression",
        "arg_type": "tuple",
        "is_parameterised": 1,
        "notes": "new[] { id } — parameterised",
    },
    {
        "id": "cs-collection-expression",
        "language": "csharp",
        "node_type": "collection_expression",
        "arg_type": "tuple",
        "is_parameterised": 1,
        "notes": "C# 12 collection expression [id] — parameterised",
    },

    # ── Java ──────────────────────────────────────────────────────────────────
    {
        "id": "java-string-literal",
        "language": "java",
        "node_type": "string_literal",
        "arg_type": "string_literal",
        "notes": "plain Java string literal",
    },
    {
        "id": "java-binop-plus",
        "language": "java",
        "node_type": "binary_expression",
        "arg_type": "binary_op",
        "is_concatenated": 1, "contains_var": 1,
        "operator_text": "+",
        "notes": "\"SELECT \" + id — string concatenation",
    },
    {
        "id": "java-identifier",
        "language": "java",
        "node_type": "identifier",
        "arg_type": "identifier",
        "contains_var": 1,
    },
    {
        "id": "java-text-block",
        "language": "java",
        "node_type": "text_block",
        "arg_type": "string_literal",
        "notes": "Java 15+ text block — plain string",
    },

    # ── Go ────────────────────────────────────────────────────────────────────
    {
        "id": "go-interp-string",
        "language": "go",
        "node_type": "interpreted_string_literal",
        "arg_type": "string_literal",
        "notes": "Go double-quoted string",
    },
    {
        "id": "go-raw-string",
        "language": "go",
        "node_type": "raw_string_literal",
        "arg_type": "string_literal",
        "notes": "Go backtick string",
    },
    {
        "id": "go-binop-plus",
        "language": "go",
        "node_type": "binary_expression",
        "arg_type": "binary_op",
        "is_concatenated": 1, "contains_var": 1,
        "operator_text": "+",
        "notes": "\"SELECT \" + id concatenation",
    },
    {
        "id": "go-identifier",
        "language": "go",
        "node_type": "identifier",
        "arg_type": "identifier",
        "contains_var": 1,
    },
    {
        "id": "go-sprintf",
        "language": "go",
        "node_type": "call_expression",
        "arg_type": "f_string",
        "is_concatenated": 1, "contains_var": 1,
        "notes": "fmt.Sprintf(...) — handled separately by str_format detection",
    },
]

# ──────────────────────────────────────────────────────────────────────────────
# entry_point_patterns
# ──────────────────────────────────────────────────────────────────────────────

ENTRY_POINT_PATTERNS: list[dict] = [
    # ── Python ────────────────────────────────────────────────────────────────
    {"id": "py-ep-route",   "language": "python", "pattern": ".route(",   "match_type": "substring"},
    {"id": "py-ep-get",     "language": "python", "pattern": ".get(",     "match_type": "substring"},
    {"id": "py-ep-post",    "language": "python", "pattern": ".post(",    "match_type": "substring"},
    {"id": "py-ep-put",     "language": "python", "pattern": ".put(",     "match_type": "substring"},
    {"id": "py-ep-delete",  "language": "python", "pattern": ".delete(",  "match_type": "substring"},
    {"id": "py-ep-patch",   "language": "python", "pattern": ".patch(",   "match_type": "substring"},
    {"id": "py-ep-command", "language": "python", "pattern": ".command(", "match_type": "substring",
     "notes": "Click/Typer CLI command"},
    {"id": "py-ep-task",    "language": "python", "pattern": ".task(",    "match_type": "substring",
     "notes": "Celery task"},
    {"id": "py-ep-api-view","language": "python", "pattern": "api_view",  "match_type": "substring",
     "notes": "DRF @api_view"},
    # aiohttp call-registration style: app.router.add_route / add_get / add_post / etc.
    {"id": "py-ep-add-route", "language": "python", "pattern": ".add_route(", "match_type": "substring",
     "notes": "aiohttp app.router.add_route(method, path, handler)"},
    {"id": "py-ep-add-get",   "language": "python", "pattern": ".add_get(",   "match_type": "substring",
     "notes": "aiohttp router.add_get(path, handler)"},
    {"id": "py-ep-add-post",  "language": "python", "pattern": ".add_post(",  "match_type": "substring",
     "notes": "aiohttp router.add_post(path, handler)"},
    {"id": "py-ep-add-put",   "language": "python", "pattern": ".add_put(",   "match_type": "substring"},
    {"id": "py-ep-add-patch", "language": "python", "pattern": ".add_patch(", "match_type": "substring"},
    {"id": "py-ep-add-delete","language": "python", "pattern": ".add_delete(","match_type": "substring"},

    # ── JavaScript / TypeScript ───────────────────────────────────────────────
    {"id": "js-ep-express-get",    "language": "javascript", "pattern": r"(app|router)\.(get|post|put|patch|delete|use|all)\(", "match_type": "regex"},
    {"id": "ts-ep-nestjs-get",     "language": "typescript", "pattern": "@Get(",     "match_type": "substring"},
    {"id": "ts-ep-nestjs-post",    "language": "typescript", "pattern": "@Post(",    "match_type": "substring"},
    {"id": "ts-ep-nestjs-put",     "language": "typescript", "pattern": "@Put(",     "match_type": "substring"},
    {"id": "ts-ep-nestjs-delete",  "language": "typescript", "pattern": "@Delete(",  "match_type": "substring"},
    {"id": "ts-ep-nestjs-patch",   "language": "typescript", "pattern": "@Patch(",   "match_type": "substring"},
    {"id": "ts-ep-controller",     "language": "typescript", "pattern": "@Controller", "match_type": "substring"},

    # ── Java ──────────────────────────────────────────────────────────────────
    {"id": "java-ep-getmapping",     "language": "java", "pattern": "@GetMapping",     "match_type": "substring"},
    {"id": "java-ep-postmapping",    "language": "java", "pattern": "@PostMapping",    "match_type": "substring"},
    {"id": "java-ep-putmapping",     "language": "java", "pattern": "@PutMapping",     "match_type": "substring"},
    {"id": "java-ep-deletemapping",  "language": "java", "pattern": "@DeleteMapping",  "match_type": "substring"},
    {"id": "java-ep-requestmapping", "language": "java", "pattern": "@RequestMapping", "match_type": "substring"},
    {"id": "java-ep-restcontroller", "language": "java", "pattern": "@RestController", "match_type": "substring"},

    # ── Go ────────────────────────────────────────────────────────────────────
    {"id": "go-ep-handlefunc",  "language": "go", "pattern": "http.HandleFunc", "match_type": "substring"},
    {"id": "go-ep-gin-get",     "language": "go", "pattern": "gin.GET",         "match_type": "substring"},
    {"id": "go-ep-gin-post",    "language": "go", "pattern": "gin.POST",        "match_type": "substring"},
    {"id": "go-ep-echo-get",    "language": "go", "pattern": "e.GET(",          "match_type": "substring"},
    {"id": "go-ep-echo-post",   "language": "go", "pattern": "e.POST(",         "match_type": "substring"},
    {"id": "go-ep-mux",         "language": "go", "pattern": r"(mux|r)\.(Get|Post|Put|Delete|Patch|Handle)\(", "match_type": "regex"},

    # ── C# ────────────────────────────────────────────────────────────────────
    # ASP.NET Core MVC / Web API attribute annotations
    {"id": "cs-ep-httpget",      "language": "csharp", "pattern": "[HttpGet",      "match_type": "substring", "notes": "ASP.NET Core MVC/Web API GET action"},
    {"id": "cs-ep-httppost",     "language": "csharp", "pattern": "[HttpPost",     "match_type": "substring", "notes": "ASP.NET Core POST action"},
    {"id": "cs-ep-httpput",      "language": "csharp", "pattern": "[HttpPut",      "match_type": "substring", "notes": "ASP.NET Core PUT action"},
    {"id": "cs-ep-httpdelete",   "language": "csharp", "pattern": "[HttpDelete",   "match_type": "substring", "notes": "ASP.NET Core DELETE action"},
    {"id": "cs-ep-httppatch",    "language": "csharp", "pattern": "[HttpPatch",    "match_type": "substring", "notes": "ASP.NET Core PATCH action"},
    {"id": "cs-ep-route",        "language": "csharp", "pattern": "[Route(",       "match_type": "substring", "notes": "[Route(...)] on controller action"},
    {"id": "cs-ep-apicontroller","language": "csharp", "pattern": "[ApiController","match_type": "substring", "notes": "ASP.NET Core API controller class"},
    # ASP.NET Core Minimal API (app.MapGet / app.MapPost / ...)
    {"id": "cs-ep-mapget",       "language": "csharp", "pattern": r"app\.Map(Get|Post|Put|Delete|Patch|Methods)\(", "match_type": "regex", "notes": "Minimal API route registration"},
    # SignalR hub methods are public methods on Hub subclasses — pattern-matched by class
    {"id": "cs-ep-signalr",      "language": "csharp", "pattern": ": Hub",         "match_type": "substring", "notes": "SignalR Hub subclass — public methods are entry points"},
]

# ──────────────────────────────────────────────────────────────────────────────
# language_capabilities
# ──────────────────────────────────────────────────────────────────────────────
# ENTRY_POINT_STRATEGIES
#
# Tells TaintMarker HOW to walk the AST for each language.
# The engine has three generic walkers — no language-specific code.
#
# Strategy configs (JSON keys by strategy type):
#
#   wrapped_decorator:
#     container_node   — node that wraps both decorator and function (e.g. "decorated_definition")
#     decorator_type   — child node type for decorator text       (e.g. "decorator")
#     function_type    — child node type for the function          (e.g. "function_definition")
#     name_child_type  — node type of the function name identifier  (e.g. "identifier")
#
#   annotated_function:
#     function_node         — the method/function declaration node type (e.g. "method_declaration")
#     annotation_container  — child node holding annotations (e.g. "modifiers"); null if annotations
#                             are direct children of function_node
#     annotation_types      — list of node types that are annotations (e.g. ["annotation","marker_annotation"])
#     name_field            — field name on function_node for the method name  (e.g. "name")
#
#   call_registration:
#     call_node             — the call AST node type        (e.g. "call_expression")
#     callee_field          — field name of the callee       (e.g. "function")
#     args_field            — field name of the argument list (e.g. "arguments")
#     handler_types         — arg node types that represent handlers (e.g. ["identifier","selector_expression"])
#     selector_name_field   — for selector-type handlers, which field is the function name (e.g. "field")
#     append_paren          — append "(" to callee before matching patterns (true for most languages)
# ──────────────────────────────────────────────────────────────────────────────

ENTRY_POINT_STRATEGIES: list[dict] = [
    # ── Python: decorated_definition wraps decorator + function ───────────────
    {
        "id": "python-ep-strategy",
        "language": "python",
        "strategy": "wrapped_decorator",
        "config": {
            "container_node":  "decorated_definition",
            "decorator_type":  "decorator",
            "function_type":   "function_definition",
            "name_child_type": "identifier",
        },
        "notes": "Python decorator: @app.route / @click.command / etc.",
    },
    # ── Python: aiohttp / call-registration style ─────────────────────────────
    {
        "id": "python-ep-strategy-aiohttp",
        "language": "python",
        "strategy": "call_registration",
        "config": {
            "call_node":            "call",
            "callee_field":         "function",
            "args_field":           "arguments",
            "handler_types":        ["attribute", "identifier"],
            "inline_handler_types": [],
            "selector_name_field":  "attribute",
            "append_paren":         True,
        },
        "notes": "aiohttp: app.router.add_route/add_get/add_post(path, handler)",
    },
    # ── Java: Spring MVC annotations via modifiers container ──────────────────
    {
        "id": "java-ep-strategy",
        "language": "java",
        "strategy": "annotated_function",
        "config": {
            "function_node":         "method_declaration",
            "annotation_container":  "modifiers",
            "annotation_types":      ["annotation", "marker_annotation"],
            "name_field":            "name",
        },
        "notes": "Java Spring: @GetMapping / @PostMapping / @RequestMapping",
    },
    # ── TypeScript: NestJS decorators (direct child of method_definition) ─────
    {
        "id": "typescript-ep-strategy-nestjs",
        "language": "typescript",
        "strategy": "annotated_function",
        "config": {
            "function_node":         "method_definition",
            "annotation_container":  None,
            "annotation_types":      ["decorator"],
            "name_field":            "name",
        },
        "notes": "TypeScript NestJS: @Get() / @Post() decorators on class methods",
    },
    # ── TypeScript + JavaScript: Express call-site registration ───────────────
    {
        "id": "typescript-ep-strategy-express",
        "language": "typescript",
        "strategy": "call_registration",
        "config": {
            "call_node":              "call_expression",
            "callee_field":           "function",
            "args_field":             "arguments",
            "handler_types":          ["identifier", "member_expression"],
            "inline_handler_types":   ["arrow_function", "function_expression"],
            "selector_name_field":    "property",
            "append_paren":           True,
        },
        "notes": "TypeScript Express: app.get('/path', handler) or app.get('/path', (req,res)=>{})",
    },
    {
        "id": "javascript-ep-strategy-express",
        "language": "javascript",
        "strategy": "call_registration",
        "config": {
            "call_node":              "call_expression",
            "callee_field":           "function",
            "args_field":             "arguments",
            "handler_types":          ["identifier", "member_expression"],
            "inline_handler_types":   ["arrow_function", "function_expression"],
            "selector_name_field":    "property",
            "append_paren":           True,
        },
        "notes": "JavaScript Express: app.get('/path', handler) or router.post('/path', function(req,res){})",
    },
    # ── Go: http.HandleFunc / gin / gorilla-mux call-site registration ────────
    {
        "id": "go-ep-strategy",
        "language": "go",
        "strategy": "call_registration",
        "config": {
            "call_node":           "call_expression",
            "callee_field":        "function",
            "args_field":          "arguments",
            "handler_types":       ["identifier", "selector_expression"],
            "selector_name_field": "field",
            "append_paren":        True,
        },
        "notes": "Go: http.HandleFunc, r.GET, mux.Handle, etc.",
    },
    # ── C#: ASP.NET MVC attribute-annotated actions ───────────────────────────
    {
        "id": "csharp-ep-strategy-mvc",
        "language": "csharp",
        "strategy": "annotated_function",
        "config": {
            "function_node":         "method_declaration",
            "annotation_container":  "attribute_list",
            "annotation_types":      ["attribute"],
            "name_field":            "name",
        },
        "notes": "C# ASP.NET MVC: [HttpGet] / [HttpPost] / [Route] on controller methods",
    },
    # ── C#: Minimal API call-site registration ────────────────────────────────
    {
        "id": "csharp-ep-strategy-minimal",
        "language": "csharp",
        "strategy": "call_registration",
        "config": {
            "call_node":           "invocation_expression",
            "callee_field":        "function",
            "args_field":          "argument_list",
            "handler_types":       ["identifier", "member_access_expression"],
            "selector_name_field": "name",
            "append_paren":        True,
        },
        "notes": "C# Minimal API: app.MapGet / app.MapPost / etc.",
    },
]

# ──────────────────────────────────────────────────────────────────────────────

LANGUAGE_CAPABILITIES: list[dict] = [
    # Python — full support
    {"id": "py-parse",        "language": "python",     "capability": "structural_parsing",   "status": "supported", "description": "Extracts nodes (File, Class, Function) and edges (CALLS, IMPORTS, INHERITS)"},
    {"id": "py-arg",          "language": "python",     "capability": "arg_classification",   "status": "supported", "description": "Classifies call arguments: concat / f-string / parameterised / identifier"},
    {"id": "py-entry",        "language": "python",     "capability": "entry_point_detection","status": "supported", "description": "Detects Flask, FastAPI, Django, Click, Celery entry points via decorators"},
    {"id": "py-taint",        "language": "python",     "capability": "taint_annotation",     "status": "supported", "description": "Annotates SOURCE / SINK / SANITIZER nodes from vulns.db signatures"},
    {"id": "py-missing",      "language": "python",     "capability": "missing_checks",       "status": "supported", "description": "Detects absent auth / rate-limit / CSRF / validation in call chains"},
    {"id": "py-taintpath",    "language": "python",     "capability": "taint_paths",          "status": "supported", "description": "Finds source → sink paths with no sanitizer"},
    {"id": "py-sigs",         "language": "python",     "capability": "builtin_signatures",   "status": "supported", "description": "Ships with signatures for SQLi, CMDi, Path Traversal, SSRF, Deserialisation"},

    # JavaScript
    {"id": "js-parse",        "language": "javascript", "capability": "structural_parsing",   "status": "supported", "description": "Extracts nodes and edges via tree-sitter"},
    {"id": "js-arg",          "language": "javascript", "capability": "arg_classification",   "status": "supported", "description": "Classifies template literals, binary +, member/subscript expressions, array (parameterised)"},
    {"id": "js-entry",        "language": "javascript", "capability": "entry_point_detection","status": "supported", "description": "Detects Express route handlers (app.get/post/...) and Express Router"},
    {"id": "js-taint",        "language": "javascript", "capability": "taint_annotation",     "status": "supported", "description": "Sources: req.body/query/params/headers/cookies; Sinks: db.query, exec, eval, fs.readFile, res.send"},
    {"id": "js-missing",      "language": "javascript", "capability": "missing_checks",       "status": "supported", "description": "BFS checks for missing auth middleware, rate limiting, CSRF"},
    {"id": "js-sigs",         "language": "javascript", "capability": "builtin_signatures",   "status": "supported", "description": "Ships with Node.js/Express signatures: SQLi, CMDi, Path Traversal, XSS, SSRF, Deserialisation"},

    # TypeScript
    {"id": "ts-parse",        "language": "typescript", "capability": "structural_parsing",   "status": "supported", "description": "Extracts nodes and edges via tree-sitter"},
    {"id": "ts-arg",          "language": "typescript", "capability": "arg_classification",   "status": "supported", "description": "Same node types as JavaScript; includes await_expression unwrapping"},
    {"id": "ts-entry",        "language": "typescript", "capability": "entry_point_detection","status": "supported", "description": "Detects NestJS decorators (@Get, @Post, @Controller) and Express-style handlers"},
    {"id": "ts-taint",        "language": "typescript", "capability": "taint_annotation",     "status": "supported", "description": "Same sources/sinks as JS; also covers NestJS request decorators"},
    {"id": "ts-sigs",         "language": "typescript", "capability": "builtin_signatures",   "status": "supported", "description": "Shares JS/Node.js signatures; TypeScript AST node names are identical to JS"},

    # Java
    {"id": "java-parse",      "language": "java",       "capability": "structural_parsing",   "status": "supported", "description": "Extracts nodes and edges via tree-sitter"},
    {"id": "java-arg",        "language": "java",       "capability": "arg_classification",   "status": "supported", "description": "Classifies string_literal, binary_expression +, identifier"},
    {"id": "java-entry",      "language": "java",       "capability": "entry_point_detection","status": "supported", "description": "Detects Spring MVC annotations (@GetMapping, @PostMapping, @RequestMapping) via annotation AST walker"},
    {"id": "java-taint",      "language": "java",       "capability": "taint_annotation",     "status": "partial",   "description": "Annotation works; Java-specific signatures not yet included"},

    # Go
    {"id": "go-parse",        "language": "go",         "capability": "structural_parsing",   "status": "supported", "description": "Extracts nodes and edges via tree-sitter"},
    {"id": "go-arg",          "language": "go",         "capability": "arg_classification",   "status": "supported", "description": "Classifies interpreted/raw string literals, binary + expression"},
    {"id": "go-entry",        "language": "go",         "capability": "entry_point_detection","status": "supported", "description": "Detects http.HandleFunc, gin/mux route registration via call-site AST walker"},
    {"id": "go-taint",        "language": "go",         "capability": "taint_annotation",     "status": "partial",   "description": "Annotation works; Go-specific signatures not yet included"},

    # C#
    {"id": "cs-parse",        "language": "csharp",     "capability": "structural_parsing",   "status": "supported", "description": "Extracts nodes and edges via tree-sitter-c-sharp"},
    {"id": "cs-arg",          "language": "csharp",     "capability": "arg_classification",   "status": "supported", "description": "Classifies string_literal, verbatim, interpolated ($\"\"), binary +, member/element access, arrays"},
    {"id": "cs-entry",        "language": "csharp",     "capability": "entry_point_detection","status": "supported", "description": "Detects [HttpGet/Post/Put/Delete/Patch], [Route], [ApiController], Minimal API app.MapGet/Post/..."},
    {"id": "cs-taint",        "language": "csharp",     "capability": "taint_annotation",     "status": "supported", "description": "Sources: Request.Query/Form/Headers/Cookies, route params; Sinks: SqlCommand, Process.Start, File.*, BinaryFormatter, HttpClient"},
    {"id": "cs-missing",      "language": "csharp",     "capability": "missing_checks",       "status": "supported", "description": "BFS checks for missing [Authorize], rate limiting, anti-forgery token"},
    {"id": "cs-sigs",         "language": "csharp",     "capability": "builtin_signatures",   "status": "supported", "description": "Ships with ASP.NET Core signatures: SQLi, CMDi, Path Traversal, SSRF, Deserialisation, Open Redirect"},
]


def load_builtin_lang_rules(vuln_db: VulnStore) -> dict[str, int]:
    """Seed all built-in language support rules into vuln_db."""
    for row in ARG_NODE_TYPES:
        vuln_db.upsert_arg_node_type(row)

    for row in ENTRY_POINT_PATTERNS:
        vuln_db.upsert_entry_point_pattern(row)

    for row in ENTRY_POINT_STRATEGIES:
        vuln_db.upsert_entry_point_strategy(row)

    for row in LANGUAGE_CAPABILITIES:
        vuln_db.upsert_capability(row)

    vuln_db.commit()
    return {
        "arg_node_types":          len(ARG_NODE_TYPES),
        "entry_point_patterns":    len(ENTRY_POINT_PATTERNS),
        "entry_point_strategies":  len(ENTRY_POINT_STRATEGIES),
        "language_capabilities":   len(LANGUAGE_CAPABILITIES),
    }
