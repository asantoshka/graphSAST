"""vulns.db schema DDL."""

SCHEMA_SQL = """
-- ─── Language support ────────────────────────────────────────────────────────

-- AST node type → arg classification mapping (drives ArgInspector)
-- Adding a new language = inserting rows here, no code changes needed.
CREATE TABLE IF NOT EXISTS arg_node_types (
    id                  TEXT PRIMARY KEY,
    language            TEXT NOT NULL,
    node_type           TEXT NOT NULL,       -- tree-sitter node.type exactly
    arg_type            TEXT NOT NULL,       -- ARG_* constant: binary_op|f_string|string_literal|tuple|identifier|percent_format|other
    is_concatenated     INTEGER NOT NULL DEFAULT 0,
    is_parameterised    INTEGER NOT NULL DEFAULT 0,
    contains_var        INTEGER NOT NULL DEFAULT 0,
    -- For nodes requiring a child check (e.g. Python 'string' → check string_start child)
    child_type_check    TEXT,                -- child.type to check (NULL = skip)
    child_text_prefix   TEXT,               -- required text prefix of that child
    -- For nodes where operator symbol disambiguates (e.g. binary_operator + vs %)
    operator_text       TEXT,               -- literal operator (NULL = not applicable)
    notes               TEXT
);
CREATE INDEX IF NOT EXISTS idx_argnode_lang ON arg_node_types(language, node_type);

-- HTTP/CLI entry point decorator/annotation patterns (drives TaintMarker)
CREATE TABLE IF NOT EXISTS entry_point_patterns (
    id          TEXT PRIMARY KEY,
    language    TEXT NOT NULL,
    pattern     TEXT NOT NULL,               -- substring or regex to match in decorator text
    match_type  TEXT NOT NULL DEFAULT 'substring',  -- 'substring' | 'regex'
    notes       TEXT
);
CREATE INDEX IF NOT EXISTS idx_ep_lang ON entry_point_patterns(language);

-- Human-readable capability checklist per language
CREATE TABLE IF NOT EXISTS language_capabilities (
    id          TEXT PRIMARY KEY,
    language    TEXT NOT NULL,
    capability  TEXT NOT NULL,               -- short key, e.g. 'arg_classification'
    description TEXT NOT NULL,               -- one sentence
    status      TEXT NOT NULL DEFAULT 'supported'  -- 'supported' | 'partial' | 'planned'
);
CREATE INDEX IF NOT EXISTS idx_langcap_lang ON language_capabilities(language);

-- ─── Vulnerability patterns ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS vuln_classes (
    id          TEXT PRIMARY KEY,
    cwe_id      TEXT,
    owasp_cat   TEXT,
    name        TEXT NOT NULL,
    description TEXT,
    severity    TEXT NOT NULL DEFAULT 'MEDIUM',
    language    TEXT NOT NULL DEFAULT 'any',
    source      TEXT NOT NULL DEFAULT 'custom'
);

CREATE TABLE IF NOT EXISTS detectors (
    id              TEXT PRIMARY KEY,
    vuln_class_id   TEXT NOT NULL REFERENCES vuln_classes(id),
    detector_type   TEXT NOT NULL,
    content         TEXT NOT NULL,
    language        TEXT NOT NULL DEFAULT 'any',
    confidence      TEXT NOT NULL DEFAULT 'MEDIUM'
);

CREATE TABLE IF NOT EXISTS taint_signatures (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    qualified_pattern   TEXT NOT NULL,
    language            TEXT NOT NULL DEFAULT 'any',
    sig_type            TEXT NOT NULL,
    cwe_ids             TEXT NOT NULL DEFAULT '[]',
    vuln_class_id       TEXT REFERENCES vuln_classes(id),
    description         TEXT,
    source              TEXT NOT NULL DEFAULT 'custom'
);

CREATE INDEX IF NOT EXISTS idx_taintsig_lang ON taint_signatures(language);
CREATE INDEX IF NOT EXISTS idx_taintsig_type ON taint_signatures(sig_type);
CREATE INDEX IF NOT EXISTS idx_detector_class ON detectors(vuln_class_id);
CREATE INDEX IF NOT EXISTS idx_vulnclass_cwe ON vuln_classes(cwe_id);
"""
