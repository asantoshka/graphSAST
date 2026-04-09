"""GraphSAST CLI entry point."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

import typer

from graphsast.config import get_settings

app = typer.Typer(
    name="graphsast",
    help="Security analysis tool combining a code graph, vulnerability pattern DB, and LLM layer.",
    no_args_is_help=True,
)

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _default_db_dir(target: Path) -> Path:
    cfg = get_settings(project_root=target)
    return target / cfg.paths.db_subdir


# ──────────────────────────────────────────────────────────────────────────────
# build-graph
# ──────────────────────────────────────────────────────────────────────────────

@app.command("build-graph")
def build_graph(
    target: Path = typer.Argument(..., help="Source directory to analyse"),
    db_dir: Optional[Path] = typer.Option(None, "--db-dir", help="Where to store graph.db and vulns.db"),
    incremental: bool = typer.Option(True, "--incremental/--full", help="Skip unchanged files"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Parse a codebase and build the security-annotated code graph."""
    _setup_logging(verbose)
    log = logging.getLogger("graphsast.cli")

    target = target.resolve()
    if not target.exists():
        typer.echo(f"Error: target path does not exist: {target}", err=True)
        raise typer.Exit(1)

    db_dir = (db_dir or _default_db_dir(target)).resolve()
    db_dir.mkdir(parents=True, exist_ok=True)

    graph_db_path = db_dir / "graph.db"
    vuln_db_path = db_dir / "vulns.db"

    log.info("Graph DB : %s", graph_db_path)
    log.info("Vuln DB  : %s", vuln_db_path)

    from graphsast.graph_db.store import SecurityGraphStore
    from graphsast.vuln_db.store import VulnStore
    from graphsast.ingestion.pipeline import IngestionPipeline

    vuln_db = None
    if vuln_db_path.exists():
        vuln_db = VulnStore(vuln_db_path)
        stats = vuln_db.stats()
        log.info(
            "Vuln DB loaded: %d classes, %d signatures",
            stats["vuln_classes"], stats["taint_signatures"],
        )
    else:
        typer.echo(
            "Warning: vulns.db not found. Run `graphsast update-vuln-db` first for taint annotation.",
            err=True,
        )

    with SecurityGraphStore(graph_db_path) as graph:
        pipeline = IngestionPipeline(graph, vuln_db=vuln_db, incremental=incremental)
        summary = pipeline.run(target)

    if vuln_db:
        vuln_db.close()

    typer.echo("\n── Build Graph Summary ──────────────────────")
    typer.echo(f"  Files parsed       : {summary['files_processed']}")
    typer.echo(f"  Files skipped      : {summary['files_skipped']} (unchanged)")
    typer.echo(f"  Call arg records   : {summary['call_arg_records']}")
    typer.echo(f"  Taint annotations  : {summary['taint_annotations']}")
    typer.echo(f"  Entry points       : {summary['entry_points']}")
    typer.echo(f"  Missing checks     : {summary['missing_checks']}")
    typer.echo(f"  Elapsed            : {summary['elapsed_seconds']}s")
    typer.echo(f"\n  Graph DB: {graph_db_path}")


# ──────────────────────────────────────────────────────────────────────────────
# update-vuln-db
# ──────────────────────────────────────────────────────────────────────────────

@app.command("update-vuln-db")
def update_vuln_db(
    target: Path = typer.Argument(Path("."), help="Project root (looks for .graphsast/custom/ here)"),
    db_dir: Optional[Path] = typer.Option(None, "--db-dir"),
    source: Optional[str] = typer.Option(None, "--source", help="Loader to run: builtin, custom, semgrep, wstg (comma-separated or single)"),
    semgrep_rules_path: Optional[Path] = typer.Option(None, "--semgrep-rules-path", help="Path to local semgrep-rules clone (skips git clone/pull)"),
    no_semgrep_update: bool = typer.Option(False, "--no-semgrep-update", help="Skip git pull on existing semgrep-rules clone"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Populate / update the vulnerability pattern database."""
    _setup_logging(verbose)
    log = logging.getLogger("graphsast.cli")

    target = target.resolve()
    db_dir = (db_dir or _default_db_dir(target)).resolve()
    db_dir.mkdir(parents=True, exist_ok=True)

    vuln_db_path = db_dir / "vulns.db"

    from graphsast.vuln_db.store import VulnStore
    from graphsast.vuln_db.loader import load_all

    # Parse comma-separated sources
    sources = None
    if source:
        sources = [s.strip() for s in source.split(",")]

    with VulnStore(vuln_db_path) as vuln_db:
        results = load_all(
            vuln_db,
            project_root=target,
            sources=sources,
            semgrep_rules_path=semgrep_rules_path,
            semgrep_update=not no_semgrep_update,
        )

    typer.echo("\n── Update Vuln DB Summary ───────────────────")
    for loader, count in results.items():
        typer.echo(f"  {loader:<20}: {count} records")
    typer.echo(f"\n  Vuln DB: {vuln_db_path}")


# ──────────────────────────────────────────────────────────────────────────────
# query
# ──────────────────────────────────────────────────────────────────────────────

@app.command("query")
def query(
    target: Path = typer.Argument(Path("."), help="Project root"),
    db_dir: Optional[Path] = typer.Option(None, "--db-dir"),
    taint_paths: bool = typer.Option(False, "--taint-paths", help="Show source→sink taint paths"),
    missing_checks: bool = typer.Option(False, "--missing-checks", help="Show missing security checks"),
    entry_points: bool = typer.Option(False, "--entry-points", help="List all entry points"),
    sinks: bool = typer.Option(False, "--sinks", help="List all sink-annotated nodes"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Query the code graph for security information."""
    _setup_logging(verbose)

    target = target.resolve()
    db_dir = (db_dir or _default_db_dir(target)).resolve()
    graph_db_path = db_dir / "graph.db"

    if not graph_db_path.exists():
        typer.echo(f"Error: graph.db not found at {graph_db_path}. Run build-graph first.", err=True)
        raise typer.Exit(1)

    from graphsast.graph_db.store import SecurityGraphStore

    with SecurityGraphStore(graph_db_path) as graph:
        if entry_points:
            eps = graph.get_entry_points()
            typer.echo(f"\nEntry points ({len(eps)}):")
            for ep in eps:
                typer.echo(f"  {ep}")

        if sinks:
            s = graph.get_all_sinks()
            typer.echo(f"\nSink nodes ({len(s)}):")
            for node in s:
                typer.echo(f"  {node}")

        if missing_checks:
            mcs = graph.get_all_missing_checks()
            typer.echo(f"\nMissing security checks ({len(mcs)}):")
            for mc in mcs:
                typer.echo(f"  [{mc.missing_type:12}] {mc.entry_point_qn}")

        if taint_paths:
            typer.echo("\nFinding taint paths (source → sink, no sanitizer)...")
            paths = graph.find_taint_paths()
            typer.echo(f"Found {len(paths)} taint paths:")
            for p in paths:
                path_str = " → ".join(p["path"])
                typer.echo(f"  [{p['depth']} hops] {path_str}")

        if not any([entry_points, sinks, missing_checks, taint_paths]):
            # Default: print stats
            conn = graph._conn
            nodes = conn.execute("SELECT count(*) FROM nodes").fetchone()[0]
            edges = conn.execute("SELECT count(*) FROM edges").fetchone()[0]
            call_args = conn.execute("SELECT count(*) FROM call_arguments").fetchone()[0]
            taints = conn.execute("SELECT count(*) FROM taint_annotations").fetchone()[0]
            missing = conn.execute("SELECT count(*) FROM missing_checks").fetchone()[0]
            eps = conn.execute(
                "SELECT count(*) FROM nodes WHERE is_entry_point = 1"
            ).fetchone()[0]

            typer.echo(f"\n── Graph Stats ──────────────────────────────")
            typer.echo(f"  Nodes              : {nodes}")
            typer.echo(f"  Edges              : {edges}")
            typer.echo(f"  Call arg records   : {call_args}")
            typer.echo(f"  Taint annotations  : {taints}")
            typer.echo(f"  Entry points       : {eps}")
            typer.echo(f"  Missing checks     : {missing}")


@app.command("capabilities")
def capabilities(
    target: Path = typer.Argument(Path("."), help="Project root"),
    db_dir: Optional[Path] = typer.Option(None, "--db-dir"),
    language: Optional[str] = typer.Option(None, "--language", "-l", help="Filter by language"),
) -> None:
    """Show what GraphSAST can detect per language."""
    target = target.resolve()
    db_dir = (db_dir or _default_db_dir(target)).resolve()
    vuln_db_path = db_dir / "vulns.db"

    if not vuln_db_path.exists():
        typer.echo("Error: vulns.db not found. Run `graphsast update-vuln-db` first.", err=True)
        raise typer.Exit(1)

    from graphsast.vuln_db.store import VulnStore

    STATUS_ICON = {"supported": "✓", "partial": "~", "planned": "○"}

    with VulnStore(vuln_db_path) as vuln_db:
        rows = vuln_db.get_capabilities(language)

    if not rows:
        typer.echo("No capability data found. Run `graphsast update-vuln-db` first.")
        raise typer.Exit(0)

    # Group by language
    by_lang: dict[str, list[dict]] = {}
    for r in rows:
        by_lang.setdefault(r["language"], []).append(r)

    for lang, caps in by_lang.items():
        typer.echo(f"\n── {lang} {'─' * (40 - len(lang))}")
        for cap in caps:
            icon = STATUS_ICON.get(cap["status"], "?")
            typer.echo(f"  [{icon}] {cap['capability']:<25} {cap['description']}")

    typer.echo(f"\n  ✓ = supported   ~ = partial   ○ = planned")


# ──────────────────────────────────────────────────────────────────────────────
# scan
# ──────────────────────────────────────────────────────────────────────────────

@app.command("scan")
def scan(
    target: Path = typer.Argument(..., help="Source directory to scan"),
    db_dir: Optional[Path] = typer.Option(None, "--db-dir", help="Where graph.db and vulns.db live"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write report to file"),
    fmt: Optional[str] = typer.Option(None, "--format", "-f", help="Output format: markdown|json|sarif (default from config)"),
    no_semgrep: bool = typer.Option(False, "--no-semgrep", help="Skip Semgrep pass (faster)"),
    max_semgrep_rules: int = typer.Option(0, "--max-semgrep-rules", help="Limit semgrep rules (0 = all)"),
    language: Optional[str] = typer.Option(None, "--language", "-l", help="Filter semgrep rules to this language"),
    build_first: bool = typer.Option(False, "--build-first", help="Run build-graph before scanning"),
    incremental: bool = typer.Option(True, "--incremental/--full"),
    # LLM options
    llm: bool = typer.Option(False, "--llm", help="Enable Ollama LLM analysis (Phase 1A + 1B)"),
    llm_model: Optional[str] = typer.Option(None, "--llm-model", help="Ollama model name (default from config)"),
    llm_url: Optional[str] = typer.Option(None, "--llm-url", help="Ollama base URL (default from config)"),
    llm_max_ep: Optional[int] = typer.Option(None, "--llm-max-ep", help="Max entry points for Phase 1A (0 = all, default from config)"),
    llm_timeout: Optional[float] = typer.Option(None, "--llm-timeout", help="Per-request LLM timeout in seconds (default from config)"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Run a full security scan and produce a report."""
    _setup_logging(verbose)
    log = logging.getLogger("graphsast.cli")

    target = target.resolve()
    if not target.exists():
        typer.echo(f"Error: target path does not exist: {target}", err=True)
        raise typer.Exit(1)

    # Resolve configuration: config file < env vars < CLI flags
    cfg = get_settings(project_root=target)
    effective_fmt       = fmt       or cfg.output.format
    effective_llm_model = llm_model or cfg.llm.model
    effective_llm_url   = llm_url   or cfg.llm.base_url
    effective_llm_timeout = llm_timeout if llm_timeout is not None else cfg.llm.timeout
    effective_llm_max_ep  = llm_max_ep  if llm_max_ep  is not None else cfg.llm.max_entry_points

    db_dir = (db_dir or _default_db_dir(target)).resolve()
    graph_db_path = db_dir / "graph.db"
    vuln_db_path  = db_dir / "vulns.db"

    # Optionally build the graph first
    if build_first or not graph_db_path.exists():
        typer.echo("Building code graph...")
        db_dir.mkdir(parents=True, exist_ok=True)
        from graphsast.graph_db.store import SecurityGraphStore
        from graphsast.vuln_db.store import VulnStore as VS
        from graphsast.vuln_db.loader import load_all as _load_all
        from graphsast.ingestion.pipeline import IngestionPipeline

        vuln_db_build = VS(vuln_db_path) if vuln_db_path.exists() else None
        if not vuln_db_path.exists():
            typer.echo(
                "Warning: vulns.db not found — run `graphsast update-vuln-db` for better results.",
                err=True,
            )

        with SecurityGraphStore(graph_db_path) as g:
            pipeline = IngestionPipeline(g, vuln_db=vuln_db_build, incremental=incremental)
            summary = pipeline.run(target)

        if vuln_db_build:
            vuln_db_build.close()

        typer.echo(
            f"  Graph built: {summary['files_processed']} files, "
            f"{summary['taint_annotations']} taint annotations, "
            f"{summary['entry_points']} entry points"
        )

    if not graph_db_path.exists():
        typer.echo(
            f"Error: graph.db not found at {graph_db_path}. "
            "Run `graphsast build-graph` first, or use --build-first.",
            err=True,
        )
        raise typer.Exit(1)

    from graphsast.graph_db.store import SecurityGraphStore
    from graphsast.vuln_db.store import VulnStore
    from graphsast.analysis.scanner import Scanner
    from graphsast.output.sarif import to_sarif
    from graphsast.output.json_report import to_json
    from graphsast.output.markdown import to_markdown

    vuln_db = VulnStore(vuln_db_path) if vuln_db_path.exists() else None

    typer.echo(f"\nScanning {target} ...")

    with SecurityGraphStore(graph_db_path) as graph:
        scanner = Scanner(
            graph,
            vuln_db=vuln_db,
            run_semgrep=not no_semgrep,
            language=language,
            max_semgrep_rules=max_semgrep_rules,
        )
        findings, summary = scanner.scan(target)

        # ── LLM Phase 1A + 1B (optional) ──
        p1a_count = 0
        p1b_confirmed = 0
        p1b_fp = 0
        p1a_results: list[dict] = []
        p1b_results: list[dict] = []
        if llm:
            from graphsast.llm.factory import get_llm_client
            from graphsast.llm.phase1a import run_phase1a
            from graphsast.llm.phase1b import run_phase1b

            # Build an effective config with CLI overrides applied
            from graphsast.config import LLMSettings
            effective_llm_cfg = LLMSettings(
                backend=cfg.llm.backend,
                base_url=effective_llm_url,
                model=effective_llm_model,
                timeout=effective_llm_timeout,
                temperature=cfg.llm.temperature,
                num_ctx=cfg.llm.num_ctx,
                health_check_timeout=cfg.llm.health_check_timeout,
                claude_api_key=cfg.llm.claude_api_key,
                max_entry_points=effective_llm_max_ep,
                phase1a_max_turns=cfg.llm.phase1a_max_turns,
                phase1b_max_turns_l2=cfg.llm.phase1b_max_turns_l2,
                phase1b_max_turns_l3=cfg.llm.phase1b_max_turns_l3,
            )
            cfg_with_overrides = cfg.model_copy(update={"llm": effective_llm_cfg})

            with get_llm_client(cfg_with_overrides) as llm_client:
                if not llm_client.is_available():
                    typer.echo(
                        f"Warning: LLM backend '{cfg.llm.backend}' not reachable "
                        f"(model: '{effective_llm_model}'). Skipping LLM analysis.",
                        err=True,
                    )
                    available = llm_client.list_models()
                    if available:
                        typer.echo(f"  Available models: {', '.join(available)}", err=True)
                else:
                    typer.echo(f"\n  LLM Phase 1A: autonomous analysis ({effective_llm_model}) ...")
                    p1a_results = run_phase1a(
                        graph, llm_client,
                        scan_run_id=summary["scan_run_id"],
                        max_entry_points=effective_llm_max_ep,
                    )
                    p1a_count = len(p1a_results)
                    typer.echo(f"  Phase 1A: {p1a_count} LLM findings")

                    typer.echo(f"  LLM Phase 1B: validating Phase 2 findings ...")
                    p1b_results = run_phase1b(
                        graph, findings, llm_client,
                        scan_run_id=summary["scan_run_id"],
                    )
                    p1b_confirmed = sum(1 for r in p1b_results if r["verdict"] == "CONFIRMED")
                    p1b_fp        = sum(1 for r in p1b_results if r["verdict"] == "FALSE_POSITIVE")
                    typer.echo(f"  Phase 1B: {p1b_confirmed} confirmed, {p1b_fp} false positives")

        # ── Merge LLM results into findings ──────────────────────────────────
        if p1a_results or p1b_results:
            from graphsast.analysis.phase3.llm_merge import merge_llm_results
            findings = merge_llm_results(findings, p1a_results, p1b_results)

        # ── Reachability severity adjustment (always) ─────────────────────────
        from graphsast.analysis.phase3.reachability import apply_reachability
        findings = apply_reachability(findings, graph, target=target)

    if vuln_db:
        vuln_db.close()

    scan_run_id = summary["scan_run_id"]

    # Active findings only (suppress FPs from severity counts)
    active_findings = [f for f in findings if not f.is_suppressed]

    # ── Render output ──
    effective_fmt = effective_fmt.lower()
    if effective_fmt == "sarif":
        doc = to_sarif(active_findings, target, scan_run_id=scan_run_id)
        import json as _json
        rendered = _json.dumps(doc, indent=2)
    elif effective_fmt == "json":
        doc = to_json(findings, target, scan_run_id=scan_run_id, elapsed=summary["elapsed_seconds"])
        import json as _json
        rendered = _json.dumps(doc, indent=2)
    else:
        rendered = to_markdown(findings, target, scan_run_id=scan_run_id, elapsed=summary["elapsed_seconds"])

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        typer.echo(f"  Report written to: {output}")
    else:
        typer.echo(rendered)

    # ── Console summary ──
    from graphsast.analysis.scanner import _count_by_severity
    active_sev  = _count_by_severity(active_findings)
    suppressed  = [f for f in findings if f.is_suppressed]

    typer.echo("\n── Scan Summary ─────────────────────────────")
    typer.echo(f"  Pass A (semgrep)     : {summary['pass_a_semgrep']} findings")
    typer.echo(f"  Pass B (taint BFS)   : {summary['pass_b_taint']} findings")
    typer.echo(f"  Pass C (structure)   : {summary['pass_c_structure']} findings")
    typer.echo(f"  After correlation    : {summary['findings_after_correlation']} unique findings")
    if llm:
        typer.echo(f"  Phase 1A (LLM)       : {p1a_count} autonomous findings")
        typer.echo(f"  Phase 1B confirmed   : {p1b_confirmed}")
        typer.echo(f"  Phase 1B suppressed  : {len(suppressed)} (false positives)")
    typer.echo(f"  Active findings      : {len(active_findings)}")
    typer.echo(f"  CRITICAL             : {active_sev.get('CRITICAL', 0)}")
    typer.echo(f"  HIGH                 : {active_sev.get('HIGH', 0)}")
    typer.echo(f"  MEDIUM               : {active_sev.get('MEDIUM', 0)}")
    typer.echo(f"  LOW                  : {active_sev.get('LOW', 0)}")
    typer.echo(f"  Elapsed              : {summary['elapsed_seconds']}s")

    # Exit 1 if any HIGH or CRITICAL active findings (useful for CI)
    if active_sev.get("CRITICAL", 0) + active_sev.get("HIGH", 0) > 0:
        raise typer.Exit(1)


@app.command("check-llm")
def check_llm(
    url: Optional[str] = typer.Option(None, "--url", help="Ollama base URL (ollama backend only)"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model to check for (default from config)"),
    backend: Optional[str] = typer.Option(None, "--backend", help="Backend to check: ollama|claude (default from config)"),
) -> None:
    """Check LLM backend connectivity and list available models."""
    from graphsast.llm.factory import get_llm_client
    from graphsast.config import LLMSettings

    cfg = get_settings()
    effective_backend = backend or cfg.llm.backend
    effective_model   = model   or cfg.llm.model
    effective_url     = url     or cfg.llm.base_url

    effective_llm_cfg = LLMSettings(
        backend=effective_backend,
        base_url=effective_url,
        model=effective_model,
        claude_api_key=cfg.llm.claude_api_key,
    )
    cfg_override = cfg.model_copy(update={"llm": effective_llm_cfg})

    with get_llm_client(cfg_override) as client:
        available_models = client.list_models()
        reachable        = client.is_available()

    if not reachable:
        typer.echo(
            f"Error: backend '{effective_backend}' not reachable "
            f"(model: '{effective_model}')",
            err=True,
        )
        if available_models:
            typer.echo(f"  Available models: {', '.join(available_models)}", err=True)
        raise typer.Exit(1)

    typer.echo(f"\n── LLM backend: {effective_backend} ────────────────────────────")
    if effective_backend == "ollama":
        typer.echo(f"  URL: {effective_url}")
    typer.echo(f"  Available models ({len(available_models)}):")
    for m in available_models:
        marker = " ◀ selected" if m.startswith(effective_model.split(":")[0]) else ""
        typer.echo(f"    {m}{marker}")
    typer.echo(f"\n  Model '{effective_model}' is ready for LLM analysis.")


if __name__ == "__main__":
    app()
