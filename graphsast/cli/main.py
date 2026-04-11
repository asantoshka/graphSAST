"""GraphSAST CLI."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import typer

from graphsast.config import get_settings

app = typer.Typer(
    name="graphsast",
    help=(
        "Security analysis: code-review-graph builds the graph, "
        "Semgrep finds issues, LLM reasons about them."
    ),
    no_args_is_help=True,
)


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _db_dir(target: Path) -> Path:
    cfg = get_settings(project_root=target)
    return target / cfg.paths.db_subdir


def _ensure_vuln_db(vuln_db_path: Path) -> None:
    """Seed vulns.db with offline built-in data if it doesn't exist or is empty.

    Runs OWASP WSTG + lang_sigs importers (embedded, no network).
    Safe to call every time — all upserts are idempotent.
    """
    from graphsast.vuln_db.store import VulnStore
    from graphsast.vuln_db.loader import load_all

    log = logging.getLogger("graphsast.cli")
    with VulnStore(vuln_db_path) as vdb:
        stats = vdb.stats()
        if stats["vuln_classes"] == 0 and stats["taint_signatures"] == 0:
            log.info("VulnDB: seeding built-in data (WSTG + lang_sigs) ...")
            load_all(vdb, vuln_db_path.parent.parent, sources=["wstg", "lang_sigs"])
            after = vdb.stats()
            log.info(
                "VulnDB: seeded %d vuln classes, %d taint signatures",
                after["vuln_classes"], after["taint_signatures"],
            )
        else:
            log.debug(
                "VulnDB: %d vuln classes, %d taint signatures (already seeded)",
                stats["vuln_classes"], stats["taint_signatures"],
            )


# ──────────────────────────────────────────────────────────────────────────────
# scan
# ──────────────────────────────────────────────────────────────────────────────

@app.command("scan")
def scan(
    target: Path = typer.Argument(..., help="Repository to scan"),
    db_dir: Optional[Path] = typer.Option(
        None, "--db-dir", help="Where to store graph.db (default: <target>/.graphsast/)"
    ),
    semgrep_config: str = typer.Option(
        "auto", "--semgrep-config",
        help="Semgrep --config value: 'auto', 'p/default', or path to rules file",
    ),
    semgrep_timeout: int = typer.Option(300, "--semgrep-timeout", help="Semgrep timeout in seconds"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write report to file"),
    fmt: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown|json|sarif"),
    llm: bool = typer.Option(False, "--llm", help="Enable LLM analysis of each finding"),
    llm_backend: Optional[str] = typer.Option(None, "--llm-backend", help="ollama|claude|openai|bedrock"),
    llm_model: Optional[str] = typer.Option(None, "--llm-model", help="Model name"),
    llm_max_turns: int = typer.Option(
        0, "--llm-max-turns",
        help="Max tool-use turns per finding (0 = use config default)",
    ),
    hunt: bool = typer.Option(False, "--hunt", help="Also run autonomous LLM hunt after Semgrep scan (requires --llm)"),
    hunt_max_entries: int = typer.Option(10, "--hunt-max-entries", help="Max entry points for hunt (used with --hunt)"),
    full_hunt: bool = typer.Option(False, "--full-hunt", help="Hunt all entry points and flows — no cap (implies --hunt)"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Scan a repository: build graph → run Semgrep → (optionally) analyse with LLM → (optionally) hunt."""
    _setup_logging(verbose)
    log = logging.getLogger("graphsast.cli")

    target = target.resolve()
    if not target.exists():
        typer.echo(f"Error: {target} does not exist", err=True)
        raise typer.Exit(1)

    cfg = get_settings(project_root=target)
    effective_db_dir = (db_dir or _db_dir(target)).resolve()
    effective_db_dir.mkdir(parents=True, exist_ok=True)
    graph_db = effective_db_dir / "graph.db"

    _ensure_vuln_db(effective_db_dir / "vulns.db")

    # --full-hunt implies --hunt
    if full_hunt:
        hunt = True
        log.debug("--full-hunt implies --hunt")

    # --hunt implies --llm
    if hunt and not llm:
        llm = True
        log.debug("--hunt implies --llm; enabling LLM analysis")

    log.info("Target   : %s", target)
    log.info("Graph DB : %s", graph_db)

    # ── LLM client (optional) ──────────────────────────────────────────────────
    llm_client = None
    if llm:
        from graphsast.config import LLMSettings
        from graphsast.llm.factory import get_llm_client

        llm_cfg = LLMSettings(
            backend=llm_backend or cfg.llm.backend,
            model=llm_model or cfg.llm.model,
            base_url=cfg.llm.base_url,
            claude_api_key=cfg.llm.claude_api_key,
            openai_api_key=cfg.llm.openai_api_key,
            bedrock_region=cfg.llm.bedrock_region,
            timeout=cfg.llm.timeout,
            temperature=cfg.llm.temperature,
            num_ctx=cfg.llm.num_ctx,
            analyst_max_turns=llm_max_turns if llm_max_turns > 0 else cfg.llm.analyst_max_turns,
        )
        llm_client_obj = get_llm_client(cfg.model_copy(update={"llm": llm_cfg}))
        if not llm_client_obj.is_available():
            typer.echo(
                f"Warning: LLM backend '{llm_cfg.backend}' not available. "
                "Running without LLM analysis.",
                err=True,
            )
            llm_client_obj.close()
        else:
            llm_client = llm_client_obj
            log.info("LLM      : %s / %s", llm_cfg.backend, llm_cfg.model)

    # ── Run scan ───────────────────────────────────────────────────────────────
    from graphsast.analysis.scanner import scan as _scan

    effective_turns = llm_max_turns if llm_max_turns > 0 else cfg.llm.analyst_max_turns

    try:
        findings, summary = _scan(
            target=target,
            graph_db=graph_db,
            llm_client=llm_client,
            semgrep_config=semgrep_config,
            semgrep_timeout=semgrep_timeout,
            llm_max_turns=effective_turns,
        )
    finally:
        if llm_client:
            llm_client.close()

    # ── Render report ──────────────────────────────────────────────────────────
    import json as _json

    fmt = fmt.lower()
    if fmt == "sarif":
        from graphsast.output.sarif import to_sarif
        rendered = _json.dumps(to_sarif(findings, target), indent=2)
    elif fmt == "json":
        from graphsast.output.json_report import to_json
        rendered = _json.dumps(
            to_json(findings, target, elapsed=summary["elapsed_seconds"]), indent=2
        )
    else:
        from graphsast.output.markdown import to_markdown
        rendered = to_markdown(findings, target, elapsed=summary["elapsed_seconds"])

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        typer.echo(f"Report written to: {output}")
    else:
        typer.echo(rendered)

    # ── Console summary ────────────────────────────────────────────────────────
    from graphsast.cli._render import print_scan_summary, print_findings_table

    active = [f for f in findings if not f.is_false_positive]
    by_sev: dict[str, int] = {}
    for f in active:
        s = f.effective_severity
        by_sev[s] = by_sev.get(s, 0) + 1

    # Print active findings table before the summary panel
    if active:
        active_rows = [
            {
                "rule_id":      f.rule_id,
                "severity":     f.severity,
                "llm_severity": f.llm_severity,
                "llm_verdict":  f.llm_verdict,
                "file_path":    f.file_path,
                "line_start":   f.line_start,
                "llm_reasoning": f.llm_reasoning,
            }
            for f in active
        ]
        print_findings_table(active_rows, title="Active Findings", verbose=verbose)

    print_scan_summary(summary, by_sev, graph_db, target, has_llm=llm_client is not None)

    # ── Optional hunt phase ────────────────────────────────────────────────────
    if hunt:
        if not llm_client:
            # shouldn't reach here since --hunt implies --llm above, but guard anyway
            typer.echo("Warning: hunt skipped — no LLM client available.", err=True)
        else:
            from graphsast.analysis.hunter import hunt as _hunt
            from graphsast.analysis.models import Finding as _Finding
            from graphsast.analysis.store import FindingStore as _FindingStore
            from graphsast.graph.client import GraphClient as _GraphClient
            from graphsast.cli._render import print_findings_table as _print_findings_table

            # Re-open a fresh LLM client (previous one was closed in finally above)
            from graphsast.llm.factory import get_llm_client as _get_llm_client
            from graphsast.config import LLMSettings as _LLMSettings
            hunt_llm_cfg = _LLMSettings(
                backend=llm_backend or cfg.llm.backend,
                model=llm_model or cfg.llm.model,
                base_url=cfg.llm.base_url,
                claude_api_key=cfg.llm.claude_api_key,
                openai_api_key=cfg.llm.openai_api_key,
                bedrock_region=cfg.llm.bedrock_region,
                timeout=cfg.llm.timeout,
                temperature=cfg.llm.temperature,
                num_ctx=cfg.llm.num_ctx,
                analyst_max_turns=effective_turns,
            )
            hunt_client = _get_llm_client(cfg.model_copy(update={"llm": hunt_llm_cfg}))
            _vuln_db_path = effective_db_dir / "vulns.db"
            try:
                with _GraphClient(graph_db, target) as graph:
                    effective_max = (
                        len(graph.list_entry_points()) + 200  # covers all entries + flows
                        if full_hunt else hunt_max_entries
                    )
                    if full_hunt:
                        log.info("Full hunt: scanning all entry points and flows")
                    raw_hunt = _hunt(
                        graph=graph,
                        llm_client=hunt_client,
                        max_entry_points=effective_max,
                        max_turns=effective_turns,
                        vuln_db_path=_vuln_db_path if _vuln_db_path.exists() else None,
                    )
            finally:
                hunt_client.close()

            hunt_findings: list[_Finding] = []
            with _FindingStore(graph_db) as store:
                hunt_run_id = store.start_run(str(target), "hunter", hunt_llm_cfg.model)
                for raw in raw_hunt:
                    hf = _Finding(
                        rule_id=raw["rule_id"],
                        title=raw["title"],
                        message=raw["message"],
                        severity=raw["severity"],
                        file_path=raw["file_path"],
                        line_start=raw["line_start"],
                        line_end=raw["line_end"],
                    )
                    hf.llm_verdict      = "CONFIRMED"
                    hf.llm_severity     = raw["severity"]
                    hf.llm_reasoning    = raw.get("reasoning", "")
                    hf.llm_description  = raw.get("description")
                    hf.llm_poc          = raw.get("poc")
                    hf.llm_cvss_score   = raw.get("cvss_score")
                    hf.llm_cvss_vector  = raw.get("cvss_vector")
                    store.upsert_finding(hf, hunt_run_id, source="hunter")
                    hunt_findings.append(hf)
                hunt_summary = {
                    "run_id": hunt_run_id, "semgrep_findings": 0,
                    "deduplicated": 0, "new_findings": len(raw_hunt),
                    "recurring": 0, "fixed": 0, "cache_hits": 0,
                    "llm_analysed": len(raw_hunt), "confirmed": len(raw_hunt),
                    "false_positives": 0, "needs_review": 0, "elapsed_seconds": 0,
                }
                store.finish_run(hunt_run_id, hunt_summary)

            if hunt_findings:
                hunt_rows = [
                    {
                        "rule_id": f.rule_id, "severity": f.severity,
                        "llm_severity": f.llm_severity, "llm_verdict": f.llm_verdict,
                        "file_path": f.file_path, "line_start": f.line_start,
                        "llm_reasoning": f.llm_reasoning,
                    }
                    for f in hunt_findings
                ]
                _print_findings_table(hunt_rows, title="Hunt Findings", verbose=verbose)
            else:
                from graphsast.cli._render import console
                console.print("[dim]  Hunt: no additional findings.[/dim]")

    has_critical_high = by_sev.get("CRITICAL", 0) + by_sev.get("HIGH", 0) > 0
    if has_critical_high:
        raise typer.Exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# describe
# ──────────────────────────────────────────────────────────────────────────────

@app.command("describe")
def describe_cmd(
    target: Path = typer.Argument(..., help="Repository to describe"),
    db_dir: Optional[Path] = typer.Option(
        None, "--db-dir", help="Graph DB directory (default: <target>/.graphsast/)"
    ),
    llm: bool = typer.Option(False, "--llm", help="Generate an LLM narrative description"),
    llm_backend: Optional[str] = typer.Option(None, "--llm-backend", help="ollama|claude|openai|bedrock"),
    llm_model: Optional[str] = typer.Option(None, "--llm-model", help="Model name"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write report to file"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Describe and explain the code graph — stats, architecture, attack surface, flows.

    Builds the graph automatically if it doesn't exist yet (no Semgrep or LLM scan).
    Add --llm for an AI-generated narrative (architecture, data flows, security observations).
    """
    _setup_logging(verbose)
    log = logging.getLogger("graphsast.cli")

    target = target.resolve()
    if not target.exists():
        typer.echo(f"Error: {target} does not exist", err=True)
        raise typer.Exit(1)

    cfg = get_settings(project_root=target)
    effective_db_dir = (db_dir or _db_dir(target)).resolve()
    effective_db_dir.mkdir(parents=True, exist_ok=True)
    graph_db = effective_db_dir / "graph.db"

    if not graph_db.exists():
        log.info("No graph DB found — building code graph for %s ...", target)
        from graphsast.analysis.scanner import _build_graph
        _build_graph(target, graph_db)

    from graphsast.graph.client import GraphClient

    with GraphClient(graph_db, target) as graph:
        stats       = graph.get_stats()
        entry_points = graph.list_entry_points()
        flows        = graph.get_flows(limit=20)

    # ── Structured report ─────────────────────────────────────────────────────
    import shutil
    width = min(shutil.get_terminal_size((80, 20)).columns, 100)
    sep = "─" * width

    lines: list[str] = []

    def _h(title: str) -> None:
        lines.append(f"\n{sep}")
        lines.append(f"  {title}")
        lines.append(sep)

    lines.append(f"\n  GraphSAST · Codebase Description")
    lines.append(f"  Target : {target}")
    lines.append(f"  DB     : {graph_db}")

    # ── Stats ─────────────────────────────────────────────────────────────────
    _h("Graph Statistics")
    lines.append(f"  Files parsed        {stats['files']}")
    lines.append(f"  Total nodes         {stats['nodes_total']}")
    for kind, cnt in stats["nodes_by_kind"].items():
        lines.append(f"    {kind:<20} {cnt}")
    lines.append(f"  Total edges         {stats['edges_total']}")
    for kind, cnt in stats["edges_by_kind"].items():
        lines.append(f"    {kind:<20} {cnt}")
    lines.append(f"  Pre-computed flows  {stats['flows']}")
    lines.append(f"  Entry points        {len(entry_points)}")

    # ── Languages ─────────────────────────────────────────────────────────────
    if stats["languages"]:
        _h("Language Breakdown")
        total_lang = sum(stats["languages"].values()) or 1
        bar_width = 30
        for lang, cnt in stats["languages"].items():
            pct = round(100 * cnt / total_lang)
            bar = "█" * round(bar_width * cnt / total_lang)
            lines.append(f"  {lang:<14} {bar:<{bar_width}}  {cnt:>5}  ({pct}%)")

    # ── Top files ─────────────────────────────────────────────────────────────
    _h("Top Files by Symbol Count")
    for tf in stats["top_files"]:
        try:
            rel = Path(tf["file_path"]).relative_to(target).as_posix()
        except ValueError:
            rel = tf["file_path"]
        lines.append(f"  {tf['symbol_count']:>4}  {rel}")

    # ── Hub functions ─────────────────────────────────────────────────────────
    if stats["hub_functions"]:
        _h("Most-Called Functions (Hubs)")
        for hf in stats["hub_functions"]:
            qname = hf["qualified_name"]
            name  = qname.split("::")[-1] if "::" in qname else qname
            try:
                rel_q = Path(qname.split("::")[0]).relative_to(target).as_posix() + "::" + name if "::" in qname else qname
            except ValueError:
                rel_q = qname
            lines.append(f"  {hf['caller_count']:>4} caller(s)  {rel_q}")

    # ── Entry points ──────────────────────────────────────────────────────────
    _h(f"Attack Surface — Entry Points ({len(entry_points)} total)")
    by_file: dict[str, list] = {}
    for ep in entry_points:
        fp = ep.get("file_path") or "unknown"
        try:
            fp = Path(fp).relative_to(target).as_posix()
        except ValueError:
            pass
        by_file.setdefault(fp, []).append(ep)
    for fp, eps in by_file.items():
        lines.append(f"\n  {fp}")
        for ep in eps:
            lines.append(f"    line {ep.get('line_start', '?'):<6} {ep.get('name', '?')}")

    # ── Flows ─────────────────────────────────────────────────────────────────
    if flows:
        _h(f"Pre-Computed Execution Flows — top {min(len(flows), 20)} by criticality")
        for i, flow in enumerate(flows[:20], 1):
            name       = flow.get("name") or flow.get("entry_point", "?")
            depth      = flow.get("depth", "?")
            node_count = flow.get("node_count", "?")
            file_count = flow.get("file_count", "?")
            crit       = flow.get("criticality", 0)
            lines.append(
                f"  {i:>2}. crit={crit:.2f}  depth={depth}  nodes={node_count}  "
                f"files={file_count}  {name}"
            )

    report = "\n".join(lines) + "\n"

    # ── Optional LLM narrative ────────────────────────────────────────────────
    llm_narrative = ""
    if llm:
        from graphsast.config import LLMSettings
        from graphsast.llm.factory import get_llm_client
        from graphsast.analysis.describer import describe as _llm_describe

        llm_cfg = LLMSettings(
            backend=llm_backend or cfg.llm.backend,
            model=llm_model or cfg.llm.model,
            base_url=cfg.llm.base_url,
            claude_api_key=cfg.llm.claude_api_key,
            openai_api_key=cfg.llm.openai_api_key,
            bedrock_region=cfg.llm.bedrock_region,
            timeout=cfg.llm.timeout,
            temperature=cfg.llm.temperature,
            num_ctx=cfg.llm.num_ctx,
        )
        with get_llm_client(cfg.model_copy(update={"llm": llm_cfg})) as llm_client:
            if not llm_client.is_available():
                typer.echo(
                    f"Warning: LLM backend '{llm_cfg.backend}' not available. Skipping narrative.",
                    err=True,
                )
            else:
                log.info("Generating LLM narrative (%s / %s) ...", llm_cfg.backend, llm_cfg.model)
                with GraphClient(graph_db, target) as graph:
                    llm_narrative = _llm_describe(graph, llm_client, target)

        if llm_narrative:
            report += f"\n{sep}\n  LLM Narrative\n{sep}\n\n{llm_narrative}\n"

    # ── Output ────────────────────────────────────────────────────────────────
    if output:
        output.write_text(report, encoding="utf-8")
        typer.echo(f"Report written to {output}")
    else:
        typer.echo(report)


# ──────────────────────────────────────────────────────────────────────────────
# findings
# ──────────────────────────────────────────────────────────────────────────────

@app.command("findings")
def findings_cmd(
    target: Path = typer.Argument(..., help="Repository whose findings to query"),
    db_dir: Optional[Path] = typer.Option(None, "--db-dir"),
    run_id: Optional[int] = typer.Option(None, "--run", "-r", help="Show a specific run (default: latest scan run)"),
    compare: bool = typer.Option(False, "--compare", "-c", help="Diff latest run against previous"),
    runs: bool = typer.Option(False, "--runs", help="List all scan runs"),
    all_findings: bool = typer.Option(False, "--all", "-a", help="Show all findings across all runs (combined view)"),
    source: Optional[str] = typer.Option(None, "--source", "-s", help="Filter by source: semgrep|hunter"),
    detail: bool = typer.Option(False, "--detail", "-d", help="Full detail view: description, PoC, CVSS, code snippet"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Query persisted findings and scan history."""
    _setup_logging(verbose)

    target = target.resolve()
    effective_db_dir = (db_dir or _db_dir(target)).resolve()
    graph_db = effective_db_dir / "graph.db"

    if not graph_db.exists():
        typer.echo(f"No findings DB found at {graph_db}. Run 'graphsast scan' first.", err=True)
        raise typer.Exit(1)

    from graphsast.analysis.store import FindingStore
    from graphsast.cli._render import (
        console, print_comparison, print_finding_detail,
        print_findings_table, print_runs_table,
    )

    def _show(rows: list[dict], title: str) -> None:
        if detail:
            if not rows:
                console.print("[dim]  No findings.[/dim]")
                return
            console.print(f"\n[bold]{title}[/bold]")
            active = [r for r in rows if r.get("llm_verdict") != "FALSE_POSITIVE"]
            fp_rows = [r for r in rows if r.get("llm_verdict") == "FALSE_POSITIVE"]
            for i, r in enumerate(active, 1):
                print_finding_detail(r, i, target)
            if fp_rows:
                console.print(f"\n[dim]── False positives ({len(fp_rows)}) ──[/dim]")
                print_findings_table(fp_rows, title="", verbose=False)
        else:
            print_findings_table(rows, title=title, verbose=verbose)

    with FindingStore(graph_db) as store:
        # ── List runs ──────────────────────────────────────────────────────────
        if runs:
            all_runs = store.list_runs()
            if not all_runs:
                console.print("[dim]No scan runs recorded yet.[/dim]")
                return
            print_runs_table(all_runs)
            return

        # ── Combined all-findings view ─────────────────────────────────────────
        if all_findings or source:
            rows = store.get_all_findings(source=source)
            src_label = f" [{source}]" if source else " [all sources]"
            _show(rows, f"All Findings{src_label}  ·  {len(rows)} total")
            return

        # ── Resolve run (skip hunt-only runs for the default view) ─────────────
        if run_id is None:
            all_runs = store.list_runs()
            if not all_runs:
                console.print("[dim]No scan runs recorded yet.[/dim]")
                return
            scan_run = next((r for r in all_runs if r.get("semgrep_config") != "hunter"), None)
            run_id = (scan_run or all_runs[0])["id"]

        run = store.get_run(run_id)
        if run is None:
            typer.echo(f"Run #{run_id} not found.", err=True)
            raise typer.Exit(1)

        # ── Compare mode ───────────────────────────────────────────────────────
        if compare:
            diff = store.compare_with_previous(run_id)
            print_comparison(diff, run_id)
            return

        # ── Default: show run findings ─────────────────────────────────────────
        run_findings = store.get_run_findings(run_id)
        title = (
            f"Run #{run_id}  ·  {(run['started_at'] or '')[:16]}"
            f"  ·  {run['model'] or 'no LLM'}"
            f"  ·  {len(run_findings)} findings"
        )
        _show(run_findings, title)


# ──────────────────────────────────────────────────────────────────────────────
# hunt
# ──────────────────────────────────────────────────────────────────────────────

@app.command("hunt")
def hunt_cmd(
    target: Path = typer.Argument(..., help="Repository to hunt"),
    db_dir: Optional[Path] = typer.Option(
        None, "--db-dir", help="Graph DB directory (default: <target>/.graphsast/)"
    ),
    max_entries: int = typer.Option(
        10, "--max-entries", "-n",
        help="Max entry points / flows to audit",
    ),
    full_hunt: bool = typer.Option(False, "--full-hunt", help="Audit all entry points and flows — no cap"),
    llm_backend: Optional[str] = typer.Option(None, "--llm-backend", help="ollama|claude|openai|bedrock"),
    llm_model: Optional[str] = typer.Option(None, "--llm-model", help="Model name"),
    llm_max_turns: int = typer.Option(0, "--llm-max-turns", help="Max tool-use turns per entry point (0 = config default)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write report to file"),
    fmt: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown|json|sarif"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Autonomous LLM-driven hunt — no Semgrep required.

    Starts from entry points and pre-computed flows, asks the LLM to trace
    data and find vulnerabilities on its own.
    """
    _setup_logging(verbose)
    log = logging.getLogger("graphsast.cli")

    target = target.resolve()
    if not target.exists():
        typer.echo(f"Error: {target} does not exist", err=True)
        raise typer.Exit(1)

    cfg = get_settings(project_root=target)
    effective_db_dir = (db_dir or _db_dir(target)).resolve()
    graph_db = effective_db_dir / "graph.db"

    if not graph_db.exists():
        typer.echo(
            f"No graph DB found at {graph_db}. Run 'graphsast scan' first to build the graph.",
            err=True,
        )
        raise typer.Exit(1)

    _ensure_vuln_db(effective_db_dir / "vulns.db")

    # ── LLM client (required for hunt) ────────────────────────────────────────
    from graphsast.config import LLMSettings
    from graphsast.llm.factory import get_llm_client

    llm_cfg = LLMSettings(
        backend=llm_backend or cfg.llm.backend,
        model=llm_model or cfg.llm.model,
        base_url=cfg.llm.base_url,
        claude_api_key=cfg.llm.claude_api_key,
        openai_api_key=cfg.llm.openai_api_key,
        bedrock_region=cfg.llm.bedrock_region,
        timeout=cfg.llm.timeout,
        temperature=cfg.llm.temperature,
        num_ctx=cfg.llm.num_ctx,
        analyst_max_turns=llm_max_turns if llm_max_turns > 0 else cfg.llm.analyst_max_turns,
    )
    effective_turns = llm_max_turns if llm_max_turns > 0 else cfg.llm.analyst_max_turns

    llm_client_obj = get_llm_client(cfg.model_copy(update={"llm": llm_cfg}))
    if not llm_client_obj.is_available():
        typer.echo(
            f"Error: LLM backend '{llm_cfg.backend}' not available.",
            err=True,
        )
        llm_client_obj.close()
        raise typer.Exit(1)

    log.info("LLM      : %s / %s", llm_cfg.backend, llm_cfg.model)

    # ── Run hunt ───────────────────────────────────────────────────────────────
    from graphsast.analysis.hunter import hunt as _hunt
    from graphsast.analysis.models import Finding
    from graphsast.analysis.store import FindingStore
    from graphsast.graph.client import GraphClient

    vuln_db_path = effective_db_dir / "vulns.db"
    try:
        with GraphClient(graph_db, target) as graph:
            effective_max = (
                len(graph.list_entry_points()) + 200
                if full_hunt else max_entries
            )
            if full_hunt:
                log.info("Full hunt: scanning all entry points and flows")
            raw_findings = _hunt(
                graph=graph,
                llm_client=llm_client_obj,
                max_entry_points=effective_max,
                max_turns=effective_turns,
                vuln_db_path=vuln_db_path if vuln_db_path.exists() else None,
            )
    finally:
        llm_client_obj.close()

    # ── Persist findings ───────────────────────────────────────────────────────
    findings: list[Finding] = []
    with FindingStore(graph_db) as store:
        run_id = store.start_run(str(target), "hunter", llm_cfg.model)
        for raw in raw_findings:
            f = Finding(
                rule_id=raw["rule_id"],
                title=raw["title"],
                message=raw["message"],
                severity=raw["severity"],
                file_path=raw["file_path"],
                line_start=raw["line_start"],
                line_end=raw["line_end"],
            )
            f.llm_verdict      = "CONFIRMED"
            f.llm_severity     = raw["severity"]
            f.llm_reasoning    = raw.get("reasoning", "")
            f.llm_description  = raw.get("description")
            f.llm_poc          = raw.get("poc")
            f.llm_cvss_score   = raw.get("cvss_score")
            f.llm_cvss_vector  = raw.get("cvss_vector")
            store.upsert_finding(f, run_id, source="hunter")
            findings.append(f)

        summary = {
            "run_id":           run_id,
            "semgrep_findings": 0,
            "deduplicated":     0,
            "new_findings":     len(raw_findings),
            "recurring":        0,
            "fixed":            0,
            "cache_hits":       0,
            "llm_analysed":     len(raw_findings),
            "confirmed":        len(raw_findings),
            "false_positives":  0,
            "needs_review":     0,
            "elapsed_seconds":  0,
        }
        store.finish_run(run_id, summary)

    # ── Render report ──────────────────────────────────────────────────────────
    import json as _json

    fmt = fmt.lower()
    if fmt == "sarif":
        from graphsast.output.sarif import to_sarif
        rendered = _json.dumps(to_sarif(findings, target), indent=2)
    elif fmt == "json":
        from graphsast.output.json_report import to_json
        rendered = _json.dumps(to_json(findings, target, elapsed=0), indent=2)
    else:
        from graphsast.output.markdown import to_markdown
        rendered = to_markdown(findings, target, elapsed=0)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        typer.echo(f"Report written to: {output}")
    else:
        typer.echo(rendered)

    # ── Console summary ────────────────────────────────────────────────────────
    from graphsast.cli._render import print_findings_table, print_scan_summary

    by_sev: dict[str, int] = {}
    for f in findings:
        s = f.effective_severity
        by_sev[s] = by_sev.get(s, 0) + 1

    if findings:
        rows = [
            {
                "rule_id":       f.rule_id,
                "severity":      f.severity,
                "llm_severity":  f.llm_severity,
                "llm_verdict":   f.llm_verdict,
                "file_path":     f.file_path,
                "line_start":    f.line_start,
                "llm_reasoning": f.llm_reasoning,
            }
            for f in findings
        ]
        print_findings_table(rows, title="Hunt Findings", verbose=verbose)

    print_scan_summary(summary, by_sev, graph_db, target, has_llm=True)

    if by_sev.get("CRITICAL", 0) + by_sev.get("HIGH", 0) > 0:
        raise typer.Exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# update-vuln-db
# ──────────────────────────────────────────────────────────────────────────────

@app.command("update-vuln-db")
def update_vuln_db(
    target: Path = typer.Argument(
        Path("."), help="Repository whose .graphsast/vulns.db to update (default: cwd)"
    ),
    db_dir: Optional[Path] = typer.Option(None, "--db-dir"),
    sources: str = typer.Option(
        "wstg,lang_sigs",
        "--sources",
        help="Comma-separated sources to load: wstg,lang_sigs,semgrep,builtin,custom",
    ),
    semgrep_rules_path: Optional[Path] = typer.Option(
        None, "--semgrep-rules-path",
        help="Path to local semgrep-rules clone (semgrep source only)",
    ),
    no_update: bool = typer.Option(
        False, "--no-update",
        help="Skip git pull when refreshing semgrep-rules clone",
    ),
) -> None:
    """Build or refresh the vulnerability database (vulns.db).

    By default loads embedded offline sources (OWASP WSTG + lang_sigs).
    Add --sources semgrep to also import the full Semgrep rules registry
    (requires network, clones ~50 MB git repo on first run).
    """
    from graphsast.vuln_db.store import VulnStore
    from graphsast.vuln_db.loader import load_all

    target = target.resolve()
    effective_db_dir = (db_dir or _db_dir(target)).resolve()
    effective_db_dir.mkdir(parents=True, exist_ok=True)
    vuln_db_path = effective_db_dir / "vulns.db"

    source_list = [s.strip() for s in sources.split(",") if s.strip()]

    typer.echo(f"Updating vulns.db at {vuln_db_path}")
    typer.echo(f"Sources: {', '.join(source_list)}")

    with VulnStore(vuln_db_path) as vdb:
        results = load_all(
            vdb,
            project_root=target,
            sources=source_list,
            semgrep_rules_path=semgrep_rules_path,
            semgrep_update=not no_update,
        )

    typer.echo("\nDone:")
    for key, count in results.items():
        typer.echo(f"  {key}: {count}")

    with VulnStore(vuln_db_path) as vdb:
        stats = vdb.stats()
    typer.echo(
        f"\nDB totals: {stats['vuln_classes']} vuln classes, "
        f"{stats['taint_signatures']} taint signatures, "
        f"{stats['detectors']} detectors"
    )


# ──────────────────────────────────────────────────────────────────────────────
# check-llm
# ──────────────────────────────────────────────────────────────────────────────

@app.command("check-llm")
def check_llm(
    backend: Optional[str] = typer.Option(None, "--backend", help="ollama|claude|openai|bedrock"),
    model: Optional[str] = typer.Option(None, "--model", "-m"),
    url: Optional[str] = typer.Option(None, "--url", help="Ollama base URL"),
) -> None:
    """Test LLM backend connectivity."""
    from graphsast.config import LLMSettings
    from graphsast.llm.factory import get_llm_client

    cfg = get_settings()
    llm_cfg = LLMSettings(
        backend=backend or cfg.llm.backend,
        model=model or cfg.llm.model,
        base_url=url or cfg.llm.base_url,
        claude_api_key=cfg.llm.claude_api_key,
        openai_api_key=cfg.llm.openai_api_key,
        bedrock_region=cfg.llm.bedrock_region,
    )

    with get_llm_client(cfg.model_copy(update={"llm": llm_cfg})) as client:
        available = client.list_models()
        reachable = client.is_available()

    if not reachable:
        typer.echo(
            f"Error: backend '{llm_cfg.backend}' not reachable (model: '{llm_cfg.model}')",
            err=True,
        )
        if available:
            typer.echo(f"  Available: {', '.join(available)}", err=True)
        raise typer.Exit(1)

    typer.echo(f"\n── LLM: {llm_cfg.backend} ──────────────────────────────────")
    if llm_cfg.backend == "ollama":
        typer.echo(f"  URL: {llm_cfg.base_url}")
    typer.echo(f"  Model '{llm_cfg.model}' is ready.")
    if available:
        typer.echo(f"  All available models: {', '.join(available)}")


if __name__ == "__main__":
    app()
