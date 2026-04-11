"""Rich-based CLI rendering helpers."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

# ── Severity colours ───────────────────────────────────────────────────────────

_SEV_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "dim",
}

_VERDICT_STYLE = {
    "CONFIRMED":      "bold red",
    "FALSE_POSITIVE": "green",
    "NEEDS_REVIEW":   "yellow",
}


def _sev(s: str) -> str:
    style = _SEV_STYLE.get(s.upper(), "")
    return f"[{style}]{s}[/{style}]" if style else s


def _verdict(v: str) -> str:
    style = _VERDICT_STYLE.get(v.upper(), "")
    return f"[{style}]{v}[/{style}]" if style else v


def _short_path(fp: str) -> str:
    """Keep only the last two path components."""
    parts = Path(fp).parts
    return str(Path(*parts[-2:])) if len(parts) >= 2 else fp


# ── Scan summary ───────────────────────────────────────────────────────────────

def print_scan_summary(summary: dict, active_by_sev: dict, graph_db: Path, target: Path, has_llm: bool) -> None:
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    t.add_column(style="dim")
    t.add_column()

    t.add_row("Run #",     str(summary["run_id"]))
    t.add_row("Target",    str(target))
    t.add_row("Semgrep",   str(summary["semgrep_findings"]) +
              (f"  ({summary['deduplicated']} deduplicated)" if summary.get("deduplicated") else ""))
    t.add_row("New",       f"[cyan]{summary['new_findings']}[/cyan]")
    t.add_row("Recurring", str(summary["recurring"]))
    if summary.get("fixed"):
        t.add_row("Fixed",  f"[green]{summary['fixed']}[/green]")

    if has_llm:
        t.add_section()
        if summary.get("cache_hits"):
            t.add_row("Cache hits",  f"[dim]{summary['cache_hits']}[/dim]")
        t.add_row("LLM analysed",    str(summary["llm_analysed"]))
        t.add_row("Confirmed",       f"[red]{summary['confirmed']}[/red]")
        t.add_row("False positives", f"[green]{summary['false_positives']}[/green]")
        t.add_row("Needs review",    f"[yellow]{summary['needs_review']}[/yellow]")

    t.add_section()
    t.add_row("CRITICAL", f"[bold red]{active_by_sev.get('CRITICAL', 0)}[/bold red]")
    t.add_row("HIGH",     f"[red]{active_by_sev.get('HIGH', 0)}[/red]")
    t.add_row("MEDIUM",   f"[yellow]{active_by_sev.get('MEDIUM', 0)}[/yellow]")
    t.add_row("LOW",      f"[dim]{active_by_sev.get('LOW', 0)}[/dim]")
    t.add_section()
    t.add_row("Elapsed",  f"{summary['elapsed_seconds']}s")
    t.add_row("DB",       str(graph_db))

    console.print()
    console.print(Panel(t, title="[bold]Scan Summary[/bold]", border_style="blue", expand=False))
    console.print(f"  [dim]Run history:[/dim]  graphsast findings {target}")


# ── CVSS helpers ───────────────────────────────────────────────────────────────

def _cvss_badge(score) -> str:
    if score is None:
        return "[dim]—[/dim]"
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "[dim]—[/dim]"
    if score >= 9.0:
        return f"[bold red]{score:.1f}[/bold red]"
    if score >= 7.0:
        return f"[red]{score:.1f}[/red]"
    if score >= 4.0:
        return f"[yellow]{score:.1f}[/yellow]"
    return f"[dim]{score:.1f}[/dim]"


# ── Findings table ─────────────────────────────────────────────────────────────

def print_findings_table(rows: list[dict], title: str = "Findings", verbose: bool = False) -> None:
    if not rows:
        console.print("[dim]  No findings.[/dim]")
        return

    t = Table(
        title=title,
        box=box.ROUNDED,
        show_lines=False,
        header_style="bold",
        expand=True,
    )
    t.add_column("Sev",     min_width=8,  no_wrap=True)
    t.add_column("CVSS",    min_width=6,  no_wrap=True, justify="right")
    t.add_column("Verdict", min_width=12, no_wrap=True)
    t.add_column("Rule",    no_wrap=True, max_width=40, ratio=3)
    t.add_column("File",    no_wrap=True, max_width=36, ratio=2)
    t.add_column("Line",    min_width=5,  no_wrap=True, justify="right")
    if verbose:
        t.add_column("Description", max_width=50)

    for r in rows:
        sev     = r.get("llm_severity") or r.get("severity", "?")
        verdict = r.get("llm_verdict") or "—"
        rule    = r.get("rule_id") or ""
        rule_short = ".".join(rule.split(".")[-2:]) if "." in rule else rule
        fp      = _short_path(r.get("file_path") or "")
        line    = str(r.get("line_start") or "")
        cvss    = _cvss_badge(r.get("llm_cvss_score"))
        row = [_sev(sev), cvss, _verdict(verdict), rule_short, fp, line]
        if verbose:
            desc = r.get("llm_description") or r.get("llm_reasoning") or ""
            row.append(desc[:200])
        t.add_row(*row)

    console.print(t)


# ── Full finding detail ─────────────────────────────────────────────────────────

_SEV_BORDER = {
    "CRITICAL": "red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "blue",
}

def print_finding_detail(r: dict, idx: int, target: Path | None = None) -> None:
    """Render one finding with all enrichment fields."""
    sev       = (r.get("llm_severity") or r.get("severity", "MEDIUM")).upper()
    verdict   = r.get("llm_verdict") or "—"
    rule      = r.get("rule_id") or "unknown"
    fp        = r.get("file_path") or ""
    line      = r.get("line_start") or ""
    title_str = r.get("title") or rule.split(".")[-1].replace("-", " ").title()

    if target:
        try:
            fp_display = Path(fp).relative_to(target).as_posix()
        except ValueError:
            fp_display = fp
    else:
        fp_display = _short_path(fp)

    # Header table
    meta = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    meta.add_column(style="bold dim", width=14)
    meta.add_column()
    meta.add_row("Rule",     f"[dim]{escape(rule)}[/dim]")
    meta.add_row("Location", f"[cyan]{escape(fp_display)}[/cyan] line {line}")
    meta.add_row("Severity", _sev(sev))
    meta.add_row("Verdict",  _verdict(verdict))

    cvss_score = r.get("llm_cvss_score")
    if cvss_score is not None:
        vec = r.get("llm_cvss_vector") or ""
        meta.add_row("CVSS", f"{_cvss_badge(cvss_score)}  [dim]{escape(vec)}[/dim]")

    cwe = r.get("cwe_id") or ""
    if cwe:
        meta.add_row("CWE", f"[dim]{escape(cwe)}[/dim]")

    border = _SEV_BORDER.get(sev, "blue")
    console.print()
    console.print(Panel(
        meta,
        title=f"[bold]{idx}. {escape(title_str)}[/bold]",
        border_style=border,
        expand=False,
    ))

    # Description
    desc = r.get("llm_description") or r.get("message") or ""
    if desc:
        console.print(f"\n[bold]Description[/bold]\n{escape(desc)}")

    # Snippet
    snippet = r.get("snippet") or ""
    if snippet:
        console.print("\n[bold]Vulnerable code[/bold]")
        # Guess language from file extension
        ext = Path(fp).suffix.lstrip(".")
        lang = {"py": "python", "js": "javascript", "ts": "typescript",
                "go": "go", "java": "java", "cs": "csharp"}.get(ext, "text")
        console.print(Syntax(snippet, lang, theme="monokai", line_numbers=False))

    # PoC
    poc = r.get("llm_poc") or ""
    if poc:
        console.print(f"\n[bold]PoC / Exploit scenario[/bold]\n[italic]{escape(poc)}[/italic]")

    # Reasoning (compact)
    reasoning = r.get("llm_reasoning") or ""
    if reasoning and reasoning != desc:
        console.print(f"\n[dim bold]Reasoning[/dim bold]\n[dim]{escape(reasoning[:300])}[/dim]")


# ── Runs table ─────────────────────────────────────────────────────────────────

def print_runs_table(runs: list[dict]) -> None:
    t = Table(
        title="Scan Runs",
        box=box.ROUNDED,
        header_style="bold",
        expand=False,
    )
    t.add_column("#",          width=5,  justify="right")
    t.add_column("Started",    width=19, no_wrap=True)
    t.add_column("Findings",   width=9,  justify="right")
    t.add_column("New",        width=6,  justify="right")
    t.add_column("Recurring",  width=10, justify="right")
    t.add_column("Confirmed",  width=10, justify="right")
    t.add_column("FP",         width=6,  justify="right")
    t.add_column("Model",      no_wrap=True)

    for r in runs:
        t.add_row(
            str(r["id"]),
            (r["started_at"] or "")[:19],
            str(r["semgrep_total"] or 0),
            f"[cyan]{r['new_findings'] or 0}[/cyan]",
            str(r["recurring"] or 0),
            f"[red]{r['confirmed'] or 0}[/red]",
            f"[green]{r['false_positives'] or 0}[/green]",
            r["model"] or "—",
        )

    console.print(t)


# ── Comparison view ────────────────────────────────────────────────────────────

def print_comparison(diff: dict, run_id: int) -> None:
    prev_id = diff["prev_run_id"]
    console.print(
        f"\n[bold]Run #{run_id}[/bold] vs [bold]Run #{prev_id or 'none'}[/bold]\n"
    )

    if diff["new"]:
        console.print(f"[cyan bold]🆕  New  ({len(diff['new'])})[/cyan bold]")
        print_findings_table(diff["new"])

    if diff["fixed"]:
        console.print(f"\n[green bold]✅  Fixed / no longer detected  ({len(diff['fixed'])})[/green bold]")
        print_findings_table(diff["fixed"])

    if diff["recurring"]:
        console.print(f"\n[yellow bold]🔁  Recurring  ({len(diff['recurring'])})[/yellow bold]")
        print_findings_table(diff["recurring"])

    if not any([diff["new"], diff["fixed"], diff["recurring"]]):
        console.print("[dim]No findings in either run.[/dim]")
