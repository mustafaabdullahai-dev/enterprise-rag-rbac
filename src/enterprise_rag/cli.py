"""Command-line interface: seed, ingest, ask, evaluate, audit, serve.

Everything the HTTP API can do is available here, which is what makes the
security properties easy to demonstrate without a browser:

    enterprise-rag seed
    enterprise-rag ingest --reset
    enterprise-rag ask "What is our leave policy?" --user amina.yusuf --password intern-demo
    enterprise-rag ask "Salary bands?" --user amina.yusuf --password intern-demo   # refused
    enterprise-rag eval --suite both
    enterprise-rag audit verify
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from enterprise_rag import __version__
from enterprise_rag.config import get_settings
from enterprise_rag.security.identity import DEMO_PASSWORDS

console = Console()

ROLE_STYLES = {
    "answer": "bold green",
    "refuse": "bold yellow",
    "blocked": "bold red",
    "insufficient_evidence": "bold cyan",
}


def _settings():
    return get_settings()


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_seed(args: argparse.Namespace) -> int:
    from enterprise_rag.demo_corpus import build_corpus

    root = Path(args.root) if args.root else _settings().corpus_path
    written = build_corpus(root, force=args.force)
    console.print(f"[green]Wrote {len(written)} file(s) to {root}[/green]")
    for path in written:
        console.print(f"  - {path.relative_to(root)}")
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    from enterprise_rag.context import AppContext

    context = AppContext.build()
    report = context.pipeline.run(reset=args.reset, dry_run=args.dry_run)
    table = Table(title="Ingestion report")
    table.add_column("Document")
    table.add_column("Classification")
    table.add_column("Chunks")
    table.add_column("By")
    table.add_column("Notes")
    for document in report.documents:
        style = "red" if document.escalated else ""
        classification = (
            f"[{style}]{document.classification}[/{style}]" if style else document.classification
        )
        table.add_row(
            document.doc_id,
            classification,
            str(document.chunks),
            document.classification_source,
            "; ".join(document.findings[:2])[:70],
        )
    console.print(table)
    console.print(
        f"[bold]{len(report.documents)} documents, {report.total_chunks} chunks, "
        f"{len(report.errors)} errors[/bold]"
    )
    for error in report.errors:
        console.print(f"[red]error:[/red] {error['path']}: {error['error']}")
    return 1 if report.errors else 0


def cmd_ask(args: argparse.Namespace) -> int:
    from enterprise_rag.context import AppContext
    from enterprise_rag.security.auth import AuthError

    context = AppContext.build()
    context.ensure_ready()
    try:
        user, _token = context.authenticate(args.user, args.password)
    except AuthError as exc:
        console.print(f"[red]Authentication failed:[/red] {exc.message}")
        return 2

    result = context.graph.run(user, args.question)
    style = ROLE_STYLES.get(result.action, "white")
    console.print(
        f"[dim]{user.display_name} - {user.department.value} "
        f"(clearance {user.clearance}; roles: {', '.join(sorted(user.role_names))})[/dim]"
    )
    console.rule()
    console.print(f"[{style}]{result.answer}[/{style}]")

    if result.documents:
        console.print("\n[bold]Sources[/bold]")
        for document in result.documents:
            console.print(
                f"  [cyan]{document['citation']}[/cyan] {document['doc_title']} "
                f"({document['classification']}, score {document['score']})"
            )
    if result.citations:
        verified = sum(1 for c in result.citations if c["verified"])
        console.print(f"\nCitations verified: {verified}/{len(result.citations)}")
    if result.withheld_count:
        console.print(
            f"[yellow]{result.withheld_count} document(s) withheld by the ACL for this "
            "principal.[/yellow]"
        )
        if args.verbose:
            for withheld in result.withheld:
                console.print(f"  - {withheld['doc_id']} [{withheld['rule']}] {withheld['reason']}")

    console.print(
        f"\n[dim]action={result.action} reason={result.reason_code} "
        f"risk={result.guardrails.get('risk_score')} latency={result.latency_ms:.0f}ms[/dim]"
    )
    if args.trace:
        console.print("\n[bold]Pipeline trace[/bold]")
        for step in result.trace:
            console.print(
                f"  {step['node']:<18} {step['ms']:>7.1f} ms  {json.dumps(step['detail'])}"
            )
    return 0 if result.action == "answer" else 1


def cmd_eval(args: argparse.Namespace) -> int:
    from enterprise_rag.context import AppContext
    from enterprise_rag.evaluation.rag_eval import run_quality, save_report
    from enterprise_rag.evaluation.red_team import run_red_team

    context = AppContext.build()
    context.ensure_ready()

    report = run_quality(context, engine=args.engine) if args.suite in {"quality", "both"} else None
    security = run_red_team(context) if args.suite in {"security", "both"} else None

    if report is not None:
        console.rule(f"RAG quality ({report.engine})")
        if not report.ok:
            console.print(f"[red]{report.error}[/red]")
        else:
            table = Table(show_header=True)
            table.add_column("Metric")
            table.add_column("Score", justify="right")
            for name, value in sorted(report.metrics.items()):
                table.add_row(name, f"{value:.3f}")
            console.print(table)

    if security is not None:
        console.rule("Red team")
        table = Table(show_header=True)
        table.add_column("Probe")
        table.add_column("User")
        table.add_column("Expected")
        table.add_column("Actual")
        table.add_column("Result")
        for probe in security.results:
            table.add_row(
                f"{probe.case_id} {probe.probe}",
                probe.username,
                probe.expected,
                probe.actual,
                "[green]PASS[/green]" if probe.passed else "[red]FAIL[/red]",
            )
        console.print(table)
        console.print(
            f"[bold]{security.passed}/{len(security.results)} passed, "
            f"{security.leaks} leak(s)[/bold]"
        )

    saved = save_report(report, security, context.settings)
    if saved:
        console.print(f"\nReport written to [cyan]{saved}[/cyan]")
    return 1 if (security and not security.ok) else 0


def cmd_audit(args: argparse.Namespace) -> int:
    from enterprise_rag.context import AppContext

    context = AppContext.build()
    if args.audit_command == "verify":
        ok, message, records = context.audit.verify()
        colour = "green" if ok else "red"
        console.print(f"[{colour}]{message}[/{colour}] ({records} records checked)")
        return 0 if ok else 1

    events = context.audit.read(limit=args.limit, severity=args.severity, actor=args.actor)
    table = Table(title="Audit trail")
    table.add_column("When")
    table.add_column("Actor")
    table.add_column("Action")
    table.add_column("Outcome")
    table.add_column("Severity")
    for event in events:
        severity_style = {"info": "dim", "warning": "yellow", "critical": "red"}[event.severity]
        table.add_row(
            event.ts[:19],
            event.actor,
            event.action,
            event.outcome,
            f"[{severity_style}]{event.severity}[/{severity_style}]",
        )
    console.print(table)
    return 0


def cmd_users(args: argparse.Namespace) -> int:
    from enterprise_rag.context import AppContext

    context = AppContext.build()
    context.ensure_ready()
    table = Table(title="Directory")
    table.add_column("Username")
    table.add_column("Name")
    table.add_column("Department")
    table.add_column("Clearance")
    table.add_column("Roles")
    table.add_column("Visible docs")
    for user in context.user_store.list():
        table.add_row(
            user.username,
            user.display_name,
            user.department.value,
            str(user.clearance),
            ", ".join(sorted(user.role_names)),
            str(len(context.authorizer.visible_doc_ids(user, context.catalog.acls()))),
        )
    console.print(table)
    if args.passwords:
        console.print("\n[bold]Demo passwords[/bold]")
        for username, password in DEMO_PASSWORDS.items():
            console.print(f"  {username:<16} {password}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    settings = _settings()
    console.print(f"[green]Starting {settings.app_name} on http://{args.host}:{args.port}[/green]")
    uvicorn.run(
        "enterprise_rag.api.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=settings.log_level.lower(),
    )
    return 0


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="enterprise-rag",
        description="Enterprise RAG with role-based access control and guardrails.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    seed = sub.add_parser("seed", help="generate the synthetic demo corpus")
    seed.add_argument("--root", default=None, help="target directory")
    seed.add_argument("--force", action="store_true", help="overwrite existing files")
    seed.set_defaults(func=cmd_seed)

    ingest = sub.add_parser("ingest", help="load the corpus into the vector store")
    ingest.add_argument("--reset", action="store_true", help="drop the index first")
    ingest.add_argument("--dry-run", action="store_true", help="classify without indexing")
    ingest.set_defaults(func=cmd_ingest)

    ask = sub.add_parser("ask", help="ask a question as a given user")
    ask.add_argument("question")
    ask.add_argument("--user", required=True, help="username")
    ask.add_argument("--password", default=None, help="password (demo passwords in README)")
    ask.add_argument("--trace", action="store_true", help="print the pipeline trace")
    ask.add_argument("--verbose", "-v", action="store_true", help="list withheld documents")
    ask.set_defaults(func=cmd_ask)

    evaluate = sub.add_parser("eval", help="run quality and/or red-team evaluation")
    evaluate.add_argument("--suite", choices=["quality", "security", "both"], default="both")
    evaluate.add_argument(
        "--engine",
        choices=["auto", "offline", "ragas"],
        default="auto",
        help="auto uses Ragas when configured, otherwise offline metrics",
    )
    evaluate.set_defaults(func=cmd_eval)

    audit = sub.add_parser("audit", help="inspect or verify the audit trail")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    audit_tail = audit_sub.add_parser("tail", help="show the most recent events")
    audit_tail.add_argument("--limit", type=int, default=20)
    audit_tail.add_argument("--severity", choices=["info", "warning", "critical"], default=None)
    audit_tail.add_argument("--actor", default=None)
    audit_verify = audit_sub.add_parser("verify", help="verify the hash chain")
    audit_verify.set_defaults(limit=0)
    audit.set_defaults(func=cmd_audit)

    users = sub.add_parser("users", help="list the directory and visible documents")
    users.add_argument("--passwords", action="store_true", help="also print demo passwords")
    users.set_defaults(func=cmd_users)

    serve = sub.add_parser("serve", help="run the HTTP API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--reload", action="store_true")
    serve.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint (console script: ``enterprise-rag``)."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "password", None) is None and getattr(args, "func", None) is cmd_ask:
        console.print("[red]--password is required[/red]")
        return 2
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
