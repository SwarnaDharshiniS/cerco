"""
cerco – Python source analysis toolkit

Commands
--------
  ast    Serialize Python source to a JSON AST node tree.
  cfg    Build a control-flow graph and emit JSON.
  taint  Run taint analysis and report dangerous data flows.

Examples
--------
  python3 main.py ast --src "x = 1 + 2"
  python3 main.py ast myfile.py
  python3 main.py cfg --src "for i in range(3): print(i)"
  python3 main.py cfg myfile.py --function myFunc
  python3 main.py cfg myfile.py --function "*"
  python3 main.py taint --src "import os; os.system(input())"
  python3 main.py taint myfile.py
"""

import argparse
import json
import sys

from pathlib import Path

from parser.ast_parser import parse_file, parse_source
from cfg.cfg_builder import build_cfg
from analysis.taint import analyze_source as taint_source, analyze_to_dict as taint_dict
from analysis.capability import analyze_source as cap_source, analyze_to_dict as cap_dict
from analysis.resource import analyze_to_dict as resource_dict
from analysis.manifest import generate_manifest_from_source, manifest_to_json
from analysis.safety_ir import build_safety_ir_from_source, safety_ir_to_json


def _add_source_args(sub: argparse.ArgumentParser) -> None:
    grp = sub.add_mutually_exclusive_group(required=True)
    grp.add_argument("file", nargs="?", metavar="FILE", help="Python source file")
    grp.add_argument("--src", metavar="SOURCE", help="Python source string")
    sub.add_argument("--indent", type=int, default=2, metavar="N", help="JSON indent (default: 2)")


def cmd_ast(args: argparse.Namespace) -> None:
    try:
        tree = parse_source(args.src) if args.src else parse_file(args.file)
    except FileNotFoundError:
        sys.exit(f"error: file not found: {args.file}")
    except SyntaxError as exc:
        sys.exit(f"error: syntax error: {exc}")
    print(json.dumps(tree, indent=args.indent, ensure_ascii=False))


def cmd_cfg(args: argparse.Namespace) -> None:
    kwargs: dict = {}
    if args.src:
        kwargs["source"] = args.src
    else:
        kwargs["file"] = args.file
    if args.function:
        kwargs["function"] = args.function

    try:
        result = build_cfg(**kwargs)
    except FileNotFoundError:
        sys.exit(f"error: file not found: {args.file}")
    except SyntaxError as exc:
        sys.exit(f"error: syntax error: {exc}")
    except KeyError as exc:
        sys.exit(f"error: {exc}")

    if isinstance(result, dict):
        output = {name: cfg.to_dict() for name, cfg in result.items()}
    else:
        output = result.to_dict()

    print(json.dumps(output, indent=args.indent, ensure_ascii=False))


def cmd_taint(args: argparse.Namespace) -> None:
    try:
        if args.src:
            source = args.src
        else:
            from pathlib import Path
            source = Path(args.file).read_text(encoding="utf-8")
    except FileNotFoundError:
        sys.exit(f"error: file not found: {args.file}")

    try:
        report = taint_dict(source)
    except SyntaxError as exc:
        sys.exit(f"error: syntax error: {exc}")

    if args.json:
        print(json.dumps(report, indent=args.indent, ensure_ascii=False))
    else:
        total = report["total"]
        if total == 0:
            print("✓ No taint findings.")
            return
        print(f"Found {total} finding(s): "
              f"{report['critical']} CRITICAL, "
              f"{report['high']} HIGH, "
              f"{report['medium']} MEDIUM\n")
        for i, f in enumerate(report["findings"], 1):
            print(f"  [{i}] {f['message']}")
            for path in f["taint_paths"]:
                print("      Path:")
                for step in path:
                    if step["kind"] == "source":
                        print(f"        ← SOURCE  {step['expr']}  (line {step['line']})")
                    else:
                        print(f"        → {step['kind']:12s}  {step.get('variable','')}  (line {step['line']})")
            print()


def cmd_caps(args: argparse.Namespace) -> None:
    try:
        source = args.src if args.src else Path(args.file).read_text(encoding="utf-8")
    except FileNotFoundError:
        sys.exit(f"error: file not found: {args.file}")

    try:
        report = cap_dict(source)
    except SyntaxError as exc:
        sys.exit(f"error: syntax error: {exc}")

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return

    summary = report["summary"]
    caps = summary["capabilities"]
    if not caps:
        print("✓ No capability signals detected.")
        return

    print(f"Capabilities detected: {', '.join(caps)}")
    print(f"Highest severity: {summary['highest_severity']}  "
          f"| Total uses: {summary['total_uses']}")
    print(f"  FS={summary['FS']}  NET={summary['NET']}  "
          f"PROC={summary['PROC']}  DYN={summary['DYN']}\n")

    SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for cap, uses in report["by_capability"].items():
        print(f"  [{cap}]")
        for u in sorted(uses, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["line"] or 0)):
            alias_str = f"  (alias: {u['alias']})" if u["alias"] else ""
            line_str  = f"line {u['line']}" if u["line"] else "import"
            print(f"    {u['severity']:6s}  {u['kind']:6s}  {u['symbol']:<40s} "
                  f"{line_str}{alias_str}")
        print()


def cmd_resource(args: argparse.Namespace) -> None:
    try:
        source = args.src if args.src else Path(args.file).read_text(encoding="utf-8")
    except FileNotFoundError:
        sys.exit(f"error: file not found: {args.file}")

    try:
        report = resource_dict(source)
    except SyntaxError as exc:
        sys.exit(f"error: syntax error: {exc}")

    if args.json:
        print(json.dumps(report, indent=args.indent, ensure_ascii=False))
        return

    metrics = report["metrics"]
    print(f"Resource risk: {report['risk_score']}")
    print(
        f"Loop depth={metrics['loop_nesting_depth']}  "
        f"Recursion={metrics['recursion_present']}  "
        f"Potentially-unbounded-loops={metrics['potentially_unbounded_loops']}  "
        f"Call-depth={metrics['max_function_call_depth']}"
    )
    print(f"Complexity heuristic: {metrics['complexity_heuristic']}")

    if not report["flags"]:
        print("\n✓ No high-risk resource patterns detected.")
        return

    print("\nFlags:")
    for f in report["flags"]:
        loc = f"line {f['line']}" if f["line"] else "unknown line"
        ev = f" | evidence: {f['evidence']}" if f["evidence"] else ""
        print(f"  - [{f['kind']}] {f['message']} ({loc}){ev}")


def cmd_manifest(args: argparse.Namespace) -> None:
    try:
        source = args.src if args.src else Path(args.file).read_text(encoding="utf-8")
    except FileNotFoundError:
        sys.exit(f"error: file not found: {args.file}")

    try:
        manifest = generate_manifest_from_source(
            source,
            source_name=args.file or "<string>",
            timestamp=args.timestamp,
            analysis_version=args.analysis_version,
        )
    except SyntaxError as exc:
        sys.exit(f"error: syntax error: {exc}")

    if args.json:
        print(manifest_to_json(manifest, indent=args.indent))
        return

    print(f"Verdict: {manifest['overall_verdict']}")
    print(f"Timestamp: {manifest['timestamp']}")
    print(f"Analysis version: {manifest['analysis_version']}")
    print(f"Manifest digest: {manifest['manifest_digest']}")

    if manifest["rejection_reasons"]:
        print("Rejection reasons:")
        for reason in manifest["rejection_reasons"]:
            print(f"  - {reason}")
    else:
        print("No rejection reasons.")


def cmd_safety_ir(args: argparse.Namespace) -> None:
    try:
        source = args.src if args.src else Path(args.file).read_text(encoding="utf-8")
    except FileNotFoundError:
        sys.exit(f"error: file not found: {args.file}")

    try:
        ir = build_safety_ir_from_source(
            source,
            source_name=args.file or "<string>",
            timestamp=args.timestamp,
            analysis_version=args.analysis_version,
        )
    except SyntaxError as exc:
        sys.exit(f"error: syntax error: {exc}")

    print(safety_ir_to_json(ir, indent=args.indent))


def main() -> None:
    ap = argparse.ArgumentParser(
        description="cerco – Python source analysis toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subs = ap.add_subparsers(dest="command", required=True)

    ast_p = subs.add_parser("ast", help="Emit AST as JSON")
    _add_source_args(ast_p)

    cfg_p = subs.add_parser("cfg", help="Emit control-flow graph as JSON")
    _add_source_args(cfg_p)
    cfg_p.add_argument(
        "--function", metavar="NAME",
        help="Build CFG for a specific function (use '*' for all)",
    )

    taint_p = subs.add_parser("taint", help="Run taint analysis")
    _add_source_args(taint_p)
    taint_p.add_argument("--json", action="store_true", help="Emit JSON report")

    cap_p = subs.add_parser("caps", help="Run capability analysis")
    _add_source_args(cap_p)
    cap_p.add_argument("--json", action="store_true", help="Emit JSON report")

    resource_p = subs.add_parser("resource", help="Run static resource estimation")
    _add_source_args(resource_p)
    resource_p.add_argument("--json", action="store_true", help="Emit JSON report")

    manifest_p = subs.add_parser("manifest", help="Generate deterministic safety manifest")
    _add_source_args(manifest_p)
    manifest_p.add_argument("--json", action="store_true", help="Emit JSON manifest")
    manifest_p.add_argument(
        "--analysis-version",
        default="1.0.0",
        help="Analysis pipeline version included in manifest",
    )
    manifest_p.add_argument(
        "--timestamp",
        default=None,
        help="RFC3339 UTC timestamp (default: deterministic epoch)",
    )

    safety_ir_p = subs.add_parser("safety-ir", help="Generate compiler-inspired Safety IR")
    _add_source_args(safety_ir_p)
    safety_ir_p.add_argument(
        "--analysis-version",
        default="1.0.0",
        help="Analysis pipeline version included in IR",
    )
    safety_ir_p.add_argument(
        "--timestamp",
        default="1970-01-01T00:00:00Z",
        help="RFC3339 UTC timestamp",
    )

    args = ap.parse_args()
    {
        "ast": cmd_ast,
        "cfg": cmd_cfg,
        "taint": cmd_taint,
        "caps": cmd_caps,
        "resource": cmd_resource,
        "manifest": cmd_manifest,
        "safety-ir": cmd_safety_ir,
    }[args.command](args)


if __name__ == "__main__":
    main()
