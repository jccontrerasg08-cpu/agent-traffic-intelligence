"""Command-line interface for Agent Traffic Intelligence."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from contextlib import nullcontext
from pathlib import Path
from typing import TextIO

from agent_traffic_intelligence.engine import Detector
from agent_traffic_intelligence.parsers.jsonl import ParseError, iter_jsonl
from agent_traffic_intelligence.registry import AgentRegistry


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ati",
        description="Observe-only analysis of automated and AI-originated web traffic.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze JSONL access logs.")
    analyze.add_argument("input", help="JSONL input path, or '-' for stdin.")
    analyze.add_argument("--output", help="Write detection JSONL to this path; defaults to stdout.")
    analyze.add_argument("--source", default="jsonl", help="Source adapter label stored on events.")
    analyze.add_argument(
        "--hash-key-env",
        default="ATI_HASH_KEY",
        help="Environment variable containing the client pseudonymization key.",
    )

    explain = subparsers.add_parser("explain", help="Pretty-print one detection and its evidence.")
    explain.add_argument("input", help="Detection JSONL file.")
    explain.add_argument("--request-id", required=True, help="Request identifier to explain.")

    registry = subparsers.add_parser("registry", help="Inspect the curated agent registry.")
    registry_sub = registry.add_subparsers(dest="registry_command", required=True)
    registry_sub.add_parser("validate", help="Validate the packaged registry.")

    return parser


def _open_input(path: str) -> tuple[TextIO, bool]:
    if path == "-":
        return sys.stdin, False
    return Path(path).open("r", encoding="utf-8"), True


def _analyze(args: argparse.Namespace) -> int:
    key_text = os.environ.get(args.hash_key_env)
    hash_key = key_text.encode("utf-8") if key_text else None
    detector = Detector()
    processed = 0

    input_stream, should_close_input = _open_input(args.input)
    output_context = (
        Path(args.output).open("w", encoding="utf-8")
        if args.output
        else nullcontext(sys.stdout)
    )

    try:
        with output_context as output_stream:
            try:
                for event in iter_jsonl(input_stream, hash_key=hash_key, source=args.source):
                    detection = detector.detect(event)
                    output_stream.write(
                        json.dumps(detection.to_dict(), separators=(",", ":"), sort_keys=True)
                        + "\n"
                    )
                    processed += 1
            except ParseError as exc:
                print(
                    f"error: {exc}. If the input contains raw client IPs, set {args.hash_key_env}.",
                    file=sys.stderr,
                )
                return 2
    finally:
        if should_close_input:
            input_stream.close()

    print(f"processed={processed}", file=sys.stderr)
    return 0


def _explain(args: argparse.Namespace) -> int:
    path = Path(args.input)
    try:
        with path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    print(f"error: invalid JSON on line {line_number}", file=sys.stderr)
                    return 2
                if payload.get("request_id") == args.request_id:
                    print(json.dumps(payload, indent=2, sort_keys=True))
                    return 0
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"error: request_id not found: {args.request_id}", file=sys.stderr)
    return 1


def _registry_validate() -> int:
    try:
        registry = AgentRegistry.default()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"invalid registry: {exc}", file=sys.stderr)
        return 2

    providers = sorted({entry.provider for entry in registry.entries})
    print(f"valid entries={len(registry.entries)} providers={','.join(providers)}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns a process-compatible status code."""

    args = _parser().parse_args(argv)
    if args.command == "analyze":
        return _analyze(args)
    if args.command == "explain":
        return _explain(args)
    if args.command == "registry" and args.registry_command == "validate":
        return _registry_validate()
    raise RuntimeError("unreachable command dispatch")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
