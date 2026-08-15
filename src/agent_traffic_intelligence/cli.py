"""Command-line interface for Agent Traffic Intelligence."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import TextIO

from agent_traffic_intelligence.engine import Detector
from agent_traffic_intelligence.evaluation import EvaluationError, evaluate_automation_scores
from agent_traffic_intelligence.features.session import SessionFeatureState
from agent_traffic_intelligence.identity.configured import ProviderAwareVerificationManager
from agent_traffic_intelligence.identity.policy import VerificationMode
from agent_traffic_intelligence.identity.source_service import (
    refresh_sources,
    source_status,
    validate_sources,
)
from agent_traffic_intelligence.identity.sources.cache import SourceCache
from agent_traffic_intelligence.identity.sources.fetcher import (
    FetchProtocolError,
    FetchSecurityError,
)
from agent_traffic_intelligence.parsers.jsonl import (
    ParseError,
    iter_jsonl,
    iter_jsonl_with_context,
)
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
        "--max-line-characters",
        type=_positive_integer,
        default=1_000_000,
        help="Reject JSONL records longer than this many characters (default: 1000000).",
    )
    analyze.add_argument(
        "--max-clients",
        type=_positive_integer,
        default=10_000,
        help="Retain at most this many active client sessions with LRU eviction (default: 10000).",
    )
    analyze.add_argument(
        "--max-events-per-client",
        type=_positive_integer,
        default=128,
        help="Retain at most this many events per active client session (default: 128).",
    )
    analyze.add_argument(
        "--session-window-seconds",
        type=_positive_integer,
        default=300,
        help="Discard session events older than this window in seconds (default: 300).",
    )
    analyze.add_argument(
        "--hash-key-env",
        default="ATI_HASH_KEY",
        help="Environment variable containing the client pseudonymization key.",
    )
    analyze.add_argument(
        "--verify-identity",
        action="store_true",
        help="Enable V1 identity verification. Sources remain offline unless explicitly refreshed.",
    )
    analyze.add_argument(
        "--verification-mode",
        choices=[item.value for item in VerificationMode],
        default=VerificationMode.OFFLINE.value,
        help="Identity verification mode; defaults to offline.",
    )

    explain = subparsers.add_parser("explain", help="Pretty-print one detection and its evidence.")
    explain.add_argument("input", help="Detection JSONL file.")
    explain.add_argument("--request-id", required=True, help="Request identifier to explain.")

    evaluate = subparsers.add_parser(
        "evaluate",
        help="Evaluate automation scores against an authorized local label corpus.",
    )
    evaluate.add_argument("input", help="Detection JSONL file.")
    evaluate.add_argument(
        "--labels",
        required=True,
        help="JSONL labels with request_id and automated.",
    )
    evaluate.add_argument(
        "--threshold",
        type=_unit_interval,
        default=0.5,
        help="Automation decision threshold from 0 to 1 (default: 0.5).",
    )

    registry = subparsers.add_parser("registry", help="Inspect the curated agent registry.")
    registry_sub = registry.add_subparsers(dest="registry_command", required=True)
    registry_sub.add_parser("validate", help="Validate the packaged registry.")

    sources = subparsers.add_parser("sources", help="Inspect or refresh trusted identity sources.")
    sources_sub = sources.add_subparsers(dest="sources_command", required=True)
    sources_sub.add_parser("status", help="Show cache state for configured official sources.")
    refresh = sources_sub.add_parser(
        "refresh",
        help="Fetch configured official sources over HTTPS.",
    )
    refresh.add_argument("--provider", help="Refresh only one configured provider.")
    sources_sub.add_parser("validate", help="Validate all cached source documents offline.")

    return parser


def _unit_interval(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not 0.0 <= parsed <= 1.0:
        raise argparse.ArgumentTypeError("must be between 0 and 1")
    return parsed


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def _open_input(path: str) -> tuple[TextIO, bool]:
    if path == "-":
        return sys.stdin, False
    return Path(path).open("r", encoding="utf-8"), True


@contextmanager
def _atomic_output(path: Path) -> Iterator[TextIO]:
    """Write to a sibling temporary file and replace the destination on success."""

    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            yield stream
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _source_cache_path() -> Path:
    configured = os.environ.get("ATI_SOURCE_CACHE")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".cache" / "agent-traffic-intelligence" / "identity-sources"


def _source_cache() -> SourceCache:
    return SourceCache(_source_cache_path())


def _analyze(args: argparse.Namespace) -> int:
    key_text = os.environ.get(args.hash_key_env)
    hash_key = key_text.encode("utf-8") if key_text else None
    if hash_key is not None and len(hash_key) > 64:
        print(
            f"error: {args.hash_key_env} exceeds the 64-byte BLAKE2b key limit.",
            file=sys.stderr,
        )
        return 2
    mode = VerificationMode(args.verification_mode)
    session_state = SessionFeatureState(
        max_clients=args.max_clients,
        max_events_per_client=args.max_events_per_client,
        window_seconds=args.session_window_seconds,
    )
    verification_manager = (
        ProviderAwareVerificationManager(_source_cache(), mode=mode)
        if args.verify_identity
        else None
    )
    detector = Detector(
        session_state=session_state,
        verification_manager=verification_manager,
    )
    processed = 0

    try:
        input_stream, should_close_input = _open_input(args.input)
        with ExitStack() as stack:
            if should_close_input:
                stack.callback(input_stream.close)
            output_stream = (
                stack.enter_context(_atomic_output(Path(args.output)))
                if args.output
                else sys.stdout
            )
            if args.verify_identity:
                for event, context in iter_jsonl_with_context(
                    input_stream,
                    hash_key=hash_key,
                    source=args.source,
                    max_line_characters=args.max_line_characters,
                ):
                    detection = detector.detect(event, verification_context=context)
                    output_stream.write(_json_line(detection.to_dict()))
                    processed += 1
            else:
                for event in iter_jsonl(
                    input_stream,
                    hash_key=hash_key,
                    source=args.source,
                    max_line_characters=args.max_line_characters,
                ):
                    detection = detector.detect(event)
                    output_stream.write(_json_line(detection.to_dict()))
                    processed += 1
    except ParseError as exc:
        hint = (
            f" If the input contains raw client IPs, set {args.hash_key_env}."
            if "hash key" in str(exc)
            else ""
        )
        print(f"error: {exc}.{hint}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    metrics = detector.session_resource_metrics()
    print(
        "processed={processed} active_clients={active_client_count} "
        "evicted_clients={evicted_client_count} max_clients={max_client_count}".format(
            processed=processed,
            **metrics,
        ),
        file=sys.stderr,
    )
    return 0


def _json_line(payload: dict[str, object]) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n"


def _iter_json_objects(path: Path, *, kind: str) -> Iterator[dict[str, object]]:
    try:
        with path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise EvaluationError(
                        f"{kind} JSONL has invalid JSON on line {line_number}"
                    ) from exc
                if not isinstance(payload, dict):
                    raise EvaluationError(
                        f"{kind} JSONL expects an object on line {line_number}"
                    )
                yield payload
    except OSError as exc:
        raise EvaluationError(f"cannot read {kind} JSONL: {exc}") from exc


def _load_automation_labels(path: Path) -> dict[str, bool]:
    labels: dict[str, bool] = {}
    for payload in _iter_json_objects(path, kind="label"):
        request_id = payload.get("request_id")
        automated = payload.get("automated")
        if not isinstance(request_id, str) or not request_id:
            raise EvaluationError("label request_id must be a non-empty string")
        if not isinstance(automated, bool):
            raise EvaluationError("label automated must be a boolean")
        if request_id in labels:
            raise EvaluationError(f"duplicate label request_id: {request_id}")
        labels[request_id] = automated
    return labels


def _evaluate(args: argparse.Namespace) -> int:
    try:
        labels = _load_automation_labels(Path(args.labels))
        result = evaluate_automation_scores(
            _iter_json_objects(Path(args.input), kind="detection"),
            labels,
            threshold=args.threshold,
        )
    except EvaluationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
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
                if not isinstance(payload, dict):
                    print(f"error: expected object on line {line_number}", file=sys.stderr)
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


def _sources_status() -> int:
    rows = source_status(_source_cache())
    print(json.dumps(rows, indent=2, sort_keys=True))
    return 0


def _sources_validate() -> int:
    errors = validate_sources(_source_cache())
    if errors:
        for error in errors:
            print(f"invalid source: {error}", file=sys.stderr)
        return 2
    print("valid cached sources")
    return 0


def _sources_refresh(provider: str | None) -> int:
    try:
        refreshed, not_modified = refresh_sources(_source_cache(), provider=provider)
    except (FetchProtocolError, FetchSecurityError, OSError, ValueError) as exc:
        print(f"source refresh failed: {exc}", file=sys.stderr)
        return 2
    print(f"refreshed={refreshed} not_modified={not_modified}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns a process-compatible status code."""

    args = _parser().parse_args(argv)
    if args.command == "analyze":
        return _analyze(args)
    if args.command == "explain":
        return _explain(args)
    if args.command == "evaluate":
        return _evaluate(args)
    if args.command == "registry" and args.registry_command == "validate":
        return _registry_validate()
    if args.command == "sources" and args.sources_command == "status":
        return _sources_status()
    if args.command == "sources" and args.sources_command == "validate":
        return _sources_validate()
    if args.command == "sources" and args.sources_command == "refresh":
        return _sources_refresh(args.provider)
    raise RuntimeError("unreachable command dispatch")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
