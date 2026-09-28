"""Command-line interface for Agent Traffic Intelligence."""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import sys
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from agent_traffic_intelligence import __version__
from agent_traffic_intelligence.engine import Detector
from agent_traffic_intelligence.evaluation import (
    EvaluationError,
    evaluate_automation_scores,
    evaluate_stratified_automation_scores,
    validate_corpus_manifest,
)
from agent_traffic_intelligence.evaluation.campaign import (
    build_navigation_campaign_plan,
    validate_campaign_runtime,
)
from agent_traffic_intelligence.evaluation.pf2.baseline import (
    PF2BaselineError,
    evaluate_pf2_baseline,
)
from agent_traffic_intelligence.evaluation.pf2.export import (
    PF2ExportError,
    bigquery_ddl,
    build_bigquery_export,
)
from agent_traffic_intelligence.evaluation.pf2.protocol import (
    PF2ProtocolError,
    prepare_pf2_dataset,
)
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
from agent_traffic_intelligence.identity.standards_health import (
    DatatrackerJsonClient,
    DatatrackerPayloadError,
    StandardsHealthOperationalError,
    StandardsHealthReport,
    UrllibDatatrackerTransport,
    check_pinned_drafts,
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
    _add_analysis_arguments(analyze)
    analyze.add_argument("--output", help="Write detection JSONL to this path; defaults to stdout.")

    run = subparsers.add_parser(
        "run",
        help="Create one local, atomic analysis and evaluation artifact directory.",
    )
    _add_analysis_arguments(run)
    run.add_argument("--run-dir", required=True, help="New local directory for safe outputs.")
    run.add_argument("--labels", required=True, help="Authorized local JSONL labels.")
    run.add_argument("--manifest", required=True, help="Authorized local corpus manifest.")
    run.add_argument(
        "--threshold",
        type=_unit_interval,
        default=0.5,
        help="Automation decision threshold from 0 to 1 (default: 0.5).",
    )

    explain = subparsers.add_parser("explain", help="Pretty-print one detection and its evidence.")
    explain.add_argument("input", help="Detection JSONL file.")
    explain.add_argument("--request-id", required=True, help="Request identifier to explain.")
    explain.add_argument(
        "--max-line-characters",
        type=_positive_integer,
        default=1_000_000,
        help="Reject JSONL records longer than this many characters (default: 1000000).",
    )

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
        "--manifest",
        help=(
            "Single-object JSON corpus manifest. When supplied, labels must contain only "
            "request_id, automated, label_source, label_confidence, and matching corpus_id."
        ),
    )
    evaluate.add_argument(
        "--threshold",
        type=_unit_interval,
        default=0.5,
        help="Automation decision threshold from 0 to 1 (default: 0.5).",
    )
    evaluate.add_argument(
        "--max-line-characters",
        type=_positive_integer,
        default=1_000_000,
        help="Reject JSONL records longer than this many characters (default: 1000000).",
    )

    evaluate_stratified = subparsers.add_parser(
        "evaluate-stratified",
        help="Evaluate grouped, temporal, family and provider/UA holdout strata.",
    )
    evaluate_stratified.add_argument("input", help="Detection JSONL file.")
    evaluate_stratified.add_argument(
        "--labels", required=True, help="Authorized local JSONL labels."
    )
    evaluate_stratified.add_argument(
        "--metadata",
        required=True,
        help="Local JSONL with opaque session, declared family/provider/UA bucket and time.",
    )
    evaluate_stratified.add_argument(
        "--manifest", required=True, help="Authorized local corpus manifest."
    )
    evaluate_stratified.add_argument("--output", required=True, help="Local JSON aggregate result.")
    evaluate_stratified.add_argument(
        "--threshold",
        type=_unit_interval,
        default=0.5,
        help="Automation decision threshold from 0 to 1 (default: 0.5).",
    )
    evaluate_stratified.add_argument(
        "--max-line-characters",
        type=_positive_integer,
        default=1_000_000,
        help="Reject JSONL records longer than this many characters (default: 1000000).",
    )

    pf2_preflight = subparsers.add_parser(
        "pf2-preflight",
        help="Prepare privacy-first ATI-PF-2 session features for a local baseline.",
    )
    pf2_preflight.add_argument("input", help="Authorized local ATI-PF-2 access-log JSONL.")
    pf2_preflight.add_argument(
        "--labels-by-session",
        required=True,
        help="Local JSON object mapping opaque session IDs to boolean targets.",
    )
    pf2_preflight.add_argument(
        "--tasks-by-session",
        required=True,
        help="Local JSON object mapping opaque session IDs to audit-only task names.",
    )
    pf2_preflight.add_argument(
        "--collection-windows-by-session",
        help="Optional local JSON object mapping opaque session IDs to audit-only windows.",
    )
    pf2_preflight.add_argument(
        "--model-output",
        required=True,
        help="New JSONL path for target plus allowed model features only.",
    )
    pf2_preflight.add_argument(
        "--split-output",
        required=True,
        help="New JSONL path for separate local session/task split metadata.",
    )
    pf2_preflight.add_argument(
        "--preflight-output",
        required=True,
        help="New JSON path for aggregate readiness checks.",
    )
    pf2_preflight.add_argument(
        "--min-sessions-per-task-class",
        type=_positive_integer,
        default=8,
        help="Required complete sessions per task and class (default: 8).",
    )
    pf2_preflight.add_argument(
        "--max-line-characters",
        type=_positive_integer,
        default=1_000_000,
        help="Reject JSONL records longer than this many characters (default: 1000000).",
    )

    pf2_baseline = subparsers.add_parser(
        "pf2-baseline",
        help="Run the ATI-PF-2 constant-prevalence and regularized-logistic baseline ladder.",
    )
    pf2_baseline.add_argument("model", help="Local ATI-PF-2 preflight model-table JSONL.")
    pf2_baseline.add_argument(
        "--split-manifest",
        required=True,
        help="Local ATI-PF-2 preflight split JSONL; used only to build partitions.",
    )
    pf2_baseline.add_argument(
        "--output",
        required=True,
        help="New JSON path for the ladder report, firewall assertions and verdict.",
    )
    pf2_baseline.add_argument(
        "--l2",
        type=_positive_float,
        default=1.0,
        help="L2 penalty strength for the logistic baseline (default: 1.0).",
    )
    pf2_baseline.add_argument(
        "--target-false-positive-rate",
        type=_unit_interval,
        help="Predeclared operating point; the threshold is chosen on the train partition.",
    )
    pf2_baseline.add_argument(
        "--resamples",
        type=_positive_integer,
        default=1000,
        help="Session-cluster bootstrap resamples per reported metric (default: 1000).",
    )
    pf2_baseline.add_argument(
        "--grouped-holdout-fraction",
        type=_open_unit_interval,
        default=0.25,
        help="Share of opaque sessions held out by the grouped split (default: 0.25).",
    )
    pf2_baseline.add_argument(
        "--seed",
        type=int,
        default=0,
        help="Deterministic seed for the grouped split and resampling (default: 0).",
    )
    pf2_baseline.add_argument(
        "--max-line-characters",
        type=_positive_integer,
        default=1_000_000,
        help="Reject JSONL records longer than this many characters (default: 1000000).",
    )

    pf2_export = subparsers.add_parser(
        "pf2-export-bigquery",
        help="Write privacy-safe aggregate warehouse tables from one PF-2 baseline run.",
    )
    pf2_export.add_argument("model", help="Local ATI-PF-2 preflight model-table JSONL.")
    pf2_export.add_argument(
        "--report", required=True, help="Local ATI-PF-2 baseline report JSON."
    )
    pf2_export.add_argument(
        "--output-dir", required=True, help="New local directory for export artifacts."
    )
    pf2_export.add_argument("--run-id", required=True, help="Non-sensitive run identifier.")
    pf2_export.add_argument(
        "--corpus-id", required=True, help="Approved non-sensitive corpus identifier."
    )
    pf2_export.add_argument(
        "--dataset", required=True, help="Target BigQuery dataset name for the DDL."
    )
    pf2_export.add_argument("--project", help="Optional BigQuery project for the DDL.")
    pf2_export.add_argument(
        "--exported-at",
        help="Optional ISO 8601 export timestamp; defaults to the current UTC time.",
    )
    pf2_export.add_argument(
        "--max-line-characters",
        type=_positive_integer,
        default=1_000_000,
        help="Reject JSONL records longer than this many characters (default: 1000000).",
    )

    campaign = subparsers.add_parser(
        "campaign",
        help="Create privacy-safe ground-truth labels from controlled traffic.",
    )
    campaign_sub = campaign.add_subparsers(dest="campaign_command", required=True)
    campaign_labels = campaign_sub.add_parser(
        "labels",
        help="Generate labels for records carrying one allowlisted campaign marker.",
    )
    campaign_labels.add_argument("input", help="JSONL access-log path.")
    campaign_labels.add_argument(
        "--campaign-id",
        required=True,
        help="Opaque value expected only in the ati_campaign_id log field.",
    )
    campaign_labels.add_argument(
        "--corpus-id",
        required=True,
        help="Authorized corpus identifier written to generated labels.",
    )
    campaign_labels.add_argument("--output", required=True, help="Write labels JSONL to this path.")
    campaign_labels.add_argument(
        "--source", default="jsonl", help="Source adapter label used to derive request IDs."
    )
    campaign_labels.add_argument(
        "--max-line-characters",
        type=_positive_integer,
        default=1_000_000,
        help="Reject JSONL records longer than this many characters (default: 1000000).",
    )
    campaign_labels.add_argument(
        "--hash-key-env",
        default="ATI_HASH_KEY",
        help="Environment variable containing the client pseudonymization key.",
    )
    campaign_plan = campaign_sub.add_parser(
        "plan",
        help="Write a privacy-safe navigation campaign plan without secrets.",
    )
    campaign_plan.add_argument("--campaign-id", required=True, help="Opaque allowlisted marker.")
    campaign_plan.add_argument(
        "--corpus-id", required=True, help="Authorized local corpus identifier."
    )
    campaign_plan.add_argument(
        "--family",
        action="append",
        required=True,
        help="Runtime family as name=expected-user-agent-token; repeat for each family.",
    )
    campaign_plan.add_argument(
        "--sessions-per-family",
        type=_positive_integer,
        required=True,
        help="Planned independent sessions for each runtime family.",
    )
    campaign_plan.add_argument("--output", required=True, help="New local JSON plan path.")
    runtime_validate = campaign_sub.add_parser(
        "runtime-validate",
        help="Summarize declared campaign runtime compatibility from privacy-safe JSONL.",
    )
    runtime_validate.add_argument("input", help="Privacy-safe access-log JSONL path.")
    runtime_validate.add_argument("--campaign-id", required=True, help="Opaque campaign marker.")
    runtime_validate.add_argument(
        "--expected-ua-token",
        required=True,
        help="Expected non-sensitive User-Agent token for this declared runtime.",
    )
    runtime_validate.add_argument("--output", required=True, help="Local JSON summary path.")
    runtime_validate.add_argument(
        "--max-line-characters",
        type=_positive_integer,
        default=1_000_000,
        help="Reject JSONL records longer than this many characters (default: 1000000).",
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

    standards = subparsers.add_parser(
        "standards",
        help="Inspect pinned standards and draft health.",
    )
    standards_sub = standards.add_subparsers(dest="standards_command", required=True)
    standards_sub.add_parser(
        "health",
        help="Check pinned Internet-Draft revisions directly against Datatracker.",
    )

    return parser


def _add_analysis_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("input", help="JSONL input path, or '-' for stdin.")
    parser.add_argument("--source", default="jsonl", help="Source adapter label stored on events.")
    parser.add_argument(
        "--max-line-characters",
        type=_positive_integer,
        default=1_000_000,
        help="Reject JSONL records longer than this many characters (default: 1000000).",
    )
    parser.add_argument(
        "--max-clients",
        type=_positive_integer,
        default=10_000,
        help="Retain at most this many active client sessions with LRU eviction (default: 10000).",
    )
    parser.add_argument(
        "--max-events-per-client",
        type=_positive_integer,
        default=128,
        help="Retain at most this many events per active client session (default: 128).",
    )
    parser.add_argument(
        "--session-window-seconds",
        type=_positive_integer,
        default=300,
        help="Discard session events older than this window in seconds (default: 300).",
    )
    parser.add_argument(
        "--hash-key-env",
        default="ATI_HASH_KEY",
        help="Environment variable containing the client pseudonymization key.",
    )
    parser.add_argument(
        "--verify-identity",
        action="store_true",
        help="Enable V1 identity verification. Sources remain offline unless explicitly refreshed.",
    )
    parser.add_argument(
        "--verification-mode",
        choices=[item.value for item in VerificationMode],
        default=VerificationMode.OFFLINE.value,
        help="Identity verification mode; defaults to offline.",
    )


def _unit_interval(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not 0.0 <= parsed <= 1.0:
        raise argparse.ArgumentTypeError("must be between 0 and 1")
    return parsed


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not parsed > 0.0 or not math.isfinite(parsed):
        raise argparse.ArgumentTypeError("must be a positive finite number")
    return parsed


def _open_unit_interval(value: str) -> float:
    parsed = _unit_interval(value)
    if parsed in {0.0, 1.0}:
        raise argparse.ArgumentTypeError("must be strictly between 0 and 1")
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


def _analysis_hash_key(args: argparse.Namespace) -> bytes | None:
    key_text = os.environ.get(args.hash_key_env)
    hash_key = key_text.encode("utf-8") if key_text else None
    if hash_key is not None and len(hash_key) > 64:
        raise ValueError(f"{args.hash_key_env} exceeds the 64-byte BLAKE2b key limit")
    return hash_key


def _analyze(args: argparse.Namespace) -> int:
    try:
        hash_key = _analysis_hash_key(args)
    except ValueError as exc:
        print(f"error: {exc}.", file=sys.stderr)
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


def _campaign_labels(args: argparse.Namespace) -> int:
    try:
        hash_key = _analysis_hash_key(args)
        records = _iter_json_objects(
            Path(args.input),
            kind="access-log",
            max_line_characters=args.max_line_characters,
        )
        with Path(args.input).open("r", encoding="utf-8") as stream:
            events = iter_jsonl(
                stream,
                hash_key=hash_key,
                source=args.source,
                max_line_characters=args.max_line_characters,
            )
            generated = 0
            with _atomic_output(Path(args.output)) as output_stream:
                for record, event in zip(records, events, strict=True):
                    if record.get("ati_campaign_id") != args.campaign_id:
                        continue
                    output_stream.write(
                        _json_line(
                            {
                                "request_id": event.request_id,
                                "automated": True,
                                "label_source": "controlled-campaign",
                                "label_confidence": 1.0,
                                "corpus_id": args.corpus_id,
                            }
                        )
                    )
                    generated += 1
    except (EvaluationError, OSError, ParseError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"generated_label_count={generated}", file=sys.stderr)
    return 0


def _campaign_families(values: Sequence[str]) -> dict[str, str]:
    families: dict[str, str] = {}
    for value in values:
        name, separator, ua_token = value.partition("=")
        if not separator or not name.strip() or not ua_token.strip():
            raise EvaluationError("family must use name=expected-user-agent-token")
        if name in families:
            raise EvaluationError(f"duplicate runtime family: {name}")
        families[name] = ua_token
    return families


def _campaign_plan(args: argparse.Namespace) -> int:
    try:
        plan = build_navigation_campaign_plan(
            campaign_id=args.campaign_id,
            corpus_id=args.corpus_id,
            families=_campaign_families(args.family),
            sessions_per_family=args.sessions_per_family,
        )
        _write_json(Path(args.output), plan)
    except (EvaluationError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"output": args.output, "protocol": plan["protocol"]}, sort_keys=True))
    return 0


def _campaign_runtime_validate(args: argparse.Namespace) -> int:
    try:
        result = validate_campaign_runtime(
            _iter_json_objects(
                Path(args.input),
                kind="access-log",
                max_line_characters=args.max_line_characters,
            ),
            campaign_id=args.campaign_id,
            expected_ua_token=args.expected_ua_token,
        )
        _write_json(Path(args.output), result)
    except (EvaluationError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


def _json_line(payload: dict[str, object]) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n"


def _iter_json_objects(
    path: Path,
    *,
    kind: str,
    max_line_characters: int,
) -> Iterator[dict[str, object]]:
    try:
        with path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if len(line) > max_line_characters:
                    raise EvaluationError(
                        f"{kind} JSONL line {line_number} exceeds character limit "
                        f"of {max_line_characters}"
                    )
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


def _load_corpus_manifest(path: Path, *, max_characters: int) -> str:
    try:
        with path.open("r", encoding="utf-8") as stream:
            content = stream.read(max_characters + 1)
    except OSError as exc:
        raise EvaluationError(f"cannot read corpus manifest: {exc}") from exc
    if len(content) > max_characters:
        raise EvaluationError(
            f"corpus manifest exceeds character limit of {max_characters}"
        )
    try:
        manifest = json.loads(content)
    except json.JSONDecodeError as exc:
        raise EvaluationError("corpus manifest has invalid JSON") from exc
    if not isinstance(manifest, dict):
        raise EvaluationError("corpus manifest expects one JSON object")
    return validate_corpus_manifest(manifest)


def _load_automation_labels(
    path: Path,
    *,
    max_line_characters: int,
    corpus_id: str | None = None,
) -> dict[str, bool]:
    labels: dict[str, bool] = {}
    for payload in _iter_json_objects(
        path,
        kind="label",
        max_line_characters=max_line_characters,
    ):
        request_id = payload.get("request_id")
        automated = payload.get("automated")
        if not isinstance(request_id, str) or not request_id:
            raise EvaluationError("label request_id must be a non-empty string")
        if not isinstance(automated, bool):
            raise EvaluationError("label automated must be a boolean")
        if corpus_id is not None:
            if set(payload) - {
                "request_id",
                "automated",
                "label_source",
                "label_confidence",
                "corpus_id",
            }:
                raise EvaluationError("manifest-gated label contains unsupported fields")
            label_source = payload.get("label_source")
            label_confidence = payload.get("label_confidence")
            label_corpus_id = payload.get("corpus_id")
            if not isinstance(label_source, str) or not label_source.strip():
                raise EvaluationError("label label_source must be a non-empty string")
            if (
                isinstance(label_confidence, bool)
                or not isinstance(label_confidence, (int, float))
                or not 0.0 <= float(label_confidence) <= 1.0
            ):
                raise EvaluationError(
                    "label label_confidence must be a number between 0 and 1"
                )
            if label_corpus_id != corpus_id:
                raise EvaluationError("label corpus_id must match the corpus manifest")
        if request_id in labels:
            raise EvaluationError(f"duplicate label request_id: {request_id}")
        labels[request_id] = automated
    return labels


def _evaluate_files(
    *,
    detections: Path,
    labels_path: Path,
    manifest_path: Path | None,
    threshold: float,
    max_line_characters: int,
) -> tuple[dict[str, int | float | None], str | None]:
    corpus_id = (
        _load_corpus_manifest(manifest_path, max_characters=max_line_characters)
        if manifest_path is not None
        else None
    )
    labels = _load_automation_labels(
        labels_path,
        max_line_characters=max_line_characters,
        corpus_id=corpus_id,
    )
    result = evaluate_automation_scores(
        _iter_json_objects(
            detections,
            kind="detection",
            max_line_characters=max_line_characters,
        ),
        labels,
        threshold=threshold,
    )
    return result.to_dict(), corpus_id


def _pf2_baseline(args: argparse.Namespace) -> int:
    try:
        model_rows = list(
            _iter_json_objects(
                Path(args.model),
                kind="ATI-PF-2 model-table",
                max_line_characters=args.max_line_characters,
            )
        )
        split_rows = list(
            _iter_json_objects(
                Path(args.split_manifest),
                kind="ATI-PF-2 split manifest",
                max_line_characters=args.max_line_characters,
            )
        )
        report = evaluate_pf2_baseline(
            model_rows,
            split_rows,
            l2=args.l2,
            target_false_positive_rate=args.target_false_positive_rate,
            resamples=args.resamples,
            seed=args.seed,
            grouped_holdout_fraction=args.grouped_holdout_fraction,
        ).to_dict()
        _write_json(Path(args.output), report)
    except (EvaluationError, OSError, PF2BaselineError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {"output": args.output, "status": report["status"]},
            sort_keys=True,
        )
    )
    return 0


def _pf2_export_bigquery(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    try:
        if output_dir.exists():
            raise EvaluationError(f"export directory already exists: {output_dir}")
        model_rows = list(
            _iter_json_objects(
                Path(args.model),
                kind="ATI-PF-2 model-table",
                max_line_characters=args.max_line_characters,
            )
        )
        report = _load_json_object(
            Path(args.report),
            kind="ATI-PF-2 baseline report",
            max_characters=args.max_line_characters,
        )
        exported_at = args.exported_at or datetime.now(UTC).isoformat()
        export = build_bigquery_export(
            model_rows,
            report,
            run_id=args.run_id,
            corpus_id=args.corpus_id,
            exported_at=exported_at,
            ati_version=__version__,
        )
        ddl = bigquery_ddl(args.dataset, project=args.project)
        staging = Path(tempfile.mkdtemp(dir=output_dir.parent, prefix=f".{output_dir.name}."))
        try:
            for table, rows in export.tables.items():
                with (staging / f"{table}.ndjson").open("w", encoding="utf-8") as stream:
                    for row in rows:
                        stream.write(_json_line(dict(row)))
                with (staging / f"{table}.schema.json").open("w", encoding="utf-8") as stream:
                    json.dump(list(export.schemas[table]), stream, indent=2)
                    stream.write("\n")
            (staging / "ddl.sql").write_text(ddl, encoding="utf-8")
            with (staging / "export.json").open("w", encoding="utf-8") as stream:
                json.dump(
                    {
                        "run_id": args.run_id,
                        "corpus_id": args.corpus_id,
                        "dataset": args.dataset,
                        "project": args.project,
                        "exported_at": exported_at,
                        "ati_version": __version__,
                        "row_counts": {
                            table: len(rows) for table, rows in export.tables.items()
                        },
                    },
                    stream,
                    indent=2,
                    sort_keys=True,
                )
                stream.write("\n")
            staging.replace(output_dir)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
    except (EvaluationError, OSError, PF2BaselineError, PF2ExportError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "output_dir": str(output_dir),
                "tables": sorted(export.tables),
                "row_counts": {table: len(rows) for table, rows in export.tables.items()},
            },
            sort_keys=True,
        )
    )
    return 0


def _load_json_object(path: Path, *, kind: str, max_characters: int) -> dict[str, object]:
    try:
        with path.open("r", encoding="utf-8") as stream:
            content = stream.read(max_characters + 1)
    except OSError as exc:
        raise EvaluationError(f"cannot read {kind}: {exc}") from exc
    if len(content) > max_characters:
        raise EvaluationError(f"{kind} exceeds character limit of {max_characters}")
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise EvaluationError(f"{kind} has invalid JSON") from exc
    if not isinstance(payload, dict):
        raise EvaluationError(f"{kind} expects one JSON object")
    return payload


def _write_jsonl(path: Path, rows: Sequence[Mapping[str, object]]) -> None:
    with _atomic_output(path) as stream:
        for row in rows:
            stream.write(_json_line(dict(row)))


def _pf2_preflight(args: argparse.Namespace) -> int:
    try:
        labels = _load_json_object(
            Path(args.labels_by_session),
            kind="ATI-PF-2 labels",
            max_characters=args.max_line_characters,
        )
        tasks = _load_json_object(
            Path(args.tasks_by_session),
            kind="ATI-PF-2 task metadata",
            max_characters=args.max_line_characters,
        )
        windows = (
            _load_json_object(
                Path(args.collection_windows_by_session),
                kind="ATI-PF-2 collection-window metadata",
                max_characters=args.max_line_characters,
            )
            if args.collection_windows_by_session is not None
            else None
        )
        if any(
            not isinstance(session_id, str) or not isinstance(automated, bool)
            for session_id, automated in labels.items()
        ):
            raise EvaluationError("ATI-PF-2 labels must map session strings to boolean targets")
        if any(
            not isinstance(session_id, str) or not isinstance(task, str)
            for session_id, task in tasks.items()
        ):
            raise EvaluationError("ATI-PF-2 task metadata must map session strings to task strings")
        labels_by_session: dict[str, bool] = {
            session_id: automated
            for session_id, automated in labels.items()
            if isinstance(session_id, str) and isinstance(automated, bool)
        }
        task_by_session: dict[str, str] = {
            session_id: task
            for session_id, task in tasks.items()
            if isinstance(session_id, str) and isinstance(task, str)
        }
        if windows is not None and any(
            not isinstance(session_id, str) or not isinstance(window, str)
            for session_id, window in windows.items()
        ):
            raise EvaluationError(
                "ATI-PF-2 collection-window metadata must map session strings to window strings"
            )
        collection_window_by_session = (
            {
                session_id: window
                for session_id, window in windows.items()
                if isinstance(session_id, str) and isinstance(window, str)
            }
            if windows is not None
            else None
        )
        dataset = prepare_pf2_dataset(
            _iter_json_objects(
                Path(args.input),
                kind="ATI-PF-2 access-log",
                max_line_characters=args.max_line_characters,
            ),
            labels_by_session=labels_by_session,
            task_by_session=task_by_session,
            collection_window_by_session=collection_window_by_session,
            min_sessions_per_task_class=args.min_sessions_per_task_class,
        )
        _write_jsonl(Path(args.model_output), dataset.model_rows)
        _write_jsonl(Path(args.split_output), dataset.split_rows)
        _write_json(Path(args.preflight_output), dataset.preflight)
    except (EvaluationError, OSError, PF2ProtocolError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {"preflight_output": args.preflight_output, "status": dataset.preflight["status"]},
            sort_keys=True,
        )
    )
    return 0


def _evaluate(args: argparse.Namespace) -> int:
    try:
        result, _ = _evaluate_files(
            detections=Path(args.input),
            labels_path=Path(args.labels),
            manifest_path=Path(args.manifest) if args.manifest is not None else None,
            threshold=args.threshold,
            max_line_characters=args.max_line_characters,
        )
    except EvaluationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _load_stratified_metadata(
    path: Path, *, max_line_characters: int
) -> dict[str, dict[str, object]]:
    fields = {
        "request_id",
        "session_id",
        "family",
        "provider",
        "ua_bucket",
        "time_iso8601",
    }
    metadata: dict[str, dict[str, object]] = {}
    for payload in _iter_json_objects(
        path, kind="stratified metadata", max_line_characters=max_line_characters
    ):
        if set(payload) != fields:
            raise EvaluationError("stratified metadata has unsupported or missing fields")
        request_id = payload["request_id"]
        if not isinstance(request_id, str) or not request_id:
            raise EvaluationError("stratified metadata request_id must be a non-empty string")
        if request_id in metadata:
            raise EvaluationError(f"duplicate stratified metadata request_id: {request_id}")
        metadata[request_id] = payload
    return metadata


def _evaluate_stratified(args: argparse.Namespace) -> int:
    try:
        corpus_id = _load_corpus_manifest(
            Path(args.manifest), max_characters=args.max_line_characters
        )
        labels = _load_automation_labels(
            Path(args.labels),
            max_line_characters=args.max_line_characters,
            corpus_id=corpus_id,
        )
        result = evaluate_stratified_automation_scores(
            _iter_json_objects(
                Path(args.input),
                kind="detection",
                max_line_characters=args.max_line_characters,
            ),
            labels,
            _load_stratified_metadata(
                Path(args.metadata), max_line_characters=args.max_line_characters
            ),
            threshold=args.threshold,
        )
        _write_json(Path(args.output), result)
    except (EvaluationError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    with _atomic_output(path) as stream:
        json.dump(payload, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _quality_status(evaluation: Mapping[str, int | float | None]) -> str:
    if (
        evaluation["evaluated_request_count"]
        and not evaluation["unlabeled_request_count"]
        and not evaluation["unmatched_label_count"]
    ):
        return "ready"
    return "review-required"


def _run_summary(
    run: dict[str, object], evaluation: Mapping[str, int | float | None]
) -> str:
    artifacts = run["artifacts"]
    assert isinstance(artifacts, dict)
    return (
        "# ATI local run\n\n"
        f"- Tool version: `{run['tool_version']}`\n"
        f"- Corpus ID: `{run['corpus_id']}`\n"
        f"- Quality status: `{_quality_status(evaluation)}`\n"
        f"- Evaluated detections: `{evaluation['evaluated_request_count']}`\n"
        f"- Unlabeled detections: `{evaluation['unlabeled_request_count']}`\n"
        f"- Unmatched labels: `{evaluation['unmatched_label_count']}`\n"
        f"- Detections: `{artifacts['detections']}`\n"
        f"- Evaluation: `{artifacts['evaluation']}`\n"
    )


def _run(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    if os.path.lexists(run_dir):
        print(f"error: run directory already exists: {run_dir}", file=sys.stderr)
        return 2
    try:
        run_dir.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=f".{run_dir.name}.", dir=run_dir.parent))
    except OSError as exc:
        print(f"error: cannot create run directory: {exc}", file=sys.stderr)
        return 2
    try:
        args.output = str(staging / "detections.jsonl")
        if _analyze(args) != 0:
            return 2
        evaluation, corpus_id = _evaluate_files(
            detections=Path(args.output),
            labels_path=Path(args.labels),
            manifest_path=Path(args.manifest),
            threshold=args.threshold,
            max_line_characters=args.max_line_characters,
        )
        run = {
            "schema_version": 1,
            "tool_version": __version__,
            "corpus_id": corpus_id,
            "analysis": {
                "source": args.source,
                "verify_identity": args.verify_identity,
                "verification_mode": args.verification_mode,
            },
            "artifacts": {
                "detections": "detections.jsonl",
                "evaluation": "evaluation.json",
                "summary": "summary.md",
            },
        }
        _write_json(staging / "evaluation.json", evaluation)
        _write_json(staging / "run.json", run)
        with _atomic_output(staging / "summary.md") as stream:
            stream.write(_run_summary(run, evaluation))
        os.replace(staging, run_dir)
    except (EvaluationError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    print(json.dumps({"corpus_id": corpus_id, "run_dir": str(run_dir)}, sort_keys=True))
    return 0


def _explain(args: argparse.Namespace) -> int:
    path = Path(args.input)
    try:
        with path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if len(line) > args.max_line_characters:
                    print(
                        f"error: line {line_number}: exceeds configured character limit",
                        file=sys.stderr,
                    )
                    return 2
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


def _standards_health_payload(report: StandardsHealthReport) -> dict[str, object]:
    return {
        "review_required": report.review_required,
        "drafts": [
            {
                "pinned": draft.pin.pinned,
                "observed_revision": draft.observed_revision,
                "status": draft.status.value,
                "reasons": list(draft.reasons),
            }
            for draft in report.drafts
        ],
    }


def _standards_health() -> int:
    client = DatatrackerJsonClient(transport=UrllibDatatrackerTransport())
    try:
        report = check_pinned_drafts(client=client)
    except (DatatrackerPayloadError, StandardsHealthOperationalError, ValueError) as exc:
        print(f"standards health failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(_standards_health_payload(report), indent=2, sort_keys=True))
    return 1 if report.review_required else 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns a process-compatible status code."""

    args = _parser().parse_args(argv)
    if args.command == "analyze":
        return _analyze(args)
    if args.command == "run":
        return _run(args)
    if args.command == "explain":
        return _explain(args)
    if args.command == "evaluate":
        return _evaluate(args)
    if args.command == "pf2-preflight":
        return _pf2_preflight(args)
    if args.command == "pf2-baseline":
        return _pf2_baseline(args)
    if args.command == "pf2-export-bigquery":
        return _pf2_export_bigquery(args)
    if args.command == "evaluate-stratified":
        return _evaluate_stratified(args)
    if args.command == "campaign" and args.campaign_command == "labels":
        return _campaign_labels(args)
    if args.command == "campaign" and args.campaign_command == "plan":
        return _campaign_plan(args)
    if args.command == "campaign" and args.campaign_command == "runtime-validate":
        return _campaign_runtime_validate(args)
    if args.command == "registry" and args.registry_command == "validate":
        return _registry_validate()
    if args.command == "sources" and args.sources_command == "status":
        return _sources_status()
    if args.command == "sources" and args.sources_command == "validate":
        return _sources_validate()
    if args.command == "sources" and args.sources_command == "refresh":
        return _sources_refresh(args.provider)
    if args.command == "standards" and args.standards_command == "health":
        return _standards_health()
    raise RuntimeError("unreachable command dispatch")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
