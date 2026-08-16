from __future__ import annotations

import pytest
from agent_traffic_intelligence.identity.standards_health import (
    DatatrackerPayloadError,
    DraftHealthStatus,
    DraftPin,
    evaluate_datatracker_document,
    state_api_url,
)


def test_draft_pin_splits_base_name_and_revision() -> None:
    pin = DraftPin.from_pinned("draft-meunier-webbotauth-httpsig-protocol-01")

    assert pin.pinned == "draft-meunier-webbotauth-httpsig-protocol-01"
    assert pin.document_name == "draft-meunier-webbotauth-httpsig-protocol"
    assert pin.revision == "01"


@pytest.mark.parametrize(
    "value",
    [
        "RFC9421",
        "draft-example-no-revision",
        "draft-example-1",
        "draft-example-aa",
    ],
)
def test_draft_pin_rejects_non_revisioned_internet_draft(value: str) -> None:
    with pytest.raises(ValueError, match="revision"):
        DraftPin.from_pinned(value)


def test_matching_revision_and_non_terminal_state_is_current() -> None:
    pin = DraftPin.from_pinned("draft-example-widget-03")
    health = evaluate_datatracker_document(
        pin,
        {
            "name": "draft-example-widget",
            "rev": "03",
            "states": ["/api/v1/doc/state/1/"],
        },
        state_payloads={
            "/api/v1/doc/state/1/": {
                "name": "Active",
                "slug": "active",
                "type": "/api/v1/doc/statetype/draft/",
            }
        },
    )

    assert health.status is DraftHealthStatus.CURRENT
    assert health.observed_revision == "03"
    assert health.reasons == ()


def test_newer_revision_requires_review_without_mutating_pin() -> None:
    pin = DraftPin.from_pinned("draft-example-widget-03")
    health = evaluate_datatracker_document(
        pin,
        {
            "name": "draft-example-widget",
            "rev": "04",
            "states": [],
        },
        state_payloads={},
    )

    assert health.status is DraftHealthStatus.REVIEW_REQUIRED
    assert health.observed_revision == "04"
    assert any("revision" in reason for reason in health.reasons)
    assert pin.pinned == "draft-example-widget-03"


@pytest.mark.parametrize("state_name", ["Expired", "Dead", "Replaced", "Withdrawn"])
def test_terminal_or_replaced_state_requires_review(state_name: str) -> None:
    pin = DraftPin.from_pinned("draft-example-widget-03")
    health = evaluate_datatracker_document(
        pin,
        {
            "name": "draft-example-widget",
            "rev": "03",
            "states": ["/api/v1/doc/state/9/"],
        },
        state_payloads={
            "/api/v1/doc/state/9/": {
                "name": state_name,
                "slug": state_name.casefold(),
                "type": "/api/v1/doc/statetype/draft/",
            }
        },
    )

    assert health.status is DraftHealthStatus.REVIEW_REQUIRED
    assert any(state_name.casefold() in reason.casefold() for reason in health.reasons)


def test_document_name_mismatch_is_payload_error() -> None:
    pin = DraftPin.from_pinned("draft-example-widget-03")
    with pytest.raises(DatatrackerPayloadError, match="document name"):
        evaluate_datatracker_document(
            pin,
            {"name": "draft-example-other", "rev": "03", "states": []},
            state_payloads={},
        )


def test_state_api_url_rejects_absolute_or_unexpected_paths() -> None:
    assert (
        state_api_url("/api/v1/doc/state/42/")
        == "https://datatracker.ietf.org/api/v1/doc/state/42/"
    )
    for unsafe in (
        "https://evil.example/api/v1/doc/state/42/",
        "//evil.example/api/v1/doc/state/42/",
        "/api/v1/group/group/42/",
        "/api/v1/doc/state/../../group/42/",
    ):
        with pytest.raises(DatatrackerPayloadError):
            state_api_url(unsafe)
