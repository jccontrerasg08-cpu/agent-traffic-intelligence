from __future__ import annotations

import json
from dataclasses import dataclass

import pytest

from agent_traffic_intelligence.identity.standards_health import (
    DatatrackerHttpResponse,
    DatatrackerJsonClient,
    DatatrackerPayloadError,
    DraftHealthStatus,
    StandardsHealthOperationalError,
    check_pinned_drafts,
    default_draft_pins,
    document_api_url,
)


@dataclass
class FakeTransport:
    responses: dict[str, DatatrackerHttpResponse]

    def __post_init__(self) -> None:
        self.calls: list[tuple[str, float, int]] = []

    def get(
        self,
        url: str,
        *,
        timeout_seconds: float,
        max_body_bytes: int,
    ) -> DatatrackerHttpResponse:
        self.calls.append((url, timeout_seconds, max_body_bytes))
        return self.responses[url]


def response(
    url: str,
    payload: object,
    *,
    status: int = 200,
    final_url: str | None = None,
    content_type: str = "application/json; charset=utf-8",
) -> DatatrackerHttpResponse:
    return DatatrackerHttpResponse(
        status=status,
        final_url=final_url or url,
        content_type=content_type,
        body=json.dumps(payload).encode("utf-8"),
    )


def test_default_draft_pins_follow_the_current_standards_profile() -> None:
    pins = default_draft_pins()

    assert tuple(pin.pinned for pin in pins) == (
        "draft-meunier-webbotauth-httpsig-protocol-01",
        "draft-meunier-webbotauth-httpsig-directory-00",
        "draft-illyes-webbotauth-jafar-00",
        "draft-meunier-webbotauth-registry-03",
    )


def test_document_api_url_is_generated_from_the_pin_only() -> None:
    pin = default_draft_pins()[0]
    assert document_api_url(pin) == (
        "https://datatracker.ietf.org/api/v1/doc/document/"
        "draft-meunier-webbotauth-httpsig-protocol/"
    )


def test_json_client_accepts_only_exact_datatracker_json_response() -> None:
    url = document_api_url(default_draft_pins()[0])
    transport = FakeTransport({url: response(url, {"name": "example"})})
    client = DatatrackerJsonClient(
        transport=transport,
        timeout_seconds=3.0,
        max_body_bytes=1024,
    )

    assert client.fetch_json(url) == {"name": "example"}
    assert transport.calls == [(url, 3.0, 1024)]


@pytest.mark.parametrize(
    ("http_response", "error_match"),
    [
        (
            lambda url: response(url, {}, status=503),
            "HTTP status",
        ),
        (
            lambda url: response(
                url,
                {},
                final_url="https://datatracker.ietf.org/api/v1/doc/document/other/",
            ),
            "redirect",
        ),
        (
            lambda url: response(url, {}, content_type="text/html"),
            "content type",
        ),
    ],
)
def test_json_client_rejects_status_redirect_or_wrong_media_type(
    http_response,
    error_match: str,
) -> None:
    url = document_api_url(default_draft_pins()[0])
    client = DatatrackerJsonClient(
        transport=FakeTransport({url: http_response(url)}),
        max_body_bytes=1024,
    )

    with pytest.raises(StandardsHealthOperationalError, match=error_match):
        client.fetch_json(url)


def test_json_client_rejects_oversized_invalid_or_non_object_json() -> None:
    url = document_api_url(default_draft_pins()[0])
    for body, expected_error in (
        (b"x" * 33, StandardsHealthOperationalError),
        (b"{not-json", DatatrackerPayloadError),
        (b"[]", DatatrackerPayloadError),
    ):
        client = DatatrackerJsonClient(
            transport=FakeTransport(
                {
                    url: DatatrackerHttpResponse(
                        status=200,
                        final_url=url,
                        content_type="application/json",
                        body=body,
                    )
                }
            ),
            max_body_bytes=32,
        )
        with pytest.raises(expected_error):
            client.fetch_json(url)


def test_json_client_rejects_urls_outside_constrained_datatracker_api() -> None:
    client = DatatrackerJsonClient(transport=FakeTransport({}))
    for unsafe in (
        "http://datatracker.ietf.org/api/v1/doc/document/example/",
        "https://evil.example/api/v1/doc/document/example/",
        "https://datatracker.ietf.org/api/v1/group/group/1/",
        "https://datatracker.ietf.org/api/v1/doc/document/../../group/1/",
    ):
        with pytest.raises(StandardsHealthOperationalError, match="allowed Datatracker API"):
            client.fetch_json(unsafe)


def test_check_pinned_drafts_aggregates_current_results_without_mutation() -> None:
    responses: dict[str, DatatrackerHttpResponse] = {}
    for index, pin in enumerate(default_draft_pins(), start=1):
        document_url = document_api_url(pin)
        state_path = f"/api/v1/doc/state/{index}/"
        state_url = f"https://datatracker.ietf.org{state_path}"
        responses[document_url] = response(
            document_url,
            {
                "name": pin.document_name,
                "rev": pin.revision,
                "states": [state_path],
            },
        )
        responses[state_url] = response(
            state_url,
            {
                "name": "Active",
                "slug": "active",
                "type": "/api/v1/doc/statetype/draft/",
            },
        )

    report = check_pinned_drafts(
        client=DatatrackerJsonClient(transport=FakeTransport(responses))
    )

    assert report.review_required is False
    assert len(report.drafts) == 4
    assert all(item.status is DraftHealthStatus.CURRENT for item in report.drafts)


@pytest.mark.parametrize(
    ("states", "error_match"),
    [
        (["/api/v1/doc/state/1/", "/api/v1/doc/state/1/"], "duplicates"),
        ([f"/api/v1/doc/state/{index}/" for index in range(17)], "too many"),
    ],
)
def test_check_pinned_drafts_rejects_duplicate_or_excessive_states(
    states: list[str],
    error_match: str,
) -> None:
    pin = default_draft_pins()[0]
    document_url = document_api_url(pin)
    transport = FakeTransport(
        {
            document_url: response(
                document_url,
                {
                    "name": pin.document_name,
                    "rev": pin.revision,
                    "states": states,
                },
            )
        }
    )

    with pytest.raises(DatatrackerPayloadError, match=error_match):
        check_pinned_drafts(
            client=DatatrackerJsonClient(transport=transport),
            pins=(pin,),
        )

    assert [call[0] for call in transport.calls] == [document_url]


def test_check_pinned_drafts_surfaces_review_required_without_rewriting_pins() -> None:
    pins = default_draft_pins()
    first = pins[0]
    responses: dict[str, DatatrackerHttpResponse] = {}
    for pin in pins:
        url = document_api_url(pin)
        observed_revision = "02" if pin is first else pin.revision
        responses[url] = response(
            url,
            {
                "name": pin.document_name,
                "rev": observed_revision,
                "states": [],
            },
        )

    report = check_pinned_drafts(
        client=DatatrackerJsonClient(transport=FakeTransport(responses))
    )

    assert report.review_required is True
    assert report.drafts[0].status is DraftHealthStatus.REVIEW_REQUIRED
    assert default_draft_pins()[0].pinned == first.pinned
