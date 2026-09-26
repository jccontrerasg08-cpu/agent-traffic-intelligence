"""ATI's ATI-PF-2 route mapping is pinned to the laboratory's closed catalogue.

The source of truth is `observation_lab/pf2/catalogue.json` in ati-observation-lab, whose
`tests/test_pf2_catalogue.py` pins this identical literal and version. A route cannot
change on one side alone: change the catalogue, both pins, and both repositories together.
"""

from agent_traffic_intelligence.evaluation.pf2 import (
    PF2_CATALOGUE_VERSION,
    PF2_ROUTE_CATEGORIES,
    PF2ProtocolError,
    prepare_pf2_dataset,
)

LAB_PINNED_VERSION = "ati-pf2-catalogue-1"
LAB_PINNED_CATEGORIES = {
    "/lab/start": "start",
    "/lab/page/landing": "landing",
    "/lab/page/catalog": "catalog",
    "/lab/page/detail": "detail",
    "/lab/page/related": "related",
    "/lab/complete": "complete",
    "/lab/assets/site.css": "asset",
    "/lab/assets/pixel.svg": "asset",
}


def test_route_mapping_matches_the_laboratory_catalogue() -> None:
    assert PF2_CATALOGUE_VERSION == LAB_PINNED_VERSION
    assert dict(PF2_ROUTE_CATEGORIES) == LAB_PINNED_CATEGORIES


def test_the_laboratory_integrity_route_is_rejected_by_the_preflight() -> None:
    session = "hmac-sha256:" + "a" * 64
    record = {
        "session_id": session,
        "request_uri": "/lab/missing",
        "request_method": "GET",
        "status": 404,
        "time_iso8601": "2026-09-26T10:00:00+00:00",
    }

    try:
        prepare_pf2_dataset(
            [record],
            labels_by_session={session: False},
            task_by_session={session: "task-detail"},
            min_sessions_per_task_class=1,
        )
    except PF2ProtocolError as error:
        assert "eligible ATI-PF-2 route" in str(error)
    else:  # pragma: no cover - the assertion documents the contract
        raise AssertionError("/lab/missing must never enter an ATI-PF-2 corpus")
