"""ATI-PF-2: the privacy-first controlled-session laboratory protocol.

`protocol` builds the firewall-checked session table, `baseline` runs the
constant-prevalence and regularized-logistic ladder over fixed holdouts, and `export`
prepares aggregate warehouse tables. Nothing here uploads a corpus, and nothing here
establishes generalization, calibration or an operating threshold for public traffic.
"""

from agent_traffic_intelligence.evaluation.pf2.baseline import (
    PF2BaselineError,
    PF2BaselineReport,
    PF2Split,
    assert_pf2_model_table,
    build_pf2_splits,
    evaluate_pf2_baseline,
)
from agent_traffic_intelligence.evaluation.pf2.export import (
    PF2Export,
    PF2ExportError,
    bigquery_ddl,
    build_bigquery_export,
)
from agent_traffic_intelligence.evaluation.pf2.protocol import (
    PF2_CATALOGUE_VERSION,
    PF2_FEATURE_FAMILIES,
    PF2_ROUTE_CATEGORIES,
    PF2_TARGET_NAME,
    PF2PreparedDataset,
    PF2ProtocolError,
    is_pf2_session_id,
    pf2_feature_names,
    prepare_pf2_dataset,
)

__all__ = [
    "PF2_CATALOGUE_VERSION",
    "PF2_FEATURE_FAMILIES",
    "PF2_ROUTE_CATEGORIES",
    "PF2_TARGET_NAME",
    "PF2BaselineError",
    "PF2BaselineReport",
    "PF2Export",
    "PF2ExportError",
    "PF2PreparedDataset",
    "PF2ProtocolError",
    "PF2Split",
    "assert_pf2_model_table",
    "bigquery_ddl",
    "build_bigquery_export",
    "build_pf2_splits",
    "evaluate_pf2_baseline",
    "is_pf2_session_id",
    "pf2_feature_names",
    "prepare_pf2_dataset",
]
