from agent_traffic_intelligence.identity.crypto.directory import parse_key_directory
from agent_traffic_intelligence.identity.source_service import configured_sources
from agent_traffic_intelligence.identity.sources.models import SourceType
from agent_traffic_intelligence.identity.standards import DEFAULT_STANDARDS_PROFILE


def test_key_directory_reports_current_standard_profile() -> None:
    directory = parse_key_directory({"keys": []})
    assert (
        directory.profile
        == DEFAULT_STANDARDS_PROFILE.message_signatures_directory
    )


def test_configured_directory_sources_use_current_standard_profile() -> None:
    profiles = {
        source.parser_profile
        for source in configured_sources()
        if source.source_type is SourceType.KEY_DIRECTORY
    }
    assert profiles
    assert profiles == {DEFAULT_STANDARDS_PROFILE.message_signatures_directory}
