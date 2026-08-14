"""Content-addressed offline cache for identity source documents."""

from __future__ import annotations

import os
import tempfile
from contextlib import suppress
from pathlib import Path

from agent_traffic_intelligence.identity.sources.manifest import (
    load_manifest,
    write_manifest_atomic,
)
from agent_traffic_intelligence.identity.sources.models import SourceDocument, SourceMetadata
from agent_traffic_intelligence.identity.sources.trust import canonicalize_source_uri


class SourceCache:
    """Small content-addressed cache with an atomic URI-to-metadata manifest."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.blobs = root / "blobs" / "sha256"
        self.manifest_path = root / "manifest.json"

    def _blob_path(self, digest: str) -> Path:
        return self.blobs / digest[:2] / digest

    def put(self, document: SourceDocument) -> None:
        canonical_uri = canonicalize_source_uri(document.metadata.uri)
        blob_path = self._blob_path(document.metadata.sha256)
        blob_path.parent.mkdir(parents=True, exist_ok=True)
        if not blob_path.exists():
            fd, temp_name = tempfile.mkstemp(prefix="blob-", dir=blob_path.parent)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(document.content)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp_name, blob_path)
            except BaseException:
                with suppress(FileNotFoundError):
                    os.unlink(temp_name)
                raise

        manifest = load_manifest(self.manifest_path)
        entries = manifest["entries"]
        assert isinstance(entries, dict)
        entries[canonical_uri] = document.metadata.to_dict()
        write_manifest_atomic(self.manifest_path, manifest)

    def get(self, uri: str) -> SourceDocument | None:
        canonical_uri = canonicalize_source_uri(uri)
        manifest = load_manifest(self.manifest_path)
        entries = manifest["entries"]
        assert isinstance(entries, dict)
        raw = entries.get(canonical_uri)
        if not isinstance(raw, dict):
            return None
        metadata = SourceMetadata.from_dict(raw)
        content = self._blob_path(metadata.sha256).read_bytes()
        return SourceDocument(metadata=metadata, content=content)
