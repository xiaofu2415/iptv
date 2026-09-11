#!/usr/bin/env python3
"""Verify a StarFlowTV live bundle before publishing it."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Dict, Optional, Sequence
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from m3u_to_starflow import sanitize_url


ALLOWED_ROOT = {"schemaVersion", "configVersion", "generatedAt", "channels"}
ALLOWED_CHANNEL = {"id", "name", "group", "logo", "epgId", "sources"}
ALLOWED_SOURCE = {"id", "url", "priority", "protocol"}
ALLOWED_FILES = {
    "live.json",
    "live.m3u",
    "live.txt",
    "tvbox-live.json",
    "epg.xml",
    "checksums.sha256",
}
ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _verify_live_json(path: Path) -> Dict[str, int]:
    try:
        root = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError("invalid_live_json") from exc
    if not isinstance(root, dict) or set(root) - ALLOWED_ROOT:
        raise ValueError("unknown_live_json_field")
    if root.get("schemaVersion") != 1 or not isinstance(root.get("configVersion"), int):
        raise ValueError("invalid_live_json_version")
    if root["configVersion"] <= 0 or not _text(root.get("generatedAt")):
        raise ValueError("invalid_live_json_metadata")
    channels = root.get("channels")
    if not isinstance(channels, list) or not channels:
        raise ValueError("live_json_has_no_channels")
    urls = set()
    line_count = 0
    for channel in channels:
        if not isinstance(channel, dict) or set(channel) - ALLOWED_CHANNEL:
            raise ValueError("invalid_live_json_channel")
        if not ID.fullmatch(_text(channel.get("id"))):
            raise ValueError("invalid_live_json_channel_id")
        if not _text(channel.get("name")) or not _text(channel.get("group")):
            raise ValueError("invalid_live_json_channel_metadata")
        sources = channel.get("sources")
        if not isinstance(sources, list) or not sources:
            raise ValueError("channel_has_no_sources")
        for source in sources:
            if not isinstance(source, dict) or set(source) - ALLOWED_SOURCE:
                raise ValueError("invalid_live_json_source")
            if not ID.fullmatch(_text(source.get("id"))):
                raise ValueError("invalid_live_json_source_id")
            if not isinstance(source.get("priority"), int) or source["priority"] <= 0:
                raise ValueError("invalid_live_json_priority")
            url = _text(source.get("url"))
            protocol = _text(source.get("protocol")).lower()
            sanitized = sanitize_url(url)
            if not sanitized.ok or sanitized.url != url:
                raise ValueError("unsanitized_or_unsafe_stream_url")
            if urlsplit(url).scheme.lower() != protocol or url in urls:
                raise ValueError("duplicate_or_mismatched_stream_url")
            urls.add(url)
            line_count += 1
    return {"channelCount": len(channels), "lineCount": line_count}


def _verify_signature(bundle: Path, public_key_b64: Optional[str]) -> None:
    if not public_key_b64:
        return
    try:
        public_key_bytes = base64.b64decode(public_key_b64, validate=True)
        signature = base64.b64decode(
            (bundle / "manifest.sig").read_text(encoding="ascii").strip(),
            validate=True,
        )
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, (bundle / "manifest.json").read_bytes())
    except Exception as exc:
        raise ValueError("invalid_manifest_signature") from exc


def _verify_manifest(bundle: Path) -> Dict[str, object]:
    try:
        manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError("invalid_manifest_json") from exc
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 1:
        raise ValueError("invalid_manifest_schema")
    version = manifest.get("configVersion")
    if not isinstance(version, int) or version <= 0:
        raise ValueError("invalid_manifest_version")
    if manifest.get("signatureAlgorithm") != "Ed25519":
        raise ValueError("invalid_manifest_signature_algorithm")
    if manifest.get("signatureStatus") != "ready":
        raise ValueError("manifest_is_not_ready")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("manifest_has_no_files")
    names = set()
    for entry in files:
        if not isinstance(entry, dict):
            raise ValueError("invalid_manifest_entry")
        name = entry.get("name")
        if name not in ALLOWED_FILES or name in names:
            raise ValueError("invalid_manifest_file_name")
        names.add(name)
        path = bundle / name
        if not path.is_file():
            raise ValueError("manifest_file_missing")
        data = path.read_bytes()
        if entry.get("size") != len(data) or entry.get("sha256") != hashlib.sha256(data).hexdigest():
            raise ValueError("manifest_file_hash_mismatch")
        url = entry.get("url", "")
        parsed = urlsplit(url)
        expected_suffix = "/releases/%s/%s" % (version, name)
        if parsed.scheme != "https" or not parsed.netloc or not parsed.path.endswith(expected_suffix):
            raise ValueError("unsafe_manifest_file_url")
    if "live.json" not in names or "live.txt" not in names:
        raise ValueError("manifest_requires_live_files")
    return manifest


def _verify_checksums(bundle: Path) -> None:
    path = bundle / "checksums.sha256"
    if not path.is_file():
        return
    for line in path.read_text(encoding="ascii").splitlines():
        digest, separator, name = line.partition("  ")
        if not separator or not re.fullmatch(r"[a-f0-9]{64}", digest) or not (bundle / name).is_file():
            raise ValueError("invalid_checksums")
        if hashlib.sha256((bundle / name).read_bytes()).hexdigest() != digest:
            raise ValueError("checksums_mismatch")


def verify_bundle(bundle: Path, public_key_b64: Optional[str] = None) -> Dict[str, object]:
    bundle = Path(bundle)
    if not (bundle / "manifest.json").is_file():
        raise ValueError("manifest_missing")
    live_report = _verify_live_json(bundle / "live.json")
    _verify_manifest(bundle)
    _verify_signature(bundle, public_key_b64)
    _verify_checksums(bundle)
    return {"passed": True, **live_report}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--public-key-b64")
    args = parser.parse_args(argv)
    report = verify_bundle(args.bundle, args.public_key_b64)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
