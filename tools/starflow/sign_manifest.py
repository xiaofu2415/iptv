#!/usr/bin/env python3
"""Sign a StarFlowTV configuration manifest with an Ed25519 key."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Optional, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def load_private_key(encoded: str) -> Ed25519PrivateKey:
    if not encoded:
        raise ValueError("missing_ed25519_private_key")
    try:
        key_bytes = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise ValueError("invalid_ed25519_private_key_base64") from exc

    for loader in (serialization.load_der_private_key, serialization.load_pem_private_key):
        try:
            candidate = loader(key_bytes, password=None)
            if isinstance(candidate, Ed25519PrivateKey):
                return candidate
        except (TypeError, ValueError):
            continue
    if len(key_bytes) == 32:
        return Ed25519PrivateKey.from_private_bytes(key_bytes)
    raise ValueError("unsupported_ed25519_private_key")


def sign_manifest(
    manifest_path: Path,
    signature_path: Path,
    digest_path: Path,
    private_key_b64: str,
    expected_public_key_b64: str,
    key_id: str,
) -> None:
    if not key_id:
        raise ValueError("missing_config_key_id")
    private_key = load_private_key(private_key_b64)
    actual_public_key_b64 = base64.b64encode(
        private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    if actual_public_key_b64 != expected_public_key_b64:
        raise ValueError("ed25519_private_key_does_not_match_client_public_key")

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError("invalid_manifest_json") from exc
    if not isinstance(manifest, dict) or int(manifest.get("configVersion", 0)) <= 0:
        raise ValueError("invalid_manifest_config_version")
    if not isinstance(manifest.get("files"), list) or not manifest["files"]:
        raise ValueError("manifest_has_no_files")
    manifest["signatureAlgorithm"] = "Ed25519"
    manifest["signatureStatus"] = "ready"
    manifest["keyId"] = key_id
    payload = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    manifest_path.write_bytes(payload)
    signature_path.write_text(
        base64.b64encode(private_key.sign(payload)).decode("ascii") + "\n",
        encoding="ascii",
    )
    digest_path.write_text(
        hashlib.sha256(payload).hexdigest() + "  " + manifest_path.name + "\n",
        encoding="ascii",
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--digest", required=True, type=Path)
    parser.add_argument("--private-key-b64", default=os.environ.get("STARFLOW_CONFIG_SIGNING_KEY_B64", ""))
    parser.add_argument("--expected-public-key-b64", required=True)
    parser.add_argument("--key-id", default=os.environ.get("STARFLOW_CONFIG_KEY_ID", ""))
    args = parser.parse_args(argv)
    sign_manifest(
        args.manifest,
        args.signature,
        args.digest,
        args.private_key_b64,
        args.expected_public_key_b64,
        args.key_id,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
