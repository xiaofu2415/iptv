import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MODULE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(MODULE_DIR))

from m3u_to_starflow import build_manifest, convert_text, write_bundle  # noqa: E402
from sign_manifest import sign_manifest  # noqa: E402
from verify_bundle import verify_bundle  # noqa: E402


class VerifyBundleTest(unittest.TestCase):
    def test_verifies_hashes_signature_and_client_urls(self):
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        private_b64 = base64.b64encode(
            key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        ).decode("ascii")
        public_b64 = base64.b64encode(
            key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        ).decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = convert_text(
                """#EXTM3U
#EXTINF:-1 tvg-id="CCTV1" group-title="央视频道",CCTV1
https://stream.example/cctv1.m3u8?id=cctv1
#EXTINF:-1 tvg-id="HUNAN" group-title="卫视频道",湖南卫视
https://stream.example/hunan.m3u8?id=hunan
#EXTINF:-1 tvg-id="ZHEJIANG" group-title="卫视频道",浙江卫视
https://stream.example/zhejiang.m3u8?id=zhejiang
#EXTINF:-1 tvg-id="CCTV1" group-title="央视频道",CCTV1
https://backup.example/cctv1.m3u8?id=cctv1backup
""",
                123,
                "2026-09-09T00:00:00Z",
                probe_fn=lambda url: True,
            )
            write_bundle(result, root)
            manifest = build_manifest(
                root,
                "https://config.example/starflow/config",
                123,
                "2026-09-09T00:00:00Z",
                "test-key",
            )
            (root / "manifest.json").write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            sign_manifest(
                root / "manifest.json",
                root / "manifest.sig",
                root / "manifest.sha256",
                private_b64,
                public_b64,
                "test-key",
            )
            report = verify_bundle(root, public_b64)
            self.assertTrue(report["passed"])
            self.assertEqual(4, report["lineCount"])

    def test_rejects_temporary_query_in_live_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "live.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "configVersion": 1,
                        "generatedAt": "2026-09-09T00:00:00Z",
                        "channels": [
                            {
                                "id": "cctv1",
                                "name": "CCTV1",
                                "group": "央视频道",
                                "sources": [
                                    {
                                        "id": "bad",
                                        "priority": 1,
                                        "protocol": "https",
                                        "url": "https://stream.example/a.m3u8?token=secret",
                                    }
                                ],
                            }
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                verify_bundle(root)


if __name__ == "__main__":
    unittest.main()
