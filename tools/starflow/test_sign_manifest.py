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

from sign_manifest import sign_manifest  # noqa: E402


class SignManifestTest(unittest.TestCase):
    def setUp(self):
        self.private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.private_key_b64 = base64.b64encode(
            self.private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        ).decode("ascii")
        self.public_key_b64 = base64.b64encode(
            self.private_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        ).decode("ascii")

    def test_signs_ready_manifest_and_verifies_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = root / "manifest.json"
            signature_path = root / "manifest.sig"
            digest_path = root / "manifest.sha256"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "configVersion": 123,
                        "keyId": "test-key",
                        "signatureStatus": "pending",
                        "files": [
                            {
                                "name": "live.json",
                                "size": 1,
                                "sha256": "0" * 64,
                                "url": "https://config.example/releases/123/live.json",
                                "mediaType": "application/json",
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            sign_manifest(
                manifest_path,
                signature_path,
                digest_path,
                self.private_key_b64,
                self.public_key_b64,
                "test-key",
            )
            payload = manifest_path.read_bytes()
            signature = base64.b64decode(signature_path.read_text(encoding="ascii"))
            self.private_key.public_key().verify(signature, payload)
            self.assertEqual(
                "ready",
                json.loads(manifest_path.read_text(encoding="utf-8"))["signatureStatus"],
            )
            self.assertIn("manifest.json", digest_path.read_text(encoding="ascii"))

    def test_rejects_key_mismatch_and_missing_key(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "manifest.json"
            signature_path = Path(directory) / "manifest.sig"
            digest_path = Path(directory) / "manifest.sha256"
            manifest_path.write_text('{"signatureStatus":"pending"}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                sign_manifest(
                    manifest_path,
                    signature_path,
                    digest_path,
                    self.private_key_b64,
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    "test-key",
                )
            with self.assertRaises(ValueError):
                sign_manifest(
                    manifest_path,
                    signature_path,
                    digest_path,
                    "",
                    self.public_key_b64,
                    "test-key",
                )


if __name__ == "__main__":
    unittest.main()
