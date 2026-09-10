import unittest
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "sync-upstream.yml"
EXPECTED_PUBLIC_KEY = "kBZZK4w6OTEWuAQVUrXPK7AVo4kgktUZEV0wBVvrDFM="
EXPECTED_KEY_ID = "starflow-production-2026-09-r1"


class SigningConfigurationTest(unittest.TestCase):
    def test_source_workflow_uses_rotated_public_key_and_key_id(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(f"CONFIG_KEY_ID: ${{{{ vars.STARFLOW_CONFIG_KEY_ID || '{EXPECTED_KEY_ID}' }}}}", workflow)
        self.assertIn(f'CONFIG_PUBLIC_KEY_B64: "{EXPECTED_PUBLIC_KEY}"', workflow)


if __name__ == "__main__":
    unittest.main()
