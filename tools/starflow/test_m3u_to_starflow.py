import json
import sys
import unittest
from pathlib import Path

MODULE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(MODULE_DIR))

from m3u_to_starflow import convert_text, redact_url, sanitize_url  # noqa: E402


M3U = """#EXTM3U x-tvg-url="https://epg.example/e.xml"
#EXTINF:-1 tvg-id="CCTV1" tvg-name="CCTV1" tvg-logo="https://logo.example/cctv1.png" group-title="央视频道",CCTV1
http://stream.example/cctv1.m3u8?key=txiptv&playlive=0&authid=0&token=secret
#EXTINF:-1 tvg-id="CCTV1" tvg-name="CCTV1" tvg-logo="https://logo.example/cctv1.png" group-title="央视频道",CCTV1
http://stream.example/cctv1.m3u8?key=txiptv&playlive=0&authid=0&token=other
#EXTINF:-1 tvg-id="CCTV1" tvg-name="CCTV1" group-title="央视频道",CCTV1
http://backup.example/cctv1.m3u8?id=cctv1hd&signature=temporary
#EXTINF:-1 tvg-id="HUNAN" tvg-name="湖南卫视" tvg-logo="https://logo.example/hunan.png" group-title="卫视频道",湖南卫视
https://stream.example/hunan.m3u8?id=hunan&signature=temporary
#EXTINF:-1 tvg-id="ZHEJIANG" tvg-name="浙江卫视" group-title="卫视频道",浙江卫视
https://stream.example/zhejiang.m3u8?id=zhejiang&expires=123
#EXTINF:-1 tvg-id="UNKNOWN" group-title="测试",未知线路
https://stream.example/unknown.m3u8?quality=hd
"""


class M3UToStarflowTest(unittest.TestCase):
    def test_sanitize_preserves_public_parameters_and_removes_temporary_values(self):
        result = sanitize_url(
            "http://stream.example/live.m3u8?key=txiptv&playlive=0"
            "&authid=0&token=secret&signature=temporary"
        )
        self.assertTrue(result.ok)
        self.assertEqual(
            "http://stream.example/live.m3u8?key=txiptv&playlive=0&authid=0",
            result.url,
        )
        self.assertEqual(("token", "signature"), result.removed_keys)
        self.assertNotIn("secret", redact_url(result.url))

    def test_sanitize_rejects_unknown_public_key_value_and_malformed_url(self):
        self.assertFalse(sanitize_url("http://stream.example/live.m3u8?key=unknown").ok)
        self.assertFalse(sanitize_url("http://stream.example/live.m3u8?bad=%ZZ").ok)
        self.assertFalse(sanitize_url("not-a-url").ok)
        self.assertFalse(sanitize_url("http://user:password@stream.example/live.m3u8").ok)

    def test_conversion_keeps_multiple_lines_and_removes_sensitive_values(self):
        result = convert_text(
            M3U,
            config_version=123,
            generated_at="2026-09-09T00:00:00Z",
            probe_fn=lambda url: "unknown" not in url,
        )
        self.assertTrue(result.passed)
        self.assertEqual(3, len(result.channels))
        cctv1 = next(channel for channel in result.channels if channel["id"] == "cctv1")
        self.assertEqual(2, len(cctv1["sources"]))
        self.assertEqual(
            "http://stream.example/cctv1.m3u8?key=txiptv&playlive=0&authid=0",
            cctv1["sources"][0]["url"],
        )
        all_urls = [
            source["url"]
            for channel in result.channels
            for source in channel["sources"]
        ]
        self.assertTrue(
            all("token=" not in url and "signature=" not in url for url in all_urls)
        )
        self.assertEqual(result.live_m3u, result.live_txt)
        self.assertNotIn("secret", result.live_m3u)
        self.assertNotIn("temporary", result.live_m3u)
        self.assertEqual(
            {
                "lives": [
                    {"name": "StarFlowTV", "playerType": 1, "type": 0, "url": "live.txt"}
                ]
            },
            json.loads(result.tvbox_live_json),
        )

    def test_quality_gate_requires_core_categories_and_multi_line(self):
        result = convert_text(
            M3U,
            config_version=123,
            generated_at="2026-09-09T00:00:00Z",
            probe_fn=lambda url: "backup" not in url and "unknown" not in url,
        )
        self.assertFalse(result.passed)
        self.assertIn("multi_line", result.report["qualityGate"]["failed"])

    def test_report_is_redacted(self):
        result = convert_text(
            M3U,
            config_version=123,
            generated_at="2026-09-09T00:00:00Z",
            probe_fn=lambda url: True,
        )
        report_text = json.dumps(result.report, ensure_ascii=False)
        self.assertNotIn("secret", report_text)
        self.assertNotIn("temporary", report_text)
        self.assertNotIn("token=", report_text)


if __name__ == "__main__":
    unittest.main()
