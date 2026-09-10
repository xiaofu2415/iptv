import json
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(MODULE_DIR))

import m3u_to_starflow as converter  # noqa: E402

build_manifest = converter.build_manifest
convert_text = converter.convert_text
convert_files = converter.convert_files
redact_url = converter.redact_url
sanitize_url = converter.sanitize_url
write_bundle = converter.write_bundle


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


TXT = """央视频道,#genre#
CCTV1,http://one.example/cctv1.m3u8?key=txiptv&playlive=0&authid=0
CCTV1,http://two.example/cctv1.m3u8?key=txiptv&playlive=1&authid=0
CCTV17,https://live.example/cctv17?streamid=abc&livekey=xyz
电影频道,#genre#
老电影,https://vod.example/20221018/movie/index.m3u8
春晚频道,#genre#
2022年春晚,https://vod.example/archive.mp4
更新时间,#genre#
2026-09-09,https://vod.example/update.mp4
卫视频道,#genre#
录播卫视,https://txmov2.a.kwimgs.com/bs3/video-hls/5219953535631090825_hlsb.m3u8
海外公开频道,#genre#
CGTN,https://live.example/cgtn.m3u8
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

    def test_sanitize_preserves_required_stream_parameters(self):
        result = sanitize_url(
            "https://live.example/cctv17?streamid=abc&livekey=xyz&token=temporary"
        )
        self.assertTrue(result.ok)
        self.assertEqual(
            "https://live.example/cctv17?streamid=abc&livekey=xyz",
            result.url,
        )
        self.assertEqual(("token",), result.removed_keys)

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
        all_urls = [source["url"] for channel in result.channels for source in channel["sources"]]
        self.assertTrue(all("token=" not in url and "signature=" not in url for url in all_urls))
        self.assertEqual(result.live_m3u, result.live_txt)
        self.assertNotIn("secret", result.live_m3u)
        self.assertNotIn("temporary", result.live_m3u)
        self.assertEqual(
            {"lives": [{"name": "StarFlowTV", "playerType": 1, "type": 0, "url": "live.txt"}]},
            json.loads(result.tvbox_live_json),
        )

    def test_quality_gate_requires_core_categories_and_multi_line(self):
        result = convert_text(
            M3U,
            config_version=123,
            generated_at="2026-09-09T00:00:00Z",
            probe_fn=lambda url: (
                True
                if "backup" not in url and "unknown" not in url
                else {"status": "failed", "reason": "http_status_404"}
            ),
        )
        self.assertFalse(result.passed)
        self.assertIn("multi_line", result.report["qualityGate"]["failed"])

    def test_txt_catalog_keeps_multiple_cctv_lines_and_required_parameters(self):
        try:
            result = convert_text(
                TXT,
                config_version=123,
                generated_at="2026-09-09T00:00:00Z",
                probe_fn=lambda url: True,
                source_format="txt",
            )
        except TypeError as exc:
            self.fail("converter must support source_format=txt: %s" % exc)
        cctv1 = next(channel for channel in result.channels if channel["name"] == "CCTV1")
        self.assertEqual(2, len(cctv1["sources"]))
        cctv17 = next(channel for channel in result.channels if channel["name"] == "CCTV17")
        self.assertIn("streamid=abc", cctv17["sources"][0]["url"])
        self.assertIn("livekey=xyz", cctv17["sources"][0]["url"])

    def test_core_cctv_lines_are_retained_when_probe_has_network_failure(self):
        result = convert_text(
            TXT,
            config_version=123,
            generated_at="2026-09-09T00:00:00Z",
            probe_fn=lambda url: {"status": "failed", "reason": "request_failed"},
            require_quality_gate=False,
            source_format="txt",
        )
        names = {channel["name"] for channel in result.channels}
        self.assertEqual({"CCTV1", "CCTV17"}, names)
        retained = [item for item in result.report["accepted"] if item["status"] == "unverified"]
        self.assertEqual(3, len(retained))

    def test_core_cctv_lines_are_not_retained_when_probe_proves_vod(self):
        result = convert_text(
            TXT,
            config_version=123,
            generated_at="2026-09-09T00:00:00Z",
            probe_fn=lambda url: {"status": "failed", "reason": "not_live_playlist"},
            require_quality_gate=False,
            source_format="txt",
        )
        self.assertEqual([], result.channels)

    def test_txt_catalog_drops_historical_and_vod_groups(self):
        try:
            result = convert_text(
                TXT,
                config_version=123,
                generated_at="2026-09-09T00:00:00Z",
                probe_fn=lambda url: True,
                source_format="txt",
            )
        except TypeError as exc:
            self.fail("converter must support source_format=txt: %s" % exc)
        names = {channel["name"] for channel in result.channels}
        self.assertEqual({"CCTV1", "CCTV17", "CGTN"}, names)

    def test_generated_groups_show_source_label(self):
        try:
            result = convert_text(
                TXT,
                config_version=123,
                generated_at="2026-09-09T00:00:00Z",
                probe_fn=lambda url: True,
                source_format="txt",
            )
        except TypeError as exc:
            self.fail("converter must support source_format=txt: %s" % exc)
        self.assertTrue(all("｜来源：iptv" in channel["group"] for channel in result.channels))

    def test_multiple_input_formats_are_merged_without_losing_cctv_lines(self):
        m3u = """#EXTM3U
#EXTINF:-1 tvg-id="CCTV1" group-title="央视频道",CCTV1
https://one.example/cctv1.m3u8?id=one
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.m3u").write_text(m3u, encoding="utf-8")
            (root / "source.txt").write_text(
                "央视频道,#genre#\nCCTV1,https://two.example/cctv1.m3u8?id=two\n",
                encoding="utf-8",
            )
            result = convert_files(
                [root / "source.m3u", root / "source.txt"],
                config_version=123,
                generated_at="2026-09-09T00:00:00Z",
                probe_fn=lambda url: True,
            )
        cctv1 = next(channel for channel in result.channels if channel["name"] == "CCTV1")
        self.assertEqual(2, len(cctv1["sources"]))

    def test_hls_vod_playlist_is_not_live(self):
        body = b"#EXTM3U\n#EXT-X-PLAYLIST-TYPE:VOD\n#EXTINF:6,\na.ts\n#EXT-X-ENDLIST\n"
        classifier = getattr(converter, "classify_playlist_body", None)
        self.assertTrue(callable(classifier), "classify_playlist_body must be implemented")
        if callable(classifier):
            self.assertEqual((False, "not_live_playlist"), classifier(body))

    def test_hls_live_playlist_without_endlist_is_live(self):
        body = b"#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:42\n#EXTINF:6,\na.ts\n"
        classifier = getattr(converter, "classify_playlist_body", None)
        self.assertTrue(callable(classifier), "classify_playlist_body must be implemented")
        if callable(classifier):
            self.assertEqual((True, ""), classifier(body))

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

    def test_bundle_and_manifest_have_consistent_hashes_and_urls(self):
        with self.subTest("bundle"):
            result = convert_text(
                M3U,
                config_version=123,
                generated_at="2026-09-09T00:00:00Z",
                probe_fn=lambda url: True,
            )
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                write_bundle(result, output)
                manifest = build_manifest(
                    output,
                    "https://config.example/starflow/config",
                    123,
                    "2026-09-09T00:00:00Z",
                    "test-key",
                )
                self.assertEqual(
                    {"live.json", "live.m3u", "live.txt", "tvbox-live.json", "checksums.sha256"},
                    {entry["name"] for entry in manifest["files"]},
                )
                self.assertTrue(
                    all(
                        entry["url"].startswith(
                            "https://config.example/starflow/config/releases/123/"
                        )
                        for entry in manifest["files"]
                    )
                )
                live_json = next(
                    entry for entry in manifest["files"] if entry["name"] == "live.json"
                )
                self.assertEqual(live_json["size"], (output / "live.json").stat().st_size)


if __name__ == "__main__":
    unittest.main()
