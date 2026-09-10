# StarFlowTV Live Source Merge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore the complete CCTV1–CCTV17 candidate set from the Forked IPTV source, merge it with the synchronized upstream catalog, and prevent historical/VOD and obviously non-live entries from reaching StarFlowTV.

**Architecture:** Parse both upstream `tv/iptv4.m3u` and the richer `tv/iptv4.txt` catalog, deduplicate only after URL sanitization, and apply a live-source policy before probing. Keep all surviving lines grouped by canonical channel, append a visible `｜来源：iptv` suffix to generated group names, and retain multiple fallback lines instead of replacing a channel with one probe result.

**Tech Stack:** Python 3.12, `unittest`, GitHub Actions, StarFlowTV signed JSON/M3U bundle.

**Spec:** `../repos/StarFlowTV/docs/superpowers/specs/2026-09-05-starflowtv-design.md`

## Global Constraints

- Source collection remains based on `xiaofu2415/iptv`, synchronized from `vbskycn/iptv`.
- The VPS/1Panel host remains static distribution only; source probing runs in GitHub Actions.
- Preserve required playback parameters such as `key`, `playlive`, `authid`, `streamid`, and `livekey`; redact values only in reports.
- Do not publish obvious VOD or historical entries such as movie, Spring Festival archive, update-video, and MP4 records.
- Preserve multiple lines per channel, including the CCTV1–CCTV17 lines present in `tv/iptv4.txt`.
- A network-only probe failure must not delete a core CCTV1–CCTV17 candidate; retain it as `unverified` and record the probe reason. A probe result that proves VOD/non-live must still delete it.
- The existing signing key and APK key-rotation work are out of scope for this change.

### Task 1: Add failing tests for richer input and live-only filtering

**Files:**
- Modify: `tools/starflow/test_m3u_to_starflow.py`
- Test: `tools/starflow/test_m3u_to_starflow.py`

**Interfaces:**
- The tests will define the required behavior for `parse_txt`, `parse_source_text`, and the conversion option that excludes non-live source groups.

- [ ] **Step 1: Write the failing tests**

Add tests that prove:

```python
TXT = """央视频道,#genre#
CCTV1,http://one.example/cctv1.m3u8?key=txiptv&playlive=0&authid=0
CCTV1,http://two.example/cctv1.m3u8?key=txiptv&playlive=1&authid=0
CCTV17,https://live.example/cctv17?streamid=abc&livekey=xyz
电影频道,#genre#
老电影,https://vod.example/20221018/movie/index.m3u8
春晚频道,#genre#
2022年春晚,https://vod.example/archive.mp4
海外公开频道,#genre#
CGTN,https://live.example/cgtn.m3u8
"""

def test_txt_catalog_keeps_multiple_cctv_lines_and_required_parameters():
    result = convert_text(TXT, 123, probe_fn=lambda url: True, source_format="txt")
    cctv1 = next(channel for channel in result.channels if channel["name"] == "CCTV1")
    assert len(cctv1["sources"]) == 2
    cctv17 = next(channel for channel in result.channels if channel["name"] == "CCTV17")
    assert "streamid=abc" in cctv17["sources"][0]["url"]
    assert "livekey=xyz" in cctv17["sources"][0]["url"]

def test_txt_catalog_drops_historical_and_vod_groups():
    result = convert_text(TXT, 123, probe_fn=lambda url: True, source_format="txt")
    names = {channel["name"] for channel in result.channels}
    assert names == {"CCTV1", "CCTV17", "CGTN"}

def test_generated_groups_show_source_label():
    result = convert_text(TXT, 123, probe_fn=lambda url: True, source_format="txt")
    assert all("｜来源：iptv" in channel["group"] for channel in result.channels)
```

- [ ] **Step 2: Run tests to verify they fail for the expected reason**

Run: `python -m unittest tools/starflow/test_m3u_to_starflow.py -v` from the worktree root.

Expected: FAIL because the converter cannot parse the TXT catalog, drops required unknown query parameters, and has no source-group filtering or source label.

### Task 2: Implement catalog parsing, source merging, and live-source policy

**Files:**
- Modify: `tools/starflow/m3u_to_starflow.py`
- Modify: `tools/starflow/test_m3u_to_starflow.py`
- Modify: `.github/workflows/sync-upstream.yml`
- Modify: `tools/starflow/README.md`

**Interfaces:**
- `parse_txt(text: str) -> Tuple[str, List[M3UEntry]]` parses the upstream `name,url`/`,#genre#` catalog.
- `parse_source_text(text: str, source_format: str = "auto") -> Tuple[str, List[M3UEntry]]` selects M3U or TXT parsing.
- CLI accepts repeatable `--input` paths and `--source-format auto|m3u|txt`.
- `convert_text(..., source_format="m3u", source_label="iptv")` remains backward compatible for existing tests and callers.

- [ ] **Step 1: Implement only the smallest parser and policy needed by the failing tests**

Implement TXT section parsing with `tvg-name`, a canonical `tvg-id` derived from the name, and `group-title`. Apply these source exclusions before probing:

```python
EXCLUDED_GROUP_MARKERS = ("电影", "春晚", "更新时间")
NON_LIVE_SUFFIXES = (".mp4", ".flv", ".mov", ".avi", ".mkv", ".mp3")
ARCHIVE_PATH_MARKERS = ("/video-hls/", "/upic/", "/playback/", "/vod/")
```

Reject a candidate when its group or channel label is an excluded archive/update label, when its URL is an obvious downloadable media file, or when its path is a known archive/clip path. Keep all URLs that pass this policy, including required query parameters; only known temporary credentials remain removable. Core CCTV candidates that fail only because of a network/HTTP availability probe are retained as unverified fallbacks.

- [ ] **Step 2: Run the focused tests to verify they pass**

Run: `python -m unittest tools/starflow/test_m3u_to_starflow.py -v`.

Expected: PASS, including both CCTV1 lines, the CCTV17 required parameters, and the source suffix.

- [ ] **Step 3: Change the workflow to consume both upstream catalogs**

Replace the single input with:

```bash
test -s tv/iptv4.m3u
test -s tv/iptv4.txt
python tools/starflow/m3u_to_starflow.py \
  --input tv/iptv4.m3u \
  --input tv/iptv4.txt \
  --source-format auto \
  --source-label iptv \
  ...
```

Deduplicate after sanitization so entries available only in the richer TXT catalog are restored while entries shared by both files appear once.

- [ ] **Step 4: Update pipeline documentation**

Document that `iptv4.txt` is intentionally consumed for multiple fallback lines, archive groups are excluded, core CCTV lines survive network-only probe failures as unverified fallbacks, and generated group names carry `｜来源：iptv`.

### Task 3: Add regression coverage for HLS archive markers and generated output

**Files:**
- Modify: `tools/starflow/test_m3u_to_starflow.py`
- Modify: `tools/starflow/m3u_to_starflow.py`

**Interfaces:**
- `classify_playlist_body(body: bytes) -> Tuple[bool, str]` identifies an HLS VOD/endlisted playlist without network access.
- `probe_url` uses this classification after fetching a playlist body.

- [ ] **Step 1: Write the failing tests**

Add tests for these bodies:

```python
assert classify_playlist_body(b"#EXTM3U\n#EXT-X-PLAYLIST-TYPE:VOD\n#EXTINF:6,\na.ts\n#EXT-X-ENDLIST\n") == (False, "not_live_playlist")
assert classify_playlist_body(b"#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:42\n#EXTINF:6,\na.ts\n") == (True, "")
```

- [ ] **Step 2: Run the focused tests and verify the new tests fail**

Run: `python -m unittest tools/starflow/test_m3u_to_starflow.py -v`.

Expected: FAIL because no playlist-body classifier exists.

- [ ] **Step 3: Implement the classifier and connect it to HTTP probing**

Reject HLS bodies containing `#EXT-X-ENDLIST` or `#EXT-X-PLAYLIST-TYPE:VOD`; require at least one media segment for a media playlist. Keep master playlists valid for a later variant probe, and preserve redacted reporting.

- [ ] **Step 4: Run focused and full source-pipeline tests**

Run:

```bash
python -m unittest discover -s tools/starflow -p 'test_*.py' -v
```

Expected: all tests pass.

### Task 4: Generate and validate a representative merged bundle

**Files:**
- Create: `build/` files only as ignored verification output
- Test: `tools/starflow/verify_bundle.py`

- [ ] **Step 1: Generate from both current upstream files without publishing**

Run the converter against `tv/iptv4.m3u` and `tv/iptv4.txt` with a local deterministic probe function or the workflow probe settings, then inspect the report for CCTV coverage and archive drops.

- [ ] **Step 2: Verify required channel coverage and source labels**

Assert that the report/output includes CCTV1 through CCTV17 where candidates are present, multiple lines are retained when distinct, no generated group contains an excluded archive marker, and every group has `｜来源：iptv`.

- [ ] **Step 3: Run bundle verification**

Run `python tools/starflow/verify_bundle.py --bundle <generated-bundle> --public-key-b64 <configured-public-key>` and require a passing signature/hash/schema check before any deployment.

### Task 5: Review and publish only after verification

- [ ] **Step 1: Inspect the diff and report counts**

Run `git diff --check` and review the source report for channel count, line count, dropped archive reasons, and preserved CCTV lines.

- [ ] **Step 2: Commit the source-pipeline fix**

Commit with: `fix: merge full live catalog and filter archive sources`.

- [ ] **Step 3: Run the workflow manually with force rebuild and deploy enabled**

Use the existing GitHub Actions workflow inputs `force_rebuild=true` and `deploy=true`. Confirm the generation, signature, verification, and 1Panel atomic publish steps all pass before asking the user to pull the source on TV.

## Self-Review Checklist

- CCTV1–CCTV17 candidates come from `tv/iptv4.txt`, not only the reduced M3U.
- Historical/VOD groups and MP4 entries cannot reach `live.json`.
- Required playback query parameters are preserved in published URLs.
- Source provenance is visible in every group title.
- Existing StarFlowTV signing configuration is unchanged.
- A failed generation or verification cannot replace the 1Panel current bundle.
