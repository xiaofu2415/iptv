#!/usr/bin/env python3
"""Convert an upstream M3U into a validated StarFlowTV live bundle."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import unquote_plus, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen


SUPPORTED_SCHEMES = frozenset(("http", "https", "rtsp", "rtp", "udp"))
TEMPORARY_QUERY_KEYS = frozenset(
    (
        "access_token",
        "apikey",
        "api_key",
        "auth",
        "authorization",
        "password",
        "session",
        "sessionid",
        "sig",
        "signature",
        "token",
        "expires",
        "exp",
        "nonce",
    )
)
PUBLIC_QUERY_KEYS = frozenset(("key", "playlive", "authid", "id"))
PUBLIC_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
DIGITS = re.compile(r"^[0-9]+$")
INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
ATTRIBUTE = re.compile(r'([A-Za-z0-9_-]+)\s*=\s*"([^"]*)"')
ID_ALLOWED = re.compile(r"[^a-z0-9._-]+")

MEDIA_TYPES = {
    "live.json": "application/json",
    "live.m3u": "application/vnd.apple.mpegurl",
    "live.txt": "text/plain",
    "tvbox-live.json": "application/json",
    "epg.xml": "application/xml",
    "checksums.sha256": "text/plain",
}


@dataclass(frozen=True)
class SanitizeResult:
    ok: bool
    url: str = ""
    removed_keys: Tuple[str, ...] = ()
    reason: str = ""


@dataclass(frozen=True)
class M3UEntry:
    attributes: Dict[str, str]
    name: str
    url: str


@dataclass
class ConversionResult:
    channels: List[Dict[str, object]]
    live_json: str
    live_m3u: str
    live_txt: str
    tvbox_live_json: str
    report: Dict[str, object]
    passed: bool


def _strict_unquote(value: str) -> str:
    if INVALID_PERCENT_ESCAPE.search(value):
        raise ValueError("invalid_percent_escape")
    return unquote_plus(value, encoding="utf-8", errors="strict")


def _parse_query(raw_query: str) -> List[Tuple[str, str]]:
    if not raw_query:
        return []
    pairs: List[Tuple[str, str]] = []
    for component in raw_query.split("&"):
        if not component:
            raise ValueError("empty_query_parameter")
        raw_key, separator, raw_value = component.partition("=")
        if not separator or not raw_key:
            raise ValueError("malformed_query_parameter")
        pairs.append((_strict_unquote(raw_key), _strict_unquote(raw_value)))
    return pairs


def _public_parameter(key: str, value: str) -> Optional[Tuple[str, str]]:
    normalized = key.lower()
    if normalized == "key" and value.lower() == "txiptv":
        return "key", "txiptv"
    if normalized == "playlive" and value in ("0", "1"):
        return "playlive", value
    if normalized == "authid" and DIGITS.fullmatch(value):
        return "authid", value
    if normalized == "id" and PUBLIC_ID.fullmatch(value):
        return "id", value
    return None


def sanitize_url(raw_url: str) -> SanitizeResult:
    """Remove temporary/unknown query parameters and validate the final URL."""

    if raw_url is None:
        return SanitizeResult(False, reason="empty_url")
    try:
        parts = urlsplit(raw_url.strip())
        scheme = parts.scheme.lower()
        if scheme not in SUPPORTED_SCHEMES:
            return SanitizeResult(False, reason="unsupported_scheme")
        if not parts.hostname or parts.username is not None or parts.password is not None:
            return SanitizeResult(False, reason="unsafe_authority")
        if parts.fragment:
            return SanitizeResult(False, reason="fragment_not_allowed")
        _ = parts.port
        query = _parse_query(parts.query)
    except ValueError as exc:
        return SanitizeResult(False, reason=str(exc) or "invalid_url")
    except Exception:
        return SanitizeResult(False, reason="invalid_url")

    kept: List[Tuple[str, str]] = []
    removed: List[str] = []
    for key, value in query:
        normalized = key.lower()
        if normalized in PUBLIC_QUERY_KEYS:
            public_value = _public_parameter(key, value)
            if public_value is None:
                return SanitizeResult(False, removed_keys=tuple(removed), reason="invalid_public_parameter")
            kept.append(public_value)
        elif normalized in TEMPORARY_QUERY_KEYS:
            removed.append(normalized)
        else:
            removed.append(normalized)

    canonical = urlunsplit(
        (
            scheme,
            parts.netloc,
            parts.path,
            urlencode(kept),
            "",
        )
    )
    return SanitizeResult(True, url=canonical, removed_keys=tuple(removed))


def redact_url(url: str) -> str:
    """Keep URL shape and parameter names while hiding every parameter value."""

    try:
        parts = urlsplit(url)
        if not parts.query:
            return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        redacted: List[str] = []
        for component in parts.query.split("&"):
            raw_key = component.split("=", 1)[0]
            try:
                key = _strict_unquote(raw_key)
            except Exception:
                key = "<invalid>"
            redacted.append(urlencode(((key, "***"),)))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(redacted), ""))
    except Exception:
        return "<invalid-url>"


def probe_url(url: str, timeout: float = 5.0, retries: int = 2) -> Dict[str, object]:
    """Perform a bounded request against the sanitized URL."""

    request = Request(
        url,
        headers={
            "Accept": "application/vnd.apple.mpegurl, application/x-mpegURL, "
            "application/vnd.apple.mpegurl.audio, */*",
            "User-Agent": "StarFlowTV-source-check/1.0",
        },
    )
    last_reason = "request_failed"
    for _ in range(max(1, retries)):
        try:
            with urlopen(request, timeout=timeout) as response:
                status = int(response.getcode() or 0)
                body = response.read(8192)
                if status < 200 or status >= 400:
                    last_reason = "http_status"
                    continue
                content_type = response.headers.get("Content-Type", "").lower()
                path = urlsplit(response.geturl() or url).path.lower()
                looks_like_playlist = (
                    path.endswith((".m3u8", ".m3u"))
                    or "mpegurl" in content_type
                    or "vnd.apple" in content_type
                )
                if looks_like_playlist and b"#EXTM3U" not in body:
                    last_reason = "not_m3u_playlist"
                    continue
                if not body:
                    last_reason = "empty_response"
                    continue
                return {"status": "passed", "httpStatus": status}
        except HTTPError as exc:
            last_reason = "http_status_%s" % exc.code
        except (URLError, TimeoutError, OSError):
            last_reason = "request_failed"
        except Exception:
            last_reason = "request_failed"
    return {"status": "failed", "reason": last_reason}


def parse_m3u(text: str) -> Tuple[str, List[M3UEntry]]:
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    header = "#EXTM3U"
    pending: Optional[Tuple[Dict[str, str], str]] = None
    entries: List[M3UEntry] = []
    for raw_line in lines:
        line = raw_line.strip().lstrip("\ufeff")
        if not line:
            continue
        if line.startswith("#EXTM3U"):
            header = line
            continue
        if line.startswith("#EXTINF"):
            metadata, separator, name = line.partition(",")
            if not separator:
                continue
            attrs = {key.lower(): value.strip() for key, value in ATTRIBUTE.findall(metadata)}
            pending = (attrs, name.strip() or attrs.get("tvg-name", "").strip())
            continue
        if line.startswith("#") or pending is None:
            continue
        attrs, name = pending
        entries.append(M3UEntry(dict(attrs), name, line))
        pending = None
    return header, entries


def _channel_id(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value or "").lower()
    ascii_value = normalized.encode("ascii", "ignore").decode("ascii")
    slug = ID_ALLOWED.sub("-", ascii_value).strip("-._")
    if not slug:
        slug = "channel-" + hashlib.sha256((value or "channel").encode("utf-8")).hexdigest()[:12]
    return slug[:64]


def _safe_attribute(value: str) -> str:
    return (value or "").replace('"', "'").replace("\r", " ").replace("\n", " ").strip()


def _probe_state(value: object) -> Tuple[str, str]:
    if isinstance(value, bool):
        return ("passed", "") if value else ("failed", "probe_failed")
    if isinstance(value, dict):
        status = str(value.get("status", "")).lower()
        passed = status in ("passed", "ok", "valid", "available") or value.get("ok") is True
        return ("passed", "") if passed else ("failed", str(value.get("reason", "probe_failed")))
    return "failed", "invalid_probe_result"


def quality_gate(
    channels: Sequence[Dict[str, object]],
    line_statuses: Dict[str, Sequence[str]],
) -> Dict[str, object]:
    cctv = any(
        "CCTV" in ("%s %s" % (channel.get("name", ""), channel.get("group", ""))).upper()
        for channel in channels
    )
    satellite_count = sum(
        "卫视" in ("%s %s" % (channel.get("name", ""), channel.get("group", "")))
        for channel in channels
    )
    multi_line = any(
        sum(status == "passed" for status in line_statuses.get(str(channel.get("id")), ())) >= 2
        for channel in channels
    )
    failed: List[str] = []
    if not cctv:
        failed.append("cctv")
    if satellite_count < 2:
        failed.append("satellite")
    if not multi_line:
        failed.append("multi_line")
    return {
        "passed": not failed,
        "cctv": cctv,
        "satelliteChannels": satellite_count,
        "multiLine": multi_line,
        "failed": failed,
    }


def convert_text(
    text: str,
    config_version: int,
    generated_at: Optional[str] = None,
    probe_fn: Optional[Callable[[str], object]] = None,
    require_quality_gate: bool = True,
    probe_workers: int = 8,
) -> ConversionResult:
    if config_version <= 0:
        raise ValueError("config_version_must_be_positive")
    header, entries = parse_m3u(text)
    generated_at = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    report: Dict[str, object] = {
        "inputEntries": len(entries),
        "accepted": [],
        "dropped": [],
        "qualityGate": {},
    }
    accepted_report = report["accepted"]
    dropped_report = report["dropped"]
    assert isinstance(accepted_report, list)
    assert isinstance(dropped_report, list)

    candidates: List[Tuple[M3UEntry, str, SanitizeResult]] = []
    seen_urls: Dict[str, str] = {}
    for entry in entries:
        label = entry.name or entry.attributes.get("tvg-name", "")
        sanitized = sanitize_url(entry.url)
        if not sanitized.ok:
            dropped_report.append(
                {"channel": label, "reason": sanitized.reason, "url": redact_url(entry.url)}
            )
            continue
        if sanitized.url in seen_urls:
            dropped_report.append(
                {
                    "channel": label,
                    "reason": "duplicate_url",
                    "url": redact_url(sanitized.url),
                    "firstChannel": seen_urls[sanitized.url],
                }
            )
            continue
        seen_urls[sanitized.url] = label
        channel_value = entry.attributes.get("tvg-id") or entry.attributes.get("tvg-name") or label
        candidates.append((entry, _channel_id(channel_value), sanitized))

    probe_results: Dict[str, Tuple[str, str]] = {}
    if probe_fn is not None and candidates:
        urls = [
            sanitized.url
            for _, _, sanitized in candidates
            if urlsplit(sanitized.url).scheme.lower() in ("http", "https")
        ]
        worker_count = max(1, min(probe_workers, len(urls)))
        if urls:
            with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
                values = executor.map(probe_fn, urls)
                for url, value in zip(urls, values):
                    probe_results[url] = _probe_state(value)

    channel_data: Dict[str, Dict[str, object]] = {}
    line_statuses: Dict[str, List[str]] = {}
    for entry, channel_id, sanitized in candidates:
        if probe_fn is None:
            status, reason = "skipped", "not_probed"
        elif urlsplit(sanitized.url).scheme.lower() not in ("http", "https"):
            status, reason = "skipped", "non_http_not_probed"
        else:
            status, reason = probe_results.get(sanitized.url, ("failed", "probe_missing"))
        if status == "failed":
            dropped_report.append(
                {
                    "channel": entry.name,
                    "reason": reason,
                    "url": redact_url(sanitized.url),
                }
            )
            continue
        channel = channel_data.setdefault(
            channel_id,
            {
                "epgId": entry.attributes.get("tvg-id", ""),
                "group": entry.attributes.get("group-title", "") or "直播",
                "id": channel_id,
                "logo": entry.attributes.get("tvg-logo", ""),
                "name": entry.name or entry.attributes.get("tvg-name", "") or channel_id,
                "sources": [],
            },
        )
        sources = channel["sources"]
        assert isinstance(sources, list)
        sources.append(
            {
                "id": "source-" + hashlib.sha256(sanitized.url.encode("utf-8")).hexdigest()[:12],
                "priority": len(sources) + 1,
                "protocol": urlsplit(sanitized.url).scheme.lower(),
                "url": sanitized.url,
            }
        )
        line_statuses.setdefault(channel_id, []).append(status)
        accepted_report.append(
            {
                "channel": channel["name"],
                "status": status,
                "removedKeys": list(sanitized.removed_keys),
                "url": redact_url(sanitized.url),
            }
        )

    channels = list(channel_data.values())
    gate = quality_gate(channels, line_statuses)
    report["qualityGate"] = gate
    report["channelCount"] = len(channels)
    report["lineCount"] = sum(len(channel["sources"]) for channel in channels)
    report["probeMode"] = "enabled" if probe_fn is not None else "skipped"
    passed = bool(gate["passed"]) if require_quality_gate else True

    live_payload = {
        "schemaVersion": 1,
        "configVersion": int(config_version),
        "generatedAt": generated_at,
        "channels": channels,
    }
    live_json = json.dumps(live_payload, ensure_ascii=False, indent=2) + "\n"
    m3u_lines = [header]
    for channel in channels:
        for source in channel["sources"]:
            m3u_lines.append(
                '#EXTINF:-1 tvg-name="%s" tvg-id="%s" tvg-logo="%s" group-title="%s",%s'
                % (
                    _safe_attribute(str(channel["name"])),
                    _safe_attribute(str(channel["epgId"])),
                    _safe_attribute(str(channel["logo"])),
                    _safe_attribute(str(channel["group"])),
                    _safe_attribute(str(channel["name"])),
                )
            )
            m3u_lines.append(str(source["url"]))
    live_m3u = "\n".join(m3u_lines) + "\n"
    tvbox_live_json = (
        json.dumps(
            {"lives": [{"name": "StarFlowTV", "playerType": 1, "type": 0, "url": "live.txt"}]},
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    )
    return ConversionResult(
        channels=channels,
        live_json=live_json,
        live_m3u=live_m3u,
        live_txt=live_m3u,
        tvbox_live_json=tvbox_live_json,
        report=report,
        passed=passed,
    )


def write_bundle(
    result: ConversionResult,
    output_dir: Path,
    epg_path: Optional[Path] = None,
) -> List[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    payloads = {
        "live.json": result.live_json.encode("utf-8"),
        "live.m3u": result.live_m3u.encode("utf-8"),
        "live.txt": result.live_txt.encode("utf-8"),
        "tvbox-live.json": result.tvbox_live_json.encode("utf-8"),
    }
    if epg_path is not None and epg_path.is_file():
        payloads["epg.xml"] = epg_path.read_bytes()
    paths: List[Path] = []
    for name, content in payloads.items():
        path = output_dir / name
        path.write_bytes(content)
        paths.append(path)
    checksum_lines = [
        "%s  %s" % (hashlib.sha256(payloads[name]).hexdigest(), name)
        for name in sorted(payloads)
    ]
    checksum_path = output_dir / "checksums.sha256"
    checksum_path.write_text("\n".join(checksum_lines) + "\n", encoding="ascii")
    paths.append(checksum_path)
    return paths


def build_manifest(
    output_dir: Path,
    base_url: str,
    config_version: int,
    generated_at: str,
    key_id: str,
    published_at: Optional[str] = None,
) -> Dict[str, object]:
    base_url = base_url.rstrip("/")
    files: List[Dict[str, object]] = []
    for name in MEDIA_TYPES:
        path = output_dir / name
        if not path.is_file():
            continue
        data = path.read_bytes()
        files.append(
            {
                "mediaType": MEDIA_TYPES[name],
                "name": name,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
                "url": "%s/releases/%s/%s" % (base_url, config_version, name),
            }
        )
    if not any(item["name"] == "live.json" for item in files) or not any(
        item["name"] == "live.txt" for item in files
    ):
        raise ValueError("manifest_requires_live_json_and_live_txt")
    return {
        "catalogId": "starflow-live",
        "configVersion": int(config_version),
        "files": files,
        "generatedAt": generated_at,
        "keyId": key_id,
        "publishedAt": published_at or generated_at,
        "schemaVersion": 1,
        "signatureAlgorithm": "Ed25519",
        "signatureStatus": "pending",
    }


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, dest="input_path")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--config-version", required=True, type=int)
    parser.add_argument("--report", required=True)
    parser.add_argument("--base-url")
    parser.add_argument("--key-id", default="starflow-production-2026-01")
    parser.add_argument("--epg")
    parser.add_argument("--probe-http", action="store_true")
    parser.add_argument("--no-probe", action="store_true")
    parser.add_argument("--allow-unverified", action="store_true")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--probe-workers", type=int, default=12)
    args = parser.parse_args(argv)
    if args.probe_http and args.no_probe:
        parser.error("--probe-http and --no-probe are mutually exclusive")
    input_path = Path(args.input_path)
    output_dir = Path(args.output_dir)
    text = input_path.read_text(encoding="utf-8-sig")
    probe_fn = None
    if args.probe_http:
        probe_fn = lambda url: probe_url(url, timeout=args.timeout, retries=args.retries)
    result = convert_text(
        text,
        config_version=args.config_version,
        probe_fn=probe_fn,
        require_quality_gate=not args.allow_unverified,
        probe_workers=args.probe_workers,
    )
    write_bundle(result, output_dir, Path(args.epg) if args.epg else None)
    _write_json(Path(args.report), result.report)
    if args.base_url:
        generated_at = json.loads(result.live_json)["generatedAt"]
        manifest = build_manifest(
            output_dir,
            args.base_url,
            args.config_version,
            generated_at,
            args.key_id,
        )
        _write_json(output_dir / "manifest.json", manifest)
    if not result.passed:
        print("quality gate failed: %s" % ",".join(result.report["qualityGate"]["failed"]), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
