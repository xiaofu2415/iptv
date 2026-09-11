# StarFlowTV source pipeline

These scripts convert the upstream IPv4 catalog into the signed live
configuration consumed by StarFlowTV.

The workflow reads the synchronized `tv/iptv4.m3u` and `tv/iptv4.txt` plus the
protected `tools/starflow/legacy-iptv4.m3u` snapshot. The TXT catalog is
intentional: it is the current upstream view, while the protected, already
sanitized snapshot retains the previous Fork candidates for CCTV1-CCTV17 and
international channels when an upstream refresh temporarily removes them.
Identical sanitized URLs are deduplicated only after all inputs are merged.

Generated groups carry the visible suffix `｜来源：iptv`, so a TV user can tell
that the catalog came from the `xiaofu2415/iptv` Fork synchronized from
`vbskycn/iptv`.

Archive/VOD groups such as movies, Spring Festival recordings, update videos,
music, commentary, record/documentary groups, and obvious downloadable media
are excluded before probing. The known CCTV13 Zhejiang `channel21` replay clip
is also excluded; other CCTV13 candidates are still evaluated independently.
HLS playlists marked VOD or ending with `#EXT-X-ENDLIST` are also rejected.
For CCTV1-CCTV17, a network-only probe failure is recorded as `unverified` and
kept as a fallback; a probe that proves the stream is VOD still removes it.

The URL policy deliberately keeps the public playback parameters used by the
upstream source:

- key=txiptv
- playlive=0|1
- numeric authid
- safe id values
- streamid and livekey when the source requires them for playback

Temporary authentication parameters such as token, signature, session, and
expires, as well as unknown parameters, never enter the generated
configuration. Required `streamid`/`livekey` values are preserved, while
reports redact every query value. Probes run against the sanitized URL.

The workflow must run test_*.py, generate with --probe-http, sign the final
manifest, and run verify_bundle.py before uploading a release. A failed
quality gate must not update the 1Panel static directory.
