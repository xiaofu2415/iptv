# StarFlowTV source pipeline

These scripts convert the upstream IPv4 M3U into the signed live configuration
consumed by StarFlowTV.

The URL policy deliberately keeps the public playback parameters used by the
upstream source:

- key=txiptv
- playlive=0|1
- numeric authid
- safe id values

Temporary authentication parameters such as token, signature, session, and
expires, as well as unknown parameters, never enter the generated
configuration. Probes run against the sanitized URL. Reports redact every
query value.

The workflow must run test_*.py, generate with --probe-http, sign the final
manifest, and run verify_bundle.py before uploading a release. A failed
quality gate must not update the 1Panel static directory.
