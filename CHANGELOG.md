## Changelog

All notable changes to this project will be documented in this file.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and uses semantic versioning where practical.

### [0.7.0] - 2025-08-11
#### Added
- Support for PTN protocol variant (`protocol_version='ptn'`): multi-line `STA_VIDEO.` status parsing, `OUTXX:YY.` switching.
- Protocol auto-detection over TCP/IP (`protocol_version='auto'`).
- Firmware `version()` query (PTN `STA.` parsing; caches result).
- Status caching for PTN plus `refresh_status()` (sync & async) to force reload.
- Probe utility enhancements (`examples/probe_blackbird.py`): auto protocol, version display, JSON output (`--json`), cache refresh (`--refresh`).
- Manual protocol detection documentation (netcat variants, PowerShell note).
- Asynchronous TCP socket client (`get_async_blackbird_socket`) with auto-detect, PTN caching and version query parity.
- Async probe script (`examples/async_probe_blackbird.py`) with zone mapping, JSON output, version-only mode, and raw debug dump.
- Debug raw STA. response flag (`--debug-raw-version`) for diagnostics.
- PTN error-path and async test coverage (malformed line handling, version variants, cache invalidation, auto-detect failure).
- Unified exception hierarchy: `BlackbirdError` base plus `BlackbirdConnectionError`, `BlackbirdProtocolDetectionError`, `BlackbirdTimeoutError` for clearer consumer error handling (replaces bare RuntimeError / asyncio.TimeoutError in public flows).

#### Changed
- Increased default TIMEOUT from 2s to 5s to accommodate slower multi-line PTN responses.
- README expanded with protocol, auto-detect, version, and troubleshooting guidance.
- Extended system info (`STA.`) retrieval to wait briefly after first newline to collect full delayed multi-line output (fixes truncated version fetch on some firmware).
- Auto-detect failures now raise `BlackbirdProtocolDetectionError` instead of `RuntimeError`.

#### Fixed
- Added Windows (no PTY) test coverage via dummy TCP socket server.
- Mitigated race conditions in PTN status tests by pre-populating responses.
- Version parsing now robust to late-arriving multi-line `STA.` output; firmware version correctly detected on devices emitting banner later.

### [0.6] - 202? (pre-history)
- Previous release before PTN/auto features (legacy protocol functionality).

### [0.5] - 2018 (historical)
- Earlier version referenced in setup.py prior to modernization.

---
Future: add async PTN test coverage, force refresh CLI option in probe, and Home Assistant config flow auto-detection example.
