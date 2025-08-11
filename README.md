## Status
[![Build Status](https://travis-ci.org/koolsb/pyblackbird.svg?branch=master)](https://travis-ci.org/koolsb/pyblackbird)[![Coverage Status](https://coveralls.io/repos/github/koolsb/pyblackbird/badge.svg)](https://coveralls.io/github/koolsb/pyblackbird)
# pyblackbird
Python3 interface implementation for Monoprice Blackbird 4k 8x8 HDBaseT Matrix

## Notes
This is for use with [Home-Assistant](http://home-assistant.io)

## Usage
```python
from pyblackbird import get_blackbird, get_async_blackbird_socket

# Connect via serial port
blackbird = get_blackbird('/dev/ttyUSB0')

# Connect via IP
blackbird = get_blackbird('192.168.1.50', use_serial=False)

# For newer PTN-based firmware (e.g. v1.0.1) using the alternative protocol
# where commands end with a period only and status is multi-line via STA_VIDEO.
# Provide protocol_version='ptn'.
blackbird = get_blackbird('/dev/ttyUSB0', protocol_version='ptn')
# Connect to a PTN-based Blackbird via IP (port 4001 by default)
blackbird = get_blackbird('192.168.1.50', use_serial=False, protocol_version='ptn')


# Print system lock status
print('System Lock is {}'.format('On' if blackbird.lock_status() else 'Off'))

# Valid zones are 1-8
zone_status = blackbird.zone_status(1)

# Print zone status
print('Zone Number = {}'.format(zone_status.zone))
print('Zone Power is {}'.format('On' if zone_status.power else 'Off'))
print('AV Source = {}'.format(zone_status.av))
print('IR Source = {}'.format(zone_status.ir))

# Turn off zone #1
blackbird.set_power(1, False)

# Set source 5 for zone #1
blackbird.set_zone_source(1, 5)

# Set all zones to source 2
blackbird.set_all_zone_source(2)

# Lock system buttons
blackbird.lock_front_buttons()

# Unlock system buttons
blackbird.unlock_front_buttons()

```

### Asynchronous socket usage
An asyncio-native TCP client is available (no serial dependency) supporting legacy, PTN, and auto protocol detection:

```python
import asyncio
from pyblackbird import get_async_blackbird_socket

async def main():
	# Auto-detect protocol over TCP
	bb = await get_async_blackbird_socket('192.168.1.50', protocol_version='auto', outputs=8)
	# Fetch status (PTN caches all outputs on first call)
	st1 = await bb.zone_status(1)
	print('Zone1 source', st1.av)
	# Change a source
	await bb.set_zone_source(1, 5)
	# Refresh cached PTN status explicitly
	await bb.refresh_status()
	# Firmware version (PTN only; returns None for legacy)
	print('Firmware', await bb.version())

asyncio.run(main())
```

Notes:
* `protocol_version='auto'` performs the same probe sequence as the sync client.
* Cache invalidation semantics (after source change or refresh) mirror the synchronous implementation.
* For pure serial async control, continue using `get_async_blackbird` (existing serial protocol path).

### Protocol versions
The library now supports two protocol variants:

* legacy (default): Original Monoprice Blackbird format (commands end with carriage return). Per-zone status queries using `Status{zone}.`.
* ptn: PTN-style firmware (commands terminate with a period only). Uses `STA_VIDEO.` returning multi-line status like `Output 01 Switch To In 04!` per line. Source switching commands are `OUTXX:YY.` (use `OUT00:YY.` for all outputs). A banner line starting with `Please Input Your Command` is ignored.

Select the protocol with the `protocol_version` parameter when creating a client. If not specified it defaults to `legacy` for backward compatibility.

You can also pass `protocol_version='auto'` for TCP/IP connections to have the library probe the device (it will try a PTN `STA_VIDEO.` query first, then a legacy `Status1.`). Auto-detect is not available for serial connections.

### Firmware version query
For PTN protocol devices you can obtain the firmware version once and it will be cached:

```python
bb = get_blackbird('192.168.1.50', use_serial=False, protocol_version='auto')
print('Firmware version:', bb.version())  # e.g. 1.0.1
```

The version is parsed from the multi-line `STA.` response (accepts either `Version:` lines or a standalone `V1.x.y` style string).

Some firmware variants emit the version line only after several other status / output lines. The client now keeps the socket open briefly after the first newline to gather late-arriving lines. If version still returns `None`, run the async probe with `--debug-raw-version` to inspect the raw `STA.` response.

### Library package version
The library’s own package version is single-sourced from `pyproject.toml`. At runtime you can read it with:
```python
import pyblackbird
print(pyblackbird.__version__)
```
When running directly from a source checkout without installing a wheel, this may show `0.0.0` (fallback) until the package is built/installed.

### Status caching and refresh
For PTN devices the multi-line `STA_VIDEO.` response is parsed and cached per zone to avoid repeated full status fetches. After a source change the cache is invalidated automatically. You can force a refresh manually:

```python
bb.refresh_status()  # Re-fetches and repopulates cache
```

### Probe utility
An example probe script is provided at `examples/probe_blackbird.py`:

```bash
python -m examples.probe_blackbird 192.168.1.50 --protocol auto --json
```

It will:
* Auto-detect protocol (unless you force one)
* Query and print firmware version (skip with --no-version)
* List zone power/source
* Report lock status
* Optionally output a JSON summary (`--json`)
* Force a fresh PTN status read with `--refresh`

Windows / PowerShell users: this probe command is the recommended (and simplest) way to determine protocol and version—no extra PowerShell scripting required.

An asynchronous variant with additional controls is available:
```bash
python -m examples.async_probe_blackbird <IP> --protocol auto --json --debug-raw-version
```
Use `--set Z:S` pairs to change sources (e.g. `--set 1:5 2:7`) and `--version-only` to print only firmware.

### Manual protocol test (netcat / nc)
If you want to determine protocol quickly from a shell (e.g. your Home Assistant host) you can probe with `nc` (netcat). Replace `<IP>` with the matrix IP (default TCP port 4001).

Why you might only see `Please Input Your Command :`:
Many netcat variants close immediately after stdin EOF, causing the matrix to stop sending the rest of the multi‑line PTN response. Adding a small delay (using `-i`, `-q`, or an explicit `sleep`) keeps the socket open long enough to receive all lines.

PTN firmware probe (multi-line expected: `Output XX Switch To In YY!` lines):
Try these in order (stop when one produces full output):
```bash
# OpenBSD / traditional nc supporting -i
echo -n "STA." | nc -i 1 -w 2 <IP> 4001

# GNU/OpenBSD nc alternative using quit timeout after EOF
echo -n "STA." | nc -w 2 -q 1 <IP> 4001

# BusyBox nc (often lacks -i/-q). Use subshell + sleep to delay close.
( printf "STA."; sleep 1 ) | nc <IP> 4001

# Some firmware variants respond more fully to STA_VIDEO.
echo -n "STA_VIDEO." | nc -i 1 -w 2 <IP> 4001
```
Typical PTN response (abridged):
```
GUI Or RS232 Query Status:
8x8 HDMI Matrix
24180
V1.0.1
Power ON!
...
Output 01 Switch To In 01!
Output 02 Switch To In 07!
...
```

Legacy firmware probe (short single-zone style):
```bash
printf "Status1.\r" | nc -w 2 <IP> 4001         # GNU / OpenBSD
printf "Status1.\r" | nc <IP> 4001              # BusyBox (no -w)
```
Example legacy response:
```
AV: 02->01\r\nIR: 02->01\r
```

Interpretation:
* Multi-line with `Output XX Switch To In YY!` → PTN → use `protocol_version='ptn'` (or 'auto').
* Only legacy `Status1.` returns AV/IR, PTN probes empty → legacy.
* Neither: check network reachability (port 4001), firewall, power.

Notes:
* macOS: prefer `printf` over `echo -n` for portability.
* BusyBox: may not support `-i`, `-q`, or `-w`; use the subshell with `sleep`.
* Serial usage: connect via `screen /dev/ttyUSB0 9600` (or similar) and type `STA.` (PTN) or `Status1.` + Enter (legacy) manually.

### Home Assistant integration notes
When integrating into a Home Assistant config flow you can mimic the probe logic: attempt PTN first, fall back to legacy, then store the resolved protocol. Expose a manual override if detection fails. The provided `PROTOCOL_AUTO` constant and internal probing can simplify onboarding.

### Exceptions
The library now exposes a small exception hierarchy to make error handling explicit:

* `BlackbirdError`: Base class (catch-all).
* `BlackbirdConnectionError`: Failure to open / connect a TCP or serial connection.
* `BlackbirdProtocolDetectionError`: Auto protocol detection failed (device didn’t yield recognizable PTN or legacy signatures).
* `BlackbirdTimeoutError`: A command did not produce a complete response within the allotted timeout.

Example:
```python
from pyblackbird import (
	get_blackbird, BlackbirdConnectionError, BlackbirdProtocolDetectionError, BlackbirdTimeoutError
)

try:
	bb = get_blackbird('192.168.1.50', use_serial=False, protocol_version='auto')
	print(bb.version())
except BlackbirdProtocolDetectionError:
	print('Could not determine protocol; specify manually or check connectivity.')
except BlackbirdConnectionError as e:
	print('Connection failed:', e)
except BlackbirdTimeoutError as e:
	print('Device timed out:', e)
```

Timeout semantics: For PTN multi-line queries (e.g. `STA_VIDEO.` or `STA.`) a short idle grace period is applied to gather delayed lines before the overall timeout window is enforced.

