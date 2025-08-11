#!/usr/bin/env python3
"""Blackbird matrix probe utility.

Usage:
    python -m examples.probe_blackbird 192.168.1.17 [--protocol auto|legacy|ptn] [--debug]

If --protocol is omitted, the script will attempt to auto-detect by first
trying the PTN multi-line status command (STA_VIDEO.) and falling back to the
legacy per-zone command (Status1.).

It prints status for zones 1..8 without altering device state.
"""
from __future__ import annotations
import argparse
import logging
import socket
from typing import Optional

import os, sys
# Ensure parent directory (project root) is on sys.path when run as a script
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pyblackbird import get_blackbird, PROTOCOL_PTN, PROTOCOL_LEGACY, PROTOCOL_AUTO

DEFAULT_PORT = 4001
SOCKET_RECV = 2048


def _try_ptn(host: str, timeout: float = 1.5) -> bool:
    """Return True if PTN protocol appears to be supported."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, DEFAULT_PORT))
        # Read any banner/login (ignore)
        try:
            s.recv(SOCKET_RECV)
        except Exception:
            pass
        s.send(b'STA_VIDEO.')
        data = b''
        try:
            while True:
                chunk = s.recv(SOCKET_RECV)
                if not chunk:
                    break
                data += chunk
                if b'Output ' in data:
                    return True
                # If we already saw a newline without Output, break early
                if b'\n' in data:
                    break
        except socket.timeout:
            return False
        return b'Output ' in data
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def _try_legacy(host: str, timeout: float = 1.5) -> bool:
    """Return True if legacy protocol responds to a Status1. query."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, DEFAULT_PORT))
        try:
            s.recv(SOCKET_RECV)  # banner
        except Exception:
            pass
        s.send(b'Status1.\r')
        data = b''
        try:
            while True:
                chunk = s.recv(SOCKET_RECV)
                if not chunk:
                    break
                data += chunk
                if b'AV:' in data and b'IR:' in data:
                    return True
                if b'\r' in data:
                    break
        except socket.timeout:
            return False
        return b'AV:' in data
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def autodetect_protocol(host: str) -> str:
    if _try_ptn(host):
        return PROTOCOL_PTN
    if _try_legacy(host):
        return PROTOCOL_LEGACY
    raise RuntimeError("Unable to detect protocol (neither PTN nor legacy responded as expected)")


def main():
    parser = argparse.ArgumentParser(description="Probe a Monoprice Blackbird matrix switch")
    parser.add_argument("host", help="Matrix IP address")
    parser.add_argument("--protocol", choices=[PROTOCOL_AUTO, PROTOCOL_LEGACY, PROTOCOL_PTN], default=PROTOCOL_AUTO, help="Protocol selection (auto by default)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--zones", type=str, default="1-8", help="Zones to query (e.g. 1-4,6,8)")
    parser.add_argument("--json", action="store_true", help="Output JSON summary at end")
    parser.add_argument("--no-version", action="store_true", help="Skip version query")
    parser.add_argument("--refresh", action="store_true", help="Force PTN cache refresh before listing zones")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format='%(levelname)s %(message)s')

    if args.protocol == PROTOCOL_AUTO:
        logging.info("Auto-detecting protocol...")
        try:
            protocol = autodetect_protocol(args.host)
        except Exception as e:
            logging.error("Protocol auto-detect failed: %s", e)
            return 1
        logging.info("Detected protocol: %s", protocol)
    else:
        protocol = args.protocol
        logging.info("Using protocol: %s", protocol)

    # Parse zones specification
    zones: list[int] = []
    for part in args.zones.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            zones.extend(range(int(a), int(b) + 1))
        else:
            zones.append(int(part))
    zones = sorted(set(zones))

    bb = get_blackbird(args.host, use_serial=False, protocol_version=protocol)

    print("Host:", args.host, "Protocol:", protocol)

    version = None
    if not args.no_version:
        try:
            version = bb.version()
        except Exception as e:  # pragma: no cover
            logging.debug("Version query failed: %s", e)
    if version:
        print("Version:", version)
    if args.refresh:
        try:
            bb.refresh_status()
        except Exception:
            pass

    zone_entries = []
    for z in zones:
        try:
            st = bb.zone_status(z)
        except Exception as e:  # pragma: no cover - runtime/hardware
            print(f"Zone {z}: ERROR {e}")
            zone_entries.append({"zone": z, "error": str(e)})
            continue
        if not st:
            print(f"Zone {z}: No data")
            zone_entries.append({"zone": z, "error": "no data"})
            continue
        print(f"Zone {z}: power={'on' if st.power else 'off'} av={st.av} ir={st.ir}")
        zone_entries.append({"zone": z, "power": bool(st.power), "av": st.av, "ir": st.ir})

    # Optionally report lock status
    lock_status = None
    try:
        locked = bb.lock_status()
        lock_status = 'locked' if locked else 'unlocked'
        print("Lock status:", lock_status)
    except Exception:
        pass

    if args.json:
        import json
        print(json.dumps({
            "host": args.host,
            "protocol": protocol,
            "version": version,
            "lock_status": lock_status,
            "zones": zone_entries,
        }, indent=2, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
