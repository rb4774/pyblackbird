import argparse
import asyncio
import json
import logging
from typing import Dict, List, Tuple

from pyblackbird import get_async_blackbird_socket, PROTOCOL_AUTO, PROTOCOL_PTN, PROTOCOL_LEGACY, _format_system_info

LOG = logging.getLogger("async_probe")


def parse_zone_sources(pairs: List[str]) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    for p in pairs:
        if ':' not in p:
            raise ValueError(f"Invalid zone:source pair '{p}', expected Z:S")
        z_s = p.split(':', 1)
        try:
            z = int(z_s[0])
            s = int(z_s[1])
        except ValueError as e:
            raise ValueError(f"Zone/source must be integers in '{p}'") from e
        out.append((z, s))
    return out


async def main() -> int:
    parser = argparse.ArgumentParser(description="Async probe / control for a Blackbird matrix (legacy or PTN protocol)")
    parser.add_argument("host", help="Host or host:port of the matrix (default port 4001)")
    parser.add_argument("--protocol", choices=[PROTOCOL_AUTO, PROTOCOL_PTN, PROTOCOL_LEGACY], default=PROTOCOL_AUTO,
                        help="Protocol: legacy, ptn, or auto (TCP only)")
    parser.add_argument("--outputs", type=int, default=8, help="Number of outputs (default 8)")
    parser.add_argument("--set", nargs='*', default=[], metavar="Z:S",
                        help="Apply zone:source mappings (e.g. 1:5 2:3). Applied sequentially then statuses re-fetched.")
    parser.add_argument("--json", action="store_true", help="Emit JSON summary to stdout")
    parser.add_argument("--refresh", action="store_true", help="Force status refresh after any changes")
    parser.add_argument("--log", default="WARNING", help="Logging level (DEBUG, INFO, WARNING, ...)")
    parser.add_argument("--version-only", action="store_true", help="Only fetch and print firmware version")
    parser.add_argument("--no-version", action="store_true", help="Skip firmware version query")
    parser.add_argument("--debug-raw-version", action="store_true", help="Dump raw STA. response (PTN) used for version parsing")

    args = parser.parse_args()
    logging.basicConfig(level=getattr(logging, args.log.upper(), logging.INFO))

    try:
        zone_sets = parse_zone_sources(args.set)
    except ValueError as e:
        parser.error(str(e))

    bb = await get_async_blackbird_socket(args.host, protocol_version=args.protocol, outputs=args.outputs)

    proto = getattr(bb, '_protocol_version', 'unknown')

    fw_version = None
    if not args.no_version and proto == PROTOCOL_PTN and not args.version_only:
        try:
            fw_version = await bb.version()
        except Exception as exc:  # pragma: no cover - hardware / network variability
            LOG.warning("Firmware version query failed: %s", exc)
    elif args.version_only and not args.no_version:
        if proto == PROTOCOL_PTN:
            # Optionally dump raw for diagnostics
            if args.debug_raw_version and hasattr(bb, '_send'):
                try:
                    raw = await bb._send(_format_system_info(PROTOCOL_PTN), multiline=True, expect_outputs=0)  # type: ignore[attr-defined]
                    print(raw)
                except Exception as exc:  # pragma: no cover
                    LOG.warning("Raw STA. dump failed: %s", exc)
            fw_version = await bb.version()
            print(fw_version or '')
        else:
            print('')
        return 0

    # Capture initial statuses
    initial: Dict[int, Dict[str, int | bool | None]] = {}
    for z in range(1, args.outputs + 1):
        st = await bb.zone_status(z)
        if st:
            initial[z] = {"power": st.power, "source": st.av}

    # Apply zone:source mappings
    if zone_sets:
        for (z, s) in zone_sets:
            try:
                await bb.set_zone_source(z, s)
            except Exception as exc:  # pragma: no cover
                LOG.error("Failed to set zone %d source %d: %s", z, s, exc)
        if args.refresh:
            await bb.refresh_status()

    final_status: Dict[int, Dict[str, int | bool | None]] = {}
    for z in range(1, args.outputs + 1):
        st = await bb.zone_status(z)
        if st:
            final_status[z] = {"power": st.power, "source": st.av}

    summary = {
        "protocol": proto,
        "firmware_version": fw_version,
        "initial": initial,
        "changes": zone_sets,
        "final": final_status,
    }

    # Debug raw version if requested (non version-only path)
    if args.debug_raw_version and proto == PROTOCOL_PTN and hasattr(bb, '_send'):
        try:
            raw = await bb._send(_format_system_info(PROTOCOL_PTN), multiline=True, expect_outputs=0)  # type: ignore[attr-defined]
            summary["raw_version_response"] = raw
        except Exception as exc:  # pragma: no cover
            LOG.warning("Raw STA. dump failed: %s", exc)

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"Protocol: {summary['protocol']}")
        if fw_version:
            print(f"Firmware: {fw_version}")
        print("Initial zone sources:")
        for z, st in initial.items():
            print(f"  Zone {z}: src {st['source']}")
        if zone_sets:
            print("Applied changes:")
            for z, s in zone_sets:
                print(f"  Zone {z} -> source {s}")
            print("Final zone sources:")
            for z, st in final_status.items():
                print(f"  Zone {z}: src {st['source']}")

    return 0


if __name__ == '__main__':  # pragma: no cover - manual execution
    raise SystemExit(asyncio.run(main()))
