import asyncio
import functools
import logging
import re
import serial
import socket
from functools import wraps
from serial_asyncio import create_serial_connection
from threading import RLock
from typing import Dict, Optional

_LOGGER = logging.getLogger(__name__)
ZONE_PATTERN_ON = re.compile(r'\D\D\D\s(\d\d)\D\D\d\d\s\s\D\D\D\s(\d\d)\D\D\d\d\s')
ZONE_PATTERN_OFF = re.compile(r'\D\D\DOFF\D\D\d\d\s\s\D\D\D\D\D\D\D\D\d\d\s')
EOL_LEGACY = b'\r'
LEN_EOL_LEGACY = len(EOL_LEGACY)
EOL_PTN_LINE = b'\n'
PROTOCOL_LEGACY = 'legacy'
PROTOCOL_PTN = 'ptn'
PROTOCOL_AUTO = 'auto'
BANNER_PREFIX = 'Please Input Your Command'
TIMEOUT = 5 # Increased from 2 to better accommodate slower multi-line PTN responses
PORT = 4001
SOCKET_RECV = 2048

class ZoneStatus(object):
    def __init__(self,
                 zone: int,
                 power: bool,
                 av: Optional[int],
                 ir: Optional[int]):
        self.zone = zone
        self.power = power
        self.av = av
        self.ir = ir

    @classmethod
    def from_string(cls, zone: int, string: str):
        """Parse legacy single-zone response string."""
        if not string:
            return None
        match_on = re.search(ZONE_PATTERN_ON, string)
        if not match_on:
            match_off = re.search(ZONE_PATTERN_OFF, string)
            if not match_off:
                return None
            return ZoneStatus(zone, 0, None, None)
        return ZoneStatus(zone, 1, *[int(m) for m in match_on.groups()])

    @classmethod
    def from_ptn_protocol_line(cls, line: str):
        """Parse a single line of the PTN multi-line STA_VIDEO response.

        Expected format example: 'Output 01 Switch To In 04!' (CRLF stripped)
        Returns (zone, ZoneStatus) or (None, None) if not parsable.
        """
        # Quick rejection
        if not line or not line.startswith('Output '):
            return None, None
        # Regex capturing output and input numbers
        m = re.match(r'Output\s+(\d+)\s+Switch\s+To\s+In\s+(\d+)!', line.strip())
        if not m:
            return None, None
        zone = int(m.group(1))
        source = int(m.group(2))
    # PTN protocol lacks IR per-zone in status; assume power True
        return zone, ZoneStatus(zone, True, source, None)

class LockStatus(object):
    def __init__(self,
                 lock: bool):
        self.lock = lock

    @classmethod
    def from_string(cls, string: str):
        if not string:
            return None
        if string.startswith('System Locked'):
            return True
        else:
            return False


class Blackbird(object):
    """
    Monoprice blackbird amplifier interface
    """

    def zone_status(self, zone: int):
        """
        Get the structure representing the status of the zone
        :param zone: zone 1..8
        :return: status of the zone or None
        """
        raise NotImplemented()

    def set_zone_power(self, zone: int, power: bool):
        """
        Turn zone on or off
        :param zone: Zone 1-8
        :param power: True to turn on, False to turn off
        """
        raise NotImplemented()

    def set_zone_source(self, zone: int, source: int):
        """
        Set source for zone
        :param zone: Zone 1-8
        :param source: integer from 1-8
        """
        raise NotImplemented()

    def set_all_zone_source(self, source: int):
        """
        Set source for all zones
        :param source: integer from 1-8
        """
        raise NotImplemented()

    def lock_front_buttons():
        """
        Lock front panel buttons
        """
        raise NotImplemented()

    def unlock_front_buttons():
        """
        Unlock front panel buttons
        """
        raise NotImplemented()

    def lock_status():
        """
        Report system locking status
        """
        raise NotImplemented()


# Helpers

def _append_eol(command: str, protocol_version: str) -> bytes:
    if protocol_version == PROTOCOL_PTN:
        return command.encode()
    return (command + '\r').encode()

def _format_zone_status_request(zone: int, protocol_version: str) -> bytes:
    if protocol_version == PROTOCOL_PTN:
        return _append_eol('STA_VIDEO.', protocol_version)
    return _append_eol(f'Status{zone}.', protocol_version)

def _format_set_zone_power(zone: int, power: bool, protocol_version: str) -> bytes:
    return _append_eol(f'{zone}{"@" if power else "$"}.', protocol_version)

def _format_set_zone_source(zone: int, source: int, protocol_version: str) -> bytes:
    source = int(max(1, min(source, 8)))
    if protocol_version == PROTOCOL_PTN:
        return _append_eol(f'OUT{zone:02d}:{source:02d}.', protocol_version)
    return _append_eol(f'{source}B{zone}.', protocol_version)

def _format_set_all_zone_source(source: int, protocol_version: str) -> bytes:
    source = int(max(1, min(source, 8)))
    if protocol_version == PROTOCOL_PTN:
        return _append_eol(f'OUT00:{source:02d}.', protocol_version)
    return _append_eol(f'{source}All.', protocol_version)

def _format_lock_front_buttons(protocol_version: str) -> bytes:
    return _append_eol('/%Lock;', protocol_version)

def _format_unlock_front_buttons(protocol_version: str) -> bytes:
    return _append_eol('/%Unlock;', protocol_version)

def _format_lock_status(protocol_version: str) -> bytes:
    return _append_eol('%9961.', protocol_version)

def _format_system_info(protocol_version: str) -> Optional[bytes]:
    """Return command to query system information (firmware version etc.).

    Currently only implemented for PTN protocol via 'STA.' which returns
    multi-line system info including a version line.
    Returns None for legacy protocol (no known equivalent command).
    """
    if protocol_version == PROTOCOL_PTN:
        return _append_eol('STA.', protocol_version)
    return None


def _detect_protocol_over_socket(host: str, timeout: float = 1.0) -> str:
    """Attempt to detect protocol by probing STA_VIDEO. then Status1. over TCP.

    Returns protocol string (PROTOCOL_PTN or PROTOCOL_LEGACY) or raises RuntimeError.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, PORT))
        try:
            s.recv(SOCKET_RECV)
        except Exception:
            pass
        # Try PTN first
        try:
            s.sendall(b'STA_VIDEO.')
            data = b''
            while True:
                chunk = s.recv(SOCKET_RECV)
                if not chunk:
                    break
                data += chunk
                if b'Output ' in data:
                    return PROTOCOL_PTN
                if b'\n' in data or b'\r' in data:
                    break
        except Exception:
            pass
    finally:
        try:
            s.close()
        except Exception:
            pass

    # Legacy attempt
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.settimeout(timeout)
    try:
        s2.connect((host, PORT))
        try:
            s2.recv(SOCKET_RECV)
        except Exception:
            pass
        try:
            s2.sendall(b'Status1.\r')
            data = b''
            while True:
                chunk = s2.recv(SOCKET_RECV)
                if not chunk:
                    break
                data += chunk
                if b'AV:' in data and b'IR:' in data:
                    return PROTOCOL_LEGACY
                if b'\r' in data:
                    break
        except Exception:
            pass
    finally:
        try:
            s2.close()
        except Exception:
            pass
    raise RuntimeError('Auto-detect failed (no recognizable PTN or legacy response).')


def get_blackbird(url, use_serial=True, protocol_version: str = PROTOCOL_LEGACY, outputs: int = 8):
    """
    Return synchronous version of Blackbird interface
    :param port_url: serial port, i.e. '/dev/ttyUSB0'
    :return: synchronous implementation of Blackbird interface
    """
    lock = RLock()
    print(serial)

    def synchronized(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with lock:
                return func(*args, **kwargs)
        return wrapper

    class BlackbirdSync(Blackbird):
        def __init__(self, url):
            """
            Initialize the client.
            """
            # Resolve auto protocol for socket usage
            resolved_protocol = protocol_version
            if protocol_version == PROTOCOL_AUTO:
                if use_serial:
                    raise ValueError("Auto protocol detection not supported over serial; specify 'legacy' or 'ptn'.")
                resolved_protocol = _detect_protocol_over_socket(url)
                _LOGGER.info("Auto-detected protocol '%s' for host %s", resolved_protocol, url)
            self._protocol_version = resolved_protocol
            self._outputs = outputs
            # Cache for new protocol multi-line status
            self._status_cache: Dict[int, ZoneStatus] = {}
            if use_serial:
                self._port = serial.serial_for_url(url, do_not_open=True)
                self._port.baudrate = 9600
                self._port.stopbits = serial.STOPBITS_ONE
                self._port.bytesize = serial.EIGHTBITS
                self._port.parity = serial.PARITY_NONE
                self._port.timeout = TIMEOUT
                self._port.write_timeout = TIMEOUT
                self._port.open()

            else:
                self.host = url
                self.port = PORT
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(TIMEOUT)
                self.socket.connect((self.host, self.port))

                # Clear login message
                self.socket.recv(SOCKET_RECV)

        def _process_request(self, request: bytes, skip=0, multiline: bool = False, expect_outputs: int = 0):
            """
            Send data to socket
            :param request: request that is sent to the blackbird
            :param skip: number of bytes to skip for end of transmission decoding
            :param multiline: for new protocol multi-line responses
            :param expect_outputs: number of output lines expected (new protocol status)
            :return: ascii string returned by blackbird
            """
            _LOGGER.debug('Sending "%s"', request)

            if use_serial:
                # clear
                self._port.reset_output_buffer()
                self._port.reset_input_buffer()
                # send
                self._port.write(request)
                self._port.flush()
                # receive
                result = bytearray()
                if self._protocol_version == PROTOCOL_LEGACY and not multiline:
                    while True:
                        c = self._port.read(1)
                        if c is None:
                            break
                        if not c:
                            raise serial.SerialTimeoutException(
                                'Connection timed out! Last received bytes {}'.format([hex(a) for a in result]))
                        result += c
                        if len(result) > skip and result[-LEN_EOL_LEGACY:] == EOL_LEGACY:
                            break
                    ret = bytes(result)
                    _LOGGER.debug('Received "%s"', ret)
                    return ret.decode('ascii')
                else:
                    # PTN protocol or multiline: read lines until condition satisfied
                    lines = []
                    current_line = bytearray()
                    outputs_found = 0
                    end_time = asyncio.get_event_loop().time() + TIMEOUT
                    # Fallback if no event loop (sync context)
                    try:
                        loop_time = asyncio.get_event_loop().time
                    except RuntimeError:
                        import time as _time
                        loop_time = _time.time
                        end_time = loop_time() + TIMEOUT
                    while loop_time() < end_time:
                        c = self._port.read(1)
                        if not c:
                            # Timeout waiting for next byte
                            break
                        current_line += c
                        if c == EOL_PTN_LINE:
                            decoded = current_line.decode('ascii', errors='ignore')
                            lines.append(decoded)
                            if decoded.startswith('Output '):
                                outputs_found += 1
                            current_line = bytearray()
                            if multiline and expect_outputs and outputs_found >= expect_outputs:
                                break
                            if not multiline:
                                break
                    # Append any residual buffer
                    if current_line:
                        lines.append(current_line.decode('ascii', errors='ignore'))
                    ret = ''.join(lines)
                    _LOGGER.debug('Received "%s"', ret.encode())
                    return ret

            else:
                self.socket.send(request)

                response = ''

                while True:
                    data = self.socket.recv(SOCKET_RECV)
                    if not data:
                        break
                    decoded = data.decode('ascii', errors='ignore')
                    response += decoded
                    if multiline:
                        outputs_found = sum(1 for l in response.splitlines() if l.startswith('Output '))
                        if expect_outputs and outputs_found >= expect_outputs:
                            break
                    else:
                        if self._protocol_version == PROTOCOL_LEGACY and EOL_LEGACY in data and len(response) > skip:
                            break
                        if self._protocol_version == PROTOCOL_PTN and ('\n' in decoded or '\r' in decoded):
                            break
                return response

        @synchronized
        def zone_status(self, zone: int):
            # Returns status of a zone
            if self._protocol_version == PROTOCOL_PTN:
                if not self._status_cache:
                    raw = self._process_request(
                        _format_zone_status_request(zone, self._protocol_version),
                        multiline=True,
                        expect_outputs=self._outputs,
                    )
                    self._parse_and_cache_ptn_status(raw)
                return self._status_cache.get(zone)
            return ZoneStatus.from_string(zone, self._process_request(
                _format_zone_status_request(zone, self._protocol_version), skip=20))

        @synchronized
        def set_zone_power(self, zone: int, power: bool):
            # Set zone power
            self._process_request(_format_set_zone_power(zone, power, self._protocol_version))

        @synchronized
        def set_zone_source(self, zone: int, source: int):
            # Set zone source
            # For new protocol, after changing source, refresh cache for accuracy
            self._process_request(_format_set_zone_source(zone, source, self._protocol_version))
            if self._protocol_version == PROTOCOL_PTN:
                self._status_cache = {}

        @synchronized
        def set_all_zone_source(self, source: int):
            # Set all zones to one source
            self._process_request(_format_set_all_zone_source(source, self._protocol_version))
            if self._protocol_version == PROTOCOL_PTN:
                self._status_cache = {}

        @synchronized
        def lock_front_buttons(self):
            # Lock front panel buttons
            self._process_request(_format_lock_front_buttons(self._protocol_version))

        @synchronized
        def unlock_front_buttons(self):
            # Unlock front panel buttons
            self._process_request(_format_unlock_front_buttons(self._protocol_version))

        @synchronized
        def lock_status(self):
            # Report system locking status
            return LockStatus.from_string(self._process_request(_format_lock_status(self._protocol_version)))

        @synchronized
        def version(self) -> Optional[str]:
            """Return cached device firmware version (PTN protocol only) or None.

            Issues a 'STA.' command once and parses the line containing 'Version'.
            Parsing is lenient: matches 'Version' followed by ':' or '=' and captures
            remaining characters up to line ending / !.
            """
            if self._protocol_version != PROTOCOL_PTN:
                return None
            if getattr(self, '_device_version', None):  # already cached
                return self._device_version
            cmd = _format_system_info(self._protocol_version)
            if not cmd:
                return None
            raw = self._process_request(cmd, multiline=True, expect_outputs=self._outputs)
            # Populate status cache from same response if not already
            if self._protocol_version == PROTOCOL_PTN and not self._status_cache:
                self._parse_and_cache_ptn_status(raw)
            ver = _parse_version_from_system_info(raw)
            self._device_version = ver
            return ver

        @synchronized
        def refresh_status(self):
            """Force a refresh of cached PTN status (no-op for legacy)."""
            if self._protocol_version == PROTOCOL_PTN:
                self._status_cache = {}
                # Trigger immediate fetch to repopulate
                self.zone_status(1)
            return True

        def _parse_and_cache_ptn_status(self, raw: str):
            """Parse multi-line PTN status output and populate cache, skipping banner."""
            cache: Dict[int, ZoneStatus] = {}
            for line in raw.splitlines():
                if line.startswith(BANNER_PREFIX):
                    continue
                zone, status = ZoneStatus.from_ptn_protocol_line(line)
                if zone is not None and status is not None:
                    cache[zone] = status
            self._status_cache = cache

    return BlackbirdSync(url)


async def get_async_blackbird(port_url, loop, protocol_version: str = PROTOCOL_LEGACY, outputs: int = 8):
    """
    Return asynchronous version of Blackbird interface
    :param port_url: serial port, i.e. '/dev/ttyUSB0'
    :return: asynchronous implementation of Blackbird interface
    """

    lock = asyncio.Lock()

    def locked_coro(coro):
        @wraps(coro)
        async def wrapper(*args, **kwargs):
            with (await lock):
                return (await coro(*args, **kwargs))
        return wrapper

    class BlackbirdAsync(Blackbird):
        def __init__(self, blackbird_protocol):
            self._protocol = blackbird_protocol
            self._protocol_version = protocol_version
            self._outputs = outputs
            self._status_cache: Dict[int, ZoneStatus] = {}

        @locked_coro
        async def zone_status(self, zone: int):
            if self._protocol_version == PROTOCOL_PTN:
                if not self._status_cache:
                    raw = await self._protocol.send(
                        _format_zone_status_request(zone, self._protocol_version),
                        multiline=True,
                        expect_outputs=self._outputs,
                    )
                    self._parse_and_cache_ptn_status(raw)
                return self._status_cache.get(zone)
            string = await self._protocol.send(
                _format_zone_status_request(zone, self._protocol_version), skip=15)
            return ZoneStatus.from_string(zone, string)

        @locked_coro
        async def set_zone_power(self, zone: int, power: bool):
            await self._protocol.send(_format_set_zone_power(zone, power, self._protocol_version))

        @locked_coro
        async def set_zone_source(self, zone: int, source: int):
            await self._protocol.send(_format_set_zone_source(zone, source, self._protocol_version))
            if self._protocol_version == PROTOCOL_PTN:
                self._status_cache = {}

        @locked_coro
        async def set_all_zone_source(self, source: int):
             await self._protocol.send(_format_set_all_zone_source(source, self._protocol_version))
             if self._protocol_version == PROTOCOL_PTN:
                 self._status_cache = {}

        @locked_coro
        async def lock_front_buttons(self):
            await self._protocol.send(_format_lock_front_buttons(self._protocol_version))

        @locked_coro
        async def unlock_front_buttons(self):
            await self._protocol.send(_format_unlock_front_buttons(self._protocol_version))

        @locked_coro
        async def lock_status(self):
            string = await self._protocol.send(_format_lock_status(self._protocol_version))
            return LockStatus.from_string(string)

        async def version(self) -> Optional[str]:  # noqa: D401
            """Async version query (PTN only)."""
            if self._protocol_version != PROTOCOL_PTN:
                return None
            if getattr(self, '_device_version', None):
                return self._device_version
            cmd = _format_system_info(self._protocol_version)
            if not cmd:
                return None
            raw = await self._protocol.send(cmd, multiline=True, expect_outputs=self._outputs)
            if self._protocol_version == PROTOCOL_PTN and not self._status_cache:
                self._parse_and_cache_ptn_status(raw)
            ver = _parse_version_from_system_info(raw)
            self._device_version = ver
            return ver

        async def refresh_status(self):  # noqa: D401
            if self._protocol_version == PROTOCOL_PTN:
                self._status_cache = {}
                await self.zone_status(1)
            return True

        def _parse_and_cache_ptn_status(self, raw: str):
            cache: Dict[int, ZoneStatus] = {}
            for line in raw.splitlines():
                if line.startswith(BANNER_PREFIX):
                    continue
                zone, status = ZoneStatus.from_ptn_protocol_line(line)
                if zone is not None and status is not None:
                    cache[zone] = status
            self._status_cache = cache

    class BlackbirdProtocol(asyncio.Protocol):
        def __init__(self, loop):
            super().__init__()
            self._loop = loop
            self._lock = asyncio.Lock()
            self._transport = None
            self._connected = asyncio.Event(loop=loop)
            self.q = asyncio.Queue(loop=loop)

        def connection_made(self, transport):
            self._transport = transport
            self._connected.set()
            _LOGGER.debug('port opened %s', self._transport)

        def data_received(self, data):
            asyncio.ensure_future(self.q.put(data), loop=self._loop)

        async def send(self, request: bytes, skip=0, multiline: bool = False, expect_outputs: int = 0):
            await self._connected.wait()
            result = bytearray()
            # Only one transaction at a time
            with (await self._lock):
                self._transport.serial.reset_output_buffer()
                self._transport.serial.reset_input_buffer()
                while not self.q.empty():
                    self.q.get_nowait()
                self._transport.write(request)
                try:
                    if protocol_version == PROTOCOL_LEGACY and not multiline:
                        while True:
                            result += await asyncio.wait_for(self.q.get(), TIMEOUT, loop=self._loop)
                            if len(result) > skip and result[-LEN_EOL_LEGACY:] == EOL_LEGACY:
                                ret = bytes(result)
                                _LOGGER.debug('Received "%s"', ret)
                                return ret.decode('ascii')
                    else:
                        # PTN protocol: accumulate lines until condition met
                        text = ''
                        outputs_found = 0
                        while True:
                            chunk = await asyncio.wait_for(self.q.get(), TIMEOUT, loop=self._loop)
                            decoded = chunk.decode('ascii', errors='ignore')
                            text += decoded
                            # Count lines
                            lines = text.splitlines()
                            outputs_found = sum(1 for l in lines if l.startswith('Output '))
                            if (multiline and expect_outputs and outputs_found >= expect_outputs) or (not multiline and ('\n' in decoded or '\r' in decoded)):
                                _LOGGER.debug('Received "%s"', text.encode())
                                return text
                except asyncio.TimeoutError:
                    _LOGGER.error("Timeout during receiving response for command '%s', received='%s'", request, result)
                    raise

    _, protocol = await create_serial_connection(loop, functools.partial(BlackbirdProtocol, loop), port_url, baudrate=9600)

    return BlackbirdAsync(protocol)


def _parse_version_from_system_info(raw: str) -> Optional[str]:
    """Extract version string from PTN 'STA.' response text.

    Matches patterns like 'Version: 1.2.3', 'Version=1.2.3', or 'Version 1.2.3'.
    Returns trimmed version or None if not found.
    """
    if not raw:
        return None
    for line in raw.splitlines():
        line_clean = line.strip().rstrip('!')
        if not line_clean:
            continue
        # Match explicit 'Version:' style
        m = re.search(r'Version\s*[:=]?\s*([^\r\n!]+)', line_clean, re.IGNORECASE)
        if m:
            return m.group(1).strip()
        # Match standalone firmware like 'V1.0.1' (leading V then digits/dots)
        m2 = re.match(r'V\d+(?:\.\d+)+$', line_clean, re.IGNORECASE)
        if m2:
            return line_clean[1:]  # drop leading 'V'
    return None
