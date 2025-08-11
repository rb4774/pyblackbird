import unittest
import pytest

import serial

from pyblackbird import (
    get_blackbird, get_async_blackbird, get_async_blackbird_socket, ZoneStatus,
    BlackbirdProtocolDetectionError, BlackbirdTimeoutError
)
from tests import (create_dummy_port, create_dummy_socket, HAS_PTY)
import asyncio


class TestZoneStatus(unittest.TestCase):

    def test_zone_status_broken(self):
        self.assertIsNone(ZoneStatus.from_string(None, None))
        self.assertIsNone(ZoneStatus.from_string(1, 'VA: 09-<01\r'))
        self.assertIsNone(ZoneStatus.from_string(10, '\r\n\r\n'))

@unittest.skipIf(not HAS_PTY, "PTY not available on this platform")
class TestBlackbird(unittest.TestCase):
    def setUp(self):
        self.responses = {}
        self.blackbird = get_blackbird(create_dummy_port(self.responses))

    def test_zone_status(self):
        self.responses[b'Status1.\r'] = b'AV: 02->01\r\nIR: 02->01\r'
        status = self.blackbird.zone_status(1)
        self.assertEqual(1, status.zone)
        self.assertTrue(status.power)
        self.assertEqual(2, status.av)
        self.assertEqual(2, status.ir)
        self.assertEqual(0, len(self.responses))


    def test_set_zone_power(self):
        self.responses[b'1@.\r'] = b'01 Open.\r'
        self.blackbird.set_zone_power(1, True)
        self.responses[b'1@.\r'] = b'01 Open.\r'
        self.blackbird.set_zone_power(1, 'True')
        self.responses[b'1@.\r'] = b'01 Open.\r'
        self.blackbird.set_zone_power(1, 1)
        self.responses[b'1$.\r'] = b'01 Closed.\r'
        self.blackbird.set_zone_power(1, False)
        self.responses[b'1$.\r'] = b'01 Closed.\r'
        self.blackbird.set_zone_power(1, None)
        self.responses[b'1$.\r'] = b'01 Closed.\r'
        self.blackbird.set_zone_power(1, 0)
        self.responses[b'1$.\r'] = b'01 Closed.\r'
        self.blackbird.set_zone_power(1, '')
        self.assertEqual(0, len(self.responses))

    def test_set_zone_source(self):
        self.responses[b'1B1.\r'] = b'AV:01->01\r'
        self.blackbird.set_zone_source(1,1)
        self.responses[b'8B1.\r'] = b'AV:08->05\r'
        self.blackbird.set_zone_source(1,100)
        self.responses[b'1B1.\r'] = b'AV:01->01\r'
        self.blackbird.set_zone_source(1,-100)
        self.responses[b'2B2.\r'] = b'AV:02->02\r'
        self.blackbird.set_zone_source(2,2)
        self.assertEqual(0, len(self.responses))

    def test_set_all_zone_source(self):
        self.responses[b'1All.\r'] = b'01 To All.\r'
        self.blackbird.set_all_zone_source(1)
        self.assertEqual(0, len(self.responses))

    def test_lock_front_buttons(self):
        self.responses[b'/%Lock;\r'] = b'System Locked!\r'
        self.blackbird.lock_front_buttons()
        self.assertEqual(0, len(self.responses))


    def test_unlock_front_buttons(self):
        self.responses[b'/%Unlock;\r'] = b'System UnLock!\r'
        self.blackbird.unlock_front_buttons()
        self.assertEqual(0, len(self.responses))

    def test_front_button_status(self):
        self.responses[b'%9961.\r'] = b'System Locked!\r'
        status = self.blackbird.lock_status()
        self.assertTrue(status)
        self.responses[b'%9961.\r'] = b'System UnLock!\r'
        status = self.blackbird.lock_status()
        self.assertFalse(status)
        self.assertEqual(0, len(self.responses))

    def test_timeout(self):
        with self.assertRaises(serial.SerialTimeoutException):
           self.blackbird.set_zone_source(6,6)


@unittest.skipIf(not HAS_PTY, "PTY not available on this platform")
class TestBlackbirdPTNProtocol(unittest.TestCase):
    def setUp(self):
        self.responses = {}
        self.blackbird = get_blackbird(create_dummy_port(self.responses, terminator=b'.'), protocol_version='ptn')

    def test_status_multiline_parse(self):
        status_payload = (
            'Please Input Your Command :\r\n'
            'Output 01 Switch To In 04!\r\n'
            'Output 02 Switch To In 07!\r\n'
            'Output 03 Switch To In 02!\r\n'
        )
        self.responses[b'STA_VIDEO.'] = status_payload.encode()
        status = self.blackbird.zone_status(1)
        self.assertEqual(status.zone, 1)
        self.assertEqual(status.av, 4)
        status = self.blackbird.zone_status(2)
        self.assertEqual(status.zone, 2)
        self.assertEqual(status.av, 7)
        self.responses[b'OUT01:05.'] = b''
        self.blackbird.set_zone_source(1, 5)
        self.responses[b'STA_VIDEO.'] = (
            'Please Input Your Command :\r\n'
            'Output 01 Switch To In 05!\r\n'
            'Output 02 Switch To In 07!\r\n'
        ).encode()
        updated = self.blackbird.zone_status(1)
        self.assertEqual(updated.av, 5)

    def test_all_zone_source(self):
        self.responses[b'OUT00:02.'] = b''
        self.blackbird.set_all_zone_source(2)

    def test_version_query(self):
        # Simulate STA. response containing version info
        self.responses[b'STA.'] = (
            b'Please Input Your Command :\r\n'
            b'\r\n'
            b'GUI Or RS232 Query Status:\r\n'
            b'8x8 HDMI Matrix\r\n'
            b'24180\r\n'
            b'V1.0.1\r\n'
            b'Power ON!\r\n'
            b'Front Panel UnLock!\r\n'
            b'Local RS232 Baudrate Is 9600!\r\n'
            b'GUI_IP:192.168.1.17!\r\n'
            b'Output 01 Switch To In 01!\r\n'
            b'Output 02 Switch To In 07!\r\n'
            b'Output 03 Switch To In 01!\r\n'
            b'Output 04 Switch To In 05!\r\n'
            b'Output 05 Switch To In 04!\r\n'
            b'Output 06 Switch To In 06!\r\n'
            b'Output 07 Switch To In 07!\r\n'
            b'Output 08 Switch To In 08!\r\n'
            b'Turn ON Output 01!\r\n'
            b'Turn ON Output 02!\r\n'
            b'Turn ON Output 03!\r\n'
            b'Turn ON Output 04!\r\n'
            b'Turn ON Output 05!\r\n'
            b'Turn ON Output 06!\r\n'
            b'Turn ON Output 07!\r\n'
            b'Turn ON Output 08!\r\n'
            b'HDMI OUT 05 Down Scale ON!\r\n'
            b'HDMI OUT 06 Down Scale ON!\r\n'
            b'HDMI OUT 07 Down Scale ON!\r\n'
        )
        ver = self.blackbird.version()
        self.assertEqual(ver, '1.0.1')
        # Cached call should not consume additional responses
        ver2 = self.blackbird.version()
        self.assertEqual(ver2, '1.0.1')
        self.assertFalse(self.responses)  # STA. consumed once



@unittest.skipIf(not HAS_PTY, "PTY not available on this platform")
class TestAsyncBlackbird(TestBlackbird):

    def setUp(self):
        self.responses = {}
        loop = asyncio.get_event_loop()
        blackbird = loop.run_until_complete(get_async_blackbird(create_dummy_port(self.responses), loop))

        # Dummy blackbird that converts async to sync
        class DummyBlackbird():
            def __getattribute__(self, item):
                def f(*args, **kwargs):
                    return loop.run_until_complete(blackbird.__getattribute__(item)(*args, **kwargs))
                return f
        self.blackbird = DummyBlackbird()

    def test_timeout(self):
        with pytest.raises(BlackbirdTimeoutError):
            self.blackbird.set_zone_source(6, 6)


class TestBlackbirdSocketWindows(unittest.TestCase):
    """Fallback tests using TCP dummy server when PTY is unavailable (e.g. Windows)."""

    @unittest.skipIf(HAS_PTY, "Only runs on platforms with no PTY (Windows-only test)")
    def test_legacy_status_over_socket(self):
        responses = {}
        host = create_dummy_socket(responses)
        bb = get_blackbird(host, use_serial=False)
        responses[b'Status1.\r'] = b'AV: 02->01\r\nIR: 02->01\r'
        status = bb.zone_status(1)
        self.assertEqual(status.zone, 1)
        self.assertEqual(status.av, 2)
        self.assertEqual(status.ir, 2)

    @unittest.skipIf(HAS_PTY, "Only runs on platforms with no PTY (Windows-only test)")
    def test_ptn_multiline_status_over_socket(self):
        responses = {}
        responses[b'STA_VIDEO.'] = (
            b'Output 01 Switch To In 03!\r\n'
            b'Output 02 Switch To In 07!\r\n'
        )
        host = create_dummy_socket(responses, banner=b'\r\n')
        bb = get_blackbird(host, use_serial=False, protocol_version='ptn', outputs=2)
        st1 = bb.zone_status(1)
        self.assertEqual(st1.av, 3)
        st2 = bb.zone_status(2)
        self.assertEqual(st2.av, 7)
        responses[b'OUT01:05.'] = b'OK\n'
        responses[b'STA_VIDEO.'] = (
            b'Output 01 Switch To In 05!\r\n'
            b'Output 02 Switch To In 07!\r\n'
        )
        bb.set_zone_source(1, 5)
        updated = bb.zone_status(1)
        self.assertEqual(updated.av, 5)

    @unittest.skipIf(HAS_PTY, "Only runs on platforms with no PTY (Windows-only test)")
    def test_ptn_version_over_socket(self):
        responses = {b'STA.': (
            b'Please Input Your Command :\r\n'
            b'\r\n'
            b'GUI Or RS232 Query Status:\r\n'
            b'8x8 HDMI Matrix\r\n'
            b'24180\r\n'
            b'V1.0.1\r\n'
            b'Power ON!\r\n'
            b'Front Panel UnLock!\r\n'
            b'Local RS232 Baudrate Is 9600!\r\n'
            b'GUI_IP:192.168.1.17!\r\n'
            b'Output 01 Switch To In 01!\r\n'
            b'Output 02 Switch To In 07!\r\n'
            b'Output 03 Switch To In 01!\r\n'
            b'Output 04 Switch To In 05!\r\n'
            b'Output 05 Switch To In 04!\r\n'
            b'Output 06 Switch To In 06!\r\n'
            b'Output 07 Switch To In 07!\r\n'
            b'Output 08 Switch To In 08!\r\n'
        )}
        host = create_dummy_socket(responses, banner=b'\r\n')
        bb = get_blackbird(host, use_serial=False, protocol_version='ptn', outputs=8)
        ver = bb.version()
        self.assertEqual(ver, '1.0.1')

if __name__ == '__main__':
   unittest.main()

# --- Additional PTN-specific tests (pytest style) ---

def test_ptn_zone_status_caching():
    """First call should populate cache; second call should not consume new STA_VIDEO. response."""
    responses = {
        b'STA_VIDEO.': (
            b'Output 01 Switch To In 03!\r\n'
            b'Output 02 Switch To In 07!\r\n'
        )
    }
    host = create_dummy_socket(responses, banner=b'\r\n')
    bb = get_blackbird(host, use_serial=False, protocol_version='ptn', outputs=2)
    st1 = bb.zone_status(1)
    assert st1.av == 3
    # Add a sentinel response that would be consumed if a second STA_VIDEO. were sent
    responses[b'STA_VIDEO.'] = (
        b'Output 01 Switch To In 09!\r\n'
        b'Output 02 Switch To In 09!\r\n'
    )
    st2 = bb.zone_status(2)
    assert st2.av == 7
    # Cache prevented a second fetch
    assert b'STA_VIDEO.' in responses


def test_ptn_auto_detect_success():
    """Auto-detect should identify PTN when STA_VIDEO. yields Output lines."""
    responses = {
        # Provide two identical responses: first for auto-detect probe, second for actual status fetch
        b'STA_VIDEO.': [
            (
                b'Output 01 Switch To In 04!\r\n'
                b'Output 02 Switch To In 05!\r\n'
            ),
            (
                b'Output 01 Switch To In 04!\r\n'
                b'Output 02 Switch To In 05!\r\n'
            )
        ]
    }
    host = create_dummy_socket(responses, banner=b'\r\n')
    bb = get_blackbird(host, use_serial=False, protocol_version='auto', outputs=2)
    # Internal protocol attribute should be PTN
    assert getattr(bb, '_protocol_version') == 'ptn'
    assert bb.zone_status(1).av == 4
    assert bb.zone_status(2).av == 5


def test_ptn_auto_detect_failure():
    """Auto-detect should raise when neither PTN nor legacy responses match expected patterns."""
    responses = {
        b'STA_VIDEO.': b'Junk\r\n',           # No 'Output ' lines so PTN attempt fails
        b'Status1.\r': b'Welcome Only\r\n',   # No 'AV:' / 'IR:' tokens so legacy fails
    }
    host = create_dummy_socket(responses, banner=b'\r\n')
    with pytest.raises(BlackbirdProtocolDetectionError):
        get_blackbird(host, use_serial=False, protocol_version='auto', outputs=2)


# --- Additional PTN coverage tests (socket-based) ---

def test_ptn_version_parse_colon():
    """Version line with 'Version:' pattern should be parsed."""
    responses = {b'STA.': (
        b'Please Input Your Command :\r\n'
        b'GUI Or RS232 Query Status:\r\n'
        b'Version: 2.3.4\r\n'
        b'Output 01 Switch To In 01!\r\n'
        b'Output 02 Switch To In 02!\r\n'
    )}
    host = create_dummy_socket(responses, banner=b'\r\n')
    bb = get_blackbird(host, use_serial=False, protocol_version='ptn', outputs=2)
    assert bb.version() == '2.3.4'


def test_ptn_version_parse_equals():
    """Version line with 'Version=' pattern should be parsed."""
    responses = {b'STA.': (
        b'Please Input Your Command :\r\n'
        b'GUI Or RS232 Query Status:\r\n'
        b'Version= 3.4.5\r\n'
        b'Output 01 Switch To In 03!\r\n'
        b'Output 02 Switch To In 04!\r\n'
    )}
    host = create_dummy_socket(responses, banner=b'\r\n')
    bb = get_blackbird(host, use_serial=False, protocol_version='ptn', outputs=2)
    assert bb.version() == '3.4.5'


def test_ptn_version_parse_no_outputs():
    """Version query with no Output lines should still succeed and leave cache empty."""
    responses = {b'STA.': (
        b'Please Input Your Command :\r\n'
        b'Version: 9.9.9\r\n'
    )}
    host = create_dummy_socket(responses, banner=b'\r\n')
    bb = get_blackbird(host, use_serial=False, protocol_version='ptn', outputs=2)
    assert bb.version() == '9.9.9'
    # Since no Output lines, status cache should remain empty until first zone_status call triggers STA_VIDEO.
    assert getattr(bb, '_status_cache') == {}


def test_ptn_refresh_status_repopulates_cache():
    """refresh_status should clear and repopulate cache with new STA_VIDEO output."""
    responses = {
        b'STA_VIDEO.': [
            (b'Output 01 Switch To In 02!\r\n' b'Output 02 Switch To In 03!\r\n'),
            (b'Output 01 Switch To In 05!\r\n' b'Output 02 Switch To In 06!\r\n'),
        ]
    }
    host = create_dummy_socket(responses, banner=b'\r\n')
    bb = get_blackbird(host, use_serial=False, protocol_version='ptn', outputs=2)
    first = bb.zone_status(1)
    assert first.av == 2
    # Now refresh; should consume second STA_VIDEO.
    bb.refresh_status()
    updated = bb.zone_status(1)
    assert updated.av == 5


def test_ptn_set_all_zone_source_invalidates_cache():
    """set_all_zone_source should invalidate cache so subsequent status reflects new sources."""
    responses = {
        b'STA_VIDEO.': [
            (b'Output 01 Switch To In 02!\r\n' b'Output 02 Switch To In 03!\r\n'),
            (b'Output 01 Switch To In 07!\r\n' b'Output 02 Switch To In 07!\r\n'),
        ],
        b'OUT00:07.': b'OK\r\n',
    }
    host = create_dummy_socket(responses, banner=b'\r\n')
    bb = get_blackbird(host, use_serial=False, protocol_version='ptn', outputs=2)
    assert bb.zone_status(1).av == 2
    bb.set_all_zone_source(7)
    # After invalidation, second STA_VIDEO. response used
    assert bb.zone_status(2).av == 7


# --- Async socket client tests ---

def test_async_socket_ptn_status_and_cache():
    """Async PTN status fetch populates cache; second zone read uses cache without consuming new response."""
    responses = {
        b'STA_VIDEO.': [
            (b'Output 01 Switch To In 04!\r\n' b'Output 02 Switch To In 05!\r\n'),
        ],
    }
    host = create_dummy_socket(responses, banner=b'\r\n')

    async def _run():
        bb = await get_async_blackbird_socket(host, protocol_version='ptn', outputs=2)
        st1 = await bb.zone_status(1)
        assert st1.av == 4
        # Provide a different response that should NOT be consumed because cache is used
        responses[b'STA_VIDEO.'] = [
            (b'Output 01 Switch To In 09!\r\n' b'Output 02 Switch To In 09!\r\n'),
        ]
        st2 = await bb.zone_status(2)
        assert st2.av == 5
        # Ensure modified response still present indicating cache use
        assert b'STA_VIDEO.' in responses
    asyncio.run(_run())


def test_async_socket_ptn_cache_invalidation_after_source_change():
    """Changing a zone source invalidates cache causing second STA_VIDEO fetch."""
    responses = {
        b'STA_VIDEO.': [
            (b'Output 01 Switch To In 01!\r\n' b'Output 02 Switch To In 02!\r\n'),
            (b'Output 01 Switch To In 05!\r\n' b'Output 02 Switch To In 02!\r\n'),
        ],
        b'OUT01:05.': b'OK\r\n',
    }
    host = create_dummy_socket(responses, banner=b'\r\n')

    async def _run():
        bb = await get_async_blackbird_socket(host, protocol_version='ptn', outputs=2)
        st1 = await bb.zone_status(1)
        assert st1.av == 1
        await bb.set_zone_source(1, 5)  # invalidates cache
        st1_updated = await bb.zone_status(1)
        assert st1_updated.av == 5
    asyncio.run(_run())


def test_async_socket_ptn_version_and_status_cache_population():
    """Version call populates firmware and status cache when Output lines included."""
    responses = {
        b'STA.': (
            b'Please Input Your Command :\r\n'
            b'Version: 6.6.6\r\n'
            b'Output 01 Switch To In 03!\r\n'
            b'Output 02 Switch To In 04!\r\n'
        )
    }
    host = create_dummy_socket(responses, banner=b'\r\n')

    async def _run():
        bb = await get_async_blackbird_socket(host, protocol_version='ptn', outputs=2)
        ver = await bb.version()
        assert ver == '6.6.6'
        # After version() call cache should be primed
        st2 = await bb.zone_status(2)
        assert st2.av == 4
    asyncio.run(_run())


def test_async_socket_ptn_auto_detect():
    """Auto protocol detection works in async socket client for PTN."""
    responses = {
        b'STA_VIDEO.': [
            (b'Output 01 Switch To In 07!\r\n' b'Output 02 Switch To In 08!\r\n'),  # for detect + first fetch
            (b'Output 01 Switch To In 07!\r\n' b'Output 02 Switch To In 08!\r\n'),
        ]
    }
    host = create_dummy_socket(responses, banner=b'\r\n')

    async def _run():
        bb = await get_async_blackbird_socket(host, protocol_version='auto', outputs=2)
        st1 = await bb.zone_status(1)
        assert st1.av == 7
        assert getattr(bb, '_protocol_version') == 'ptn'
    asyncio.run(_run())


def test_ptn_status_malformed_output_line_ignored():
    """Malformed Output line should be ignored (only valid lines cached)."""
    responses = {
        b'STA_VIDEO.': [
            (b'Output 01 Switch To In 02!\r\n'  # valid
             b'Output 02 Switch To In AB!\r\n'  # malformed (non-numeric)
            ),
        ]
    }
    host = create_dummy_socket(responses, banner=b'\r\n')
    bb = get_blackbird(host, use_serial=False, protocol_version='ptn', outputs=2)
    st1 = bb.zone_status(1)
    assert st1.av == 2
    # Zone 2 should not be present due to malformed line
    assert bb.zone_status(2) is None


def test_ptn_version_v_prefix_only():
    """Version parsing should support standalone Vx.y.z line."""
    responses = {b'STA.': (
        b'Please Input Your Command :\r\n'
        b'V2.0.0!\r\n'
        b'Output 01 Switch To In 01!\r\n'
    )}
    host = create_dummy_socket(responses, banner=b'\r\n')
    bb = get_blackbird(host, use_serial=False, protocol_version='ptn', outputs=1)
    assert bb.version() == '2.0.0'


def test_async_socket_version_space_pattern():
    """Async version parsing supports 'Version 4.5.6' (space, no colon)."""
    responses = {b'STA.': (
        b'Please Input Your Command :\r\n'
        b'GUI Or RS232 Query Status:\r\n'
        b'Version 4.5.6\r\n'
        b'Output 01 Switch To In 03!\r\n'
    )}
    host = create_dummy_socket(responses, banner=b'\r\n')

    async def _run():
        bb = await get_async_blackbird_socket(host, protocol_version='ptn', outputs=1)
        assert await bb.version() == '4.5.6'
    asyncio.run(_run())


def test_ptn_banner_skipped():
    """Banner lines should be skipped when populating cache."""
    responses = {b'STA_VIDEO.': [(
        b'Please Input Your Command :\r\n'
        b'Output 01 Switch To In 08!\r\n'
    )]}
    host = create_dummy_socket(responses, banner=b'\r\n')
    bb = get_blackbird(host, use_serial=False, protocol_version='ptn', outputs=1)
    st1 = bb.zone_status(1)
    assert st1.av == 8


def test_async_socket_auto_detect_failure():
    """Async auto-detect should raise BlackbirdProtocolDetectionError when neither protocol matches."""
    responses = {
        b'STA_VIDEO.': [b'Junk\r\n'],
        b'Status1.\r': b'Welcome Only\r\n'
    }
    host = create_dummy_socket(responses, banner=b'\r\n')

    async def _run():
        with pytest.raises(BlackbirdProtocolDetectionError):
            await get_async_blackbird_socket(host, protocol_version='auto', outputs=2)
    asyncio.run(_run())


def test_async_socket_timeout():
    """Async socket client should raise BlackbirdTimeoutError when no response is received."""
    responses = {}  # No responses provided; any command will hang until timeout
    host = create_dummy_socket(responses, banner=b'\r\n')

    async def _run():
        import pyblackbird as pb
        original_timeout = pb.TIMEOUT
        pb.TIMEOUT = 1  # shorten for test speed
        try:
            bb = await get_async_blackbird_socket(host, protocol_version='ptn', outputs=1)
            # Issue a command expecting at least a line terminator; none will arrive.
            with pytest.raises(BlackbirdTimeoutError):
                await bb.set_zone_source(1, 5)
        finally:
            pb.TIMEOUT = original_timeout
    asyncio.run(_run())


def test_async_socket_version_delayed_chunks():
    """Simulate delayed multi-line STA. output arriving in chunks; ensure version captured."""
    responses = {
        b'STA.': {
            'chunks': [
                (b'GUI Or RS232 Query Status:\r\n8x8 HDMI Matrix\r\n', 0.05),
                (b'24180\r\n', 0.05),
                (b'V2.2.2\r\n', 0.05),
                (b'Output 01 Switch To In 03!\r\n', 0.05),
            ]
        }
    }
    host = create_dummy_socket(responses, banner=b'\r\n')

    async def _run():
        bb = await get_async_blackbird_socket(host, protocol_version='ptn', outputs=1)
        ver = await bb.version()
        assert ver == '2.2.2'
    asyncio.run(_run())


def test_sync_socket_version_delayed_chunks():
    """Sync client should also capture version from delayed chunked STA. output."""
    responses = {
        b'STA.': {
            'chunks': [
                (b'GUI Or RS232 Query Status:\r\n8x8 HDMI Matrix\r\n', 0.02),
                (b'24180\r\nV3.3.3\r\n', 0.05),
                (b'Output 01 Switch To In 01!\r\n', 0.02),
            ]
        }
    }
    host = create_dummy_socket(responses, banner=b'\r\n')
    bb = get_blackbird(host, use_serial=False, protocol_version='ptn', outputs=1)
    ver = bb.version()
    assert ver == '3.3.3'


def test_sync_socket_status_delayed_multiline():
    """Delayed multi-line status (STA_VIDEO.) should still populate cache fully."""
    responses = {
        b'STA_VIDEO.': {
            'chunks': [
                (b'Output 01 Switch To In 02!\r\n', 0.03),
                (b'Output 02 Switch To In 05!\r\n', 0.04),
            ]
        }
    }
    host = create_dummy_socket(responses, banner=b'\r\n')
    bb = get_blackbird(host, use_serial=False, protocol_version='ptn', outputs=2)
    st2 = bb.zone_status(2)
    assert st2.av == 5


def test_sync_socket_timeout():
    """Sync socket client should raise BlackbirdTimeoutError when no response arrives."""
    responses = {}  # No responses -> force timeout
    host = create_dummy_socket(responses, banner=b'\r\n')
    import pyblackbird as pb
    original = pb.TIMEOUT
    pb.TIMEOUT = 1  # shorten for test speed
    try:
        bb = get_blackbird(host, use_serial=False, protocol_version='ptn', outputs=1)
        with pytest.raises(BlackbirdTimeoutError):
            # Command expecting at least newline; server gives nothing.
            bb.set_zone_source(1, 5)
    finally:
        pb.TIMEOUT = original
