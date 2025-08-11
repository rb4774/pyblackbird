import unittest

import serial

from pyblackbird import (get_blackbird, get_async_blackbird, ZoneStatus)
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
        with self.assertRaises(asyncio.TimeoutError):
            self.blackbird.set_zone_source(6, 6)


class TestBlackbirdSocketWindows(unittest.TestCase):
    """Fallback tests using TCP dummy server when PTY is unavailable (e.g. Windows)."""

    # No setUp: each test creates its own isolated server/responses

    @unittest.skipIf(HAS_PTY, "Only runs on platforms without PTY (Windows)")
    def test_legacy_status_over_socket(self):
        responses = {}
        host = create_dummy_socket(responses)
        bb = get_blackbird(host, use_serial=False)
        responses[b'Status1.\r'] = b'AV: 02->01\r\nIR: 02->01\r'
        status = bb.zone_status(1)
        self.assertEqual(status.zone, 1)
        self.assertEqual(status.av, 2)
        self.assertEqual(status.ir, 2)

    @unittest.skipIf(HAS_PTY, "Only runs on platforms without PTY (Windows)")
    def test_ptn_multiline_status_over_socket(self):
        responses = {}
        # Pre-populate initial multi-line response before client issues STA_VIDEO.
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
        # Change a source
        responses[b'OUT01:05.'] = b'OK\n'
        # Prepare updated status before issuing command to avoid race
        responses[b'STA_VIDEO.'] = (
            b'Output 01 Switch To In 05!\r\n'
            b'Output 02 Switch To In 07!\r\n'
        )
        bb.set_zone_source(1, 5)
        updated = bb.zone_status(1)
        self.assertEqual(updated.av, 5)

    @unittest.skipIf(HAS_PTY, "Only runs on platforms without PTY (Windows)")
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
