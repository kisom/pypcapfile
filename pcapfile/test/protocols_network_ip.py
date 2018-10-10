#!/usr/bin/env python
"""
This is the test case for IP.
"""

import unittest

from pcapfile import savefile
from pcapfile.protocols.network.ip import IP


def str_to_ipaddr(s):
    octets = s.split('.')
    if len(octets) != 4:
        raise ValueError('Invalid IP address string: ' + s)
    octets = bytearray(map(int, octets))
    return (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]


class TestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Print a start message when loading the test suite.
        """
        print('[+] testing IP segment decoding...')

    def assertIp(self, pcap_packet, **kwargs):
        frame = pcap_packet.packet
        packet = frame.payload

        for k, v in kwargs.items():
            if hasattr(packet, k):
                self.assertEqual(getattr(packet, k), v, k)
            elif hasattr(frame, k):
                self.assertEqual(getattr(frame, k), v, k)
            else:
                raise Exception('Attribute %s not found' % k)

    def setUp(self):
        with open('pcapfile/test/test_data/http_conversation.pcap', 'rb') as f:
            self.packets = savefile.load_savefile(f, layers=2).packets

    def test_smoke_test(self):
        for pcap_packet in self.packets:
            frame = pcap_packet.packet
            packet = frame.payload
            self.assertTrue(isinstance(packet, IP))

    def test_extensive(self):
        self.assertIp(
            self.packets[0],
            src=str_to_ipaddr('192.168.54.1'),
            dst=str_to_ipaddr('192.168.54.2'))

    def test_timestamp_calc(self):
        for packet in self.packets:
            self.assertAlmostEqual(
                packet.timestamp_us,
                packet.timestamp_ms * 1000
            )
