#!/usr/bin/env python
"""
This is the test case for TCP.
"""

import binascii
import unittest

from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network.ip import IP
from pcapfile.protocols.transport.tcp import TCP

TEST_PAYLOAD=b'''\
GET /?q=1 HTTP/1.1\r
Host: 192.168.54.1:8080\r
User-Agent: curl/7.43.0\r
Accept: */*\r
\r
'''


class TestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Print a start message when loading the test suite.
        """
        print('[+] testing TCP segment decoding...')

    def assertTcp(self, pcap_packet, **kwargs):
        frame = pcap_packet.packet
        packet = frame.payload
        segment = packet.payload
        
        for k,v in kwargs.items():
            if hasattr(segment, k):
                self.assertEqual(getattr(segment, k), v, k)
            elif hasattr(packet, k):
                self.assertEqual(getattr(packet, k), v, k)
            elif hasattr(frame, k):
                self.assertEqual(getattr(frame, k), v, k)
            else:
                raise Exception('Attribute %s not found' % k)

    def setUp(self):
        with open('pcapfile/test/test_data/http_conversation.pcap', 'rb') as f:
            self.packets = savefile.load_savefile(f, layers=3).packets


    def test_basic_parsing(self):
        for pcap_packet in self.packets:
            frame = pcap_packet.packet
            packet = frame.payload
            self.assertTrue(isinstance(packet, IP))
            
            segment = packet.payload
            self.assertTrue(isinstance(segment, TCP))

    def test_extensive(self):
        self.assertTcp(self.packets[0], syn=True, ack=False, fin=False,
            rst=False, psh=False, seqnum=223930318, win=29200, sum=0xd2f6)
        self.assertTcp(self.packets[1], syn=True, ack=True, sum=0x18e3)

        self.assertTcp(self.packets[3], syn=False, ack=True, psh=True,
                payload=binascii.hexlify(TEST_PAYLOAD))

    def test_payload(self):
        self.assertTcp(self.packets[3], syn=False, ack=True, psh=True,
                payload=binascii.hexlify(TEST_PAYLOAD))

    def test_empty_payload(self):
        self.assertTcp(self.packets[0], payload=b'')

    def test_fin(self):
        self.assertTcp(self.packets[0], fin=False)
        self.assertTcp(self.packets[-2], fin=True)

    def test_len(self):
        for pcap_packet in self.packets:
            frame = pcap_packet.packet
            packet = frame.payload
            segment = packet.payload
            self.assertEqual(len(segment), packet.len - len(packet.opt) / 2 - 20)
