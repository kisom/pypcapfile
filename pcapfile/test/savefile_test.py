#!/usr/bin/env python
"""
This is the test case for the savefile.
"""

import os
import pickle
import tempfile
import unittest
import base64
import sys

import pcapfile.test.fixture as fixture
from pcapfile import savefile


def create_pcap():
    """
    Create a capture file from the test fixtures.
    """
    tfile = tempfile.NamedTemporaryFile()
    if sys.version_info[0] >= 3:  # python3
        capture = pickle.loads(base64.b64decode(fixture.TESTPCAP3))
    else:  # python2 unsupported pickle protocol: 3
        capture = pickle.loads(fixture.TESTPCAP2.decode('base64'))
    open(tfile.name, 'wb').write(capture)
    return tfile


class TestCase(unittest.TestCase):
    """
    Test case for the savefile code.
    """
    capfile = None

    def init_capfile(self, layers=0):
        """Initialise the capture file."""
        tfile = create_pcap()
        self.capfile = savefile.load_savefile(tfile, layers=layers)
        tfile.close()
        if os.path.exists(tfile.name):
            os.unlink(tfile.name)

    @classmethod
    def setUpClass(cls):
        """
        Print an intro to identify this test suite when running multiple tests.
        """
        print('[+] loading basic tests')

    def setUp(self):
        """
        Set up a default capture file.
        """
        # only need to initialise capfile on the first time, while being able
        # load it with additional decoding layers.
        if not self.capfile:
            self.init_capfile()

    def test_network_load(self):
        """
        Test that the code that loads network layer packets from the
        top level works.
        """
        self.init_capfile(layers=2)
        for packet in self.capfile.packets:
            for field in ['src', 'dst', 'v', 'hl', 'tos', 'ttl']:
                ipkt = packet.packet.payload
                self.assertTrue(hasattr(ipkt, field), 'invalid packet!')

    def test_frame_load(self):
        """
        Ensure that ethernet frames load from the top level.
        """
        self.init_capfile(layers=1)
        for packet in self.capfile.packets:
            for field in ['src', 'dst', 'type', 'payload']:
                self.assertTrue(hasattr(packet.packet, field),
                                'invalid frame!')

    def test_packet_valid(self):
        """
        Make sure raw packets load properly.
        """
        packet = self.capfile.packets[0].raw()

        self.assertEqual(int(bytearray(packet)[14]), 69, 'invalid packet')

        for packet in self.capfile.packets:
            for field in ['capture_len', 'timestamp', 'timestamp_us',
                          'packet', 'header', 'packet_len']:
                self.assertTrue(hasattr(packet, field), 'invalid packet!')

    def test_header_valid(self):
        """
        Test to ensure the header validation code works.
        """
        header = self.capfile.header
        self.assertEqual(header.major, 2, 'invalid major version!')
        self.assertEqual(header.minor, 4, 'invalid minor version!')

    def test_basic_import(self):
        """
        Validate basic parameters of a simple savefile load.
        """
        self.assertTrue(self.capfile.valid, 'invalid capture file')
        self.assertEqual(len(self.capfile.packets), 23,
                         'wrong number of packets!')
        self.assertEqual(self.capfile.__length__(), 23,
                         '__length__ not reporting correct number of packets')

    def test_lazy_import(self):
        """
        Test the lazy packet parsing against the regular implementation.
        """
        # Load the savefile again, but create an iterator for the
        # packets instead of reading them all into memory at once.
        tfile = create_pcap()
        capfile_gen = savefile.load_savefile(tfile, lazy=True)

        # Create a list of packets using the iterator. This way the
        # length can be checked before comparing any content.
        packets = list(capfile_gen.packets)

        tfile.close()
        if os.path.exists(tfile.name):
            os.unlink(tfile.name)

        self.assertEqual(len(packets), len(self.capfile.packets),
                         'lazy parsing gives different number of packets!')

        # Compare the relevant parts of the packets.
        fields = ['timestamp', 'timestamp_us', 'capture_len',
                  'packet_len', 'packet']
        for act, ref in zip(packets, capfile_gen.packets):
            for field in fields:
                self.assertEqual(getattr(act, field), getattr(ref, field),
                                 'lazy parsing gives different data!')
