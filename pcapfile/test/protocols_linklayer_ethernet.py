#!/usr/bin/env python
"""
This is the test case for the savefile.
"""

import binascii
import unittest

from pcapfile.protocols.linklayer import ethernet

# a sample ethernet frame carrying an IPv4 SYN request
TEST_PACKET = ['010203040506ffeeddccbbaa08004500003cc43800003806',
               '2898adc22552c0a8022f0050f9dc06511a336489a374a012',
               '37641b070000020405960402080a2195430027e3b0900103',
               '0306']
TEST_PACKET = binascii.unhexlify(''.join(TEST_PACKET))


class TestCase(unittest.TestCase):
    """
    Test case for the Ethernet frame parser.
    """

    @classmethod
    def setUpClass(cls):
        """
        Print a start message when loading the test suite.
        """
        print '[+] testing ethernet frame decoding...'

    def test_frame_field(self):
        """
        Verify attributes of Ethernet instance.
        """
        frame = ethernet.Ethernet(TEST_PACKET)
        self.assertEqual(frame.src, 'ff:ee:dd:cc:bb:aa',
                         'invalid frame source address')
        self.assertEqual(frame.dst, '01:02:03:04:05:06',
                         'invalid frame destination address')
        self.assertEqual(frame.type, 0x0800, 'invalid frame type')
        self.assertTrue(hasattr(frame, 'load_network'),
                        'missing load_network method')
        frame.load_network()
        self.assertTrue(hasattr(frame.payload, 'ttl'),
                        'load_network fails')

    def test_frame_load(self):
        """
        Verify the ethernet frames load.
        """
        frame = ethernet.Ethernet(TEST_PACKET)
        self.assertTrue(isinstance(frame, ethernet.Ethernet),
                        'invalid ethernet frame!')
