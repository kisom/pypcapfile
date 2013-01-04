#!/usr/bin/env python
"""
This is the test case for the savefile.
"""

import unittest

from pcapfile import linklayer
from pcapfile.protocols.linklayer import ethernet


class TestCase(unittest.TestCase):
    """
    Validate the linklayer utility functions.
    """

    capfile = None

    def init_capfile(self, layers=0):
        self.capfile = savefile.load_savefile(open('test_data/test.pcap', 'r'), 
                                              layers=layers)

    @classmethod
    def setUpClass(cls):
        """
        Print an intro to identify this test suite when running multiple tests.
        """
        print '[+] loading toplevel linklayer utility tests'

    def test_constructor_lookup(self):
        """
        Ensure the proper validation function is passed from the constructor
        lookup.
        """
        self.assertEqual(ethernet.Ethernet, linklayer.clookup(1))

    def test_lookup(self):
        """
        Test the strings returned by the short lookup functions. 
        """
        self.assertEqual('LINKTYPE_ETHERNET', linklayer.lookup(1), 
                         'invalid long name')
        self.assertEqual('ethernet', linklayer.slookup(1), 
                         'invalid short name')
