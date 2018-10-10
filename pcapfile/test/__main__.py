#!/usr/bin/env python
"""
This is the front end to the pcapfile test SUITE.
"""

import unittest
import sys


from pcapfile.test.linklayer_test import TestCase as LinklayerTest
from pcapfile.test.savefile_test import TestCase as SavefileTest
from pcapfile.test.protocols_linklayer_ethernet import TestCase as EthernetTest
from pcapfile.test.protocols_linklayer_wifi import TestCase as WifiTest
from pcapfile.test.protocols_network_ip import TestCase as IpTest
from pcapfile.test.protocols_transport_tcp import TestCase as TcpTest

if __name__ == '__main__':
    TEST_CLASSES = [SavefileTest, LinklayerTest, EthernetTest, WifiTest, IpTest, TcpTest]
    SUITE = unittest.TestSuite()
    LOADER = unittest.TestLoader()
    for test_class in TEST_CLASSES:
        SUITE.addTests(LOADER.loadTestsFromTestCase(test_class))
    result = unittest.TextTestRunner(verbosity=2).run(SUITE)
    if not result.wasSuccessful():
        sys.exit(1)
