#!/usr/bin/env python
"""
This is the front end to the pcapfile test SUITE.
"""

import unittest


from pcapfile.test.linklayer_test import TestCase as LinklayerTest
from pcapfile.test.savefile_test import TestCase as SavefileTest
from pcapfile.test.protocols_linklayer_ethernet import TestCase as EthernetTest

if __name__ == '__main__':
    TEST_CLASSES = [SavefileTest, LinklayerTest, EthernetTest]
    SUITE = unittest.TestSuite()
    LOADER = unittest.TestLoader()
    for test_class in TEST_CLASSES:
        SUITE.addTests(LOADER.loadTestsFromTestCase(test_class))
    unittest.TextTestRunner(verbosity=2).run(SUITE)
