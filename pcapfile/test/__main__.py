#!/usr/bin/env python
"""
This is the front end to the pcapfile test SUITE.
"""

import unittest


from linklayer_test import TestCase as LinklayerTest
from savefile_test import TestCase as SavefileTest
from protocols_linklayer_ethernet import TestCase as EthernetTest

if __name__ == '__main__':
    TEST_CLASSES = [SavefileTest, LinklayerTest, EthernetTest]
    SUITE = unittest.TestSuite()
    LOADER = unittest.TestLoader()
    for test_class in TEST_CLASSES:
        SUITE.addTests(LOADER.loadTestsFromTestCase(test_class))
    unittest.TextTestRunner(verbosity=2).run(SUITE)
