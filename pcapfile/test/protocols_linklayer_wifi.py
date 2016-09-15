#!/usr/bin/env/python
"""
This is the test case for the savefile.
"""

import binascii
import unittest

from pcapfile.protocols.linklayer import wifi

#partial data packet, unnecessary tailing payload removed
DATA_NON_AMSDU_WDS_PACKET = ['000026002b4820002364e679000000004000a415400',
                             '1b30000004400040474000000000000008803480088',
                             '41d82a01aa8841fc7a0fd3a08614180220387400020',
                             '00010921400b8aeed73c9b1a8aeec73cf0c0564aaaa',
                             '030000000998510005dc010140004004a4a5c0a802c',
                             '9c0a802cad3e3138940d3918980ceb976801883e7ad',
                             '9f00002101080a007a0bc700f491f13637383930313',
                             '233343536373839303132333435367738193077b23b',
                             '36217e3638391031123334353637383930313233343',
                             '5363738197c21323334353637383822313233343536',
                             '3738393031323334353637383930313633343536373',
                             '839303132333435a6a8683f43c1b337b43536773939',
                             '3031327324353637383930333223363537373839303',
                             '132a3702602347a3970311233343536373839303132',
                             '3334752d133839303432337435363738397019a233e',
                             'f3536373c3930313233343536373839303132333435',
                             '3637383930313233643536373839b0a136233115b50',
                             'd3a3930513633303536f738793031326324ce36379c',
                             '59b2353a33343536373832042132333435363738393',
                             '0313233343536373839303132333435343738393031',
                             '323334353637b83d307032437605363738393031323',
                             '334353737383b30713033342474363cb33531323334',
                             '3576368835353137333035363738393031323334353',
                             '6373839303132333437763738393031323301bce1b7',
                             '3838303132333435363738393031323334353637383',
                             '9303132333435b6373839303132333437a356f83a70',
                             '332233b43536373c393031323334353637383930313',
                             '2333435365f38383031222334053eb3883931313233',
                             '3435363738393031323334353637383930313233343',
                             '53e3738393031323334356437383930313233343532']

#entire data packet, all payload included to check number of msdu's in a-msdu
DATA_AMSDU_WDS_PACKET = ['000026002b4820002a80a778000000000000a4154001e100',
                         '0000440004045300000000000000880348008841fc2a01a6',
                         '8841fc2a01aa00000000000050020000000000008000b8ae',
                         'ed73cf08b8aeed73c9b1003caaaa03000000080045000034',
                         'c4c640004006ef19c0a802cac0a802c91389d3e380ceb976',
                         'b612736980104988e2cf00000101080a00f47d890279f75c',
                         '0279b8aeed73cf08b8aeed73c9b1003caaaa030000000800',
                         '45000034c4c740004006ef18c0a802cac0a802c91389d3e3',
                         '80ceb976b612c29980104988939f00000101080a00f47d89',
                         '0279f75c0279b8aeed73cf08b8aeed73c9b1003caaaa0300',
                         '0000080045000034c4c840004006ef17c0a802cac0a802c9',
                         '1389d3e380ceb976b61311c980104988446f00000101080a',
                         '00f47d890279f75c0279b8aeed73cf08b8aeed73c9b1003c',
                         'aaaa03000000080045000034c4c940004006ef16c0a802ca',
                         'c0a802c91389d3e380ceb976b6135b5180104988fae60000',
                         '0101080a00f47d890279f75c0279b8aeed73cf08b8aeed73',
                         'c9b1003caaaa03000000080045000034c4ca40004006ef15',
                         'c0a802cac0a802c91389d3e380ceb976b613aa8180104988',
                         'abb600000101080a00f47d890279f75c0279b8aeed73cf08',
                         'b8aeed73c9b1003caaaa03000000080045000034c4cb4000',
                         '4006ef14c0a802cac0a802c91389d3e380ceb976b613ff59',
                         '8010498856de00000101080a00f47d890279f75c0279b8ae',
                         'ed73cf08b8aeed73c9b1003caaaa03000000080045000034',
                         'c4cc40004006ef13c0a802cac0a802c91389d3e380ceb976',
                         'b6141ba1801049883a9600000101080a00f47d890279f75c']

#entire beacon packet
BEACON_PACKET = ['00001a002f48000054446f7800000000000ca4154001e80000008000',
                 '0000ffffffffffff8841fc2a01aa8841fc2a01aa101f0a70a81e0000',
                 '0000640001050014416972546965735f416972343832305f30314139',
                 '01088c1298243048606c03016c051302030000000000000000000000',
                 '00000000000007344652202401172801172c01173001173401173801',
                 '173c011740011764011e68011e6c011e70011e74011e84011e88011e',
                 '8c011e00200100c305021e1e1e002a01002d1a6f0817fffffffffeff',
                 'ffffff1f000001000000000018e6e719003d166c0500000000000000',
                 '00000000000000000000000000dd180050f2020101860003a4000027',
                 'a4000042435e0062322f00bf0c3240c33faaff0000aaff0000c00501',
                 '6a00fcffdd1e002686010300dd000000250400380006019a576938d3',
                 '0000000000000000dd37001ca8370141697234383230000000000071',
                 '68733834300000000054575f302e3200000000312e32362e322e3000',
                 '000000000200000003dd0b001ca85001012a01aae26add5f0050f204',
                 '104a0001101044000102104700108b3fddc4c80f0c0952b876f9549a',
                 'f4ca103c0001021049000e00372a0001200106ffffffffffff104900',
                 '22007fc5100018373732383835383433393337353535333338383739',
                 '32386630000101']

#entire rts packet
RTS_PACKET = ['00001a002f4800008334e27800000000000ca4154001df000000b400340',
              'b8841fc2a01aa8841fc2a01a6']

#entire cts packet
CTS_PACKET = ['00001a002f480000c634e27800000000000ca4154001e7000000c400f80',
              'a8841fc2a01a6']

#entir block ack packet
BLOCK_ACK_PACKET = ['00001a002f480000b23fe278000000000030a415400',
                    '1e8000000940000008841fc2a01a68841fc2a01aa05',
                    '00902cffffffffff010000']

BEACON_PACKET = ''.join(hex_str for hex_str in BEACON_PACKET)
BEACON_PACKET = BEACON_PACKET.decode('hex')

RTS_PACKET = ''.join(hex_str for hex_str in RTS_PACKET)
RTS_PACKET = RTS_PACKET.decode('hex')

CTS_PACKET = ''.join(hex_str for hex_str in CTS_PACKET)
CTS_PACKET = CTS_PACKET.decode('hex')

BLOCK_ACK_PACKET = ''.join(hex_str for hex_str in BLOCK_ACK_PACKET)
BLOCK_ACK_PACKET = BLOCK_ACK_PACKET.decode('hex')

DATA_AMSDU_WDS_PACKET = ''.join(hex_str for hex_str in DATA_AMSDU_WDS_PACKET)
DATA_AMSDU_WDS_PACKET = DATA_AMSDU_WDS_PACKET.decode('hex')

DATA_NON_AMSDU_WDS_PACKET = ''.join(hex_str for hex_str in DATA_NON_AMSDU_WDS_PACKET)
DATA_NON_AMSDU_WDS_PACKET = DATA_NON_AMSDU_WDS_PACKET.decode('hex')

class TestCase(unittest.TestCase):
    """
    Test case for the Wi-Fi frame parser.
    """

    @classmethod
    def setUpClass(cls):
        """
        Print a start message when loading the test suite.
        """
        print('[+] testing Wi-Fi frame decoding...')

    def test_rts_packet(self):
        """
        Verify attributes of Request to Sent instance.
        """
        frame = wifi.WIFI(RTS_PACKET)
        self.assertTrue(isinstance(frame, wifi.RTS),
                        'invalid RTS frame!')
        self.assertEqual(frame.radiotap.chan_freq, 5540,
                'invalid channel frequency in radiotap headers')
        self.assertEqual(frame.radiotap.mactime, 2028090499,
                'invalid radiotap mactime')
        self.assertEqual(frame.ta, '88:41:fc:2a:01:a6',
                'invalid transmitter address')
        self.assertEqual(frame.ra, '88:41:fc:2a:01:aa',
                'invalid receiver address')
        self.assertEqual(frame.duration, 2868,
                'invalid duration field')

    def test_cts_packet(self):
        """
        Verify attributes of Clear to Send Instance.
        """
        frame = wifi.WIFI(CTS_PACKET)
        self.assertTrue(isinstance(frame, wifi.CTS),
                        'invalid CTS frame!')
        self.assertEqual(frame.radiotap.mactime, 2028090566,
                'invalid radiotap mactime')
        self.assertEqual(frame.radiotap.chan_freq, 5540,
                'invalid channel frequency in radiotap headers')
        self.assertEqual(frame.ra, '88:41:fc:2a:01:a6',
                'invalid receiver address')
        self.assertEqual(frame.duration, 2808,
                'invalid duration field')

    def test_block_ack_packet(self):
        """
        Verify attributes of Block Acknowledgement instance.
        """
        frame = wifi.WIFI(BLOCK_ACK_PACKET)
        self.assertTrue(isinstance(frame, wifi.BACK),
                        'invalid BLOCK ACK frame!')
        self.assertEqual(frame.radiotap.mactime, 2028093362,
                'invalid radiotap mactime')
        self.assertEqual(frame.radiotap.chan_freq, 5540,
                'invalid channel frequency in radiotap headers')
        self.assertEqual(frame.ta, '88:41:fc:2a:01:aa',
                'invalid transmitter address')
        self.assertEqual(frame.ra, '88:41:fc:2a:01:a6',
                'invalid receiver address')
        self.assertEqual(frame.acked_seqs, list(xrange(713, 754)),
                'invalid sequence numbers in acknowledgement') 

    def test_beacon_packet(self):
        """
        Verify attributes of Beacon instance.
        """
        frame = wifi.WIFI(BEACON_PACKET)
        self.assertTrue(isinstance(frame, wifi.Beacon),
                        'invalid Beacon frame!')
        self.assertEqual(frame.radiotap.mactime, 2020557908,
                'invalid radiotap mactime')
        self.assertEqual(frame.radiotap.chan_freq, 5540,
                'invalid channel frequency in radiotap headers')
        self.assertEqual(frame.ta, '88:41:fc:2a:01:aa',
                'invalid transmitter address')
        self.assertEqual(frame.ra, 'ff:ff:ff:ff:ff:ff',
                'invalid receiver address')
        self.assertEqual(frame.timestamp, 514355210,
                'invalid beacon timestamp')
        self.assertEqual(frame.seq_num, 497, 'invalid sequence number')

    def test_data_amsdu_wds_packet(self):
        """
        Verify attributes of Data instance with A-MSDU usage and in
        WDS(Wireless Distribution System)
        """
        frame = wifi.WIFI(DATA_AMSDU_WDS_PACKET)
        self.assertTrue(isinstance(frame, wifi.QosData),
                        'invalid QosData frame!')
        self.assertEqual(frame.radiotap.mactime, 2024243242,
                'invalid radiotap mactime')
        self.assertEqual(frame.radiotap.chan_freq, 5540,
                'invalid channel frequency in radiotap headers')
        self.assertEqual(frame.from_ds, 1,
                'invalid flag value in frame control')
        self.assertEqual(frame.to_ds, 1,
                'invalid flag value in frame control')
        self.assertEqual(frame.amsdupresent, 1, 'invalid a-msdu information')
        self.assertEqual(frame.ta, '88:41:fc:2a:01:aa',
                'invalid transmitter address')
        self.assertEqual(frame.ra, '88:41:fc:2a:01:a6',
                'invalid receiver address')
        self.assertEqual(frame.seq_num, 37, 'invalid sequence number')
        self.assertEqual(len(frame.payload), 7,
                'invalid a-msdu aggregation formed')

    def test_data_non_amsdu_wds_packet(self):
        """
        Verify attributes of Data instance when A-MSDU is not used in
        WDS(Wireless Distribution System)
        """
        frame = wifi.WIFI(DATA_NON_AMSDU_WDS_PACKET)
        self.assertTrue(isinstance(frame, wifi.QosData),
                        'invalid QosData frame!')
        self.assertEqual(frame.radiotap.mactime, 2045142051,
                'invalid radiotap mactime')
        self.assertEqual(frame.radiotap.chan_freq, 5540,
                'invalid channel frequency in radiotap headers')
        self.assertEqual(frame.from_ds, 1,
                'invalid flag value in frame control')
        self.assertEqual(frame.to_ds, 1,
                'invalid flag value in frame control')
        self.assertEqual(frame.amsdupresent, 0, 'invalid a-msdu information')
        self.assertEqual(frame.ta, '88:41:fc:7a:0f:d3',
                'invalid transmitter address')
        self.assertEqual(frame.ra, '88:41:d8:2a:01:aa',
                'invalid receiver address')
        self.assertEqual(frame.seq_num, 1859, 'invalid sequence number')
        self.assertEqual(len(frame.payload), 1,
                'invalid a-msdu aggregation formed')
