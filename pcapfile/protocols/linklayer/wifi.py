#!/usr/bin/python
"""
Wi-Fi protocol definitions.
"""

import binascii
import ctypes
import struct

NOT_PRINT = ['rtap', 'packet', 'fc', 'info']

CATEGORY = {}

class Wifi(ctypes.Structure):

    """WiFi packet handler class. """
    _categories_ = {0:'management', 1:'control', 2:'data'}

    def __init__(self, frame):
        """Constructor method. Casts generic headers
        of all Wi-Fi frames.
        :packet: ctypes.Structure
        """
        self.rtap, self.packet = Wifi.strip_rtap(frame)
        self.fc = struct.unpack('BB', self.packet[:2]) #frame control
        self.flags = self.fc[1]
        self.vers = self.fc[0] & 0b0011
        self.category = (self.fc[0] >> 2) & 0b0011
        self.subtype = self.fc[0] >> 4

        self.to_ds = self.flags & 00000001
        self.from_ds = self.flags & 00000010
        self.more_flag = self.flags & 00000100
        self.retry = self.flags & 00001000
        self.power_mgmt = self.flags & 00010000
        self.more_data = self.flags & 00100000
        self.wep = self.flags & 01000000
        self.order = self.flags & 10000000

        self.duration = struct.unpack('H', self.packet[2:4])[0] # us

        if self.category in self._categories_.keys():
            if self.category == 0:
                self.info = self.Management(self.packet, self.subtype)
            elif self.category == 1:
                self.info = self.Control(self.packet, self.subtype)
            elif self.category == 2:
                self.info = self.Data(self.packet, self.subtype)

    def print_info(self):
        """prints attributes of object"""
        attrs = vars(self)
        attrs.update(vars(self.info))
        attrs.update(vars(self.info.ctx))
        for key, val in attrs.items():
            if key not in NOT_PRINT:
                print "{}: {}".format(key, val)

    @staticmethod
    def strip_rtap(frame):
        """strip injected radiotap header
        :return: ctypes.Structure
            radiotap header
        :return: ctypes.Structure
            actual layer 2 Wi-Fi payload
        """
        rtap_len = Wifi.get_rtap_len(frame)
        rtap = frame[:rtap_len-1]
        packet = frame[rtap_len:]
        return rtap, packet

    @staticmethod
    def get_rtap_len(frame):
        """parses length of radiotap header
        :packet: ctypes.structure
        :returns: int
        """
        r_len = struct.unpack('H', frame[2:4])
        return r_len[0]

    class Data(ctypes.Structure):

        """Data Packet Constructor"""

        _subtypes_ = {0:'Data', 1:'Data + CF-ack', 2:'Data + CF-poll',
                3:'Data+CF-ack+CF-poll', 4:'Null', 5:'CF-ack',
                6:'CF-poll', 7:'CF-ack+CF-poll', 8:'QoS data',
                9:'QoS data + CF-ack', 10:'QoS data + CF-poll',
                11:'QoS data + CF-ack + CF-poll', 12:'QoS Null',
                13:'Reserved', 14:'Qos + CF-poll(no data)',
                15:'Qos + CF-ack(no data)'}

        def __init__(self, packet, subtype):
            """Constructor Method
            :packet: ctypes.Structure
            :subtype: int
            """
            self.name = None
            self.ctx = None
            if subtype in self._subtypes_.keys():
                self.name = self._subtypes_[subtype]
            else:
                return


    class Management(ctypes.Structure):

        """Management Packet Constructor"""

        _subtypes_ = {0:'Association Request', 1:'Association Response',
                2:'Reassociation Request', 3:'Reassociation Response',
                4:'Probe Request', 5:'Probe Response', 8:'Beacon',
                9:'ATIM', 10:'Disassociation', 11:'Authentication',
                12:'Deauthentication'}

        def __init__(self, packet, subtype):
            """Constructor Method
            :packet: ctypes.Structure
            :subtype: int
            """
            self.name = None
            self.ctx = None
            if subtype in self._subtypes_.keys():
                self.name = self._subtypes_[subtype]
            else:
                return

    class Control(ctypes.Structure):

        """Control Packet Constructor"""

        _subtypes_ = {8:'BAR', 9:'BACK', 10:'PS-POLL',
                11:'RTS', 12:'CTS', 13:'ACK', 14:'CF-end',
                15:'CF-end + CF-ack'}

        def __init__(self, packet, subtype):
            """Constructor Method
            :packet: ctypes.Structure
            :subtype: int
            """
            self.name = None
            self.ctx = None
            if subtype in self._subtypes_.keys():
                self.name = self._subtypes_[subtype]
            else:
                return
            if self.name == 'RTS':
                self.ctx = self.RTS(packet)
            elif self.name == 'CTS':
                self.ctx = self.CTS(packet)
            elif self.name == 'BACK':
                self.ctx = self.BACK(packet)
            else:
                pass

        class RTS(ctypes.Structure):

            """Request to Send Frame"""

            def __init__(self, packet):
                """Constructor Method
                :packet: ctypes.Structure
                """
                (rx_mac, tx_mac) = struct.unpack('!6s6s', packet[4:16])
                rx_mac = bytearray(rx_mac)
                tx_mac = bytearray(tx_mac)
                self.ra = b':'.join([('%02x' % o).encode('ascii')
                    for o in rx_mac])
                self.ta = b':'.join([('%02x' % o).encode('ascii')
                    for o in tx_mac])

        class CTS(ctypes.Structure):

            """Clear to Send Frame"""

            def __init__(self, packet):
                """Constructor Method
                :packet: ctypes.Structure
                """
                rx_mac = struct.unpack('!6s', packet[4:10])[0]
                rx_mac = bytearray(rx_mac)
                self.ra = b':'.join([('%02x' % o).encode('ascii')
                    for o in rx_mac])

        class BACK(ctypes.Structure):

            """Block Acknowledgement Frame"""

            def __init__(self, packet):
                """Constructor Method
                :packet: ctypes.Structure
                """
                (rx_mac, tx_mac) = struct.unpack('!6s6s', packet[4:16])
                rx_mac = bytearray(rx_mac)
                tx_mac = bytearray(tx_mac)
                self.ra = b':'.join([('%02x' % o).encode('ascii')
                    for o in rx_mac])
                self.ta = b':'.join([('%02x' % o).encode('ascii')
                    for o in tx_mac])
                self.cntrl = struct.unpack('H', packet[16:18])
                self.seq_cntrl = struct.unpack('H', packet[18:20])
                self.bitmap = struct.unpack('BBBBBBBB', packet[20:])
                self.bitstr = ''
                for elem in self.bitmap:
                    self.bitstr += format(elem, '08b')[::-1]
