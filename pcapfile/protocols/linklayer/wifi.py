#!/usr/bin/python
"""
Wi-Fi protocol definitions.
"""

import binascii
import ctypes
import struct

_CATEGORIES_ = {0:'management', 1:'control', 2:'data'}

_SUBTYPES_ = {}

_SUBTYPES_[0] = {0:'Association Request',
        1:'Association Response', 2:'Reassociation Request',
        3:'Reassociation Response', 4:'Probe Request',
        5:'Probe Response', 8:'Beacon', 9:'ATIM',
        10:'Disassociation', 11:'Authentication', 12:'Deauthentication'}

_SUBTYPES_[1] = {8:'BAR', 9:'BACK', 10:'PS-POLL',
        11:'RTS', 12:'CTS', 13:'ACK', 14:'CF-end',
        15:'CF-end + CF-ack'}

_SUBTYPES_[2] = {0:'Data', 1:'Data + CF-ack', 2:'Data + CF-poll',
        3:'Data+CF-ack+CF-poll', 4:'Null', 5:'CF-ack',
        6:'CF-poll', 7:'CF-ack+CF-poll', 8:'QoS data',
        9:'QoS data + CF-ack', 10:'QoS data + CF-poll',
        11:'QoS data + CF-ack + CF-poll', 12:'QoS Null',
        13:'Reserved', 14:'Qos + CF-poll(no data)',
        15:'Qos + CF-ack(no data)'}

class WiHelper:

    @staticmethod
    def get_wifi_packet(frame):
        """returns Wi-Fi packet object.
        use obj.print_info() to get packet
        information.
        :frame: ctypes.Structure
        :returns: obj
        """
        rtap, packet = WiHelper._strip_rtap(frame)
        frame_control = struct.unpack('BB', packet[:2])
        flags = frame_control[:1]
        cat = (frame_control[0] >> 2) & 0b0011
        s_type = frame_control[0] >> 4

        if cat not in _CATEGORIES_.keys():
            print "invalid format"
            return None

        if s_type not in _SUBTYPES_[cat].keys():
            print "invalid subtype {} in {} category".format(s_type,
                    _CATEGORIES_[cat])
            return None

        print "category:{}, subtype: {}".format(cat, s_type)

        if cat == 0:
            return Management(frame)
        elif cat == 1:
            if s_type == 11:
                return RTS(frame)
            elif s_type == 12:
                return CTS(frame)
            elif s_type == 9:
                return BACK(frame)
            else:
                return Control(frame)
        elif cat == 2:
            if s_type == 8:
                return QosData(frame)
            else:
                return Data(frame)

    @staticmethod
    def _strip_rtap(frame):
        """strip injected radiotap header
        :return: ctypes.Structure
            radiotap header
        :return: ctypes.Structure
            actual layer 2 Wi-Fi payload
        """
        rtap_len = WiHelper.__get_rtap_len(frame)
        rtap = frame[:rtap_len-1]
        packet = frame[rtap_len:]
        return rtap, packet

    @staticmethod
    def __get_rtap_len(frame):
        """parses length of radiotap header
        :packet: ctypes.structure
        :returns: int
        """
        r_len = struct.unpack('H', frame[2:4])
        return r_len[0]

class Wifi(ctypes.Structure):

    def __init__(self, frame):
        """Constructor method. Parses common headers
        of all Wi-Fi frames.
        :frame: ctypes.Structure
        """
        self.rtap, self.packet = WiHelper._strip_rtap(frame)
        self.fc = struct.unpack('BB', self.packet[:2]) #frame control
        self.flags = self.fc[1]
        self.vers = self.fc[0] & 0b0011
        self.category = (self.fc[0] >> 2) & 0b0011
        self.subtype = self.fc[0] >> 4

        self.flag_bits = format(self.flags, '08b')[::-1]
        self.to_ds = int(self.flag_bits[0])
        self.from_ds = int(self.flag_bits[1])
        self.more_flag = int(self.flag_bits[2])
        self.retry = int(self.flag_bits[3])
        self.power_mgmt = int(self.flag_bits[4])
        self.more_data = int(self.flag_bits[5])
        self.wep = int(self.flag_bits[6])
        self.order = int(self.flag_bits[7])

        self.duration = struct.unpack('H', self.packet[2:4])[0] # us
        
        self.name = None
        if self.category == 0:
            if self.subtype in _SUBTYPES_[0].keys():
                self.name = _SUBTYPES_[0][self.subtype]
        elif self.category == 1:
            if self.subtype in _SUBTYPES_[1].keys():
                self.name = _SUBTYPES_[1][self.subtype]
        elif self.category == 2:
            if self.subtype in _SUBTYPES_[2].keys():
                self.name = _SUBTYPES_[2][self.subtype]

        if self.name != None:
            print self.name

    def print_info(self):
        """prints attributes of object"""
        attrs = vars(self)

        for key, val in attrs.items():
            if key != 'packet' and key != 'rtap':
                print "{}: {}".format(key, val)

    @staticmethod
    def get_mac_addr(mac_addr):
        """converts bytes to mac addr format
        :mac_addr: ctypes.structure
        :returns: str
            mac addr in format
            11:22:33:aa:bb:cc
        """
        mac_addr = bytearray(mac_addr)
        mac = b':'.join([('%02x' % o).encode('ascii')
            for o in mac_addr])
        return mac

class Data(Wifi):

    """Data Packet Constructor"""

    def __init__(self, frame):
        """Constructor Method
        :packet: ctypes.Structure
        """
        Wifi.__init__(self, frame)

class QosData(Data):

    def __init__(self, frame):
        Data.__init__(self, frame)
        seq_idx, qos_idx  = self.get_mac_addrs(self.to_ds, self.from_ds)
        self.seq_idx = seq_idx
        self.qos_idx = qos_idx

    def get_mac_addrs(self, to_ds, from_ds):
        """parses mac address information and
        sets into object.
        (wlan.ta, wlan.ra, wlan.sa, wlan.da)
        (transmitter, receiver, source, destination)
        :to_ds: int
            0 or 1 [whether packet transmitted to WDS]
        :from_ds: int
            0 or 1 [whether packet transmitted from WDS]
        :return: int
            index of sequence control
        :return: int
            index after mac addresses
        """
        qos_idx, seq_idx = 0, 0
        ta_mac, ra_mac, sa_mac, da_mac = None, None, None, None

        if self.to_ds == 1 and self.from_ds == 1:
            (ra_mac, ta_mac, da_mac) =\
                struct.unpack('!6s6s6s', self.packet[4:22])
            sa_mac = struct.unpack('!6s', self.packet[24:30])[0]
            qos_idx = 30
            seq_idx = 22 
        elif self.to_ds == 0 and self.from_ds == 1:
            (ra_mac, ta_mac, sa_mac) =\
                struct.unpack('!6s6s6s', self.packet[4:22])
            qos_idx = 22
            seq_idx = qos_idx
        elif self.to_ds == 1 and self.from_ds == 0:
            (ra_mac, ta_mac, da_mac) =\
                struct.unpack('!6s6s6s', self.packet[4:22])
            qos_idx = 22
            seq_idx = qos_idx
        
        if ta_mac != None:
            self.ta = Wifi.get_mac_addr(ta_mac)
        if ra_mac != None:
            self.ra = Wifi.get_mac_addr(ra_mac)
        if sa_mac != None:
            self.sa = Wifi.get_mac_addr(sa_mac)
        if da_mac != None:
            self.da = Wifi.get_mac_addr(da_mac)

        return seq_idx, qos_idx

    def parse_seq_cntrl(seq_cntrl):
        """
        :seq_cntrl: ctypes.Structure
        :return: int
            sequence number
        :return: int
            fragment number
        """

class Management(Wifi):

    """Management Packet Constructor"""

    def __init__(self, frame):
        """Constructor Method
        :frame: ctypes.Structure
        :subtype: int
        """
        Wifi.__init__(self, frame)

class Control(Wifi):

    """Control Packet Constructor"""

    def __init__(self, frame):
        """Constructor Method
        :frame: ctypes.Structure
        """
        Wifi.__init__(self, frame)

class RTS(Control):

    """Request to Send Frame"""

    def __init__(self, frame):
        """Constructor Method
        :frame: ctypes.Structure
        """
        Control.__init__(self, frame)
        (ra_mac, ta_mac) = struct.unpack('!6s6s', self.packet[4:16])
        self.ra = Wifi.get_mac_addr(ra_mac)
        self.ta = Wifi.get_mac_addr(ta_mac)

class CTS(Control):

    """Clear to Send Frame"""

    def __init__(self, frame):
        """Constructor Method
        :frame: ctypes.Structure
        """
        Control.__init__(self, frame)
        ra_mac = struct.unpack('!6s', self.packet[4:10])[0]
        self.ra = Wifi.get_mac_addr(ra_mac)

class BACK(Control):

    """Block Acknowledgement Frame"""

    def __init__(self, frame):
        """Constructor Method
        :frame: ctypes.Structure
        """
        Control.__init__(self, frame)
        (ra_mac, ta_mac) = struct.unpack('!6s6s', self.packet[4:16])
        self.ra = Wifi.get_mac_addr(ra_mac)
        self.ta = Wifi.get_mac_addr(ta_mac)
        self.cntrl = struct.unpack('H', self.packet[16:18])[0]
        #TODO: parse Immediate BAR-ack policy, MultiTID flag
        #      Compressed Bitmap Flag, reserverd field and TID
        self.seq_cntrl = struct.unpack('H', self.packet[18:20])[0]
        #TODO: parse starting sequence number and fragment
        self.bitmap = struct.unpack('BBBBBBBB', self.packet[20:])
        self.bitmap_str = ''
        for elem in self.bitmap:
            self.bitmap_str += format(elem, '08b')[::-1]
