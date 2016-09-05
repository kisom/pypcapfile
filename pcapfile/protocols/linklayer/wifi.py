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

class Radiotap(ctypes.Structure):

    def __init__(self, rtap_bytes):
        """
        :rtap_bytes: ctypes.Structure
        see -> http://www.radiotap.org/defined-fields
        """
        self._raw = {} #contains raw bytes, for debugging purposes
        self._bits = {} #contains bitstrings, for debugging purposes
        idx = 0
        self._rtap = rtap_bytes

        idx += self.strip_vers(idx)
        idx += self.strip_pad(idx)
        idx += self.strip_len(idx)
        idx += self.strip_present(idx)

        if self.present_tsft:
            idx += self.strip_tsft(idx)

        if self.present_flags:
            idx += self.strip_flags(idx)

        if self.present_rate:
            self.strip_rate(idx)

        idx += 1 #null byte exists, even if rate flag = 0

        if self.present_channel:
            idx += self.strip_channel(idx)

        self.prot_type = self.extract_protocol()

    def strip_vers(self, idx):
        """strip(1 byte) radiotap.version
        :idx: int
        :returns: int
            number of processed bytes
        """
        self.vers = struct.unpack('B', self._rtap[idx])[0]
        return 1

    def strip_pad(self, idx):
        """strip(1 byte) radiotap.pad
        :idx: int
        :returns: int
            number of processed bytes
        """
        self.pad = struct.unpack('B', self._rtap[idx])[0]
        return 1

    def strip_len(self, idx):
        """strip(2 byte) radiotap.length
        :idx: int
        :returns: int
            number of processed bytes
        """
        self.len = struct.unpack('H', self._rtap[idx:idx+2])[0]
        return 2

    def strip_present(self, idx):
        """strip(4 byte) radiotap.present. Those are flags that
        identify existence of incoming radiotap meta-data.
        :idx: int
        :returns: int
            number of processed bytes
        """
        self._raw['present'] = self._rtap[idx:idx+4]
        present_val = struct.unpack('<L', self._raw['present'])[0]
        self._bits['present'] = format(present_val, '032b')[::-1]
        self.present_tsft = int(self._bits['present'][0])
        self.present_flags = int(self._bits['present'][1])
        self.present_rate = int(self._bits['present'][2])
        self.present_channel = int(self._bits['present'][3])
        self.present_fhss = int(self._bits['present'][4])
        self.present_dbm_antsignal = int(self._bits['present'][5])
        self.present_dbm_antnoise = int(self._bits['present'][6])
        self.present_lock_quality = int(self._bits['present'][7])
        self.present_tx_attenuation = int(self._bits['present'][8])
        self.present_dbm_tx_attenuation = int(self._bits['present'][9])
        self.present_dbm_tx_power = int(self._bits['present'][10])
        self.present_antenna = int(self._bits['present'][11])
        self.present_db_antsignal = int(self._bits['present'][12])
        self.present_db_antnoise = int(self._bits['present'][13])
        self.present_rxflags = self._bits['present'][14:18]
        self.present_xchannel = int(self._bits['present'][18])
        self.present_mcs = int(self._bits['present'][19])
        self.present_ampdu = int(self._bits['present'][20])
        self.present_vht = int(self._bits['present'][21])
        return 4

    def strip_tsft(self, idx):
        """strip(8 byte) radiotap.mactime timestap value
        :idx: int
        :returns: int
            number of processed bytes
        """
        self._raw['mactime'] = self._rtap[idx:idx+8]
        self.mactime = struct.unpack('Q', self._raw['mactime'])[0]
        return 8

    def strip_flags(self, idx):
        """strip(1 byte) radiotap.flags
        :idx: int
        :returns: int
            number of processed bytes
        """
        self._raw['flags'] = self._rtap[idx:idx+1]
        flags = struct.unpack('<B', self._raw['flags'])[0]
        self._bits['flags'] = format(flags, '08b')[::-1]
        self.cfp = int(self._bits['flags'][0])
        self.preamble = int(self._bits['flags'][1])
        self.wep = int(self._bits['flags'][2])
        self.fragmentation = int(self._bits['flags'][3])
        self.fcs = int(self._bits['flags'][4])
        self.datapad = int(self._bits['flags'][5])
        self.badfcs = int(self._bits['flags'][6])
        self.shortgi = int(self._bits['flags'][7])
        return 1

    def strip_rate(self, idx):
        """strip(1 byte) radiotap.datarate
        note that, unit of this field is 0.5 Mbps
        """
        self._raw['rate'] = self._rtap[idx]
        rate_unit = float(1) / 2 #Mbps
        self.rate = rate_unit * struct.unpack('b', self._raw['rate'])[0] #Mbps

    def strip_channel(self, idx):
        """strip radiotap.channel.freq(2 byte) and
        radiotap.channel.flags(2 byte)
        :idx: int
        :returns: int
            number of processed bytes
        """
        self._raw['channel_freq'] = self._rtap[idx:idx+2]
        self._raw['channel_flags'] = self._rtap[idx+2:idx+4]
        self.chan_freq = struct.unpack('H', self._raw['channel_freq'])[0]
        chan_flags = struct.unpack('H', self._raw['channel_flags'])[0]
        self._bits['channel_flags'] = format(chan_flags, '016b')[::-1]

        self.chan_turbo = int(self._bits['channel_flags'][4])
        self.chan_cck = int(self._bits['channel_flags'][5])
        self.chan_ofdm = int(self._bits['channel_flags'][6])
        self.chan_2ghz = int(self._bits['channel_flags'][7])
        self.chan_5ghz = int(self._bits['channel_flags'][8])
        self.chan_passive = int(self._bits['channel_flags'][9])
        self.chan_dynamic = int(self._bits['channel_flags'][10])
        self.chan_gfsk = int(self._bits['channel_flags'][11])
        self.chan_gsm = int(self._bits['channel_flags'][12])
        self.chan_static_turbo = int(self._bits['channel_flags'][13])
        self.chan_half_rate = int(self._bits['channel_flags'][14])
        self.chan_quarter_rate = int(self._bits['channel_flags'][15])
        return 4

    def extract_protocol(self):
        """extract 802.11 protocol from radiotap.channel.flags
        :return: str
            protocol name
            one of below in success
            [.11a, .11b, .11g, .11n, .11ac]
            None in fail
        """
        if self.present_mcs:
            return '.11n'

        if self.present_vht:
            return '.11ac'

        if self.present_channel:
            if self.chan_5ghz:
                if self.chan_ofdm:
                    return '.11a'
            elif self.chan_2ghz:
                if self.chan_cck:
                    return '.11b'
                elif self.chan_ofdm or self.chan_dynamic:
                    return '.11g'
        print "No protocol match with radiotap.channel.flags"
        return 'None'

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
        self._raw = {}
        rtap_bytes, self._packet = WiHelper._strip_rtap(frame)
        self.radiotap = Radiotap(rtap_bytes)

        self.fc = struct.unpack('BB', self._packet[:2]) #frame control
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

        self.duration = struct.unpack('H', self._packet[2:4])[0] # us
        
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

    def print_all(self):
        """prints packet headers + radiotap headers"""
        self.print_packet()
        self.print_rtap()

    def print_packet(self):
        """prints packet headers (main object)"""
        print "*** PACKET INFORMATION ***"
        attrs = vars(self)
        for key, val in attrs.items():
            if key[0] != '_':
                print "{}: {}".format(key, val)

    def print_rtap(self):
        """prints radiotap headers (radiotap object)"""
        print "*** RADIOTAP INFORMATION ***"
        attrs = vars(self.radiotap)
        for key, val in attrs.items():
            if key[0] != '_':
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
        idx = 0
        seq_idx, qos_idx  = self.strip_mac_addrs(self.to_ds, self.from_ds)
        self.seq_idx = seq_idx
        self.qos_idx = qos_idx

        self.strip_seq_cntrl(seq_idx)
        idx = qos_idx
        idx += self.strip_qos_cntrl(idx)

        if self.amsdupresent != None:
            self.amsdu_packets = []

    def strip_mac_addrs(self, to_ds, from_ds):
        """strip mac address(each 6 byte) information and
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
                struct.unpack('!6s6s6s', self._packet[4:22])
            sa_mac = struct.unpack('!6s', self._packet[24:30])[0]
            qos_idx = 30
            seq_idx = 22 
        elif self.to_ds == 0 and self.from_ds == 1:
            (ra_mac, ta_mac, sa_mac) =\
                struct.unpack('!6s6s6s', self._packet[4:22])
            qos_idx = 22
            seq_idx = qos_idx
        elif self.to_ds == 1 and self.from_ds == 0:
            (ra_mac, ta_mac, da_mac) =\
                struct.unpack('!6s6s6s', self._packet[4:22])
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

    def strip_seq_cntrl(idx):
        """strip(2 byte) wlan.seq(12 bit) and wlan.fram(4 bit)
        number information.
        :seq_cntrl: ctypes.Structure
        :return: int
        """
        seq_cntrl = struct.unpack('H', self._packet[idx:idx+2])
        self.seq_num = seq_cntrl >> 4
        self.frag_num = seq_cntrl & 0x000f

    def strip_qos_cntrl(idx):
        """strip(2 byte) wlan.qos.
        :returns: int
            number of processed bytes
        """
        #TODO: parse remaining fields with respect to from_ds and to_ds
        #https://mrncciew.com/2014/10/03/cwap-mac-header-qos-control/
        #TODO: check .11n sniffs (snice a-msdu first introduced in .11n)
        qos_cntrl = struct.unpack('H', self._packet[idx:idx+2])
        self._qos_cntrl_bits = format(qos_cntrl, '016b')[::-1]
        self.qos_priority = qos_cntrl & 0x000f
        self.amsdupresent = None
        if self.radiotap.prot_type == '.11ac':
            self.amsdupresent = int(self._qos_cntrl_bits[7])

    def strip_msdu(self, idx):
        """strip single mac servis data unit(msdu)
        :idx: int
        :return: dict
            msdu
        :return: int
            number of processed bytes
        """
        msdu = {}
        msdu['llc'] = {}

        (da_mac, sa_mac) = struct.unpack('!6s6s', self._packet[idx:idx+12])
        msdu['wlan.da'] = Wifi.get_mac_addr(da_mac)
        msdu['wlan.sa'] = Wifi.get_mac_addr(sa_mac)
        idx += 12
        offset, msdu['llc'] = self.strip_llc(idx)
        idx += offset
        msdu['msdu.length'] = struct.unpack('!H', self._packet[idx:idx+2])[0]
        idx += 2


    def strip_llc(self, idx):
        """strip(4 or 8 byte) logical link control headers
        :return: int
            number of processed bytes
        :return: dict
            llc information
        see -> http://www.wildpackets.com/resources/compendium/ethernet/frame_snap_iee8023
        """
        #TODO: find length of llc header for all combinations of sap and dsap values
        llc = {}
        llc_dsap = struct.unpack('B', self._packet[idx])[0]
        llc['dsap.dsap'] = llc_dsap >> 1
        llc['dsap.ig'] = llc_dsap & 0b01
        llc_ssap = struct.unpack('B', self._packet[idx+1])[0]
        llc['ssap.sap'] = llc_ssap >> 1
        llc['ssap.cr'] = llc_ssap & 0b01
        if llc_dsap == 170 and llc_ssap == 170:
            llc_control = struct.unpack('B', self._packet[idx+1:idx+3])[0]
            llc['control.u_modifier_cmd'] = llc_control >> 2
            llc['control.ftype'] = llc_control & 0x03
            llc['organization_code'] = self.packet[idx+2:idx+5]
            llc['type'] = self.packet[idx+5:idx+7]
            return 8, llc
        else:
            return 4, llc

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
        (ra_mac, ta_mac) = struct.unpack('!6s6s', self._packet[4:16])
        self.ra = Wifi.get_mac_addr(ra_mac)
        self.ta = Wifi.get_mac_addr(ta_mac)

class CTS(Control):

    """Clear to Send Frame"""

    def __init__(self, frame):
        """Constructor Method
        :frame: ctypes.Structure
        """
        Control.__init__(self, frame)
        ra_mac = struct.unpack('!6s', self._packet[4:10])[0]
        self.ra = Wifi.get_mac_addr(ra_mac)

class BACK(Control):

    """Block Acknowledgement Frame"""

    def __init__(self, frame):
        """Constructor Method
        :frame: ctypes.Structure
        """
        Control.__init__(self, frame)
        (ra_mac, ta_mac) = struct.unpack('!6s6s', self._packet[4:16])
        self.ra = Wifi.get_mac_addr(ra_mac)
        self.ta = Wifi.get_mac_addr(ta_mac)
        self.acked_seqs = []

        self.strip_cntrl()
        self.strip_ssc()
        self.strip_bitmap_str()
        self.acked_seqs = self.extract_acked_seqs()

    def strip_cntrl(self):
        """strip(2 byte) wlan.ba.control
        """
        self.cntrl = struct.unpack('H', self._packet[16:18])[0] #block ack request control
        self._cntrl_bits = format(self.cntrl, '016b')[::-1]
        self.ackpolicy = int(self._cntrl_bits[0])
        self.multitid = int(self._cntrl_bits[1])

    def strip_ssc(self):
        """strip(2 byte) wlan_mgt.fixed.ssc
        """
        self.ssc = struct.unpack('H', self._packet[18:20])[0] #starting sequence control
        self.ssc_sequence = self.ssc >> 4
        self.ssc_frag = self.ssc & 0x000f

    def strip_bitmap_str(self):
        """strip(8 byte) wlan.ba.bm
        """
        self.bitmap = struct.unpack('BBBBBBBB', self._packet[20:28])
        self.bitmap_str = ''
        for elem in self.bitmap:
            self.bitmap_str += format(elem, '08b')[::-1]

    def extract_acked_seqs(self):
        """extracts acknowledged sequences from bitmap and
        starting sequence number.
        :return: int[]
            acknowledged sequence numbers
        """
        acked_seqs = []
        for idx, val in enumerate(self.bitmap_str):
           if int(val) == 1:
              seq = (self.ssc_sequence + idx) % 4096
              acked_seqs.append(seq)
        return acked_seqs
