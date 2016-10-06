#!/usr/bin/python
"""
Wi-Fi protocol definitions.
"""

import binascii
import ctypes
import struct
import logging

#wlan.fc.type
_CATEGORIES_ = {0:'management', 1:'control', 2:'data'}

_SUBTYPES_ = {}

#wlan.fc.type_subtype
_SUBTYPES_[0] = {0:'Association Request',
        1:'Association Response', 2:'Reassociation Request',
        3:'Reassociation Response', 4:'Probe Request',
        5:'Probe Response', 8:'Beacon', 9:'ATIM',
        10:'Disassociation', 11:'Authentication', 12:'Deauthentication',
        13:'Action', 14:'Action No ACK'}

_SUBTYPES_[1] = {5:'VHT NDP Announcement', 7:'Control Wrapper', 8:'BAR',
        9:'BACK', 10:'PS-POLL', 11:'RTS', 12:'CTS', 13:'ACK',
        14:'CF-end', 15:'CF-end + CF-ack'}

_SUBTYPES_[2] = {0:'Data', 1:'Data + CF-ack', 2:'Data + CF-poll',
        3:'Data+CF-ack+CF-poll', 4:'Null', 5:'CF-ack',
        6:'CF-poll', 7:'CF-ack+CF-poll', 8:'QoS data',
        9:'QoS data + CF-ack', 10:'QoS data + CF-poll',
        11:'QoS data + CF-ack + CF-poll', 12:'QoS Null',
        13:'Reserved', 14:'Qos + CF-poll(no data)',
        15:'Qos + CF-ack(no data)'}

#wlan_mgt.tag
MNGMT_TAGS = {
    0: "TAG_SSID",
    1: "TAG_SUPP_RATES",
    2: "TAG_FH_PARAMETER",
    3: "TAG_DS_PARAMETER",
    4: "TAG_CF_PARAMETER",
    5: "TAG_TIM",
    6: "TAG_IBSS_PARAMETER",
    7: "TAG_COUNTRY_INFO",
    8: "TAG_FH_HOPPING_PARAMETER",
    9: "TAG_FH_HOPPING_TABLE",
    10: "TAG_REQUEST",
    11: "TAG_QBSS_LOAD",
    12: "TAG_EDCA_PARAM_SET",
    13: "TAG_TSPEC",
    14: "TAG_TCLAS",
    15: "TAG_SCHEDULE",
    16: "TAG_CHALLENGE_TEXT",
    32: "TAG_POWER_CONSTRAINT",
    33: "TAG_POWER_CAPABILITY",
    34: "TAG_TPC_REQUEST",
    35: "TAG_TPC_REPORT",
    36: "TAG_SUPPORTED_CHANNELS",
    37: "TAG_CHANNEL_SWITCH_ANN",
    38: "TAG_MEASURE_REQ",
    39: "TAG_MEASURE_REP",
    40: "TAG_QUIET",
    41: "TAG_IBSS_DFS",
    42: "TAG_ERP_INFO",
    43: "TAG_TS_DELAY",
    44: "TAG_TCLAS_PROCESS",
    45: "TAG_HT_CAPABILITY",
    46: "TAG_QOS_CAPABILITY",
    47: "TAG_ERP_INFO_OLD",
    48: "TAG_RSN_IE",
    50: "TAG_EXT_SUPP_RATES",
    51: "TAG_AP_CHANNEL_REPORT",
    52: "TAG_NEIGHBOR_REPORT",
    53: "TAG_RCPI",
    54: "TAG_MOBILITY_DOMAIN",
    55: "TAG_FAST_BSS_TRANSITION",
    56: "TAG_TIMEOUT_INTERVAL",
    57: "TAG_RIC_DATA",
    58: "TAG_DSE_REG_LOCATION",
    59: "TAG_SUPPORTED_OPERATING_CLASSES",
    60: "TAG_EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT",
    61: "TAG_HT_INFO",
    62: "TAG_SECONDARY_CHANNEL_OFFSET",
    63: "TAG_BSS_AVG_ACCESS_DELAY",
    64: "TAG_ANTENNA",
    65: "TAG_RSNI",
    66: "TAG_MEASURE_PILOT_TRANS",
    67: "TAG_BSS_AVB_ADM_CAPACITY",
    68: "TAG_BSS_AC_ACCESS_DELAY",
    69: "TAG_TIME_ADV",
    70: "TAG_RM_ENABLED_CAPABILITY",
    71: "TAG_MULTIPLE_BSSID",
    72: "TAG_20_40_BSS_CO_EX",
    73: "TAG_20_40_BSS_INTOL_CH_REP",
    74: "TAG_OVERLAP_BSS_SCAN_PAR",
    75: "TAG_RIC_DESCRIPTOR",
    76: "TAG_MMIE",
    78: "TAG_EVENT_REQUEST",
    79: "TAG_EVENT_REPORT",
    80: "TAG_DIAGNOSTIC_REQUEST",
    81: "TAG_DIAGNOSTIC_REPORT",
    82: "TAG_LOCATION_PARAMETERS",
    83: "TAG_NO_BSSID_CAPABILITY",
    84: "TAG_SSID_LIST",
    85: "TAG_MULTIPLE_BSSID_INDEX",
    86: "TAG_FMS_DESCRIPTOR",
    87: "TAG_FMS_REQUEST",
    88: "TAG_FMS_RESPONSE",
    89: "TAG_QOS_TRAFFIC_CAPABILITY",
    90: "TAG_BSS_MAX_IDLE_PERIOD",
    91: "TAG_TFS_REQUEST",
    92: "TAG_TFS_RESPONSE",
    93: "TAG_WNM_SLEEP_MODE",
    94: "TAG_TIM_BROADCAST_REQUEST",
    95: "TAG_TIM_BROADCAST_RESPONSE",
    96: "TAG_COLLOCATED_INTER_REPORT",
    97: "TAG_CHANNEL_USAGE",
    98: "TAG_TIME_ZONE",
    99: "TAG_DMS_REQUEST",
    100: "TAG_DMS_RESPONSE",
    101: "TAG_LINK_IDENTIFIER",
    102: "TAG_WAKEUP_SCHEDULE",
    104: "TAG_CHANNEL_SWITCH_TIMING",
    105: "TAG_PTI_CONTROL",
    106: "TAG_PU_BUFFER_STATUS",
    107: "TAG_INTERWORKING",
    108: "TAG_ADVERTISEMENT_PROTOCOL",
    109: "TAG_EXPIDITED_BANDWIDTH_REQ",
    110: "TAG_QOS_MAP_SET",
    111: "TAG_ROAMING_CONSORTIUM",
    112: "TAG_EMERGENCY_ALERT_ID",
    113: "TAG_MESH_CONFIGURATION",
    114: "TAG_MESH_ID",
    115: "TAG_MESH_LINK_METRIC_REPORT",
    116: "TAG_CONGESTION_NOTIFICATION",
    117: "TAG_MESH_PEERING_MGMT",
    118: "TAG_MESH_CHANNEL_SWITCH",
    119: "TAG_MESH_AWAKE_WINDOW",
    120: "TAG_BEACON_TIMING",
    121: "TAG_MCCAOP_SETUP_REQUEST",
    122: "TAG_MCCAOP_SETUP_REPLY",
    123: "TAG_MCCAOP_ADVERTISEMENT",
    124: "TAG_MCCAOP_TEARDOWN",
    125: "TAG_GANN",
    126: "TAG_RANN",
    127: "TAG_EXTENDED_CAPABILITIES",
    128: "TAG_AGERE_PROPRIETARY",
    130: "TAG_MESH_PREQ",
    131: "TAG_MESH_PREP",
    132: "TAG_MESH_PERR",
    133: "TAG_CISCO_CCX1_CKIP",
    136: "TAG_CISCO_CCX2",
    137: "TAG_PXU",
    138: "TAG_PXUC",
    139: "TAG_AUTH_MESH_PEERING_EXCH",
    140: "TAG_MIC",
    141: "TAG_DESTINATION_URI",
    142: "TAG_U_APSD_COEX",
    143: "TAG_WAKEUP_SCHEDULE_AD",
    144: "TAG_EXTENDED_SCHEDULE",
    145: "TAG_STA_AVAILABILITY",
    146: "TAG_DMG_TSPEC",
    147: "TAG_NEXT_DMG_ATI",
    148: "TAG_DMG_CAPABILITIES",
    149: "TAG_CISCO_CCX3",
    150: "TAG_CISCO_VENDOR_SPECIFIC",
    151: "TAG_DMG_OPERATION",
    152: "TAG_DMG_BSS_PRAMTER_CHANGE",
    153: "TAG_DMG_BEAM_REFINEMENT",
    154: "TAG_CHANNEL_MEASURMENT_FB",
    157: "TAG_AWAKE_WINDOW",
    158: "TAG_MULTI_BAND",
    159: "TAG_ADDBA_EXT",
    160: "TAG_NEXTPCP_LIST",
    161: "TAG_PCP_HANDOVER",
    162: "TAG_DMG_LINK_MARGIN",
    163: "TAG_SWITCHING_STREAM",
    164: "TAG_SESSION_TRANSMISSION",
    165: "TAG_DYN_TONE_PAIR_REP",
    166: "TAG_CLUSTER_REP",
    167: "TAG_RELAY_CAPABILITIES",
    168: "TAG_RELAY_TRANSFER_PARAM",
    169: "TAG_BEAMLINK_MAINTAINCE",
    170: "TAG_MULTIPLE_MAC_SUBLAYERS",
    171: "TAG_U_PID",
    172: "TAG_DMG_LINK_ADAPTION_ACK",
    173: "TAG_SYMBOL_PROPRIETARY",
    174: "TAG_MCCAOP_ADVERTISEMENT_OV",
    175: "TAG_QUIET_PERIOD_REQ",
    177: "TAG_QUIET_PERIOD_RES",
    182: "TAG_ECPAC_POLICY",
    183: "TAG_CLUSTER_TIME_OFFSET",
    190: "TAG_ANTENNA_SECTOR_ID",
    191: "TAG_VHT_CAPABILITY",
    192: "TAG_VHT_OPERATION",
    193: "TAG_EXT_BSS_LOAD",
    194: "TAG_WIDE_BW_CHANNEL_SWITCH",
    195: "TAG_VHT_TX_PWR_ENVELOPE",
    196: "TAG_CHANNEL_SWITCH_WRAPPER",
    199: "TAG_OPERATING_MODE_NOTIFICATION",
    221: "TAG_VENDOR_SPECIFIC_IE"
}

def WIFI(frame):
    """calls wifi packet discriminator and constructor.
    :frame: ctypes.Structure
    :returns: packet object in success
    :returns: int
        -1 on known error
    :returns: int
        -2 on unknown error
    """
    pack = None
    try:
        pack = WiHelper.get_wifi_packet(frame)
    except Exception as e:
        logging.exception("message")
    return pack

class WiHelper:

    """Wi-Fi packet discriminator class.
    Identifies type and subtype of packet, then trigs
    packet object creation.
    """

    @staticmethod
    def get_wifi_packet(frame):
        """Discriminates Wi-Fi packet and creates
        packet object.
        use obj.print_all() to get all header information.
        use obj.print_packet() to get layer 2 header information.
        use obj.print_rtap() to get radiotap header information.
        :frame: ctypes.Structure
        :returns: obj
            Wi-Fi packet
        """
        rtap, packet = WiHelper._strip_rtap(frame)
        frame_control = struct.unpack('BB', packet[:2])
        flags = frame_control[:1]
        cat = (frame_control[0] >> 2) & 0b0011
        s_type = frame_control[0] >> 4

        if cat not in _CATEGORIES_.keys():
            print("invalid category: %d" % (cat))
            return -1

        if s_type not in _SUBTYPES_[cat].keys():
            print("invalid subtype %d in %s category" % (s_type, _CATEGORIES_[cat]))
            return -1

        if cat == 0:
            if s_type == 4:
                return ProbeReq(frame)
            elif s_type == 5:
                return ProbeResp(frame)
            elif s_type == 8:
                return Beacon(frame)
            else:
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
        """strip injected radiotap header.
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
        """parse length of radiotap header.
        :packet: ctypes.structure
        :returns: int
        """
        r_len = struct.unpack('H', frame[2:4])
        return r_len[0]

class Radiotap(ctypes.Structure):

    """Radiotap Header Parser Class.
    Radiotap headers summarizes physical layer headers
    of Wi-Fi packet, such as MCS(modulation and coding scheme),
    NSS(number of spatial streams), BW(bandwidth) for all common
    protocol types(802.11a, 802.11n, 802.11ac etc.)
    """

    def __init__(self, rtap_bytes):
        """Constructor method.
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
        self.vers = struct.unpack('B', self._rtap[idx:idx+1])[0]
        return 1

    def strip_pad(self, idx):
        """strip(1 byte) radiotap.pad
        :idx: int
        :returns: int
            number of processed bytes
        """
        self.pad = struct.unpack('B', self._rtap[idx:idx+1])[0]
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
        self.rate = rate_unit * struct.unpack('b', self._rtap[idx:idx+1])[0] #Mbps

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
        return 'None'

class Wifi(ctypes.Structure):

    """Base Wi-Fi Packet"""

    def __init__(self, frame):
        """Constructor method.
        Parse common headers of all Wi-Fi frames.
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

    def print_all(self):
        """prints packet headers + radiotap headers"""
        self.print_packet()
        self.print_rtap()

    def print_packet(self):
        """prints packet headers (main object)"""
        print("*** PACKET INFORMATION ***")
        attrs = vars(self)
        for key, val in attrs.items():
            if key[0] != '_':
                print("%s: %s" % (key, val))

    def print_rtap(self):
        """prints radiotap headers (radiotap object)"""
        print("*** RADIOTAP INFORMATION ***")
        attrs = vars(self.radiotap)
        for key, val in attrs.items():
            if key[0] != '_':
                print("%s: %s" % (key, val))

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
        ta_mac, ra_mac, sa_mac, da_mac, bssid =\
            None, None, None, None, None

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
        elif self.to_ds == 0 and self.from_ds == 0:
            (ra_mac, ta_mac, bssid) =\
                struct.unpack('!6s6s6s', self._packet[4:22])
            seq_idx = 22
            qos_idx = None

        if ta_mac != None:
            self.ta = Wifi.get_mac_addr(ta_mac)
        if ra_mac != None:
            self.ra = Wifi.get_mac_addr(ra_mac)
        if sa_mac != None:
            self.sa = Wifi.get_mac_addr(sa_mac)
        if da_mac != None:
            self.da = Wifi.get_mac_addr(da_mac)
        if bssid != None:
            self.bssid = Wifi.get_mac_addr(bssid)

        return seq_idx, qos_idx

    def strip_seq_cntrl(self, idx):
        """strip(2 byte) wlan.seq(12 bit) and wlan.fram(4 bit)
        number information.
        :seq_cntrl: ctypes.Structure
        """
        seq_cntrl = struct.unpack('H', self._packet[idx:idx+2])[0]
        self.seq_num = seq_cntrl >> 4
        self.frag_num = seq_cntrl & 0x000f

class Data(Wifi):

    """Base Data Packet (type: 2)"""

    def __init__(self, frame):
        """Constructor method.
        :packet: ctypes.Structure
        """
        Wifi.__init__(self, frame)

class QosData(Data):

    """Qos Data (type: 2, subtype: 8)"""

    def __init__(self, frame):
        """Constructor method.
        :frame: ctypes.Structure
        """
        Data.__init__(self, frame)
        self.payload = []
        idx = 0
        self.sa, self.ta, self.ra, self.da =\
                None, None, None, None
        seq_idx, qos_idx  = self.strip_mac_addrs(self.to_ds, self.from_ds)
        self.seq_idx = seq_idx
        self.qos_idx = qos_idx

        self.strip_seq_cntrl(seq_idx)
        idx = qos_idx
        idx += self.strip_qos_cntrl(idx)

        if self.wep == 1:
            idx += self.strip_ccmp(idx)

        if self.amsdupresent != 0 and self.wep == 0:
            while idx < len(self._packet):
                msdu, offset = self.strip_msdu(idx)
                self.payload.append(msdu)
                idx += offset
        else:
            if self.wep == 0:
                msdu = {}
                offset, llc = self.strip_llc(idx)
                msdu['llc'] = llc
                msdu['payload'] = self._packet[idx+offset:]
                self.payload.append(msdu)
            else:
                self.payload.append({'payload': self._packet[idx:]})

    def strip_qos_cntrl(self, idx):
        """strip(2 byte) wlan.qos
        :returns: int
            number of processed bytes
        """
        qos_cntrl = struct.unpack('H', self._packet[idx:idx+2])[0]
        self._qos_cntrl_bits = format(qos_cntrl, '016b')[::-1]
        self.qos_priority = qos_cntrl & 0x000f
        self.qos_bit = int(self._qos_cntrl_bits[5])
        self.qos_ack = int(self._qos_cntrl_bits[6:8], 2)
        self.amsdupresent = 0
        if self.radiotap.prot_type == '.11ac':
            self.amsdupresent = int(self._qos_cntrl_bits[7])
        return 2

    def strip_ccmp(self, idx):
        """strip(8 byte) wlan.ccmp.extiv
        CCMP Extended Initialization Vector
        :returns: int
            number of processed bytes
        """
        self.ccmp_extiv = self._packet[idx:idx+8]
        return 8

    def strip_msdu(self, idx):
        """strip single mac servis data unit(msdu)
        see -> https://mrncciew.com/2014/11/01/cwap-802-11-data-frame-aggregation/
        :idx: int
        :return: dict
            msdu
        :return: int
            number of processed bytes
        """
        padding = 0 # length of msdu payload has to be multiple of 4,
                    # this guaranteed with padding
        len_payload = 0
        msdu = {}
        msdu['llc'] = {}
        msdu['wlan.da'], msdu['wlan.sa'] = None, None
        msdu['length'] = 0
        msdu['payload'] = None

        (da_mac, sa_mac) = struct.unpack('!6s6s', self._packet[idx:idx+12])
        msdu['wlan.da'] = Wifi.get_mac_addr(da_mac)
        msdu['wlan.sa'] = Wifi.get_mac_addr(sa_mac)
        idx += 12
        msdu['length'] = struct.unpack('!H', self._packet[idx:idx+2])[0]
        idx += 2
        offset, msdu['llc'] = self.strip_llc(idx)
        idx += offset
        len_payload = msdu['length'] - offset
        msdu['payload'] = self._packet[idx:idx+len_payload]
        padding = 4 - (len_payload % 4)
        return msdu, msdu['length']+padding+12

    def strip_llc(self, idx):
        """strip(4 or 8 byte) logical link control headers
        :return: int
            number of processed bytes
        :return: dict
            llc information
        see -> http://www.wildpackets.com/resources/compendium/ethernet/frame_snap_iee8023
        ABBRVS.
        ssap: source service access point
        dsap: destination service access point
        SNAP(Subnetwork Acess Protocol)
        """
        llc = {}
        snap = 170
        llc_dsap = struct.unpack('B', self._packet[idx:idx+1])[0]
        llc['dsap.dsap'] = llc_dsap >> 1
        llc['dsap.ig'] = llc_dsap & 0b01
        idx += 1
        llc_ssap = struct.unpack('B', self._packet[idx:idx+1])[0]
        llc['ssap.sap'] = llc_ssap >> 1
        llc['ssap.cr'] = llc_ssap & 0b01
        idx += 1
        if llc_dsap == snap and llc_ssap == snap:
            llc_control = struct.unpack('B', self._packet[idx:idx+1])[0]
            llc['control.u_modifier_cmd'] = llc_control >> 2
            llc['control.ftype'] = llc_control & 0x03
            idx += 1
            llc['organization_code'] = self._packet[idx:idx+3]
            idx += 3
            llc['type'] = self._packet[idx:idx+2]
            return 8, llc
        else:
            return 4, llc

    def __str__(self):
        frame = "%s (sa: %s, ta: %s, ra: %s, da: %s)"
        frame = frame % (self.name, self.sa, self.ta, self.ra, self.da)
        return frame

class Management(Wifi):

    """Management Packet (type: 0)"""

    def __init__(self, frame):
        """Constructor Method
        :frame: ctypes.Structure
        :subtype: int
        """
        Wifi.__init__(self, frame)
        self.tagged_params = None
        self._raw_tagged_params = None
        self.timestamp = None
        self.interval = None
        self.fixed_capabils = None

    def __str__(self):
        return self.name

    @staticmethod
    def parse_tagged_params(raw_tagged_params):
        """strip tagged information elements wlan_mgt.tag
        which has generic type-length-value structure
        [type, length, value]
        type(1 byte), length(1 byte), value(varies)
        [wlan_mgt.tag.number, wlan_mgt.tag.length, payload]
        structured fields.
        :returns: dict[]
            list of tagged params
        :returns: int
            0 in succ, 1 for
        """
        idx = 0
        tagged_params = []
        while idx < len(raw_tagged_params):
            tag_num, tag_len = struct.unpack('BB', raw_tagged_params[idx:idx+2])
            idx += 2
            if len(raw_tagged_params) >= idx + tag_len:
                param = {}
                param['number'], param['length'] = tag_num, tag_len
                payload = raw_tagged_params[idx:idx+tag_len]
                if tag_num in MNGMT_TAGS:
                    param['name'] = MNGMT_TAGS[tag_num]
                    if MNGMT_TAGS[tag_num] == 'TAG_VENDOR_SPECIFIC_IE':
                        param['payload'] = Management.parse_vendor_ie(payload)
                    else:
                        param['payload'] = payload
                else:
                    param['name'] = None
                tagged_params.append(param)
                idx += tag_len
            else:
                logging.warn('out tag length header points out of boundary')
                log_msg = 'index: {p_idx}, pack_len: {p_len}'
                log_msg = log_msg.format(p_idx=idx+tag_len,
                        p_len=len(raw_tagged_params))
                logging.warn(log_msg)
                return 1, tagged_params
        return 0, tagged_params

    @staticmethod
    def get_fixed_capabils(payload):
        """
        strip(2 byte) wlan_mgt.fixed.capabilities
        :payload: ctypes.structure
            2 byte
        :return: dict
            None in error
        """
        if len(payload) != 2:
            return None
        capabils = {}
        fix_cap = struct.unpack('H', payload)[0]
        cap_bits = format(fix_cap, '016b')[::-1]
        capabils['ess'] = int(cap_bits[0]) #Extended Service Set
        capabils['ibss'] = int(cap_bits[1]) #Independent Basic Service Set
        capabils['privacy'] = int(cap_bits[4]) #Privacy
        capabils['short_preamble'] = int(cap_bits[5]) #Short Preamble
        capabils['pbcc'] = int(cap_bits[6]) #Packet Binary Convolutional Code
        capabils['chan_agility'] = int(cap_bits[7]) #Channel Agility
        capabils['spec_man'] = int(cap_bits[8]) #Spectrum Management
        capabils['short_slot'] = int(cap_bits[10]) #Short Slot Time
        capabils['apsd'] = int(cap_bits[11]) #automatic power save delivery
        capabils['radio_measurement'] = int(cap_bits[12])
        capabils['dss_ofdm'] = int(cap_bits[13]) #Direct Spread Spectrum
        capabils['del_back'] = int(cap_bits[14]) #Delayed Block Acknowledgement
        capabils['imm_back'] = int(cap_bits[15]) #Immediate Block Acknowledgement
        return capabils

    @staticmethod
    def parse_vendor_ie(payload):
        """parse vendor specific information element
        oui -> organizationally unique identifier
        first 3 bytes of mac addresses
        see:https://www.wireshark.org/tools/oui-lookup.html
        strip wlan_mgt.tag.oui(3 bytes),
        wlan_mgt.tag.vendor.oui.type(1 byte)
        wlan_mgt.tag.vendor.data (varies)
        :payload: ctypes.structure
        :return: dict
            {'oui':00-11-22, 'oui_type':1, 'oui_data':ctypes.structure}
        """
        output = {}
        oui = struct.unpack('BBB', payload[0:3])
        oui = b'-'.join([('%02x' % o).encode('ascii') for o in oui])
        oui_type = struct.unpack('B', payload[3])[0]
        oui_data = payload[4:]
        output['oui'] = oui.upper()
        output['oui_type'] = oui_type
        output['oui_data'] = oui_data
        return output

    @staticmethod
    def get_timestamp(payload):
        """strip wlan_mgt.fixed.timestamp(8 bytes)
        :payload: ctypes.structure
        :return: int
            None on error
        """
        if len(payload) != 8:
            return None
        timestamp = struct.unpack('Q', payload)[0]
        return timestamp

    @staticmethod
    def get_interval(payload):
        """strip wlan_mgt.fixed.beacoN(2 bytes)
        beacon interval
        :payload: ctypes.structure
        :return: int
            None on error
        """
        if len(payload) != 2:
            return None
        interval = struct.unpack('H', payload)[0]
        return interval

    @staticmethod
    def strip_fixed_params(payload):
        """strip(12 byte) wlan_mgt.fixed.all
        :payload: ctypes.structure
        :return: int
            timestamp
        :return: int
            beacon interval
        :return: dict
            capabilities
        """
        if len(payload) != 12:
            return None, None, None
        idx = 0
        timestamp = Management.get_timestamp(payload[idx:idx+8])
        idx += 8
        interval = Management.get_interval(payload[idx:idx+2])
        idx += 2
        capabils = Management.get_fixed_capabils(payload[idx:idx+2])
        return timestamp, interval, capabils

    @staticmethod
    def is_valid_mac_oui(mac_block):
        """checks whether mac block is in format of
        00-11-22 or 00:11:22.
        :return: int
        """
        if len(mac_block) != 8:
            return 0
        if ':' in mac_block:
            if len(mac_block.split(':')) != 3:
                return 0
        elif '-' in mac_block:
            if len(mac_block.split('-')) != 3:
                return 0
        return 1

    def get_vendor_ies(self, mac_block=None, oui_type=None):
        """
        :mac_block: str
            first 3 bytes of mac addresses in format of
            00-11-22 or 00:11:22 or 001122
        :oui_type: int
            vendors ie type
        :returns: int
            is valid mac_block  format
            -1 is unknown
        :returns: dict[]
            list of oui information elements
            -1 on error (invalid v
        """
        vendor_ies = []
        if mac_block != None:
            if Management.is_valid_mac_oui(mac_block):
                mac_block = mac_block.upper()
                if ':' in mac_block:
                    mac_block.replace(':', '-')
            else:
                print("invalid oui macblock")
                return None

        for elem in self.tagged_params:
            tag_num = elem['number']
            if MNGMT_TAGS[tag_num] == 'TAG_VENDOR_SPECIFIC_IE':
                if mac_block == None:
                    vendor_ies.append(elem)
                elif elem['payload']['oui'] == mac_block:
                    if oui_type == None:
                        vendor_ies.append(elem)
                    elif elem['payload']['oui_type'] == oui_type:
                        vendor_ies.append(elem)
        return vendor_ies


class ProbeResp(Management):

    """Probe Response (type: 0, subtype: 5)"""

    def __init__(self, frame):
        """
        """
        Management.__init__(self, frame)
        idx = 0
        seq_idx, qos_idx = self.strip_mac_addrs(self.to_ds, self.from_ds)
        idx = seq_idx
        self.strip_seq_cntrl(idx)
        idx += 2
        payload = self._packet[idx:idx+12]
        timestamp, interval, capabils = self.strip_fixed_params(payload)
        if all([timestamp, interval, capabils]):
            self.timestamp, self.interval, self.fixed_capabils =\
                    timestamp, interval, capabils
            idx += 12
        else:
            logging.warn("failed to parse fixed parameters")
            return
        if idx < len(self._packet):
            self._raw_tagged_params = self._packet[idx:]
            is_out_bound, tagged_params =\
                self.parse_tagged_params(self._raw_tagged_params)
            if len(tagged_params):
                self.tagged_params = tagged_params
            if is_out_bound:
                logging.warn("tag_len header not matched with raw byte counts")

class ProbeReq(Management):

    """Probe Request (type: 0, subtype:4)"""

    def __init__(self, frame):
        """
        """
        Management.__init__(self, frame)
        idx = 0
        seq_idx, qos_idx = self.strip_mac_addrs(self.to_ds, self.from_ds)
        idx = seq_idx
        self.strip_seq_cntrl(idx)
        idx += 2
        if idx < len(self._packet):
            self._raw_tagged_params = self._packet[idx:]
            is_out_bound, tagged_params =\
                self.parse_tagged_params(self._raw_tagged_params)
            if len(tagged_params):
                self.tagged_params = tagged_params
            if is_out_bound:
                logging.warn("tag_len header not matched with raw byte counts")

class Beacon(Management):

    """Beacon (type: 0, subtype: 0)"""

    def __init__(self, frame):
        """Constructor method.
        :frame: ctypes.Structure
        """
        Management.__init__(self, frame)
        idx = 0
        seq_idx, qos_idx = self.strip_mac_addrs(self.to_ds, self.from_ds)
        idx = seq_idx
        self.strip_seq_cntrl(idx)
        idx += 2
        payload = self._packet[idx:idx+12]
        timestamp, interval, capabils = self.strip_fixed_params(payload)
        if all([timestamp, interval, capabils]):
            self.timestamp, self.interval, self.fixed_capabils =\
                    timestamp, interval, capabils
            idx += 12
        else:
            logging.warn("failed to parse fixed parameters")
            return
        if idx < len(self._packet):
            self._raw_tagged_params = self._packet[idx:]
            is_out_bound, tagged_params =\
                self.parse_tagged_params(self._raw_tagged_params)
            if len(tagged_params):
                self.tagged_params = tagged_params
            if is_out_bound:
                logging.warn("tag_len header not matched with raw byte counts")

    def __str__(self):
        frame = "%s from %s (tstamp: %d, interval: %d)"
        frame = frame % (self.name, self.bssid, self.timestamp, self.interval)
        return frame

class Control(Wifi):

    """Control Frames (type: 1)"""

    def __init__(self, frame):
        """Constructor method.
        :frame: ctypes.Structure
        """
        Wifi.__init__(self, frame)

    def __str__(self):
        return self.name

class RTS(Control):

    """Request to Send Frame (type: 1, subtype: 1)"""

    def __init__(self, frame):
        """Constructor method.
        :frame: ctypes.Structure
        """
        Control.__init__(self, frame)
        (ra_mac, ta_mac) = struct.unpack('!6s6s', self._packet[4:16])
        self.ra = Wifi.get_mac_addr(ra_mac)
        self.ta = Wifi.get_mac_addr(ta_mac)

    def __str__(self):
        frame = '%s from %s to %s (duration: %d us)'
        frame = frame % (self.name, self.ta, self.ra, self.duration)
        return frame

class CTS(Control):

    """Clear to Send Frame (type: 1, subtype: 2)"""

    def __init__(self, frame):
        """Constructor method.
        :frame: ctypes.Structure
        """
        Control.__init__(self, frame)
        ra_mac = struct.unpack('!6s', self._packet[4:10])[0]
        self.ra = Wifi.get_mac_addr(ra_mac)

    def __str__(self):
        frame = '%s to %s (duration: %d us)'
        frame = frame % (self.name, self.ra, self.duration)
        return frame

class BACK(Control):

    """Block Acknowledgement Frame (type: 1, subtype: 9)"""

    def __init__(self, frame):
        """Constructor method.
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
        """strip(2 byte) wlan.ba.control"""
        self.cntrl = struct.unpack('H', self._packet[16:18])[0] #block ack request control
        self._cntrl_bits = format(self.cntrl, '016b')[::-1]
        self.ackpolicy = int(self._cntrl_bits[0])
        self.multitid = int(self._cntrl_bits[1])

    def strip_ssc(self):
        """strip(2 byte) wlan_mgt.fixed.ssc"""
        self.ssc = struct.unpack('H', self._packet[18:20])[0] #starting sequence control
        self.ssc_sequence = self.ssc >> 4
        self.ssc_frag = self.ssc & 0x000f

    def strip_bitmap_str(self):
        """strip(8 byte) wlan.ba.bm"""
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
    
    def __str__(self):
        frame = '%s from %s to %s'
        frame = frame % (self.name, self.ta, self.ra)
        return frame
