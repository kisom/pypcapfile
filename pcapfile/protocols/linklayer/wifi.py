#!/usr/bin/python
"""
Wi-Fi protocol definitions

current supports for packets below

Management
    -Probe Request
    -Probe Response
    -Beacon

Control
    -RTS
    -CTS
    -Block Acknowledgement

Data
    -QoS Data

Also have Radiotap support
http://www.radiotap.org/defined-fields
"""
import binascii
import ctypes
import struct
import logging
import operator
import collections

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

def WIFI(frame, no_rtap=False):
    """calls wifi packet discriminator and constructor.
    :frame: ctypes.Structure
    :no_rtap: Bool
    :return: packet object in success
    :return: int
        -1 on known error
    :return: int
        -2 on unknown error
    """
    pack = None
    try:
        pack = WiHelper.get_wifi_packet(frame, no_rtap)
    except Exception as e:
        logging.exception("message")
    return pack

class WiHelper:

    """Wi-Fi packet discriminator class.
    Identifies type and subtype of packet, then trigs
    packet object creation.
    """

    @staticmethod
    def get_wifi_packet(frame, no_rtap=False):
        """Discriminates Wi-Fi packet and creates
        packet object.
        :frame: ctypes.Structure
        :no_rtap: Bool
        :return: obj
            Wi-Fi packet
        """
        rtap, packet = WiHelper._strip_rtap(frame)
        frame_control = struct.unpack('BB', packet[:2])
        flags = frame_control[:1]
        cat = (frame_control[0] >> 2) & 0b0011
        s_type = frame_control[0] >> 4

        if cat not in _CATEGORIES_.keys():
            logging.warn("unknown category: %d" % (cat))
            return Unknown(frame, no_rtap)

        if s_type not in _SUBTYPES_[cat].keys():
            logging.warn("unknown subtype %d in %s category" % (s_type, _CATEGORIES_[cat]))
            return Unknown(frame, no_rtap)

        if cat == 0:
            if s_type == 4:
                return ProbeReq(frame, no_rtap)
            elif s_type == 5:
                return ProbeResp(frame, no_rtap)
            elif s_type == 8:
                return Beacon(frame, no_rtap)
            else:
                return Management(frame, no_rtap)
        elif cat == 1:
            if s_type == 11:
                return RTS(frame, no_rtap)
            elif s_type == 12:
                return CTS(frame, no_rtap)
            elif s_type == 9:
                return BACK(frame, no_rtap)
            else:
                return Control(frame, no_rtap)
        elif cat == 2:
            if s_type == 8:
                return QosData(frame, no_rtap, parse_amsdu=True)
            else:
                return Data(frame, no_rtap)

    @staticmethod
    def _strip_rtap(frame):
        """strip injected radiotap header.
        :return: ctypes.Structure
            radiotap header
        :return: ctypes.Structure
            actual layer 2 Wi-Fi payload
        """
        rtap_len = WiHelper.__get_rtap_len(frame)
        rtap = frame[:rtap_len]
        packet = frame[rtap_len:]
        return rtap, packet

    @staticmethod
    def __get_rtap_len(frame):
        """parse length of radiotap header.
        :packet: ctypes.structure
        :return: int
        """
        r_len = struct.unpack('H', frame[2:4])
        return r_len[0]

class Radiotap(ctypes.Structure):

    """Radiotap Header Parser Class.
    Radiotap headers summarize physical layer parameters
    of Wi-Fi packet, such as MCS(modulation and coding scheme),
    NSS(number of spatial streams), BW(bandwidth) for all common
    protocol types(802.11a, 802.11n, 802.11ac etc.)
    see -> http://www.radiotap.org/defined-fields
    see -> https://github.com/boundary/wireshark/blob/master/epan/dissectors/packet-ieee80211-radiotap-defs.h
    """
    _rfields_ = [('vers', ctypes.c_uint8),
                 ('pad', ctypes.c_uint8),
                 ('len', ctypes.c_uint16),
                 ('present.tsft', ctypes.c_bool),
                 ('present.flags', ctypes.c_bool),
                 ('present.rate', ctypes.c_bool),
                 ('present.channel', ctypes.c_bool),
                 ('present.fhss', ctypes.c_bool),
                 ('present.dbm_antsignal', ctypes.c_bool),
                 ('present.dbm_antnoise', ctypes.c_bool),
                 ('present.lock_quality', ctypes.c_bool),
                 ('present.tx_attenuation', ctypes.c_bool),
                 ('present.db_tx_attenuation', ctypes.c_bool),
                 ('present.dbm_tx_power', ctypes.c_bool),
                 ('present.antenna', ctypes.c_bool),
                 ('present.db_antsignal', ctypes.c_bool),
                 ('present.db_antnoise', ctypes.c_bool),
                 ('present.rxflags', ctypes.c_bool),
                 ('present.txflags', ctypes.c_bool),
                 ('present.rts_retries', ctypes.c_bool),
                 ('present.data_retries', ctypes.c_bool),
                 ('present.xchannel', ctypes.c_bool),
                 ('present.mcs', ctypes.c_bool),
                 ('present.ampdu', ctypes.c_bool),
                 ('present.vht', ctypes.c_bool),
                 ('present.rtap_ns', ctypes.c_bool),
                 ('present.ven_ns', ctypes.c_bool),
                 ('present.ext', ctypes.c_bool),
                 ('mactime', ctypes.c_uint64),
                 ('flags.cfp', ctypes.c_bool),
                 ('flags.preamble', ctypes.c_bool),
                 ('flags.wep', ctypes.c_bool),
                 ('flags.fragmentation', ctypes.c_bool),
                 ('flags.fcs', ctypes.c_bool),
                 ('flags.datapad', ctypes.c_bool),
                 ('flags.badfcs', ctypes.c_bool),
                 ('flags.shortgi', ctypes.c_bool),
                 ('rate', ctypes.c_uint),
                 ('chan.freq', ctypes.c_uint),
                 ('chan.turbo', ctypes.c_bool),
                 ('chan.cck', ctypes.c_bool),
                 ('chan.ofdm', ctypes.c_bool),
                 ('chan.two_g', ctypes.c_bool),
                 ('chan.five_g', ctypes.c_bool),
                 ('chan.passive', ctypes.c_bool),
                 ('chan.dynamic', ctypes.c_bool),
                 ('chan.gfsk', ctypes.c_bool),
                 ('chan.gsm', ctypes.c_bool),
                 ('chan.static_turbo', ctypes.c_bool),
                 ('chan.half_rate', ctypes.c_bool),
                 ('chan.quarter_rate', ctypes.c_bool),
                 ('fhss.hopset', ctypes.c_int),
                 ('fhss.pattern', ctypes.c_uint),
                 ('dbm_antsignal', ctypes.c_uint),
                 ('dbm_antnoise', ctypes.c_uint),
                 ('lock_quality', ctypes.c_uint),
                 ('tx_attenuation', ctypes.c_uint),
                 ('db_tx_attenuation', ctypes.c_uint),
                 ('dbm_tx_power', ctypes.c_uint),
                 ('antenna', ctypes.c_uint),
                 ('db_antsignal', ctypes.c_uint),
                 ('db_antnoise', ctypes.c_uint),
                 ('rxflags.reserved', ctypes.c_bool),
                 ('rxflags.badplcp', ctypes.c_bool),
                 ('txflags', ctypes.c_uint),
                 ('rts_retries', ctypes.c_uint),
                 ('data_retries', ctypes.c_uint),
                 ('xchannel.freq', ctypes.c_uint),
                 ('xchannel.channel', ctypes.c_uint),
                 ('xchannel.max_power', ctypes.c_uint),
                 ('xchannel.flags.turbo', ctypes.c_bool),
                 ('xchannel.flags.cck', ctypes.c_bool),
                 ('xchannel.flags.ofdm', ctypes.c_bool),
                 ('xchannel.flags.two_g', ctypes.c_bool),
                 ('xchannel.flags.five_g', ctypes.c_bool),
                 ('xchannel.flags.passive', ctypes.c_bool),
                 ('xchannel.flags.dynamic', ctypes.c_bool),
                 ('xchannel.flags.gfsk', ctypes.c_bool),
                 ('xchannel.flags.gsm', ctypes.c_bool),
                 ('xchannel.flags.sturbo', ctypes.c_bool),
                 ('xchannel.flags.half', ctypes.c_bool),
                 ('xchannel.flags.quarter', ctypes.c_bool),
                 ('xchannel.flags.ht_20', ctypes.c_bool),
                 ('xchannel.flags.ht_40u', ctypes.c_bool),
                 ('xchannel.flags.ht_40d', ctypes.c_bool),
                 ('mcs.known', ctypes.c_uint8),
                 ('mcs.index', ctypes.c_uint8),
                 ('mcs.have_bw', ctypes.c_bool),
                 ('mcs.have_mcs', ctypes.c_bool),
                 ('mcs.have_gi', ctypes.c_bool),
                 ('mcs.have_format', ctypes.c_bool),
                 ('mcs.have_fec', ctypes.c_bool),
                 ('mcs.have_stbc', ctypes.c_bool),
                 ('mcs.have_ness', ctypes.c_bool),
                 ('mcs.ness_bit1', ctypes.c_bool),
                 ('ampdu.refnum', ctypes.c_uint),
                 ('ampdu.crc_val', ctypes.c_uint8),
                 ('ampdu.reserved', ctypes.c_uint8),
                 ('ampdu.flags.report_zerolen', ctypes.c_bool),
                 ('ampdu.flags.is_zerolen', ctypes.c_bool),
                 ('ampdu.flags.lastknown', ctypes.c_bool),
                 ('ampdu.flags.last', ctypes.c_bool),
                 ('ampdu.flags.delim_crc_error', ctypes.c_bool),
                 ('vht.known_bits', ctypes.c_char_p),
                 ('vht.have_stbc', ctypes.c_bool),
                 ('vht.have_txop_ps', ctypes.c_bool),
                 ('vht.have_gi', ctypes.c_bool),
                 ('vht.have_sgi_nsym_da', ctypes.c_bool),
                 ('vht.have_ldpc_extra', ctypes.c_bool),
                 ('vht.have_beamformed', ctypes.c_bool),
                 ('vht.have_bw', ctypes.c_bool),
                 ('vht.have_gid', ctypes.c_bool),
                 ('vht.have_paid', ctypes.c_bool),
                 ('vht.flag_bits', ctypes.c_bool),
                 ('vht.stbc', ctypes.c_bool),
                 ('vht.txop_ps', ctypes.c_bool),
                 ('vht.gi', ctypes.c_bool),
                 ('vht.sgi_nysm_da', ctypes.c_bool),
                 ('vht.ldpc_extra', ctypes.c_bool),
                 ('vht.beamformed', ctypes.c_bool),
                 ('vht.group_id', ctypes.c_bool),
                 ('vht.partial_id', ctypes.c_bool),
                 ('vht.bw', ctypes.c_uint),
                 ('vht.user_0.nss', ctypes.c_bool),
                 ('vht.user_0.mcs', ctypes.c_bool),
                 ('vht.user_0.coding', ctypes.c_bool),
                 ('vht.user_1.nss', ctypes.c_bool),
                 ('vht.user_1.mcs', ctypes.c_bool),
                 ('vht.user_1.coding', ctypes.c_bool),
                 ('vht.user_2.nss', ctypes.c_bool),
                 ('vht.user_2.mcs', ctypes.c_bool),
                 ('vht.user_2.coding', ctypes.c_bool),
                 ('vht.user_3.nss', ctypes.c_bool),
                 ('vht.user_3.mcs', ctypes.c_bool),
                 ('vht.user_3.coding', ctypes.c_bool),
                 ('prot_type', ctypes.c_char_p)]

    # Wireshark syntax conjugates of fields in object
    _r_shark_ = {
                 'radiotap.version': 'vers',
                 'radiotap.pad': 'pad',
                 'radiotap.length': 'len',
                 'radiotap.present.tsft': 'present.tsft',
                 'radiotap.present.flags': 'present.flags',
                 'radiotap.present.rate': 'present.rate',
                 'radiotap.present.channel': 'present.channel',
                 'radiotap.present.fhss': 'present.fhss',
                 'radiotap.present.dbm_antsignal': 'present.dbm_antsignal',
                 'radiotap.present.dbm_antnoise': 'present.dbm_antnoise',
                 'radiotap.present.lock_quality': 'present.lock_quality',
                 'radiotap.present.tx_attenuation': 'present.tx_attenuation',
                 'radiotap.present.db_tx_attenuation': 'present.db_tx_attenuation',
                 'radiotap.present.dbm_tx_power': 'present.dbm_tx_power',
                 'radiotap.present.antenna': 'present.antenna',
                 'radiotap.present.db_antsignal': 'present.db_antsignal',
                 'radiotap.present.db_antnoise': 'present.db_antnoise',
                 'radiotap.present.rxflags': 'present.rxflags',
                 'radiotap.present.xchannel': 'present.xchannel',
                 'radiotap.present.mcs': 'present.mcs',
                 'radiotap.present.ampdu': 'present.ampdu',
                 'radiotap.present.vht': 'present.vht',
                 'radiotap.present.rtap_ns': 'present.rtap_ns',
                 'radiotap.present.vendor_ns': 'present.ven_ns',
                 'radiotap.present.ext': 'present.ext',
                 'radiotap.mactime': 'mactime',
                 'radiotap.flags.cfp': 'flags.cfp',
                 'radiotap.flags.preamble': 'flags.preamble',
                 'radiotap.flags.wep': 'flags.wep',
                 'radiotap.flags.frag': 'flags.fragmentation',
                 'radiotap.flags.fcs': 'flags.fcs',
                 'radiotap.flags.datapad': 'flags.datapad',
                 'radiotap.flags.badfcs': 'flags.badfcs',
                 'radiotap.flags.shortgi': 'flags.shortgi',
                 'radiotap.datarate': 'rate',
                 'radiotap.channel.freq': 'chan.freq',
                 'radiotap.channel.flags.turbo': 'chan.turbo',
                 'radiotap.channel.flags.cck': 'chan.cck',
                 'radiotap.channel.flags.ofdm': 'chan.ofdm',
                 'radiotap.channel.flags.2ghz': 'chan.two_g',
                 'radiotap.channel.flags.5ghz': 'chan.five_g',
                 'radiotap.channel.flags.passive': 'chan.passive',
                 'radiotap.channel.flags.dynamic': 'chan.dynamic',
                 'radiotap.channel.flags.gfsk': 'chan.gfsk',
                 'radiotap.channel.flags.gsm': 'chan.gsm',
                 'radiotap.channel.flags.sturbo': 'chan.static_turbo',
                 'radiotap.channel.flags.half': 'chan.half_rate',
                 'radiotap.channel.flags.quarter': 'chan.quarter_rate',
                 'radiotap.fhss.hopset': 'fhss.hopset',
                 'radiotap.fhss.pattern': 'fhss.pattern',
                 'radiotap.dbm_antsignal': 'dbm_antsignal',
                 'radiotap.dbm_antnoise': 'dbm_antnoise',
                 'radiotap.antenna': 'antenna',
                 'radiotap.db_antsignal': 'db_antsignal',
                 'radiotap.db_antnoise': 'db_antnoise',
                 'radiotap.rxflags.badplcp': 'rxflags.badplcp',
                 'radiotap.xchannel.freq': 'xchannel.freq',
                 'radiotap.xchannel.channel': 'xchannel.channel',
                 'radiotap.xchannel.flags.turbo': 'xchannel.flags.turbo',
                 'radiotap.xchannel.flags.cck': 'xchannel.flags.cck',
                 'radiotap.xchannel.flags.ofdm': 'xchannel.flags.ofdm',
                 'radiotap.xchannel.flags.2ghz': 'xchannel.flags.two_g',
                 'radiotap.xchannel.flags.5ghz': 'xchannel.flags.five_g',
                 'radiotap.xchannel.flags.passive': 'xchannel.flags.passive',
                 'radiotap.xchannel.flags.dynamic': 'xchannel.flags.dynamic',
                 'radiotap.xchannel.flags.gfsk': 'xchannel.flags.gfsk',
                 'radiotap.xchannel.flags.gsm': 'xchannel.flags.gsm',
                 'radiotap.xchannel.flags.sturbo': 'xchannel.flags.sturbo',
                 'radiotap.xchannel.flags.half': 'xchannel.flags.half',
                 'radiotap.xchannel.flags.quarter': 'xchannel.flags.quarter',
                 'radiotap.xchannel.flags.ht20': 'xchannel.flags.ht_20',
                 'radiotap.xchannel.flags.ht40u': 'xchannel.flags.ht_40u',
                 'radiotap.xchannel.flags.ht40d': 'xchannel.flags.ht_40d',
                 'radiotap.mcs.known': 'mcs.known',
                 'radiotap.mcs.index': 'mcs.index',
                 'radiotap.mcs.have_bw': 'mcs.have_bw',
                 'radiotap.mcs.have_gi': 'mcs.have_gi',
                 'radiotap.mcs.have_format': 'mcs.have_format',
                 'radiotap.mcs.have_fec': 'mcs.have_fec',
                 'radiotap.mcs.have_stbc': 'mcs.have_stbc',
                 'radiotap.mcs.have_ness': 'mcs.have_ness',
                 'radiotap.mcs.ness_bit1': 'mcs.ness_bit1',
                 'radiotap.ampdu.reference': 'ampdu.refnum',
                 'radiotap.ampdu.crc_val': 'ampdu.crc_val',
                 'radiotap.ampdu.reserved': 'ampdu.reserved',
                 'radiotap.ampdu.flags.report_zerolen': 'ampdu.flags.report_zerolen',
                 'radiotap.ampdu.flags.is_zerolen': 'ampdu.flags.is_zerolen',
                 'radiotap.ampdu.flags.lastknown': 'ampdu.flags.lastknown',
                 'radiotap.ampdu.flags.last': 'ampdu.flags.last',
                 'radiotap.ampdu.flags.delim_crc_error': 'ampdu.flags.delim_crc_error',
                 'radiotap.vht.have_stbc': 'vht.have_stbc',
                 'radiotap.vht.have_txop_ps': 'vht.have_txop_ps',
                 'radiotap.vht.have_gi': 'vht.have_gi',
                 'radiotap.vht.have_sgi_nsym_da': 'vht.have_sgi_nsym_da',
                 'radiotap.vht.have_ldpc_extra': 'vht.have_ldpc_extra',  # this does not seem with have_ prefix in wireshark
                 'radiotap.vht.have_beamformed': 'vht.have_beamformed',  # creates conflict with ldpc_extra below; we keep radiotap
                 'radiotap.vht.have_bw': 'vht.have_bw',                  # syntax.
                 'radiotap.vht.have_gid': 'vht.have_gid',
                 'radiotap.vht.have_paid': 'vht.have_paid',
                 'radiotap.vht.stbc': 'vht.stbc',
                 'radiotap.vht.txop_ps': 'vht.txop_ps',
                 'radiotap.vht.gi': 'vht.gi',
                 'radiotap.vht.sgi_nysm_da': 'vht.sgi_nysm_da',
                 'radiotap.vht.ldpc_extra': 'vht.ldpc_extra',
                 'radiotap.vht.beamformed': 'vht.beamformed',
                 'radiotap.vht.gid': 'vht.group_id',
                 'radiotap.vht.paid': 'vht.partial_id',
                 'radiotap.vht.bw': 'vht.bw',
                 'radiotap.vht.nss.0': 'vht.user_0.nss',
                 'radiotap.vht.mcs.0': 'vht.user_0.mcs',
                 'radiotap.vht.coding.0': 'vht.user_0.coding',
                 'radiotap.vht.nss.1': 'vht.user_1.nss',
                 'radiotap.vht.mcs.1': 'vht.user_1.mcs',
                 'radiotap.vht.coding.1': 'vht.user_1.coding',
                 'radiotap.vht.nss.2': 'vht.user_2.nss',
                 'radiotap.vht.mcs.2': 'vht.user_2.mcs',
                 'radiotap.vht.coding.2': 'vht.user_2.coding',
                 'radiotap.vht.nss.3': 'vht.user_3.nss',
                 'radiotap.vht.mcs.3': 'vht.user_3.mcs',
                 'radiotap.vht.coding.3': 'vht.user_3.coding',
                }

    def __init__(self, rtap_bytes):
        """Constructor method.
        :rtap_bytes: ctypes.Structure

        """
        self._raw = {}  # contains raw bytes,  for debugging purposes
        self._bits = {} # contains bitstrings, for debugging purposes
        pre = 0
        idx = 0
        self._rtap = rtap_bytes

        # parse radiotap headers
        self.vers = Radiotap.strip_vers(self._rtap[idx:idx+1])
        idx += 1

        self.pad = Radiotap.strip_pad(self._rtap[idx:idx+1])
        idx += 1

        self.len = Radiotap.strip_len(self._rtap[idx:idx+2])
        idx += 2

        self.present, self.present_bits = Radiotap.strip_present(self._rtap[idx:idx+4])
        idx += 4

        # parse radiotap payload
        if self.present.tsft: # 8 byte
            idx, self.mactime = self.strip_tsft(idx)

        if self.present.flags: # 1 byte
            idx, self.flags = self.strip_flags(idx)

        if self.present.rate: # 1 byte
            idx, self.rate = self.strip_rate(idx)

        if self.present.channel: # 2 byte (align 2 byte)
            idx, self.chan = self.strip_chan(idx)

        if self.present.fhss: # 2 byte
            idx, self.fhss = self.strip_fhss(idx)

        if self.present.dbm_antsignal: # 1 byte
            idx, self.dbm_antsignal = self.strip_dbm_antsignal(idx)

        if self.present.dbm_antnoise: # 1 byte
            idx, self.dbm_antnoise = self.strip_dbm_antnoise(idx)

        if self.present.lock_quality: # 2 byte (align 2 byte)
            idx, self.lock_quality = self.strip_lock_quality(idx)

        if self.present.tx_attenuation: # 1 byte (align 2 byte)
            idx, self.tx_attenuation = self.strip_tx_attenuation(idx)

        if self.present.db_tx_attenuation: # 1 byte (align 2 byte)
            idx, self.db_tx_attenuation = self.strip_db_tx_attenuation(idx)

        if self.present.dbm_tx_power: # 1 byte (align 1 byte)
            idx, self.dbm_tx_power = self.strip_dbm_tx_power(idx)

        if self.present.antenna: # 1 byte
            idx, self.antenna = self.strip_antenna(idx)

        if self.present.db_antsignal: # 1 byte
            idx, self.db_antsignal = self.strip_db_antsignal(idx)

        if self.present.db_antnoise: # 1 byte
            idx, self.db_antnoise = self.strip_db_antnoise(idx)

        if self.present.rxflags: # 2 byte (align 2 byte)
            idx, self.rxflags = self.strip_rx_flags(idx)

        if self.present.txflags: # 1 byte (align 2 byte)
            idx, self.txflags = self.strip_tx_flags(idx)

        if self.present.rts_retries: # 1 byte
            idx, self.rts_retries = self.strip_rts_retries(idx)

        if self.present.data_retries: # 1 byte
            idx, self.data_retries = self.strip_data_retries(idx)

        if self.present.xchannel: # 7 byte (align 2 byte)
            idx, self.xchannel = self.strip_xchannel(idx)

        if self.present.mcs: # 3 byte (align 1 byte)
            idx, self.mcs = self.strip_mcs(idx)

        if self.present.ampdu: # 8 byte (align 4 byte)
            idx, self.ampdu = self.strip_ampdu(idx)

        if self.present.vht: # 12 byte (align 2 byte)
            idx, self.vht = self.strip_vht(idx)

        self.prot_type = self.extract_protocol()

    @staticmethod
    def strip_vers(payload):
        """strip(1 byte) radiotap.version
        :payload: ctypes.Structure
        :return: int
        """
        return struct.unpack('B', payload)[0]

    @staticmethod
    def strip_pad(payload):
        """strip(1 byte) radiotap.pad
        :payload: ctypes.Structure
        :return: int
        """
        return struct.unpack('B', payload)[0]

    @staticmethod
    def strip_len(payload):
        """strip(2 byte) radiotap.length
        :payload: ctypes.Structure
        :return: int
        """
        return struct.unpack('H', payload)[0]

    @staticmethod
    def strip_present(payload):
        """strip(4 byte) radiotap.present. Those are flags that
        identify existence of incoming radiotap meta-data.
        :idx: int
        :return: str
        :return: namedtuple
        """
        present = collections.namedtuple('present', ['tsft', 'flags', 'rate',
            'channel', 'fhss', 'dbm_antsignal', 'dbm_antnoise', 'lock_quality',
            'tx_attenuation', 'db_tx_attenuation', 'dbm_tx_power', 'antenna',
            'db_antsignal', 'db_antnoise', 'rxflags', 'txflags', 'rts_retries',
            'data_retries', 'xchannel', 'mcs', 'ampdu', 'vht', 'rtap_ns',
            'ven_ns', 'ext'])

        val = struct.unpack('<L', payload)[0]
        bits = format(val, '032b')[::-1]
        present.tsft = int(bits[0])              # timer synchronization function
        present.flags = int(bits[1])             # flags
        present.rate = int(bits[2])              # rate
        present.channel = int(bits[3])           # channel
        present.fhss = int(bits[4])              # frequency hoping spread spectrum
        present.dbm_antsignal = int(bits[5])     # dbm antenna signal
        present.dbm_antnoise = int(bits[6])      # dbm antenna noinse
        present.lock_quality = int(bits[7])      # quality of barker code lock
        present.tx_attenuation = int(bits[8])    # transmitter attenuation
        present.db_tx_attenuation = int(bits[9]) # decibel transmit attenuation
        present.dbm_tx_power = int(bits[10])     # dbm transmit power
        present.antenna = int(bits[11])          # antenna
        present.db_antsignal = int(bits[12])     # db antenna signal
        present.db_antnoise = int(bits[13])      # db antenna noise
        present.rxflags = int(bits[14])          # receiver flags
        present.txflags = int(bits[15])          # transmitter flags
        present.rts_retries = int(bits[16])      # rts(request to send) retries
        present.data_retries = int(bits[17])     # data retries
        present.xchannel = int(bits[18])         # xchannel
        present.mcs = int(bits[19])              # modulation and coding scheme
        present.ampdu = int(bits[20])            # aggregated mac protocol data unit
        present.vht = int(bits[21])              # very high throughput
        present.rtap_ns = int(bits[29])          # radiotap namespace
        present.ven_ns = int(bits[30])           # vendor namespace
        present.ext = int(bits[31])              # extension

        return present, bits

    def strip_tsft(self, idx):
        """strip(8 byte) radiotap.mactime
        :idx: int
        :return: int
            idx
        :return: int
            mactime
        """
        idx = Radiotap.align(idx, 8)
        mactime, = struct.unpack_from('<Q', self._rtap, idx)
        return idx + 8, mactime

    def strip_flags(self, idx):
        """strip(1 byte) radiotap.flags
        :idx: int
        :return: int
            idx
        :return: collections.namedtuple
        """
        flags = collections.namedtuple('flags', ['cfp', 'preamble', 'wep',
            'fragmentation', 'fcs', 'datapad', 'badfcs', 'shortgi'])
        val, = struct.unpack_from('<B', self._rtap, idx)
        bits = format(val, '08b')[::-1]
        flags.cfp = int(bits[0])
        flags.preamble = int(bits[1])
        flags.wep = int(bits[2])
        flags.fragmentation = int(bits[3])
        flags.fcs = int(bits[4])
        flags.datapad = int(bits[5])
        flags.badfcs = int(bits[6])
        flags.shortgi = int(bits[7])
        return idx + 1, flags

    def strip_rate(self, idx):
        """strip(1 byte) radiotap.datarate
        note that, unit of this field is originally 0.5 Mbps
        :idx: int
        :return: int
            idx
        :return: double
            rate in terms of Mbps
        """
        val, = struct.unpack_from('<B', self._rtap, idx)
        rate_unit = float(1) / 2    # Mbps
        return idx + 1, rate_unit * val

    def strip_chan(self, idx):
        """strip(2 byte) radiotap.channel.flags
        :idx: int
        :return: int
            idx
        :return: collections.namedtuple
        """
        chan = collections.namedtuple('chan', ['freq', 'turbo', 'cck', 'ofdm',
            'two_g', 'five_g', 'passive', 'dynamic', 'gfsk',
            'gsm', 'static_turbo', 'half_rate', 'quarter_rate'])

        idx = Radiotap.align(idx, 2)
        freq, flags, = struct.unpack_from('<HH', self._rtap, idx)
        chan.freq = freq

        bits = format(flags, '016b')[::-1]
        chan.turbo = int(bits[4])
        chan.cck = int(bits[5])
        chan.ofdm = int(bits[6])
        chan.two_g = int(bits[7])
        chan.five_g = int(bits[8])
        chan.passive = int(bits[9])
        chan.dynamic = int(bits[10])
        chan.gfsk = int(bits[11])
        chan.gsm = int(bits[12])
        chan.static_turbo = int(bits[13])
        chan.half_rate = int(bits[14])
        chan.quarter_rate = int(bits[15])
        return idx + 4, chan

    def strip_fhss(self, idx):
        """strip (2 byte) radiotap.fhss.hopset(1 byte) and
        radiotap.fhss.pattern(1 byte)
        :idx: int
        :return: int
            idx
        :return: collections.namedtuple
        """
        fhss = collections.namedtuple('fhss', ['hopset', 'pattern'])
        fhss.hopset, fhss.pattern, = struct.unpack_from('<bb', self._rtap, idx)
        return idx + 2, fhss

    def strip_dbm_antsignal(self, idx):
        """strip(1 byte) radiotap.dbm.ant_signal
        :idx: int
        :return: int
            idx
        :return: int
        """
        dbm_antsignal, = struct.unpack_from('<b', self._rtap, idx)
        return idx + 1, dbm_antsignal

    def strip_dbm_antnoise(self, idx):
        """strip(1 byte) radiotap.dbm_antnoise
        :idx: int
        :return: int
            idx
        :return: int
        """
        dbm_antnoise, = struct.unpack_from('<b', self._rtap, idx)
        return idx + 1, dbm_antnoise

    def strip_lock_quality(self, idx):
        """strip(2 byte) lock quality
        :idx: int
        :return: int
            idx
        :return: int
        """
        idx = Radiotap.align(idx, 2)
        lock_quality, = struct.unpack_from('<H', self._rtap, idx)
        return idx + 2, lock_quality

    def strip_tx_attenuation(self, idx):
        """strip(1 byte) tx_attenuation
        :idx: int
        :return: int
            idx
        :return: int
        """
        idx = Radiotap.align(idx, 2)
        tx_attenuation, = struct.unpack_from('<H', self._rtap, idx)
        return idx + 2, tx_attenuation

    def strip_db_tx_attenuation(self, idx):
        """strip(1 byte) db_tx_attenuation
        :return: int
            idx
        :return: int
        """
        idx = Radiotap.align(idx, 2)
        db_tx_attenuation, = struct.unpack_from('<H', self._rtap, idx)
        return idx + 2, db_tx_attenuation

    def strip_dbm_tx_power(self, idx):
        """strip(1 byte) dbm_tx_power
        :return: int
            idx
        :return: int
        """
        idx = Radiotap.align(idx, 1)
        dbm_tx_power, = struct.unpack_from('<b', self._rtap, idx)
        return idx + 1, dbm_tx_power

    def strip_antenna(self, idx):
        """strip(1 byte) radiotap.antenna
        :return: int
            idx
        :return: int
        """
        antenna, = struct.unpack_from('<B', self._rtap, idx)
        return idx + 1, antenna

    def strip_db_antsignal(self, idx):
        """strip(1 byte) radiotap.db_antsignal
        :return: int
            idx
        :return: int
        """
        db_antsignal, = struct.unpack_from('<B', self._rtap, idx)
        return idx + 1, db_antsignal

    def strip_db_antnoise(self, idx):
        """strip(1 byte) radiotap.db_antnoise
        :return: int
            idx
        :return: int
        """
        db_antnoise, = struct.unpack_from('<B', self._rtap, idx)
        return idx + 1, db_antnoise

    def strip_rx_flags(self, idx):
        """strip(2 byte) radiotap.rxflags
        :idx: int
        :return: int
            idx
        :return: collections.namedtuple
        """
        rx_flags = collections.namedtuple('rx_flags', ['reserved', 'badplcp'])

        idx = Radiotap.align(idx, 2)
        flags, = struct.unpack_from('<H', self._rtap, idx)
        flag_bits = format(flags, '08b')[::-1]
        rx_flags.reserved = int(flag_bits[0])
        rx_flags.badplcp = int(flag_bits[1])
        return idx + 2, rx_flags

    def strip_tx_flags(self, idx):
        """strip(1 byte) tx_flags
        :idx: int
        :return: int
            idx
        :return: int
        """
        idx = Radiotap.align(idx, 2)
        tx_flags, = struct.unpack_from('<B', self._rtap, idx)
        return idx + 1, tx_flags

    def strip_rts_retries(self, idx):
        """strip(1 byte) rts_retries
        :idx: int
        :return: int
            idx
        :return: int
        """
        rts_retries, = struct.unpack_from('<B', self._rtap, idx)
        return idx + 1, rts_retries

    def strip_data_retries(self, idx):
        """strip(1 byte) data_retries
        :idx: int
        :return: int
            idx
        :return: int
        """
        data_retries, = struct.unpack_from('<B', self._rtap, idx)
        return idx + 1, data_retries

    def strip_xchannel(self, idx):
        """strip(7 bytes) radiotap.xchannel.channel(1 byte),
        radiotap.xchannel.freq(2 bytes) and radiotap.xchannel.flags(4 bytes)
        :idx: int
        :return: int
            idx
        :return: collections.namedtuple
        """
        xchannel = collections.namedtuple('xchannel', ['flags',
            'freq', 'channel', 'max_power'])

        flags = collections.namedtuple('flags', ['turbo', 'cck',
            'ofdm', 'two_g', 'five_g', 'passive', 'dynamic', 'gfsk',
            'gsm', 'sturbo', 'hafl', 'quarter', 'ht_20', 'ht_40u', 'ht_40d'])

        idx = Radiotap.align(idx, 2)
        flag_val, freq, channel, max_power =\
                struct.unpack_from('<lHBB', self._rtap, idx)

        xchannel.freq = freq
        xchannel.channel = channel
        xchannel.max_power = max_power

        bits = format(flag_val, '032b')[::-1]
        flags.turbo = int(bits[4])
        flags.cck = int(bits[5])
        flags.ofdm = int(bits[6])
        flags.two_g = int(bits[7])
        flags.five_g = int(bits[8])
        flags.passive = int(bits[9])
        flags.dynamic = int(bits[10])
        flags.gfsk = int(bits[11])
        flags.gsm = int(bits[12])
        flags.sturbo = int(bits[13])
        flags.half = int(bits[14])
        flags.quarter = int(bits[15])
        flags.ht_20 = int(bits[16])
        flags.ht_40u = int(bits[17])
        flags.ht_40d = int(bits[18])
        xchannel.flags = flags

        return idx + 8, xchannel

    def strip_mcs(self, idx):
        """strip(3 byte) radiotap.mcs which contains 802.11n bandwidth,
        mcs(modulation and coding scheme) and stbc(space time block coding)
        information.
        :idx: int
        :return: int
            idx
        :return: collections.namedtuple
        """
        mcs = collections.namedtuple('mcs', ['known', 'index', 'have_bw',
            'have_mcs', 'have_gi', 'have_format', 'have_fec', 'have_stbc',
            'have_ness', 'ness_bit1'])

        idx = Radiotap.align(idx, 1)
        known, flags, index = struct.unpack_from('<BBB', self._rtap, idx)
        bits = format(flags, '032b')[::-1]

        mcs.known = known              # Known MCS information
        mcs.index = index              # MCS index
        mcs.have_bw = int(bits[0])     # Bandwidth
        mcs.have_mcs = int(bits[1])    # MCS
        mcs.have_gi = int(bits[2])     # Guard Interval
        mcs.have_format = int(bits[3]) # Format
        mcs.have_fec = int(bits[4])    # FEC(Forward Error Correction) type
        mcs.have_stbc = int(bits[5])   # Space Time Block Coding
        mcs.have_ness = int(bits[6])   # Number of Extension Spatial Streams
        mcs.ness_bit1 = int(bits[7])   # Number of Extension Spatial Streams bit 1
        return idx + 3, mcs

    def strip_ampdu(self, idx):
        """strip(8 byte) radiotap.ampdu
        :idx: int
        :return: int
            idx
        :return: collections.namedtuple
        """
        ampdu = collections.namedtuple('ampdu', ['reference', 'crc_val',
            'reservered', 'flags'])
        flags = collections.namedtuple('flags', ['report_zerolen', 'is_zerolen',
            'lastknown', 'last', 'delim_crc_error'])

        idx = Radiotap.align(idx, 4)
        refnum, flag_vals, crc_val, reserved = struct.unpack_from('<LHBB', self._rtap, idx)
        ampdu.flags = flags
        ampdu.reference = refnum
        ampdu.crc_val = crc_val
        ampdu.reserved = reserved

        bits = format(flag_vals, '032b')[::-1]
        ampdu.flags.report_zerolen = int(bits[0])
        ampdu.flags.is_zerolen = int(bits[1])
        ampdu.flags.lastknown = int(bits[2])
        ampdu.flags.last = int(bits[3])
        ampdu.flags.delim_crc_error = int(bits[4])
        return idx + 8, ampdu

    def strip_vht(self, idx):
        """strip(12 byte) radiotap.vht
        :idx: int
        :return: int
            idx
        :return: collections.namedtuple
        """
        vht = collections.namedtuple('vht', ['known_bits', 'have_stbc',
            'have_txop_ps', 'have_gi', 'have_sgi_nsym_da', 'have_ldpc_extra',
            'have_beamformed', 'have_bw', 'have_gid', 'have_paid',
            'stbc', 'txop_ps', 'gi', 'sgi_nysm_da', 'ldpc_extra', 'group_id',
            'partial_id', 'beamformed', 'user_0' ,'user_1', 'user_2', 'user_3'])
        user = collections.namedtuple('user', ['nss', 'mcs', 'coding'])

        idx = Radiotap.align(idx, 2)
        known, flags, bw = struct.unpack_from('<HBB', self._rtap, idx)
        mcs_nss_0, mcs_nss_1, mcs_nss_2, mcs_nss_3 =\
                struct.unpack_from('<BBBB', self._rtap, idx+4)
        coding, group_id, partial_id = struct.unpack_from('<BBH', self._rtap, idx+8)

        known_bits = format(known, '032b')[::-1]
        vht.known_bits = known_bits
        vht.have_stbc = int(known_bits[0])        # Space Time Block Coding
        vht.have_txop_ps = int(known_bits[1])     # TXOP_PS_NOT_ALLOWD
        vht.have_gi = int(known_bits[2])          # Short/Long Guard Interval
        vht.have_sgi_nsym_da = int(known_bits[3]) # Short Guard Interval Nsym Disambiguation
        vht.have_ldpc_extra = int(known_bits[4])  # LDPC(Low Density Parity Check)
        vht.have_beamformed = int(known_bits[5])  # Beamformed
        vht.have_bw = int(known_bits[6])          # Bandwidth
        vht.have_gid = int(known_bits[7])         # Group ID
        vht.have_paid = int(known_bits[8])        # Partial AID

        flag_bits = format(flags, '032b')[::-1]
        vht.flag_bits = flag_bits
        vht.stbc = int(flag_bits[0])
        vht.txop_ps = int(flag_bits[1])
        vht.gi = int(flag_bits[2])
        vht.sgi_nysm_da = int(flag_bits[3])
        vht.ldpc_extra = int(flag_bits[4])
        vht.beamformed = int(flag_bits[5])
        vht.group_id = group_id
        vht.partial_id = partial_id

        vht.bw = bw
        vht.user_0 = user(None, None, None)
        vht.user_1 = user(None, None, None)
        vht.user_2 = user(None, None, None)
        vht.user_3 = user(None, None, None)
        for (i, mcs_nss) in enumerate([mcs_nss_0, mcs_nss_1, mcs_nss_2, mcs_nss_3]):
            if mcs_nss:
                nss = mcs_nss & 0xf0 >> 4
                mcs = (mcs_nss & 0xf0) >> 4
                coding = (coding & 2**i) >> i
                if i == 0:
                    vht.user_0 = user(nss, mcs, coding)
                elif i == 1:
                    vht.user_1 = user(nss, mcs, coding)
                elif i == 2:
                    vht._user_2 = user(nss, mcs, coding)
                elif i == 3:
                    vht.user_3 = user(nss, mcs, coding)

        return idx + 12, vht

    def extract_protocol(self):
        """extract 802.11 protocol from radiotap.channel.flags
        :return: str
            protocol name
            one of below in success
            [.11a, .11b, .11g, .11n, .11ac]
            None in fail
        """
        if self.present.mcs:
            return '.11n'

        if self.present.vht:
            return '.11ac'

        if self.present.channel and hasattr(self, 'chan'):
            if self.chan.five_g:
                if self.chan.ofdm:
                    return '.11a'
            elif self.chan.two_g:
                if self.chan.cck:
                    return '.11b'
                elif self.chan.ofdm or self.chan.dynamic:
                    return '.11g'
        return 'None'

    @staticmethod
    def align(val, align):
        """
        :val: int
        :align: int
        :return: int
        """
        return (val + align - 1) & ~(align-1)

class Wifi(ctypes.Structure):

    """Base Wi-Fi Packet"""

    _fields_ = [('name',  ctypes.c_char_p),      # name of packet
                ('vers', ctypes.c_ushort),       # version
                ('category', ctypes.c_ushort),   # category
                ('subtype', ctypes.c_ushort),    # subtype
                ('ds', ctypes.c_char_p),         # distribution system
                ('to_ds', ctypes.c_bool),        # to distribution system   -> wlan.fc.ds[0]
                ('from_ds', ctypes.c_bool),      # from distribution system -> wlan.fc.ds[1]
                ('frag', ctypes.c_bool),         # more flag
                ('retry', ctypes.c_bool),        # retry
                ('power_mgmt', ctypes.c_bool),   # power management
                ('order', ctypes.c_bool),        # order
                ('wep', ctypes.c_bool),          # wired equivalent privacy
                ('duration', ctypes.c_uint)]     # duration

    # Wireshark syntax conjugates of fields in object (base)
    _shark_ = {
               'wlan.fc.version': 'vers',
               'wlan.fc.type': 'category',
               'wlan.fc.type_subtype': 'subtype',
               'wlan.fc.ds': 'ds',
               'wlan.fc.frag': 'frag',
               'wlan.fc.retry': 'retry',
               'wlan.fc.pwrmgt': 'power_mgmt',
               'wlan.fc.wep': 'wep',
               'wlan.fc.order': 'order',
               'wlan.duration': 'duration'
              }

    def __init__(self, frame, no_rtap=False):
        """Constructor method.
        Parse common headers of all Wi-Fi frames.
        :frame: ctypes.Structure
        """
        self._raw = {}
        if not no_rtap:
            rtap_bytes, self._packet = WiHelper._strip_rtap(frame)
            self.radiotap = Radiotap(rtap_bytes)
        else:
            self._packet = frame
            self.radiotap = None

        f_cntrl = struct.unpack('BB', self._packet[:2]) #frame control
        flags = f_cntrl[1]
        self.vers = f_cntrl[0] & 0b0011
        self.category = (f_cntrl[0] >> 2) & 0b0011
        self.subtype = f_cntrl[0] >> 4

        flag_bits = format(flags, '08b')[::-1]
        self.to_ds = int(flag_bits[0])
        self.from_ds = int(flag_bits[1])
        self.ds = str(int(self.to_ds)) + str(int(self.from_ds))
        self.frag = int(flag_bits[2])
        self.retry = int(flag_bits[3])
        self.power_mgmt = int(flag_bits[4])
        self.more_data = int(flag_bits[5])
        self.wep = int(flag_bits[6])
        self.order = int(flag_bits[7])

        #TODO: parse duration with respect to field/subfield
        #since some bits might be reserved for types like data (0x20)
        #https://community.arubanetworks.com/t5/Technology-Blog/802-11-Duration-ID-Field/ba-p/235872
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

    def get_shark_field(self, fields):
        """get parameters via wireshark syntax.
        out = x.get_shark_field('wlan.fc.type')
        out = x.get_shark_field(['wlan.fc.type', 'wlan.seq'])
        :fields: str or str[]
        :return: dict
            out[fields[0]] = val[0] or None
            out[fields[1]] = val[1] or None ...
        """
        keys, exist, out = None, {}, None

        if type(fields) == str:
            fields = [fields]
        elif type(fields) != list:
            logging.error('invalid input type')
            return None

        out = dict.fromkeys(fields)

        if hasattr(self, '_shark_'):
            exist.update(self._shark_)

        if hasattr(self, '_s_shark_'):
            exist.update(self._s_shark_)

        if hasattr(self.radiotap, '_r_shark_'):
            exist.update(self.radiotap._r_shark_)

        keys = exist.keys()

        for elem in fields:
            if elem in keys:
                obj_field, tmp = exist[elem], None
                try:
                    tmp = operator.attrgetter(obj_field)(self)
                except AttributeError:
                    tmp = None
                if not tmp:
                    try:
                        tmp = operator.attrgetter(obj_field)(self.radiotap)
                    except AttributeError:
                        tmp = None
                out[elem] = tmp
        return out

    @staticmethod
    def get_mac_addr(mac_addr):
        """converts bytes to mac addr format
        :mac_addr: ctypes.structure
        :return: str
            mac addr in format
            11:22:33:aa:bb:cc
        """
        mac_addr = bytearray(mac_addr)
        mac = b':'.join([('%02x' % o).encode('ascii')
            for o in mac_addr])
        return mac

    def get_hex_repr(self):
        """wlan.fc.type_subtype hex representation
        :return: str
        """
        return hex(self.category * 16 + self.subtype)

    def strip_mac_addrs(self):
        """strip mac address(each 6 byte) information.
        (wlan.ta, wlan.ra, wlan.sa, wlan.da)
        (transmitter, receiver, source, destination)
        :return: int
            index of sequence control
        :return: int
            index after mac addresses
        :return: str
            source address (sa)
        :return: str
            transmitter address (ta)
        :return: str
            receiver address (ra)
        :return: str
            destination address (da)
        :return: str
            basic service sed identifier (bssid)
        """
        qos_idx, seq_idx = 0, 0
        sa, ta, ra, da, bssid =\
            None, None, None, None, None

        if self.to_ds == 1 and self.from_ds == 1:
            (ra, ta, da) =\
                struct.unpack('!6s6s6s', self._packet[4:22])
            sa = struct.unpack('!6s', self._packet[24:30])[0]
            qos_idx = 30
            seq_idx = 22
        elif self.to_ds == 0 and self.from_ds == 1:
            (ra, ta, sa) =\
                struct.unpack('!6s6s6s', self._packet[4:22])
            qos_idx = 24
            seq_idx = 22
        elif self.to_ds == 1 and self.from_ds == 0:
            (ra, ta, da) =\
                struct.unpack('!6s6s6s', self._packet[4:22])
            qos_idx = 24
            seq_idx = 22
        elif self.to_ds == 0 and self.from_ds == 0:
            (ra, ta, bssid) =\
                struct.unpack('!6s6s6s', self._packet[4:22])
            qos_idx = 24
            seq_idx = 22

        if ta != None:
            ta = Wifi.get_mac_addr(ta)
        if ra != None:
            ra = Wifi.get_mac_addr(ra)
        if sa != None:
            sa = Wifi.get_mac_addr(sa)
        if da != None:
            da = Wifi.get_mac_addr(da)
        if bssid != None:
            bssid = Wifi.get_mac_addr(bssid)

        return seq_idx, qos_idx, sa, ta, ra, da, bssid

    def strip_seq_cntrl(self, idx):
        """strip(2 byte) wlan.seq(12 bit) and wlan.fram(4 bit)
        number information.
        :seq_cntrl: ctypes.Structure
        :return: int
            sequence number
        :return: int
            fragment number
        """
        seq_cntrl = struct.unpack('H', self._packet[idx:idx+2])[0]
        seq_num = seq_cntrl >> 4
        frag_num = seq_cntrl & 0x000f
        return seq_num, frag_num

    def __repr__(self, show_rfields=True):
        """
        :show_rfields: bool
            whether to show radiotap fields too.
        """
        out_str = ''
        all_fields = []

        if hasattr(self, '_fields_'):
            all_fields += self._fields_

        if hasattr(self, '_sfields_'):
            all_fields += self._sfields_

        if all_fields:
            for elem in all_fields:
                key = elem[0]
                try:
                    val = operator.attrgetter(key)(self)
                except:
                    val = None
                if type(val) == list:
                    if val:
                        out_str += "{} <list>[{}]\n".format(key, type(val[0]))
                    else:
                        out_str += "{} <list>\n".format(str(key))
                else:
                    out_str += "{}: {}\n".format(str(key), str(val))
        else:
            logging.error('instance does not have any field')
            return None

        if show_rfields and hasattr(self.radiotap, '_rfields_'):
            for elem in self.radiotap._rfields_:
                key = elem[0]
                try:
                    val = operator.attrgetter(key)(self.radiotap)
                except:
                    val = None
                if val != None:
                    out_str += "radiotap.{}: {}\n".format(key, val)
        return out_str

class Data(Wifi):

    """Base Data Packet (type: 2)"""

    def __init__(self, frame, no_rtap=False):
        """Constructor method.
        :packet: ctypes.Structure
        :no_rtap: Bool
            shall parse radiotap headers
        """
        Wifi.__init__(self, frame, no_rtap)

class QosData(Data):

    """Qos Data (type: 2, subtype: 8)"""

    _sfields_ = [('sa', ctypes.c_char_p),           # source address
                 ('ta', ctypes.c_char_p),           # transmitter address
                 ('ra', ctypes.c_char_p),           # receiver address
                 ('da', ctypes.c_char_p),           # destionation address
                 ('seq_num', ctypes.c_uint),        # sequence number
                 ('frag_num', ctypes.c_uint),       # fragment number
                 ('qos_pri', ctypes.c_uint),        # qualit of service priority
                 ('qos_bit', ctypes.c_bool),        # quality of service bit
                 ('qos_ack', ctypes.c_uint),        # quality of service ack
                 ('amsdupresent', ctypes.c_bool),   # aggregated mac service data unit
                 ('ccmp_extiv', ctypes.c_uint64),   # counter mode chiper block
                 ('payload', list)]                 # payload

    # Wireshark syntax conjugates of fields in object (subfield shark)
    _s_shark_ = {
                 'wlan.sa': 'sa',
                 'wlan.ta': 'ta',
                 'wlan.ra': 'ra',
                 'wlan.da': 'da',
                 'wlan.seq': 'seq_num',
                 'wlan.frag': 'frag_num',
                 'wlan.qos.priority': 'qos_pri',
                 'wlan.qos.bit4': 'qos_bit',
                 'wlan.qos.ack': 'qos_ack',
                 'wlan.qos.amsdupresent': 'amsdupresent',
                 'wlan.ccmp.extiv': 'ccmp_extiv'
                }

    def __init__(self, frame, no_rtap=False, parse_amsdu=True):
        """Constructor method.
        :frame: ctypes.Structure
        :parse_amsdu: Bool
            shall parse aggregated mac service data unit
        """
        Data.__init__(self, frame, no_rtap)
        idx = 0
        self.sa = self.ta = self.ra = self.da = None
        self.seq_num = self.frag_num = None
        self.qos_pri = self.qos_bit = self.qos_ack = None
        self.ccmp_extiv = None
        self.payload = []

        seq_idx, qos_idx, self.sa, self.ta, self.ra, self.da, _  =\
                self.strip_mac_addrs()

        self.seq_num, self.frag_num = self.strip_seq_cntrl(seq_idx)

        idx = qos_idx
        incr, self.qos_pri, self.qos_bit, self.qos_ack, self.amsdupresent =\
                self.strip_qos_cntrl(idx, self.radiotap.prot_type)
        idx += incr

        if self.wep == 1:
            incr, self.ccmp_extiv = self.strip_ccmp(idx)
            idx += incr

        if parse_amsdu:
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

    def strip_qos_cntrl(self, idx, prot_type):
        """strip(2 byte) wlan.qos
        :idx: int
        :prot_type: string
            802.11 protocol type(.11ac, .11a, .11n, etc)
        :return: int
            number of processed bytes
        :return: int
            qos priority
        :return: int
            qos bit
        :return: int
            qos acknowledgement
        :return: int
            amsdupresent(aggregated mac service data unit)
        """
        qos_cntrl, = struct.unpack('H', self._packet[idx:idx+2])
        qos_cntrl_bits = format(qos_cntrl, '016b')[::-1]
        qos_pri = qos_cntrl & 0x000f
        qos_bit = int(qos_cntrl_bits[5])
        qos_ack = int(qos_cntrl_bits[6:8], 2)
        amsdupresent = 0
        if prot_type == '.11ac':
            amsdupresent = int(qos_cntrl_bits[7])
        return 2, qos_pri, qos_bit, qos_ack, amsdupresent

    def strip_ccmp(self, idx):
        """strip(8 byte) wlan.ccmp.extiv
        CCMP Extended Initialization Vector
        :return: int
            number of processed bytes
        :return: ctypes.raw
            ccmp vector
        """
        ccmp_extiv = None
        if len(self._packet[idx:]) >= 8:
            raw_bytes = self._packet[idx:idx+8]
            ccmp_extiv, = struct.unpack_from('Q', raw_bytes, 0)
        return 8, ccmp_extiv

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
        msdu = {'llc':{}, 'wlan.da':None, 'wlan.sa':None,
                'payload':None, 'length':0}

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
        frame = "%s (sa: %s, ta: %s, ra: %s, da: %s, ds: %s, seq: %s)"
        frame = frame % (self.name, self.sa, self.ta, self.ra, self.da, self.ds, self.seq_num)
        return frame

class Management(Wifi):

    """Management Packet (type: 0)"""

    # commonly exists in some of the subtypes
    _capabilities_ = [('ess', ctypes.c_bool),            # extended service set
                      ('ibss', ctypes.c_bool),           # indepent service set
                      ('priv', ctypes.c_bool),           # privacy
                      ('short_pre', ctypes.c_bool),      # short preamble
                      ('pbcc', ctypes.c_bool),           # packet binary convolutional code
                      ('chan_agility', ctypes.c_bool),   # channel agility
                      ('spec_man', ctypes.c_bool),       # spectrum management
                      ('short_slot', ctypes.c_bool),     # short slot time
                      ('apsd', ctypes.c_bool),           # automatic power save delivery
                      ('radio_meas', ctypes.c_bool),     # radio measurement
                      ('dss_ofdm', ctypes.c_bool),       # direct spread spectrum
                      ('del_back', ctypes.c_bool),       # delayed block acknowledgement
                      ('imm_back', ctypes.c_bool)]       # immediate block acknowledgement

    _scapabilities_ = {
                       'wlan_mgt.fixed.capabilities.ess': 'ess',
                       'wlan_mgt.fixed.capabilities.ibss': 'ibss',
                       'wlan_mgt.fixed.capabilities.priv': 'priv',
                       'wlan_mgt.fixed.capabilities.preamble': 'short_pre',
                       'wlan_mgt.fixed.capabilities.pbcc': 'pbcc',
                       'wlan_mgt.fixed.capabilities.agility': 'chan_agility',
                       'wlan_mgt.fixed.capabilities.spec_man': 'spec_man',
                       'wlan_mgt.fixed.capabilities.short_slot_time': 'short_slot',
                       'wlan_mgt.fixed.capabilities.apsd': 'apsd',
                       'wlan_mgt.fixed.capabilities.radio_measurement': 'radio_meas',
                       'wlan_mgt.fixed.capabilities.dss_ofdm': 'dss_ofdm',
                       'wlan_mgt.fixed.capabilities.del_blk_ack': 'del_back',
                       'wlan_mgt.fixed_capabilities.imm_blk_ack': 'imm_back'
                      }

    def __init__(self, frame, no_rtap=False):
        """Constructor Method
        :frame: ctypes.Structure
        :subtype: int
        """
        Wifi.__init__(self, frame, no_rtap)
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
        :return: dict[]
            list of tagged params
        :return: int
            0 in succ, 1 for
        """
        fcs_len = 4 # wlan.fcs (4 bytes)
        idx = 0
        tagged_params = []
        while idx < len(raw_tagged_params) - fcs_len:
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
        """strip(2 byte) wlan_mgt.fixed.capabilities
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
        capabils['ess'] = int(cap_bits[0])            # Extended Service Set
        capabils['ibss'] = int(cap_bits[1])           # Independent Basic Service Set
        capabils['priv'] = int(cap_bits[4])           # Privacy
        capabils['short_preamble'] = int(cap_bits[5]) # Short Preamble
        capabils['pbcc'] = int(cap_bits[6])           # Packet Binary Convolutional Code
        capabils['chan_agility'] = int(cap_bits[7])   # Channel Agility
        capabils['spec_man'] = int(cap_bits[8])       # Spectrum Management
        capabils['short_slot'] = int(cap_bits[10])    # Short Slot Time
        capabils['apsd'] = int(cap_bits[11])          # Automatic Power Save Delivery
        capabils['radio_meas'] = int(cap_bits[12])    # Radio Measurement
        capabils['dss_ofdm'] = int(cap_bits[13])      # Direct Spread Spectrum
        capabils['del_back'] = int(cap_bits[14])      # Delayed Block Acknowledgement
        capabils['imm_back'] = int(cap_bits[15])      # Immediate Block Acknowledgement
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

    def set_fixed_capabils(self, capabils):
        """set keys of capabils into fields of object
        :capabils: dict
        """
        self.ess = capabils['ess']
        self.ibss = capabils['ibss']
        self.priv = capabils['priv']
        self.short_preamble = capabils['short_preamble']
        self.pbcc = capabils['pbcc']
        self.chan_agility = capabils['chan_agility']
        self.spec_man = capabils['spec_man']
        self.short_slot = capabils['short_slot']
        self.apsd = capabils['apsd']
        self.radio_meas = capabils['radio_meas']
        self.dss_ofdm = capabils['dss_ofdm']
        self.del_back = capabils['del_back']
        self.imm_back = capabils['imm_back']

    def get_vendor_ies(self, mac_block=None, oui_type=None):
        """vendor information element querying
        :mac_block: str
            first 3 bytes of mac addresses in format of
            00-11-22 or 00:11:22 or 001122
        :oui_type: int
            vendors ie type
        :return: int
            is valid mac_block  format
            -1 is unknown
        :return: dict[]
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
                logging.warn("invalid oui macblock")
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

    _sfields_ = [('ra', ctypes.c_char_p),          # receiver address
                 ('ta', ctypes.c_char_p),          # transmitter address
                 ('bssid', ctypes.c_char_p),       # basic service set identifier
                 ('frag_num', ctypes.c_uint),      # fragment number
                 ('seq_num', ctypes.c_uint),       # sequence number
                 ('timestamp', ctypes.c_uint64),   # timestamp
                 ('interval', ctypes.c_uint),      # interval
                 ('tagged_params', list)]          # tagged parameters

    # Wireshark syntax conjugates of fields in object (subfield shark)
    _s_shark_ = {
                 'wlan.ta': 'ta',
                 'wlan.ra': 'ra',
                 'wlan.bssid': 'bssid',
                 'wlan.frag': 'frag_num',
                 'wlan.seq': 'seq_num',
                 'wlan_mgt.fixed.timestamp': 'timestamp',
                 'wlan_mgt.fixed.beacon': 'interval',
                 'wlan_mgt.tagged.all': 'tagged_params'
                }

    _sfields_ += Management._capabilities_

    _s_shark_.update(Management._scapabilities_)

    def __init__(self, frame, no_rtap=False):
        """
        """
        Management.__init__(self, frame, no_rtap)
        idx = 0
        self.ta = self.ra = self.bssid = None
        self.seq_num = self.frag_num = None
        self.timestamp = self.interval = None

        #fixed capability fields
        self.ess = self.ibss = None
        self.privacy = None
        self.priv = self.short_pre = self.pbcc = self.chan_agility = None
        self.spec_man = self.short_slot = self.apsd = self.radio_meas = None
        self.dss_ofdm = self.del_back = self.imm_back = None

        seq_idx, qos_idx, _, self.ta, self.ra, _, self.bssid =\
                self.strip_mac_addrs()

        idx = seq_idx
        self.seq_num, self.frag_num = self.strip_seq_cntrl(idx)
        idx += 2

        payload = self._packet[idx:idx+12]
        timestamp, interval, fixed_capabils = self.strip_fixed_params(payload)

        if all([timestamp, interval, fixed_capabils]):
            self.timestamp = timestamp
            self.interval = interval
            self.set_fixed_capabils(fixed_capabils)
            idx += 12
        else:
            logging.error("failed to parse fixed parameters")
            return

        if idx < len(self._packet):
            self._raw_tagged_params = self._packet[idx:]
            is_out_bound, tagged_params =\
                self.parse_tagged_params(self._raw_tagged_params)
            if len(tagged_params):
                self.tagged_params = tagged_params
            if is_out_bound:
                logging.error("tag_len header not matched with raw byte counts")


class ProbeReq(Management):

    """Probe Request (type: 0, subtype:4)"""


    _sfields_ = [('ra', ctypes.c_char_p),       # receiver address
                 ('ta', ctypes.c_char_p),       # transmitter address
                 ('bssid', ctypes.c_char_p),    # basic service set identifier
                 ('frag_num', ctypes.c_uint),   # fragment number
                 ('seq_num', ctypes.c_uint),    # sequence number
                 ('tagged_params', list)]       # tagged parameters

    _s_shark_ = {
                 'wlan.ra': 'ra',
                 'wlan.ta': 'ta',
                 'wlan.bssid': 'bssid',
                 'wlan.frag': 'frag_num',
                 'wlan.seq': 'seq_num',
                 'wlan_mgt.tagged.all': 'tagged_params'
                }

    def __init__(self, frame, no_rtap=False):
        """
        """
        Management.__init__(self, frame, no_rtap)
        idx = 0
        self.ta = self.ra = self.bssid = None
        self.seq_num = self.frag_num = None

        seq_idx, qos_idx, _, self.ta, self.ra, _, self.bssid =\
                self.strip_mac_addrs()

        idx = seq_idx
        self.seq_num, self.frag_num = self.strip_seq_cntrl(idx)
        idx += 2
        if idx < len(self._packet):
            self._raw_tagged_params = self._packet[idx:]
            is_out_bound, tagged_params =\
                self.parse_tagged_params(self._raw_tagged_params)
            if len(tagged_params):
                self.tagged_params = tagged_params
            if is_out_bound:
                logging.error("tag_len header not matched with raw byte counts")

class Beacon(Management):

    """Beacon (type: 0, subtype: 0)"""

    _sfields_ = [('ra', ctypes.c_char_p),          # receiver address
                 ('ta', ctypes.c_char_p),          # transmitter address
                 ('bssid', ctypes.c_char_p),       # basic service set identifier
                 ('frag_num', ctypes.c_uint),      # fragment number
                 ('seq_num', ctypes.c_uint),       # sequence number
                 ('timestamp', ctypes.c_uint64),   # timestamp
                 ('interval', ctypes.c_uint),      # interval
                 ('tagged_params', list)]          # tagged parameters

    # Wireshark syntax conjugates of fields in object (subfield shark)
    _s_shark_ = {
                 'wlan.ta': 'ta',
                 'wlan.ra': 'ra',
                 'wlan.bssid': 'bssid',
                 'wlan.frag': 'frag_num',
                 'wlan.seq': 'seq_num',
                 'wlan_mgt.fixed.timestamp': 'timestamp',
                 'wlan_mgt.fixed.beacon': 'interval',
                 'wlan_mgt.tagged.all': 'tagged_params'
                }

    _sfields_ += Management._capabilities_

    _s_shark_.update(Management._scapabilities_)

    def __init__(self, frame, no_rtap=False):
        """Constructor method.
        :frame: ctypes.Structure
        """
        Management.__init__(self, frame, no_rtap)
        idx = 0
        self.timestamp = self.interval = None
        self.ta = self.ra = self.bssid = None
        self.seq_num = self.frag_num = None

        #fixed capability fields
        self.ess = self.ibss = None
        self.privacy = None
        self.priv = self.short_preamble = self.pbcc = self.chan_agility = None
        self.spec_man = self.short_slot = self.apsd = self.radio_meas = None
        self.dss_ofdm = self.del_back = self.imm_back = None

        seq_idx, qos_idx, _, self.ta, self.ra, _, self.bssid =\
                self.strip_mac_addrs()

        idx = seq_idx
        self.seq_num, self.frag_num = self.strip_seq_cntrl(idx)
        idx += 2

        payload = self._packet[idx:idx+12]
        timestamp, interval, fixed_capabils = self.strip_fixed_params(payload)

        if all([timestamp, interval, fixed_capabils]):
            self.timestamp = timestamp
            self.interval = interval
            self.set_fixed_capabils(fixed_capabils)
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

    def __init__(self, frame, no_rtap=False):
        """Constructor method.
        :frame: ctypes.Structure
        """
        Wifi.__init__(self, frame, no_rtap)

    def __str__(self):
        return self.name

class RTS(Control):

    """Request to Send Frame (type: 1, subtype: 1)"""

    _sfields_ = [('ta', ctypes.c_char_p),   # transmitter address
                 ('ra', ctypes.c_char_p)]   # receiver address

    # Wireshark syntax conjugates of fields in object (subfield shark)
    _s_shark_ = {
                 'wlan.ta': 'ta',
                 'wlan.ra': 'ra'
                }

    def __init__(self, frame, no_rtap=False):
        """Constructor method.
        :frame: ctypes.Structure
        """
        Control.__init__(self, frame, no_rtap)
        (ra_mac, ta_mac) = struct.unpack('!6s6s', self._packet[4:16])
        self.ra = Wifi.get_mac_addr(ra_mac)
        self.ta = Wifi.get_mac_addr(ta_mac)

    def __str__(self):
        frame = '%s from %s to %s (duration: %d us)'
        frame = frame % (self.name, self.ta, self.ra, self.duration)
        return frame

class CTS(Control):

    """Clear to Send Frame (type: 1, subtype: 2)"""

    _sfields_ = [('ra', ctypes.c_char_p)]  # receiver address -> wlan.ra

    # Wireshark syntax conjugates of fields in object (subfield shark)
    _s_shark_ = {'wlan.ra': 'ra'}

    def __init__(self, frame, no_rtap=False):
        """Constructor method.
        :frame: ctypes.Structure
        """
        Control.__init__(self, frame, no_rtap)
        ra_mac = struct.unpack('!6s', self._packet[4:10])[0]
        self.ra = Wifi.get_mac_addr(ra_mac)

    def __str__(self):
        frame = '%s to %s (duration: %d us)'
        frame = frame % (self.name, self.ra, self.duration)
        return frame

class BACK(Control):

    _sfields_ = [('ra', ctypes.c_char_p),           # receiver address
                 ('ta', ctypes.c_char_p),           # transmitter address
                 ('ackpolicy', ctypes.c_bool),      # acknowledgement policy
                 ('multitid', ctypes.c_bool),       # multiple traffic identifier
                 ('ssc_frag', ctypes.c_uint),       # starting sequence number fragment
                 ('ssc_seq', ctypes.c_uint),        # starting sequence number
                 ('bitmap_str', ctypes.c_char_p),   # bitmap string                     -> in wlan.ba.bm
                 ('acked_seqs', list)]              # acknowledged strings              -> in wlan.ba.bm and wlan_mgt.fixed.ssc.sequence

    # Wireshark syntax conjugates of fields in object (subfield shark)
    _s_shark_ = {
                 'wlan.ra': 'ra',
                 'wlan.ta': 'ta',
                 'wlan.ba.control.ackpolicy': 'ackpolicy',
                 'wlan.ba.control.multitid': 'multitid',
                 'wlan_mgt.fixed.ssc.fragment': 'ssc_frag',
                 'wlan_mgt.ssc.sequence': 'ssc_seq'
                }

    """Block Acknowledgement Frame (type: 1, subtype: 9)"""

    def __init__(self, frame, no_rtap=False):
        """Constructor method.
        :frame: ctypes.Structure
        """
        Control.__init__(self, frame, no_rtap)
        (ra_mac, ta_mac) = struct.unpack('!6s6s', self._packet[4:16])
        self.ra = self.ta = None
        self.ackpolicy = self.multitid = None
        self.ssc_frag = self.ssc_seq = None
        self.bitmap_str = None
        self.acked_seqs = []

        self.ra = Wifi.get_mac_addr(ra_mac)
        self.ta = Wifi.get_mac_addr(ta_mac)
        idx = 16

        payload = self._packet[idx:idx+2]
        self.ackpolicy, self.multitid = BACK.strip_cntrl(payload)
        idx += 2

        payload = self._packet[idx:idx+2]
        self.ssc_seq, self.ssc_frag = BACK.strip_ssc(payload)
        idx += 2

        payload = self._packet[idx:idx+8]
        self.bitmap_str = BACK.strip_bitmap_str(payload)
        idx += 8

        self.acked_seqs =\
                BACK.extract_acked_seqs(self.bitmap_str, self.ssc_seq)

    def get_shark_field(self, fields):
        """
        :fields: str[]
        """
        out = super(BACK, self).get_shark_field(fields)
        out.update({'acked_seqs':self.acked_seqs,
                    'bitmap_str':self.bitmap_str})
        return out

    @staticmethod
    def strip_cntrl(payload):
        """strip(2 byte) wlan.ba.control
        :payload: ctypes.structure
        :return: int
            multitid (tid: traffic indicator)
        :return: int
            ackpolicy
        """
        cntrl = struct.unpack('H', payload)[0]
        cntrl_bits = format(cntrl, '016b')[::-1]
        ackpolicy = int(cntrl_bits[0])
        multitid = int(cntrl_bits[1])
        return ackpolicy, multitid

    @staticmethod
    def strip_ssc(payload):
        """strip(2 byte) wlan_mgt.fixed.ssc
        :payload: ctypes.structure
        :return: int
            ssc_seq (starting sequence control sequence)
        :return: int
            ssc_frag (starting sequence control fragment number)
        """
        ssc = struct.unpack('H', payload)[0]
        ssc_seq = ssc >> 4
        ssc_frag = ssc & 0x000f
        return ssc_seq, ssc_frag

    @staticmethod
    def strip_bitmap_str(payload):
        """strip(8 byte) wlan.ba.bm
        :payload: ctypes.structure
        :return: str
            bitmap
        """
        bitmap = struct.unpack('BBBBBBBB', payload)
        bitmap_str = ''
        for elem in bitmap:
            bitmap_str += format(elem, '08b')[::-1]
        return bitmap_str

    @staticmethod
    def extract_acked_seqs(bitmap, ssc_seq):
        """extracts acknowledged sequences from bitmap and
        starting sequence number.
        :bitmap: str
        :ssc_seq: int
        :return: int[]
            acknowledged sequence numbers
        """
        acked_seqs = []
        for idx, val in enumerate(bitmap):
           if int(val) == 1:
              seq = (ssc_seq + idx) % 4096
              acked_seqs.append(seq)
        return acked_seqs

    def __str__(self):
        frame = '%s from %s to %s (starting seq: %d, num_acked: %d)'
        frame = frame % (self.name, self.ta, self.ra,
                self.ssc_seq, len(self.acked_seqs))
        return frame
class Unknown(Wifi):
    """
    un-identified packet
    """
    def __init__(self, frame, no_rtap):
        Wifi.__init__(self, frame, no_rtap)
        self.name = "Unkown"
