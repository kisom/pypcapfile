# pypcapfile.savefile.py

import ctypes
import struct
import sys

class __pcap_header__(ctypes.Structure):
    """
C-struct representation of a savefile header. See __validate_header__
for validation.
    """
    _fields_ = [('magic', ctypes.c_uint),       # file magic number
                ('major', ctypes.c_ushort),     # major version number
                ('minor', ctypes.c_ushort),     # minor version number
                ('tz_off', ctypes.c_uint),      # timezone offset
                ('ts_acc', ctypes.c_uint),      # timestamp accuracy
                ('snaplen', ctypes.c_uint),     # snapshot length
                ('ll_type', ctypes.c_uint)]     # link layer header type


def __unpack_header__(unpacked):
    hdr = struc


class pcap_packet(ctypes.Structure):
    _fields_ = [('timestamp', ctypes.c_uint),
                ('timestamp_ms', ctypes.c_uint),
                ('capture_len', ctypes.c_uint),
                ('packet_len', ctypes.c_uint),
                ('packet', ctypes.c_char_p)]


class pcap_savefile(object):
    def __init__(self, header, packets = []):
        self.header = header
        self.packets = packets
        self.valid = None
        self.byteorder = sys.byteorder
        
        if not self.__validate__():
            self.valid = False
        else:
            self.valid = True

        assert self.valid, 'Invalid savefile.'

        if header.magic == 0xa1b2c3d4:
            self.byteorder = 'big'
        elif header.magic == 0xd4c3b2a1:
            self.byteorder = 'little'
        else:
            self.byteorder = 'unknown'

        assert self.byteorder in [ 'little', 'big' ], 'Invalid byte order.'


    def __validate__(self):
        assert __validate_header__(self.header),  "Invalid header."
        if not __validate_header__(self.header):
            return False
        
        valid_packet = lambda pkt: type(pkt) == pcap_packet or pkt == None
        if not 0 == len(self.packets):
            valid_packet = [valid_packet(pkt) for pkt in self.packets]
            assert False not in valid_packet, 'Invalid packets in savefile.'
            return False
        
        return True


def _load_savefile_header(file_h):
    """
Load and validate the header of a pcap file.
    """
    raw_savefile_header = file_h.read(24)
    unpacked = struct.unpack('=IhhIIII', raw_savefile_header)
    (magic, major, minor, tz_off, ts_acc, snaplen, ll_type) = unpacked
    header = __pcap_header__(magic, major, minor, tz_off, ts_acc, snaplen, 
                             ll_type)
    if not __validate_header__(header):
        raise Exception('invalid savefile header!')
    else:
        return header


def load_savefile(filename):
    file_h = open(filename)

    header = _load_savefile_header(file_h)
    packets = _load_packets(file_h)
    sfile = pcap_savefile(header, packets)

    return sfile


def __validate_header__(header):
    if not type(header) == __pcap_header__:
        return False

    if not header.magic == 0xa1b2c3d4:
        if not header.magic == 0xd4c3b2a1:
            return False

    # as of savefile format 2.4, 'a 4-byte time zone offset; this 
    # is always 0'; the same is true of the timestamp accuracy.
    if not header.tz_off == 0:
        return False

    if not header.ts_acc == 0:
        return False

    return True


def _load_packets(file_h):
    pkts = []

    while True:
        pkt = _read_a_packet(file_h)
        if pkt:
            pkts.append(pkt)
        else:
            break

    return pkts

def _read_a_packet(file_h):
    raw_packet_header = file_h.read(16)
    #assert (not raw_packet_header == '') and (len(raw_packet_header) == 16),\
    #`    'Unexpected end of per-packet header.'

    packet_header = struct.unpack('=IIII', raw_packet_header)
    (timestamp, timestamp_ms, capture_len, packet_len) = packet_header
    raw_packet = file_h.read(capture_len)
    assert len(raw_packet) == capture_len, 'Unexpected end of packet.'

    packet = pcap_packet(timestamp, timestamp_ms, capture_len, packet_len, 
                         raw_packet)
    return packet
