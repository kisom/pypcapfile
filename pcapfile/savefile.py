# pypcapfile.savefile.py
"""
Core functionality for reading and parsing libpcap savefiles. This contains
the core classes pcap_packet and pcap_savefile, as well as the core function
load_savefile.
"""

import binascii
import ctypes
import struct
import sys

import pcapfile.linklayer as linklayer

VERBOSE = False


def __TRACE__(msg, args=None):
    if VERBOSE:
        if args:
            print msg % args
        else:
            print msg


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
                ('ll_type', ctypes.c_uint),     # link layer header type
                ('byteorder', ctypes.c_char_p)] # byte order specifier


class pcap_packet(ctypes.Structure):
    """
    ctypes Structure representation of a packet. The header field is a pointer
    to the header of the savefile the packet came from to provide context. It
    can be accessed with header[0]. By default, the raw packet is stored in
    a string of hexadecimal-encoded bytes as the packet field. The raw()
    method will return the raw binary packet.
    """
    _fields_ = [('header', ctypes.POINTER(__pcap_header__)),
                ('timestamp', ctypes.c_uint),
                ('timestamp_ms', ctypes.c_uint),
                ('capture_len', ctypes.c_uint),
                ('packet_len', ctypes.c_uint),
                ('packet', ctypes.c_char_p)]

    def raw(self):
        """
        Return the raw binary data from the packet.
        """
        return binascii.unhexlify(self.packet)

    def __repr__(self):
        return self.raw()


class pcap_savefile(object):
    """
    Represents a libpcap savefile. The packets member is a list of pcap_packet
    instances. The 'valid' member will be None for an uninitialised instance,
    False if the initial validation fails, or True if the instance has been
    successfully set up and the file has been parsed.
    """
    def __init__(self, header, packets=None):
        if not packets:
            packets = []
        self.header = header
        self.packets = packets
        self.valid = None
        self.byteorder = sys.byteorder

        if not self.__validate__():
            self.valid = False
        else:
            self.valid = True

        assert self.valid, 'Invalid savefile.'


    def __validate__(self):
        assert __validate_header__(self.header),  "Invalid header."
        if not __validate_header__(self.header):
            return False

        valid_packet = lambda pkt: type(pkt) == pcap_packet or pkt is None
        if not 0 == len(self.packets):
            valid_packet = [valid_packet(pkt) for pkt in self.packets]
            assert False not in valid_packet, 'Invalid packets in savefile.'
            if False in valid_packet:
                return False

        return True

    def __repr__(self):
        string = '%s-endian capture file version %d.%d\n'
        string += 'snapshot length: %d\n'
        string += 'linklayer type: %s\nnumber of packets: %d\n'
        string = string % (self.header.byteorder, self.header.major,
                           self.header.minor, self.header.snaplen,
                           linklayer.lookup(self.header.ll_type),
                           len(self.packets))
        return string


def _load_savefile_header(file_h):
    """
Load and validate the header of a pcap file.
    """
    raw_savefile_header = file_h.read(24)
    if raw_savefile_header[:4] == '\xa1\xb2\xc3\xd4':
        byte_order = 'big'
    elif raw_savefile_header[:4] == '\xd4\xc3\xb2\xa1':
        byte_order = 'little'
    else:
        byte_order = None
    unpacked = struct.unpack('=IhhIIII', raw_savefile_header)
    (magic, major, minor, tz_off, ts_acc, snaplen, ll_type) = unpacked
    header = __pcap_header__(magic, major, minor, tz_off, ts_acc, snaplen,
                             ll_type, ctypes.c_char_p(byte_order))
    if not __validate_header__(header):
        raise Exception('invalid savefile header!')
    else:
        return header


def load_savefile(filename, verbose=False):
    """
    Load and parse a savefile as a pcap_savefile instance. Returns the savefile
    on success and None on failure. Verbose mode prints additional information
    about the file's processing.
    """
    global VERBOSE
    old_verbose = VERBOSE
    VERBOSE = verbose

    file_h = open(filename)
    __TRACE__('[+] attempting to load %s', (filename, ))

    header = _load_savefile_header(file_h)
    if __validate_header__(header):
        __TRACE__('[+] found valid header')
        packets = _load_packets(file_h, header)
        __TRACE__('[+] loaded %d packets', (len(packets), ))
        sfile = pcap_savefile(header, packets)
        __TRACE__('[+] finished loading savefile.')
    else:
        __TRACE__('[!] invalid savefile')
        sfile = None

    VERBOSE = old_verbose
    return sfile


def __validate_header__(header):
    if not type(header) == __pcap_header__:
        return False

    if not header.magic == 0xa1b2c3d4:
        if not header.magic == 0xd4c3b2a1:
            return False

    assert header.byteorder in ['little', 'big'], 'Invalid byte order.'

    # as of savefile format 2.4, 'a 4-byte time zone offset; this
    # is always 0'; the same is true of the timestamp accuracy.
    if not header.tz_off == 0:
        return False

    if not header.ts_acc == 0:
        return False

    return True


def _load_packets(file_h, header):
    """
    Read packets from the capture file. Expects the file handle to point to
    the location immediately after the header (24 bytes).
    """
    pkts = []

    hdrp = ctypes.pointer(header)
    while True:
        pkt = _read_a_packet(file_h, hdrp)
        if pkt:
            pkts.append(pkt)
        else:
            break

    return pkts


def _read_a_packet(file_h, hdrp):
    """
    Reads the next individual packet from the capture file. Expects
    the file handle to be somewhere after the header, on the next
    per-packet header.
    """
    raw_packet_header = file_h.read(16)
    if raw_packet_header == '':
        return None
    assert len(raw_packet_header) == 16, 'Unexpected end of per-packet header.'

    packet_header = struct.unpack('=IIII', raw_packet_header)
    (timestamp, timestamp_ms, capture_len, packet_len) = packet_header
    raw_packet_data = file_h.read(capture_len)

    # if the capture file is not the same endianness as ours, we need to
    # reverse the packet data
    if not __endian_check__(hdrp):
        raw_packet_data = raw_packet_data[::-1]
    assert len(raw_packet_data) == capture_len, 'Unexpected end of packet.'

    packet = pcap_packet(hdrp, timestamp, timestamp_ms, capture_len,
                         packet_len, __pack_packet__(raw_packet_data))
    return packet


def __pack_packet__(packet):
    return ctypes.c_char_p(binascii.hexlify(packet))


def __endian_check__(hdrp):
    if hdrp[0].magic == 0xa1b2c3d4:
        return True
    elif hdrp[0].magic == 0xd4c3b2a1:
        return False
    assert False, 'failed endian check.'
