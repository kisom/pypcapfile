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
from pcapfile.structs import __pcap_header__, pcap_packet
from pcapfile import InvalidEncoding, UnknownMagicNumber, InvalidHeader

VERBOSE = False

_MAGIC_NUMBER = 0xa1b2c3d4
_MAGIC_NUMBER_NS = 0xa1b23c4d


def __TRACE__(msg, args=None):
    if VERBOSE:
        if args:
            print(msg.format(*args))
        else:
            print(msg)


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
        assert __validate_header__(self.header), "Invalid header."
        if not __validate_header__(self.header):
            return False

        # Validate the packets unless they are to be loaded lazily.
        if isinstance(self.packets, list):
            # TODO: extended validation
            valid_packet = lambda pkt: (pkt is not None or
                                        pkt.issubclass(ctypes.Structure))
            if not 0 == len(self.packets):
                valid_packet = [valid_packet(pkt) for pkt in self.packets]
                assert False not in valid_packet, 'Invalid packets in savefile.'
                if False in valid_packet:
                    return False

        return True

    def __repr__(self):
        string = '%s-endian capture file version %d.%d\n'
        string += '%ssecond time resolution\n'
        string += 'snapshot length: %d\n'
        string += 'linklayer type: %s\nnumber of packets: %d\n'
        return string % (self.header.byteorder, self.header.major,
                         self.header.minor,
                         "nano" if self.header.ns_resolution else "micro",
                         self.header.snaplen,
                         linklayer.lookup(self.header.ll_type),
                         len(self.packets))


def _load_savefile_header(file_h):
    """
    Load and validate the header of a pcap file.
    """
    try:
        raw_savefile_header = file_h.read(24)
    except UnicodeDecodeError:
        print("\nMake sure the input file is opened in read binary, 'rb'\n")
        raise InvalidEncoding("Could not read file; it might not be opened in binary mode.")

    # in case the capture file is not the same endianness as ours, we have to
    # use the correct byte order for the file header
    if raw_savefile_header[:4] in [struct.pack(">I", _MAGIC_NUMBER),
                                   struct.pack(">I", _MAGIC_NUMBER_NS)]:
        byte_order = b'big'
        unpacked = struct.unpack('>IhhIIII', raw_savefile_header)
    elif raw_savefile_header[:4] in [struct.pack("<I", _MAGIC_NUMBER),
                                     struct.pack("<I", _MAGIC_NUMBER_NS)]:
        byte_order = b'little'
        unpacked = struct.unpack('<IhhIIII', raw_savefile_header)
    else:
        raise UnknownMagicNumber("No supported Magic Number found")

    (magic, major, minor, tz_off, ts_acc, snaplen, ll_type) = unpacked
    header = __pcap_header__(magic, major, minor, tz_off, ts_acc, snaplen,
                             ll_type, ctypes.c_char_p(byte_order),
                             magic == _MAGIC_NUMBER_NS)
    if not __validate_header__(header):
        raise InvalidHeader("Invalid Header")
    else:
        return header


def load_savefile(input_file, layers=0, verbose=False, lazy=False):
    """
    Parse a savefile as a pcap_savefile instance. Returns the savefile
    on success and None on failure. Verbose mode prints additional information
    about the file's processing. layers defines how many layers to descend and
    decode the packet. input_file should be a Python file object.
    """
    global VERBOSE
    old_verbose = VERBOSE
    VERBOSE = verbose

    __TRACE__('[+] attempting to load {:s}', (input_file.name,))

    header = _load_savefile_header(input_file)
    if __validate_header__(header):
        __TRACE__('[+] found valid header')
        if lazy:
            packets = _generate_packets(input_file, header, layers)
            __TRACE__('[+] created packet generator')
        else:
            packets = _load_packets(input_file, header, layers)
            __TRACE__('[+] loaded {:d} packets', (len(packets),))
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

    if header.magic not in [_MAGIC_NUMBER, _MAGIC_NUMBER_NS]:
        return False

    assert header.byteorder in [b'little', b'big'], 'Invalid byte order.'

    # as of savefile format 2.4, 'a 4-byte time zone offset; this
    # is always 0'; the same is true of the timestamp accuracy.
    if not header.tz_off == 0:
        return False

    if not header.ts_acc == 0:
        return False

    return True


def _load_packets(file_h, header, layers=0):
    """
    Read packets from the capture file. Expects the file handle to point to
    the location immediately after the header (24 bytes).
    """
    pkts = []

    hdrp = ctypes.pointer(header)
    while True:
        pkt = _read_a_packet(file_h, hdrp, layers)
        if pkt:
            pkts.append(pkt)
        else:
            break

    return pkts


def _generate_packets(file_h, header, layers=0):
    """
    Read packets one by one from the capture file. Expects the file
    handle to point to the location immediately after the header (24
    bytes).
    """
    hdrp = ctypes.pointer(header)
    while True:
        pkt = _read_a_packet(file_h, hdrp, layers)
        if pkt:
            yield pkt
        else:
            break


def _read_a_packet(file_h, hdrp, layers=0):
    """
    Reads the next individual packet from the capture file. Expects
    the file handle to be somewhere after the header, on the next
    per-packet header.
    """
    raw_packet_header = file_h.read(16)
    if not raw_packet_header or len(raw_packet_header) != 16:
        return None

    # in case the capture file is not the same endianness as ours, we have to
    # use the correct byte order for the packet header
    if hdrp[0].byteorder == 'big':
        packet_header = struct.unpack('>IIII', raw_packet_header)
    else:
        packet_header = struct.unpack('<IIII', raw_packet_header)
    (timestamp, timestamp_us, capture_len, packet_len) = packet_header
    raw_packet_data = file_h.read(capture_len)

    if not raw_packet_data or len(raw_packet_data) != capture_len:
        return None

    if layers > 0:
        layers -= 1
        raw_packet = linklayer.clookup(hdrp[0].ll_type)(raw_packet_data,
                                                        layers=layers)
    else:
        raw_packet = binascii.hexlify(raw_packet_data)

    packet = pcap_packet(hdrp, timestamp, timestamp_us, capture_len,
                         packet_len, raw_packet)
    return packet
