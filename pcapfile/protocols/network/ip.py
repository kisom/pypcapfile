"""
IP protocol definitions.
"""

import binascii
import ctypes
import struct

class IP(ctypes.BigEndianStructure):
    """
    Represents an IP packet.
    """

    _fields_ = [('v', ctypes.c_uint8, 4),       # version
                ('hl', ctypes.c_uint8, 4),      # internet header length
                ('tos', ctypes.c_uint8),        # type of service
                ('len', ctypes.c_uint16),       # total length
                ('id', ctypes.c_uint16),        # IPID
                ('flags', ctypes.c_uint16, 3),  # flags
                ('off', ctypes.c_uint16, 13),   # fragmentation offset
                ('ttl', ctypes.c_uint8),        # TTL
                ('p', ctypes.c_uint8),          # protocol
                ('sum', ctypes.c_uint16),       # checksum
                ('src', ctypes.c_uint32),       # source address
                ('dst', ctypes.c_uint32)]       # destination address

    def __init__(self, packet, layers=0):
        ctypes.BigEndianStructure.__init__(self)
        assert self.v == 4 and self.hl > 4, 'not an IPv4 packet'
        self.payload = ctypes.c_char_p(binascii.hexlify(packet[0x14:]))

        if self.hl > 0x14:
            start = 0x15
            end = self.len - 0x14
            self.opt = binascii.hexlify(packet[start:end])
        else:
            self.opt = '\x00'
            self.payload = ctypes.c_char_p(binascii.hexlify(packet[0x14:]))

        self.pad = '\x00'

    def __str__(self):
        packet = 'ipv4 packet from %s to %s carrying %d bytes'
        packet = packet % (self.src, self.dst, (len(self.payload) / 2))
        return packet


def parse_ipv4(address):
    """
    Given a raw IPv4 address (i.e. as an unsigned integer), return it in
    dotted quad notation.
    """
    raw = struct.pack('I', address)
    octets = struct.unpack('BBBB', raw)[::-1]
    ipv4 = '.'.join(['%d' % (b,) for b in octets])
    return ipv4


def strip_ip(packet):
    """
    Remove the IP packet layer, yielding the transport layer.
    """
    if not isinstance(packet, IP):
        packet = IP(packet)
    payload = packet.payload

    if isinstance(payload, str):
        payload = binascii.unhexlify(payload)
    return payload


def __call__(packet):
    return IP(packet)
