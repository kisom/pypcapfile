"""
IP protocol definitions.
"""

import binascii
import ctypes
import struct


class Ethernet(ctypes.Structure):
    """
    Represents an Ethernet frame.
    """

    _fields_ = [('dst', ctypes.c_char_p),
                ('src', ctypes.c_char_p),
                ('type', ctypes.c_ushort),
                ('payload', ctypes.c_char_p)]

    def __init__(self, packet):
        (dst, src, self.type) = struct.unpack('!6s6sH', packet[:14])

        self.dst = ':'.join(['%02x' % (ord(octet), ) for octet in dst])
        self.src = ':'.join(['%02x' % (ord(octet), ) for octet in src])
        
        payload = binascii.hexlify(packet[14:])
        self.payload = ctypes.c_char_p(payload)


def strip_ethernet(packet):
    """
    Strip the Ethernet frame from a packet.
    """
    if not type(packet) == Ethernet:
        packet = Ethernet(packet)
    payload = packet.payload
    
    if type(payload) == str:
        payload = binascii.unhexlify(payload)
    return payload
