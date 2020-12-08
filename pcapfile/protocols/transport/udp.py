"""
UDP transport definition
"""

import ctypes
import struct


class UDP(ctypes.Structure):
    """
    Represents a UDP packet
    """

    _fields_ = [('src_port', ctypes.c_ushort),  # source port
                ('dst_port', ctypes.c_ushort),  # destination port
                ('len', ctypes.c_ushort),       # length of header and data
                ('sum', ctypes.c_ushort)]       # checksum

    udp_header_size = 8

    def __init__(self, packet, layers=0):
        super(UDP, self).__init__()
        fields = struct.unpack("!HHHH", packet[:self.udp_header_size])
        self.src_port = fields[0]
        self.dst_port = fields[1]
        self.len = fields[2]
        self.sum = fields[3]
        self.payload = packet[self.udp_header_size:]

    def __str__(self):
        packet = 'udp packet from port %d to port %d carrying %d bytes'
        packet = packet % (self.src_port, self.dst_port, len(self.payload))
        return packet

    def __len__(self):
        return self.udp_header_size + len(self.payload)
