"""
IPv4 Address Resultion Protocol (ARP)
"""

import ctypes
import struct

class ARP(ctypes.Structure):
    _fields_ = [('hw_type', ctypes.c_ushort),    # Hardware Type
                ('proto', ctypes.c_ushort),      # Protocol Type
                ('hw_size', ctypes.c_ubyte),     # Hardware size
                ('proto_size', ctypes.c_ubyte),  # Protocol size
                ('opcode', ctypes.c_ushort),     # Opcode
                ('src_mac', ctypes.c_char_p),    # Source MAC address
                ('src_ip', ctypes.c_char_p),     # Source IP address
                ('dst_mac', ctypes.c_char_p),    # Target MAC address
                ('dst_ip', ctypes.c_char_p)]     # Target IP address

    def __init__(self, packet, layers=0):

        fields = struct.unpack('!HHBBH6s4s6s4s', packet[:28])

        self.hw_type = fields[0]
        self.proto = fields[1]
        self.hw_size = fields[2]
        self.proto_size = fields[3]
        self.opcode = fields[4]
        self.src_mac = ctypes.c_char_p(parse_mac(fields[5]))
        self.src_ip = ctypes.c_char_p(parse_ip(fields[6]))
        self.dst_mac = ctypes.c_char_p(parse_mac(fields[7]))
        self.dst_ip = ctypes.c_char_p(parse_ip(fields[8]))

def parse_mac(mac):
    mac = bytearray(mac)
    mac = b':'.join([('%02x' % o).encode('ascii') for o in mac])
    return mac

def parse_ip(octets):
    ipv4 = b'.'.join([('%d' % o).encode('ascii') for o in bytearray(octets)])
    return ipv4

def __call__(packet):
    return ARP(packet)

