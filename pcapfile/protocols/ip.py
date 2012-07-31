"""
IP protocol definitions.
"""

import binascii
import ctypes
import struct

class IP(ctypes.Structure):
    """
    Represents an IP packet.
    """

    packfmt = '!BBHHHBBHII'  # 20 bytes
    _fields_ = [('v', ctypes.c_ushort),         # version
                ('hl', ctypes.c_ushort),        # internet header length
                ('tos', ctypes.c_ubyte),        # type of service
                ('len', ctypes.c_ushort),       # total length
                ('id', ctypes.c_ushort),        # IPID
                ('flags', ctypes.c_ushort, 3),  # flags
                ('off', ctypes.c_ushort, 13),   # fragmentation offset
                ('ttl', ctypes.c_ubyte),        # TTL
                ('p', ctypes.c_ubyte),          # protocol
                ('sum', ctypes.c_ushort),       # checksum
                ('src', ctypes.c_char_p),       # source address
                ('dst', ctypes.c_char_p),       # destination address
                ('opt', ctypes.c_char_p),       # IP options
                ('pad', ctypes.c_char_p),       # padding bytes
                ('payload', ctypes.c_char_p)]   # packet payload

    def __init__(self, packet):
        # parse the required header first, deal with options later
        magic = struct.unpack('B', packet[0])[0]
        assert ((magic & 0b1100) == 4 
                and (magic & 0b0111) > 4), 'not an IPv4 packet.'

        fields = struct.unpack(IP.packfmt, packet[:20])
        self.v = fields[0] & 0b1100
        self.hl = fields[0] & 0b0111
        self.tos = fields[1]
        self.len = fields[2]
        self.id = fields[3]
        self.flags = fields[4] >> 13
        self.off = fields[4] & 0x1fff
        self.ttl = fields[5]
        self.p = fields[6]
        self.sum = fields[7]
        self.src = ctypes.c_char_p(self.__parse_ipv4(fields[8]))
        self.dst = ctypes.c_char_p(self.__parse_ipv4(fields[9]))
    
        if self.len > 0x14:
            start = 0x15
            end = self.len - 0x14
            self.opt = binascii.hexlify(packet[start:end])
        else:
            self.opt = '\x00'
            self.payload = binascii.hexlify(packet[0x15:])
    
        self.pad = '\x00'

    def __parse_ipv4(self, address):
        raw = struct.pack('I', address)
        octets = struct.unpack('BBBB', raw)[::-1]
        ipv4 = '.'.join(['%d' % (b,) for b in octets])
        return ipv4

    def src_ip(self):
        return self.__parse_ipv4(self.src)

    def dst_ip(self):
        return self.__parse_ipv4(self.dst)
