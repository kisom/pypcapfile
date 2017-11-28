"""
IP protocol definitions.
"""

import ctypes
import struct


class Ethernet(ctypes.Structure):
    """
    Represents an Ethernet frame.
    """

    _fields_ = [('type', ctypes.c_ushort)]

    payload = None

    def __init__(self, packet, layers=0):
        super(Ethernet, self).__init__()
        (dst, src, self.type) = struct.unpack('!6s6sH', packet[:14])
        self.dst = bytearray(dst)
        self.src = bytearray(src)
        assert len(self.dst) == 6
        assert len(self.src) == 6

        self.payload = packet[14:]

        if layers:
            self.load_network(layers)

    def load_network(self, layers=1):
        """
        Given an Ethernet frame, determine the appropriate sub-protocol;
        If layers is greater than zerol determine the type of the payload
        and load the appropriate type of network packet. It is expected
        that the payload be a hexified string. The layers argument determines
        how many layers to descend while parsing the packet.
        """
        if layers:
            ctor = payload_type(self.type)[0]
            if ctor:
                ctor = ctor
                payload = self.payload
                self.payload = ctor(payload, layers - 1)
            else:
                # if no type is found, do not touch the packet.
                pass

    def __str__(self):
        dst = b':'.join([('%02x' % o).encode('ascii') for o in self.dst])
        src = b':'.join([('%02x' % o).encode('ascii') for o in self.src])
        frame = 'ethernet from %s to %s type %s'
        frame = frame % (src, dst, payload_type(self.type)[1])
        return frame


def strip_ethernet(packet):
    """
    Strip the Ethernet frame from a packet.
    """
    if not isinstance(packet, Ethernet):
        packet = Ethernet(packet)
    payload = packet.payload

    return payload


def payload_type(ethertype):
    """
    Returns the appropriate payload constructor based on the supplied
    EtherType.
    """
    if ethertype == 0x0800:
        from pcapfile.protocols.network.ip import IP
        return (IP, 'IPv4')
#    elif ethertype == 0x0806:
#        from pcapfile.protocols.network.arp import ARP
#        return (ARP, 'ARP')
#    elif ethertype == 0x0835:
#        from pcapfile.protocols.network.rarp import RARP
#        return (RARP, 'RARP')
#    elif ethertype == 0x08DD:
#        from pcapfile.protocols.network.ipv6 import IPv6
#        return (IPv6, 'IPv6')
    else:
        return (None, 'unknown')
