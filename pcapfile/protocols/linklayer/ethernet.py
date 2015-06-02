"""
IP protocol definitions.
"""

import binascii
import ctypes
import struct

import pcapfile.structs


class Ethernet(ctypes.BigEndianStructure):
    """
    Represents an Ethernet frame.
    """

    _fields_ = [('dst_raw', (ctypes.c_uint8 * 6)),
                ('src_raw', (ctypes.c_uint8 * 6)),
                ('type', ctypes.c_uint16)]

    payload = None

    def __init__(self, packet, layers=0):
        ctypes.BigEndianStructure.__init__(self)
        self.dst = ':'.join(['%02x' % octet for octet in self.dst_raw])
        self.src = ':'.join(['%02x' % octet for octet in self.src_raw])

        payload = binascii.hexlify(packet[14:])
        self.payload = payload

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
                payload = binascii.unhexlify(self.payload)
                self.payload = ctypes.cast(payload,
                                           ctypes.POINTER(ctor)).contents
                self.payload.__init__(payload, layers - 1)
            else:
                # if no type is found, do not touch the packet.
                pass

    def __str__(self):
        frame = 'ethernet from %s to %s type %s'
        frame = frame % (self.src, self.dst, payload_type(self.type)[1])
        return frame


def strip_ethernet(packet):
    """
    Strip the Ethernet frame from a packet.
    """
    if not isinstance(packet, Ethernet):
        packet = Ethernet(packet)
    payload = packet.payload

    if isinstance(payload, str):
        payload = binascii.unhexlify(payload)
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
