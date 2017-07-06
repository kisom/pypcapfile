"""
802.1Q (dot1Q) encapsulation
"""

import ctypes
import struct
from pcapfile.protocols.linklayer import ethernet

class Dot1q(ctypes.Structure):
    _fields_ = [('priority', ctypes.c_ubyte),   # Priority
                ('cfi', ctypes.c_ubyte),        # CFI
                ('id', ctypes.c_ushort),        # VLAN ID
                ('etype', ctypes.c_ushort)]     # Ethertype

    def __init__(self, packet, layers=0):

        fields = struct.unpack('!HH', packet[:4])

        self.priority = fields[0] >> 13
        self.cfi = (fields[0] >> 12) & 0b0001
        self.id = fields[0] & 0b0000111111111111
        self.type = fields[1]
        self.payload = packet[4:]

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
            ctor = ethernet.payload_type(self.type)[0]
            if ctor:
                ctor = ctor
                # payload = binascii.unhexlify(self.payload)
                self.payload = ctor(self.payload, layers - 1)
            else:
                # if no type is found, do not touch the packet.
                pass

    def __str__(self):
        packet = '802.1Q packet VLAN %d PRI %d CFI %d' % (self.id, self.priority, self.cfi)
        return packet

def __call__(packet):
    return Dot1q(packet)
