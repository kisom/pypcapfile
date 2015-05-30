"""
IP protocol definitions.
"""

import ctypes

class IP(ctypes.BigEndianStructure):
    """
    Represents an IP header.
    """

    _fields_ = [('version', ctypes.c_uint8, 4),
                ('ihl', ctypes.c_uint8, 4),
                ('tos', ctypes.c_uint8),
                ('len', ctypes.c_uint16),
                ('id', ctypes.c_uint16),
                ('flags', ctypes.c_uint16, 3),
                ('off', ctypes.c_uint16, 13),
                ('ttl', ctypes.c_uint8),
                ('p', ctypes.c_uint8),
                ('sum', ctypes.c_uint16),
                ('src', ctypes.c_uint32),
                ('dst', ctypes.c_uint32)]
