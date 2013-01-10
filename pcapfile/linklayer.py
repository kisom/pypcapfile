# contains definitions of link layer types from libpcap
"""
Link layer definitions and lookup functions based on libpcap's LLTYPE_*
values.
"""

import imp
import sys

import pcapfile.protocols.linklayer.ethernet as ethernet


__LL_TYPES__ = [('LINKTYPE_NULL', 0, 'null', None),
                ('LINKTYPE_ETHERNET', 1, 'ethernet',
                    ethernet.Ethernet),
                ('LINKTYPE_TOKEN_RING', 6, 'token ring', None),
                ('LINKTYPE_ARCNET', 7, 'ARCnet', None),
                ('LINKTYPE_SLIP', 8, 'SLIP', None)]


def __get_ll_type__(ll_type):
    """
    Given an lltype value, retrieve its definition.
    """
    res = [llt for llt in __LL_TYPES__
           if llt[1] == ll_type]
    assert len(res) < 2, 'Duplicate linklayer types.'

    if res:
        return res[0]
    else:
        return None


def lookup(ll_type):
    """
    Given an ll_type, retrieve the appropriate LL_TYPE.
    """
    res = __get_ll_type__(ll_type)
    if res:
        return res[0]
    else:
        return res


def slookup(ll_type):
    """
    Given an ll_type, retrieve the short name for the link layer.
    """
    res = __get_ll_type__(ll_type)
    if res:
        return res[2]
    else:
        return res


def clookup(ll_type):
    """
    Given an ll_type, retrieve the linklayer constructor to decode
    the packets.
    """
    res = __get_ll_type__(ll_type)
    if res:
        return res[3]
    else:
        return res


def __load_linktype__(link_type):
    """
    Given a string for a given module, attempt to load it.
    """

    try:
        filep, pathname, description = imp.find_module(link_type, sys.path)
        link_type_module = imp.load_module(link_type, filep, pathname,
                                           description)
    except ImportError:
        return None
    finally:
        if filep:
            filep.close()

    return link_type_module
