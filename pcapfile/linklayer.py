# contains definitions of link layer types from libpcap
"""
Link layer definitions and lookup functions based on libpcap's LLTYPE_*
values.
"""


__LL_TYPES__ = [('LINKTYPE_NULL', 0, 'null'),
                ('LINKTYPE_ETHERNET', 1, 'ethernet'),
                ('LINKTYPE_TOKEN_RING', 6, 'token ring'),
                ('LINKTYPE_ARCNET', 7, 'ARCnet'),
                ('LINKTYPE_SLIP', 8, 'SLIP')]


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
