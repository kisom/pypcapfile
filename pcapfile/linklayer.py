__LL_TYPES__ = [('LINKTYPE_NULL', 0),
                ('LINKTYPE_ETHERNET', 1),
                ('LINKTYPE_TOKEN_RING', 6),
                ('LINKTYPE_ARCNET', 7),
                ('LINKTYPE_SLIP', 8)]

def lookup(ll_type):

    res = [llt for llt in __LL_TYPES__
           if llt[1] == ll_type]
    assert len(res) < 2, 'Duplicate linklayer types.'

    if res:
        return res[0][0]
    else:
        return None
