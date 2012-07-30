#!/usr/bin/env python

import sys
from pcapfile import savefile
from pcapfile import linklayer

def pcap_info(pcap_file):
    sf = savefile.load_savefile(pcap_file)

    if sf.valid:
        print 'Packet capture file with format %u.%u:' % (sf.header.major,
                                                          sf.header.minor)
        print '\tbyte order: %s endian' % (sf.header.byteorder,)
        print '\tsnapshot length: %u' % (sf.header.snaplen,)
        print '\tlink layer type: %s' % (linklayer.lookup(sf.header.ll_type), )
    else:
        print 'Invalid packet capture!'

if __name__ == '__main__':
    pcap_info(sys.argv[1])
