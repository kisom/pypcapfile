#!/usr/bin/env python

import sys
from pcapfile import savefile
from pcapfile import linklayer

def pcap_info(pcap_file):
    sf = savefile.load_savefile(pcap_file, verbose=False)

    if sf.valid:
        print sf
    else:
        print 'Invalid packet capture!'

if __name__ == '__main__':
    pcap_info(sys.argv[1])
