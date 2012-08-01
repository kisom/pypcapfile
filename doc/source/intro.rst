============
Introduction
============

`pypcapfile <http://kisom.github.com/pypcapfile>`_ is a pure-Python library
for reading and parsing packets from a 
`libpcap <http://www.tcpdump.org/>`_
savefile.

The core functionality is implemented in pcapfile.savefile: ::

    >>> from pcapfile import savefile
    >>> sf = savefile.load_savefile('test.pcap')
    [+] attempting to load test.pcap
    [+] found valid header
    [+] loaded 11 packets
    [+] finished loading savefile.
    >>> print sf
    big-endian capture file version 2.4
    snapshot length: 65535
    linklayer type: LINKTYPE_ETHERNET
    number of packets: 11

You can a look at the packets in sf.packets: ::

    >>> pkt = sf.packets[0]
    >>> p.raw()
    <binary data snipped>
    >>> p.timestamp
    1343676707L

In the future, pypcapfile will support more enhancements, such as protocol
parsing.
