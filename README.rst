pypcapfile
==========

.. image:: https://travis-ci.org/kisom/pypcapfile.svg
    :target: https://travis-ci.org/kisom/pypcapfile

.. image:: https://img.shields.io/pypi/v/pypcapfile.svg
    :target: https://pypi.python.org/pypi/pypcapfile

.. image:: https://img.shields.io/pypi/pyversions/pypcapfile.svg
    :target: https://pypi.python.org/pypi/pypcapfile

pypcapfile is a pure Python library for handling libpcap savefiles.

Installing
----------

| The easiest way to install is from
| `pypi <http://pypi.python.org/pypi/pypcapfile/>`__:

.. code:: bash

    sudo pip install pypcapfile

| Note that for pip, the package name is ``pypcapfile``; in your code
  you will need to
| import ``pcapfile``.

| Alternatively, you can install from source. Clone the repository, and
  run setup.py with
| an install argument:

.. code:: bash

    git clone git://github.com/kisom/pypcapfile.git
    cd pypcapfile
    ./setup.py install

| This does require the Python
  `distutils <http://docs.python.org/install/>`__ to be
| installed.

Introduction
------------

The core functionality is implemented in ``pcapfile.savefile``:

.. code:: python

    >>> from pcapfile import savefile
    >>> testcap = open('test.pcap', 'rb')
    >>> capfile = savefile.load_savefile(testcap, verbose=True)
    [+] attempting to load test.pcap
    [+] found valid header
    [+] loaded 11 packets
    [+] finished loading savefile.
    >>> print(capfile)
    little-endian capture file version 2.4
    microsecond time resolution
    snapshot length: 65535
    linklayer type: LINKTYPE_ETHERNET
    number of packets: 11

You can take a look at the packets in ``capfile.packets``:

.. code:: python

    >>> pkt = capfile.packets[0]
    >>> pkt.raw()
    <binary data snipped>
    >>> pkt.timestamp
    1343676707L

| Right now there is very basic support for Ethernet and Wi-Fi frames and IPv4
  packet
| parsing.

Automatically decoding layers
-----------------------------

| The ``layers`` argument to ``load_savefile`` determines how many
  layers to
| decode; the default value of 0 does no decoding, 1 will load only the
  link
| layer, etc... For example, with no decoding:

.. code:: python

    >>> from pcapfile import savefile
    >>> from pcapfile.protocols.linklayer import ethernet
    >>> from pcapfile.protocols.linklayer import wifi
    >>> from pcapfile.protocols.network import ip
    >>> testcap = open('samples/test.pcap', 'rb')
    >>> capfile = savefile.load_savefile(testcap, verbose=True)
    [+] attempting to load samples/test.pcap
    [+] found valid header
    [+] loaded 3 packets
    [+] finished loading savefile.
    >>> eth_frame = ethernet.Ethernet(capfile.packets[0].raw())
    >>> wifi_frame = wifi.WIFI(capfile.packets[1].raw())
    >>> print(eth_frame)
    ethernet from 00:11:22:33:44:55 to ff:ee:dd:cc:bb:aa type IPv4
    >>> print(wifi_frame)
    QoS data (sa: None, ta: 00:11:22:33:44:55, ra: ff:ee:dd:cc:bb:aa, da: None)
    >>> ip_packet = ip.IP(eth_frame.payload)
    >>> print(ip_packet)
    ipv4 packet from 192.168.2.47 to 173.194.37.82 carrying 44 bytes
    >>> ip_packet = ip.IP(wifi_frame.payload[0]['payload']) #if wifi_frame.category == 2 and wifi_frame.subtype == 8
    >>> print(ip_packet)
    ipv4 packet from 192.168.2.175 to 239.255.255.250 carrying 336 bytes

and this example:

.. code:: python

    >>> from pcapfile import savefile
    >>> testcap = open('samples/test.pcap', 'rb')
    >>> capfile = savefile.load_savefile(testcap, layers=1, verbose=True)
    [+] attempting to load samples/test.pcap
    [+] found valid header
    [+] loaded 3 packets
    [+] finished loading savefile.
    >>> print(capfile.packets[0].packet.src)
    00:11:22:33:44:55
    >>> print(capfile.packets[0].packet.payload)
    <hex string snipped>

and this example to pull the raw payload from every packet in a pcap file:

.. code:: python

    >>> from pcapfile import savefile
    >>> import binascii

    >>> capfile = savefile.load_savefile(testcap)
    >>> file_length = capfile.__length__()
    >>> for packet in range(0, file_length):
    >>>     pkt = capfile.packets[packet]
    >>>     data = binascii.b2a_qp(pkt.raw())  # Do something here

and lastly:

.. code:: python

    >>> from pcapfile import savefile
    >>> testcap = open('samples/test.pcap', 'rb')
    >>> capfile = savefile.load_savefile(testcap, layers=2, verbose=True)
    >>> print(capfile.packets[0].packet.payload)
    ipv4 packet from 192.168.2.47 to 173.194.37.82 carrying 44 bytes

| The IPv4 module (``ip``) currently only supports basic IP headers,
  i.e. it
| doesn't yet parse options or add in padding.

The interface is still a bit messy.

Run Unit Tests
--------------
* ``cd /path/pypcapfile``
* ``cp pcapfile/test/__main__.py .``
* ``python __main__.py``

Future planned improvements
---------------------------

-  IP options parsing (END and NOP is supported)
-  IPv6 support
-  TCP options parsing
-  ARP support

TODO
----

#. write unit tests
#. add ``__repr__`` method that shows all of the values of the fields in
   IP packets
   and Ethernet frames.

See also
--------

-  The project's `PyPi page <http://pypi.python.org/pypi/pypcapfile>`__.
-  The project's `Sphinx <http://sphinx.pocoo.org/>`__
   `documentation on PyPI <http://packages.python.org/pypcapfile/>`__
-  The `libpcap homepage <http://www.tcpdump.org>`__

Contributors
------------

A list of the project's contributors may be found in the AUTHORS file.
