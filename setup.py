#!/usr/bin/env python

import os
from distutils.core import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(name='pypcapfile',
      version='0.8.1',
      description=('Pure Python package for reading and parsing libpcap '
                       'savefiles.'),
      long_description=read('README'),
      author='Kyle Isom',
      author_email='coder@kyleisom.net',
      license='ISC',
      url='http://kisom.github.com/pypcapfile',
      scripts=['pcapfile_info',],
      packages=['pcapfile', 
                'pcapfile.test',
                'pcapfile.protocols',
                'pcapfile.protocols.linklayer',
                'pcapfile.protocols.network',
                ],
      package_data={'pcapfile.test': ['test/test_data']},
      data_files=[('share/doc/pcapfile',
                   ['README', 'AUTHORS', 'CONTRIBUTING'])]
      )

