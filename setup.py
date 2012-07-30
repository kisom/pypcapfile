#!/usr/bin/env python

from distutils.core import setup

setup(name='pypcapfile',
      version='0.2',
      description='libpcap savefile utilities',
      long_description='Pure Python package for reading and parsing libpcap ' +
                       'savefiles.',
      author='Kyle Isom',
      author_email='coder@kyleisom.net',
      url='http://kisom.github.com/pypcapfile',
      scripts=['pcapfile_info',],
      packages=['pcapfile'])

