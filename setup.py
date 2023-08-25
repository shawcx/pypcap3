#!/usr/bin/env python3

import sys
import os
import platform
import glob

import setuptools

if 'Windows' == platform.system():
    defines = [('WIN32',None), ('WPCAP',None)]
    include = []
    libs    = ['wpcap', 'ws2_32', 'advapi32']
elif 'Darwin' == platform.system():
    defines = [('MACOS',None)]
    include = []
    libs    = ['pcap']
else:
    defines = []
    include = []
    libs    = ['pcap']

source_files = glob.glob('./src/pypcap.c')

setuptools.setup(
    name             = 'pypcap3',
    author           = 'Matthew Shaw',
    author_email     = 'mshaw.cx@gmail.com',
    version          = '0.2',
    license          = 'MIT',
    url              = 'https://github.com/shawcx/pypcap3',
    description      = 'Python 3 bindings for libpcap',
    long_description = open('README.rst').read(),
    ext_modules = [
        setuptools.Extension(
            'pypcap3',
            source_files,
            define_macros = defines,
            include_dirs  = include,
            libraries     = libs,
            )
        ],
    classifiers = [
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        ],
    )
