#!/usr/bin/env python3

# Project metadata lives in pyproject.toml; this file only describes the
# C extension, whose macros and libraries depend on the build platform.

import sys

import setuptools

if sys.platform == 'win32':
    defines = [('WIN32',None), ('WPCAP',None)]
    libs    = ['wpcap', 'ws2_32', 'advapi32']
elif sys.platform == 'darwin':
    defines = [('MACOS',None)]
    libs    = ['pcap']
else:
    defines = []
    libs    = ['pcap']

setuptools.setup(
    ext_modules = [
        setuptools.Extension(
            'pypcap3',
            sources       = ['src/pypcap.c'],
            depends       = ['src/pypcap.h'],
            define_macros = defines,
            libraries     = libs,
            )
        ],
    )
