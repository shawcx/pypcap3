#!/usr/bin/env python3

# Project metadata lives in pyproject.toml; this file only describes the
# C extension, whose macros and libraries depend on the build platform.

import os
import sys
import sysconfig

import setuptools

include = []
libdirs = []

if sys.platform == 'win32':
    defines = [('WIN32',None), ('WPCAP',None)]
    libs    = ['wpcap', 'ws2_32', 'advapi32']
    # NPCAP_SDK points at an unpacked Npcap SDK (https://npcap.com/#download)
    sdk = os.environ.get('NPCAP_SDK')
    if sdk:
        arch = {'win-amd64': 'x64', 'win-arm64': 'ARM64'}.get(sysconfig.get_platform(), '')
        include = [os.path.join(sdk, 'Include')]
        libdirs = [os.path.join(sdk, 'Lib', arch)]
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
            include_dirs  = include,
            library_dirs  = libdirs,
            libraries     = libs,
            )
        ],
    )
