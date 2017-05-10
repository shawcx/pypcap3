#!/usr/bin/env python3

import sys
import binascii

import pypcap

if len(sys.argv) == 1:
    interfaces = pypcap.find()
    for interface,settings in interfaces.items():
        if 'ip' not in settings:
            continue
        print(interface, settings)
    sys.exit(0)


class Listener:
    def __init__(self, interface):
        self.count = 0
        pd = pypcap.open_live(interface)
        pd.loop(self.onPacket)
        pd.close()
        print()
        print('Captured', self.count, 'packet%s' % ('s' if self.count != 1 else ''))

    def onPacket(self, data):
        self.count += 1
        print('%5d' % len(data), binascii.hexlify(data[:37]).decode('ascii'))


Listener(sys.argv[1])
