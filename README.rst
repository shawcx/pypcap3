
pypcap3
=======

Python 3 bindings for libpcap

Capture DNS traffic to a file until Ctrl-C (live capture needs root)::

    import pypcap3

    handle = pypcap3.open_live('eth0')
    handle.setfilter('udp port 53')
    with handle.dump_open('dns.pcap') as dumper:
        try:
            handle.loop(dumper)
        except KeyboardInterrupt:
            pass

Read it back with timestamps, or test a filter without a device::

    with pypcap3.open_file('dns.pcap') as handle:
        for packet, ts, orig_len in handle.packets(header=True):
            print(ts, orig_len)

    program = pypcap3.open_dead().compile('udp port 53')
    program.match(packet)  # True

Read from a pipe, file object or descriptor, such as tcpdump's output::

    import subprocess

    tcpdump = subprocess.Popen(['tcpdump', '-w', '-', 'icmp'], stdout=subprocess.PIPE)
    handle = pypcap3.open_file(tcpdump.stdout)
    handle.loop(print, 10)
