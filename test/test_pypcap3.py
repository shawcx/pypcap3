import os
import pathlib
import signal
import socket
import struct
import sys
import threading
import time

import pytest

import pypcap3

LINKTYPE_ETHERNET = 1
DLT_RAW = 12


def pcap_bytes(packets, linktype=LINKTYPE_ETHERNET, snaplen=65535):
    """A classic little-endian pcap file holding the given frames."""
    out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, linktype)]
    for idx, pkt in enumerate(packets):
        out.append(struct.pack('<IIII', 1700000000 + idx, idx * 1000 + 7, len(pkt), len(pkt)))
        out.append(pkt)
    return b''.join(out)


def read_pcap(path):
    """(snaplen, linktype, [(ts_sec, ts_usec, orig_len, data), ...]) from a classic pcap file."""
    raw = pathlib.Path(path).read_bytes()
    endian = '<' if raw[:4] == b'\xd4\xc3\xb2\xa1' else '>'
    snaplen, linktype = struct.unpack(endian + 'II', raw[16:24])
    records, offset = [], 24
    while offset < len(raw):
        sec, usec, caplen, length = struct.unpack(endian + 'IIII', raw[offset:offset + 16])
        offset += 16
        records.append((sec, usec, length, raw[offset:offset + caplen]))
        offset += caplen
    return snaplen, linktype, records


def ipv4_udp(dport, dst='10.0.0.2', src='10.0.0.1', sport=40000, payload=b'data'):
    """An IPv4/UDP packet with no link-layer header; checksums are left zero."""
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + udp


def ether(payload, ethertype=0x0800):
    return b'\xff' * 6 + b'\x02\x00\x00\x00\x00\x01' + struct.pack('!H', ethertype) + payload


@pytest.fixture
def packets():
    # Broadcast IPv4 Ethernet frames, each padded with its own index so they are distinct
    return [b'\xff' * 6 + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00' + bytes([idx]) * 46 for idx in range(5)]


@pytest.fixture
def make_pcap(tmp_path):
    def make(packets, **kwargs):
        path = tmp_path / f'capture{len(list(tmp_path.iterdir()))}.pcap'
        path.write_bytes(pcap_bytes(packets, **kwargs))
        return str(path)
    return make


@pytest.fixture
def handle(make_pcap, packets):
    h = pypcap3.open_file(make_pcap(packets))
    yield h
    h.close()


# module


def test_module_names():
    assert pypcap3.__name__ == 'pypcap3'
    assert pypcap3.error.__module__ == 'pypcap3'
    assert issubclass(pypcap3.error, Exception)


def test_version():
    assert 'libpcap' in pypcap3.version()


def test_find():
    devices = pypcap3.find()
    assert isinstance(devices, dict)
    for name, settings in devices.items():
        assert isinstance(name, str)
        assert set(settings) <= {'ip', 'netmask', 'broadcast'}
        assert all(isinstance(value, str) for value in settings.values())


def test_mac_requires_str():
    with pytest.raises(pypcap3.error):
        pypcap3.mac(b'lo')


def test_mac_unknown_interface():
    if sys.platform.startswith('linux'):
        with pytest.raises(pypcap3.error):
            pypcap3.mac('nosuch0')
    else:
        assert pypcap3.mac('nosuch0') is None


# opening


def test_open_file_missing(tmp_path):
    with pytest.raises(pypcap3.error):
        pypcap3.open_file(str(tmp_path / 'missing.pcap'))


def test_open_file_requires_str(make_pcap, packets):
    with pytest.raises(pypcap3.error):
        pypcap3.open_file(make_pcap(packets).encode())


def test_open_offline_alias(make_pcap, packets):
    h = pypcap3.open_offline(make_pcap(packets))
    assert h.next() == packets[0]
    h.close()


def test_open_live_unknown_interface():
    with pytest.raises(pypcap3.error):
        pypcap3.open_live('nosuch0')


def test_activate_unknown_interface():
    with pytest.raises(pypcap3.error):
        pypcap3.create('nosuch0').activate()


# reading


def test_next_reads_in_order_then_none(handle, packets):
    assert [handle.next() for _ in packets] == packets
    assert handle.next() is None
    assert handle.next() is None


def test_loop_reads_everything(handle, packets):
    seen = []
    assert handle.loop(seen.append) is None
    assert seen == packets


def test_loop_count_leaves_the_rest(handle, packets):
    seen = []
    handle.loop(seen.append, 2)
    assert seen == packets[:2]
    assert handle.next() == packets[2]


def test_loop_requires_callable(handle):
    with pytest.raises(pypcap3.error):
        handle.loop(None)


def test_loop_callback_exception_stops_loop(handle, packets):
    seen = []

    def callback(data):
        seen.append(data)
        if len(seen) == 2:
            raise ValueError('stop')

    with pytest.raises(ValueError, match='stop'):
        handle.loop(callback)
    assert seen == packets[:2]


def test_breakloop_from_callback(handle, packets):
    seen = []

    def callback(data):
        seen.append(data)
        if len(seen) == 2:
            handle.breakloop()

    assert handle.loop(callback) is None
    assert seen == packets[:2]


@pytest.mark.skipif(sys.platform == 'win32', reason='POSIX signal semantics')
def test_sigint_in_callback_raises_keyboardinterrupt(handle, packets):
    seen = []

    def callback(data):
        seen.append(data)
        signal.raise_signal(signal.SIGINT)

    with pytest.raises(KeyboardInterrupt):
        handle.loop(callback)
    assert seen == packets[:1]

    # Python's own SIGINT handling is back once the loop has returned
    with pytest.raises(KeyboardInterrupt):
        signal.raise_signal(signal.SIGINT)


@pytest.mark.skipif(sys.platform == 'win32', reason='needs /dev/fd and pthread_kill')
def test_sigint_interrupts_blocked_loop(packets):
    # The capture is a pipe that stalls after the first packet, so loop() blocks
    # in a read until SIGINT arrives. The interrupting thread can only run while
    # loop() is blocked if loop() released the GIL.
    rfd, wfd = os.pipe()
    os.write(wfd, pcap_bytes(packets[:1]))
    main = threading.get_ident()
    got_first = threading.Event()
    done = threading.Event()

    def interrupt():
        if got_first.wait(5):
            time.sleep(0.2)
            signal.pthread_kill(main, signal.SIGINT)
        # if the loop is still blocked, end the capture so the test fails instead of hanging
        if not done.wait(5):
            os.close(wfd)

    thread = threading.Thread(target=interrupt)
    thread.start()
    seen = []

    def callback(data):
        seen.append(data)
        got_first.set()

    try:
        h = pypcap3.open_file(f'/dev/fd/{rfd}')
        with pytest.raises(KeyboardInterrupt):
            h.loop(callback)
        h.close()
    finally:
        done.set()
        thread.join()
        os.close(rfd)
        try:
            os.close(wfd)
        except OSError:
            pass
    assert seen == packets[:1]


def test_loops_run_concurrently_in_threads(make_pcap, packets):
    # Each callback waits until the other loop is running too
    barrier = threading.Barrier(2, timeout=5)
    paths = {name: make_pcap(packets) for name in ('a', 'b')}
    results = {}

    def run(name):
        h = pypcap3.open_file(paths[name])
        seen = []

        def callback(data):
            if not seen:
                barrier.wait()
            seen.append(data)

        try:
            h.loop(callback)
            results[name] = seen
        except Exception as e:
            results[name] = e
        finally:
            h.close()

    threads = [threading.Thread(target=run, args=(name,)) for name in ('a', 'b')]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results == {'a': packets, 'b': packets}


@pytest.mark.parametrize('call', [
    lambda h: h.close(),
    lambda h: h.next(),
    lambda h: h.loop(print),
    lambda h: h.setfilter('udp'),
], ids=['close', 'next', 'loop', 'setfilter'])
def test_handle_busy_inside_loop(handle, call):
    with pytest.raises(pypcap3.error, match='busy'):
        handle.loop(lambda data: call(handle))
    # once the loop has ended the handle can be used again
    handle.close()


# handle state


@pytest.mark.parametrize('method, args', [
    ('next', ()),
    ('loop', (print,)),
    ('breakloop', ()),
    ('geterr', ()),
    ('inject', (b'\x00' * 60,)),
    ('stats', ()),
    ('datalink', ()),
    ('list_datalinks', ()),
    ('snapshot', ()),
    ('fileno', ()),
    ('getnonblock', ()),
    ('setnonblock', (0,)),
    ('setfilter', ('udp',)),
    ('compile', ('udp',)),
    ('dump_open', ('unused.pcap',)),
])
def test_closed_handle_raises(handle, method, args):
    handle.close()
    with pytest.raises(pypcap3.error, match='no device opened'):
        getattr(handle, method)(*args)


def test_close_twice(handle):
    handle.close()
    handle.close()


@pytest.mark.parametrize('method, args', [
    ('next', ()),
    ('loop', (print,)),
    ('datalink', ()),
    ('snapshot', ()),
] + ([] if sys.platform == 'win32' else [('setdirection', (pypcap3.D_IN,))]))
def test_unactivated_handle_raises(method, args):
    h = pypcap3.create('nosuch0')
    with pytest.raises(pypcap3.error):
        getattr(h, method)(*args)
    h.close()


def test_unactivated_handle_settings():
    h = pypcap3.create('nosuch0')
    assert h.set_snaplen(1500) is None
    assert h.set_promisc(0) is None
    h.close()


# file metadata


def test_datalink(handle):
    assert handle.datalink() == (1, 'EN10MB', 'Ethernet')
    assert handle.list_datalinks() == [(1, 'EN10MB', 'Ethernet')]


def test_unknown_datalink_has_no_name(make_pcap, packets):
    h = pypcap3.open_file(make_pcap(packets, linktype=999))
    assert h.datalink() == (999, None, None)
    assert h.list_datalinks() == [(999, None, None)]
    h.close()


def test_snapshot(make_pcap, packets):
    h = pypcap3.open_file(make_pcap(packets, snaplen=1500))
    assert h.snapshot() == 1500
    h.close()


def test_file_handle_rejects_live_only_calls(handle):
    with pytest.raises(pypcap3.error):
        handle.inject(b'\x00' * 60)
    with pytest.raises(pypcap3.error):
        handle.stats()


# filters


@pytest.fixture
def mixed():
    return [
        ether(ipv4_udp(53)),
        ether(ipv4_udp(80)),
        ether(b'\x00' * 28, ethertype=0x0806),  # ARP
        ether(ipv4_udp(53, dst='10.0.0.3')),
        ether(ipv4_udp(123)),
    ]


def test_setfilter_expression(make_pcap, mixed):
    h = pypcap3.open_file(make_pcap(mixed))
    assert h.setfilter('udp dst port 53') is None
    assert [h.next(), h.next(), h.next()] == [mixed[0], mixed[3], None]
    h.close()


def test_setfilter_compiled_program_on_two_handles(make_pcap, mixed):
    path = make_pcap(mixed)
    first, second = pypcap3.open_file(path), pypcap3.open_file(path)
    program = first.compile('arp or udp port 123')
    for h in (first, second):
        h.setfilter(program)
        seen = []
        h.loop(seen.append)
        assert seen == [mixed[2], mixed[4]]
        h.close()


def test_setfilter_syntax_error(handle):
    with pytest.raises(pypcap3.error, match='syntax error'):
        handle.setfilter('udp port')


def test_setfilter_requires_str_or_program(handle):
    with pytest.raises(pypcap3.error, match='string or a compiled program'):
        handle.setfilter(53)


def test_compile_and_match(handle, mixed):
    program = handle.compile('udp port 53', optimize=False)
    assert [program.match(frame) for frame in mixed] == [True, False, False, True, False]
    assert program.match(bytearray(mixed[0])) is True
    assert program.match(memoryview(mixed[0])) is True
    assert program.match(b'') is False


def test_netmask(handle):
    with pytest.raises(pypcap3.error, match='netmask'):
        handle.compile('ip broadcast')
    program = handle.compile('ip broadcast', netmask='255.255.255.0')
    assert program.match(ether(ipv4_udp(53, dst='10.0.0.255'))) is True
    assert program.match(ether(ipv4_udp(53, dst='10.0.0.2'))) is False


@pytest.mark.parametrize('netmask', ['255.255.255', 'nope', 0xffffff00])
def test_invalid_netmask(handle, netmask):
    with pytest.raises(pypcap3.error, match='dotted IPv4 string'):
        handle.compile('udp', netmask=netmask)


def test_compile_unactivated_handle():
    with pytest.raises(pypcap3.error):
        pypcap3.create('nosuch0').compile('udp')


def test_open_dead_compiles_for_its_linktype():
    ethernet = pypcap3.open_dead()
    raw = pypcap3.open_dead(linktype=DLT_RAW, snaplen=1500)
    assert ethernet.datalink() == (1, 'EN10MB', 'Ethernet')
    assert raw.datalink()[:2] == (DLT_RAW, 'RAW')
    assert raw.snapshot() == 1500
    packet = ipv4_udp(53)
    assert ethernet.compile('udp port 53').match(ether(packet)) is True
    assert raw.compile('udp port 53').match(packet) is True
    assert ethernet.compile('udp port 53').match(packet) is False


def test_open_dead_has_no_packets():
    with pytest.raises(pypcap3.error):
        pypcap3.open_dead().next()


@pytest.mark.skipif(sys.platform == 'win32', reason='loopback interface name')
def test_lookupnet_loopback():
    loopback = 'lo0' if sys.platform == 'darwin' else 'lo'
    assert pypcap3.lookupnet(loopback) == ('127.0.0.0', '255.0.0.0')


def test_lookupnet_errors():
    with pytest.raises(pypcap3.error):
        pypcap3.lookupnet('nosuch0')
    with pytest.raises(pypcap3.error, match='must be a string'):
        pypcap3.lookupnet(b'lo')


# capture files


def test_dump_roundtrip(handle, packets, tmp_path):
    path = tmp_path / 'out.pcap'
    dumper = handle.dump_open(path)
    for idx, pkt in enumerate(packets):
        dumper.write(pkt, ts=1700000000 + idx + 0.25)
    dumper.close()

    copy = pypcap3.open_file(str(path))
    assert [copy.next() for _ in packets] + [copy.next()] == packets + [None]
    copy.close()
    snaplen, linktype, records = read_pcap(path)
    assert (snaplen, linktype) == (65535, LINKTYPE_ETHERNET)
    assert [record[:2] for record in records] == [(1700000000 + idx, 250000) for idx in range(len(packets))]


def test_loop_into_dumper_keeps_timestamps(make_pcap, packets, tmp_path):
    source = make_pcap(packets)
    out = tmp_path / 'copy.pcap'
    h = pypcap3.open_file(source)
    with h.dump_open(out) as dumper:
        h.loop(dumper)
    h.close()
    assert read_pcap(out) == read_pcap(source)


def test_loop_into_dumper_with_filter_and_count(make_pcap, mixed, tmp_path):
    out = tmp_path / 'dns.pcap'
    h = pypcap3.open_file(make_pcap(mixed))
    h.setfilter('udp port 53')
    with h.dump_open(out) as dumper:
        h.loop(dumper, 1)
    h.close()
    assert [record[3] for record in read_pcap(out)[2]] == [mixed[0]]


@pytest.mark.parametrize('ts, expected', [
    (1700000000.25, (1700000000, 250000)),
    (1700000000, (1700000000, 0)),
    (2.9999999, (3, 0)),
])
def test_dumper_timestamps(tmp_path, ts, expected):
    path = tmp_path / 'ts.pcap'
    with pypcap3.open_dead().dump_open(path) as dumper:
        dumper.write(b'\x00' * 60, ts=ts)
    assert read_pcap(path)[2][0][:2] == expected


def test_dumper_default_timestamp_is_now(tmp_path):
    path = tmp_path / 'now.pcap'
    before = time.time()
    with pypcap3.open_dead().dump_open(path) as dumper:
        dumper.write(b'\x00' * 60)
    sec, usec = read_pcap(path)[2][0][:2]
    assert before - 1 <= sec + usec / 1e6 <= time.time() + 1


def test_dumper_lengths(tmp_path):
    path = tmp_path / 'lengths.pcap'
    with pypcap3.open_dead(snaplen=64).dump_open(path) as dumper:
        dumper.write(b'\x01' * 100)
        dumper.write(b'\x02' * 40, orig_len=1500)
        dumper.write(bytearray(b'\x03' * 10))
        dumper.write(memoryview(b'\x04' * 10))
        with pytest.raises(pypcap3.error, match='orig_len'):
            dumper.write(b'\x05' * 40, orig_len=39)
    assert [(length, data) for _, _, length, data in read_pcap(path)[2]] == [
        (100, b'\x01' * 64),
        (1500, b'\x02' * 40),
        (10, b'\x03' * 10),
        (10, b'\x04' * 10),
    ]


def test_dumper_rejects_str(tmp_path):
    with pypcap3.open_dead().dump_open(tmp_path / 'str.pcap') as dumper:
        with pytest.raises(TypeError):
            dumper.write('text')


def test_dumper_append(tmp_path):
    path = tmp_path / 'append.pcap'
    dead = pypcap3.open_dead()
    with dead.dump_open(path) as dumper:
        dumper.write(b'\x01' * 60, ts=1)
    with dead.dump_open(path, append=True) as dumper:
        dumper.write(b'\x02' * 60, ts=2)
    assert [record[0] for record in read_pcap(path)[2]] == [1, 2]

    with pytest.raises(pypcap3.error):
        pypcap3.open_dead(linktype=DLT_RAW).dump_open(path, append=True)


def test_dumper_closed(tmp_path):
    with pypcap3.open_dead().dump_open(tmp_path / 'closed.pcap') as dumper:
        dumper.flush()
    dumper.close()
    for call in (lambda: dumper.write(b'\x00'), dumper.flush, lambda: dumper.__enter__()):
        with pytest.raises(pypcap3.error, match='dumper is closed'):
            call()


def test_loop_into_closed_dumper(handle, tmp_path):
    dumper = handle.dump_open(tmp_path / 'closed.pcap')
    dumper.close()
    with pytest.raises(pypcap3.error, match='dumper is closed'):
        handle.loop(dumper)


def test_dump_open_errors(handle, tmp_path):
    with pytest.raises(pypcap3.error):
        handle.dump_open(tmp_path / 'missing' / 'out.pcap')
    with pytest.raises(pypcap3.error):
        pypcap3.create('nosuch0').dump_open(tmp_path / 'unactivated.pcap')


@pytest.mark.skipif(sys.platform == 'win32', reason='needs /dev/fd')
def test_dumper_busy_while_loop_writes_to_it(packets, tmp_path):
    # loop(dumper) blocks on a pipe after the first packet; meanwhile another
    # thread (which only runs if loop() released the GIL) can't touch the dumper
    rfd, wfd = os.pipe()
    os.write(wfd, pcap_bytes(packets[:1]))
    out = tmp_path / 'busy.pcap'
    h = pypcap3.open_file(f'/dev/fd/{rfd}')
    dumper = h.dump_open(out)
    errors = []

    def poke():
        time.sleep(0.2)
        for call in (lambda: dumper.write(b'\x00' * 60), dumper.close):
            try:
                call()
            except pypcap3.error as e:
                errors.append(str(e))
        h.breakloop()
        os.close(wfd)  # if breakloop didn't land, EOF ends the loop instead of hanging

    thread = threading.Thread(target=poke)
    thread.start()
    try:
        h.loop(dumper)
    finally:
        thread.join()
        os.close(rfd)
    assert errors == ['dumper is busy in loop()'] * 2
    dumper.close()
    h.close()
    assert [record[3] for record in read_pcap(out)[2]] == packets[:1]
