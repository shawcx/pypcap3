import ast
import faulthandler
import ipaddress
import os
import pathlib
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

import pytest

import pypcap3

LINKTYPE_ETHERNET = 1
DLT_RAW = 12


def pcap_bytes(packets, linktype=LINKTYPE_ETHERNET, snaplen=65535, endian='<'):
    """A classic pcap file holding the given frames, little-endian unless endian='>'."""
    out = [struct.pack(endian + 'IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, linktype)]
    for idx, pkt in enumerate(packets):
        out.append(struct.pack(endian + 'IIII', 1700000000 + idx, idx * 1000 + 7, len(pkt), len(pkt)))
        out.append(pkt)
    return b''.join(out)


def read_pcap(path):
    """(snaplen, linktype, [(ts_sec, ts_fraction, orig_len, data), ...]) from a classic pcap file.

    ts_fraction is in microseconds, or nanoseconds in a nanosecond file."""
    raw = pathlib.Path(path).read_bytes()
    endian = '<' if raw[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
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
        assert {'description', 'flags', 'addresses'} <= set(settings)
        assert set(settings) <= {'description', 'flags', 'addresses', 'ip', 'netmask', 'broadcast'}
        for key in ('ip', 'netmask', 'broadcast'):
            assert isinstance(settings.get(key, ''), str)


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


@pytest.mark.parametrize('convert', [str, str.encode, pathlib.Path], ids=['str', 'bytes', 'Path'])
def test_open_file_path_types(make_pcap, packets, convert):
    h = pypcap3.open_file(convert(make_pcap(packets)))
    assert h.next() == packets[0]
    h.close()


@pytest.mark.parametrize('target', [None, 1.5, ['capture.pcap']])
def test_open_file_rejects_other_types(target):
    with pytest.raises(pypcap3.error, match='path, a file object or a file descriptor'):
        pypcap3.open_file(target)


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
    lambda h: h.dispatch(print),
], ids=['close', 'next', 'loop', 'setfilter', 'dispatch'])
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
    ('bufsize', ()),
    ('fileno', ()),
    ('getnonblock', ()),
    ('setnonblock', (0,)),
    ('setfilter', ('udp',)),
    ('compile', ('udp',)),
    ('dump_open', ('unused.pcap',)),
    ('dispatch', (print,)),
    ('set_timeout', (100,)),
    ('can_set_rfmon', ()),
    ('list_tstamp_types', ()),
    ('get_tstamp_precision', ()),
    ('set_datalink', (1,)),
    ('major_version', ()),
    ('minor_version', ()),
    ('is_swapped', ()),
] + ([('setuserbuffer', (65536,))] if sys.platform == 'win32' else [
    ('get_selectable_fd', ()),
    ('get_required_select_timeout', ()),
]))
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


def test_bufsize(handle):
    assert handle.bufsize() > 0
    with pytest.raises(pypcap3.error, match='not been activated'):
        pypcap3.create('nosuch0').bufsize()


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
    for call in (lambda: dumper.write(b'\x00'), dumper.flush, dumper.tell, lambda: dumper.__enter__()):
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


# packet headers


def test_next_with_header(handle, packets):
    for idx, pkt in enumerate(packets):
        data, ts, orig_len = handle.next(header=True)
        assert data == pkt
        assert ts == pytest.approx(1700000000 + idx + (idx * 1000 + 7) / 1e6, abs=1e-6)
        assert orig_len == len(pkt)
    assert handle.next(header=True) is None


def test_header_reports_original_length(tmp_path):
    path = tmp_path / 'truncated.pcap'
    with pypcap3.open_dead(snaplen=64).dump_open(path) as dumper:
        dumper.write(b'\x01' * 100, ts=5)
    assert pypcap3.open_file(str(path)).next(header=True) == (b'\x01' * 64, 5.0, 100)


def test_loop_with_header(handle, packets):
    seen = []
    handle.loop(lambda *args: seen.append(args), header=True)
    assert [(data, orig_len) for data, _, orig_len in seen] == [(pkt, len(pkt)) for pkt in packets]


def test_loop_into_dumper_write_with_header(make_pcap, packets, tmp_path):
    # dumper.write takes (packet, ts, orig_len), so it can be the callback directly
    source = make_pcap(packets)
    out = tmp_path / 'copy.pcap'
    h = pypcap3.open_file(source)
    with h.dump_open(out) as dumper:
        h.loop(dumper.write, header=True)
    assert read_pcap(out) == read_pcap(source)


def test_header_is_keyword_only(handle):
    with pytest.raises(TypeError):
        handle.next(True)
    with pytest.raises(TypeError):
        handle.loop(print, -1, True)


def test_nanosecond_files(tmp_path):
    path = tmp_path / 'nano.pcap'
    dead = pypcap3.open_dead(precision=pypcap3.TSTAMP_PRECISION_NANO)
    assert dead.get_tstamp_precision() == pypcap3.TSTAMP_PRECISION_NANO
    with dead.dump_open(path) as dumper:
        dumper.write(b'\x00' * 60, ts=1.000000123)
        dumper.write(b'\x00' * 60, ts=2.9999999999)
    assert [record[:2] for record in read_pcap(path)[2]] == [(1, 123), (3, 0)]

    nano = pypcap3.open_file(str(path), precision=pypcap3.TSTAMP_PRECISION_NANO)
    assert nano.get_tstamp_precision() == pypcap3.TSTAMP_PRECISION_NANO
    assert nano.next(header=True)[1] == pytest.approx(1.000000123, abs=1e-12)
    # read at microsecond precision, libpcap drops the nanoseconds
    micro = pypcap3.open_file(str(path))
    assert micro.get_tstamp_precision() == pypcap3.TSTAMP_PRECISION_MICRO
    assert micro.next(header=True)[1] == 1.0


def test_nanosecond_default_timestamp_is_now(tmp_path):
    path = tmp_path / 'now.pcap'
    before = time.time()
    with pypcap3.open_dead(precision=pypcap3.TSTAMP_PRECISION_NANO).dump_open(path) as dumper:
        dumper.write(b'\x00' * 60)
    sec, nsec = read_pcap(path)[2][0][:2]
    assert nsec < 1000000000
    assert before - 1 <= sec + nsec / 1e9 <= time.time() + 1


# dispatch and select


def test_dispatch_counts(handle, packets):
    seen = []
    assert handle.dispatch(seen.append, 2) == 2
    assert handle.dispatch(seen.append) == 3
    assert handle.dispatch(seen.append) == 0
    assert seen == packets


def test_dispatch_with_header(handle, packets):
    seen = []
    assert handle.dispatch(lambda *args: seen.append(args), header=True) == len(packets)
    assert [args[0] for args in seen] == packets


def test_dispatch_into_dumper(make_pcap, packets, tmp_path):
    source = make_pcap(packets)
    out = tmp_path / 'copy.pcap'
    h = pypcap3.open_file(source)
    with h.dump_open(out) as dumper:
        assert h.dispatch(dumper) == len(packets)
    assert read_pcap(out) == read_pcap(source)


def test_dispatch_callback_exception(handle):
    def callback(data):
        raise ValueError('stop')

    with pytest.raises(ValueError, match='stop'):
        handle.dispatch(callback)


def test_breakloop_in_dispatch(handle):
    seen = []

    def callback(data):
        seen.append(data)
        if len(seen) == 2:
            handle.breakloop()

    assert handle.dispatch(callback) == 2


@pytest.mark.skipif(sys.platform == 'win32', reason='no selectable descriptors on Windows')
def test_select_then_dispatch(packets):
    # a pipe-backed capture: select() reports it readable only once a packet is written
    rfd, wfd = os.pipe()
    os.write(wfd, pcap_bytes([]))
    try:
        h = pypcap3.open_file(f'/dev/fd/{rfd}')
        fd = h.get_selectable_fd()
        assert fd >= 0
        assert h.get_required_select_timeout() is None
        assert select.select([fd], [], [], 0)[0] == []
        os.write(wfd, pcap_bytes(packets[:1])[24:])
        assert select.select([fd], [], [], 5)[0] == [fd]
        seen = []
        assert h.dispatch(seen.append, 1) == 1
        assert seen == packets[:1]
        h.close()
    finally:
        os.close(rfd)
        os.close(wfd)


@pytest.mark.skipif(sys.platform == 'win32', reason='needs /dev/fd and pthread_kill')
@pytest.mark.parametrize('read', [lambda h: h.next(), lambda h: next(iter(h))], ids=['next', 'iteration'])
def test_sigint_interrupts_blocked_read(read):
    rfd, wfd = os.pipe()
    os.write(wfd, pcap_bytes([]))
    main = threading.get_ident()
    done = threading.Event()

    def interrupt():
        time.sleep(0.3)
        signal.pthread_kill(main, signal.SIGINT)
        # if next() is still blocked, end the capture so the test fails instead of hanging
        if not done.wait(5):
            os.close(wfd)

    thread = threading.Thread(target=interrupt)
    thread.start()
    try:
        h = pypcap3.open_file(f'/dev/fd/{rfd}')
        with pytest.raises(KeyboardInterrupt):
            read(h)
        h.close()
    finally:
        done.set()
        thread.join()
        os.close(rfd)
        try:
            os.close(wfd)
        except OSError:
            pass


# settings before activate()


def test_create_settings():
    h = pypcap3.create('nosuch0')
    assert h.set_timeout(250) is None
    assert h.set_immediate_mode(True) is None
    assert h.set_buffer_size(1 << 20) is None
    assert h.set_rfmon(False) is None
    assert h.set_tstamp_type(pypcap3.TSTAMP_HOST) is None
    assert h.set_tstamp_precision(pypcap3.TSTAMP_PRECISION_MICRO) is None
    try:
        h.set_tstamp_precision(pypcap3.TSTAMP_PRECISION_NANO)
    except pypcap3.error as e:
        # macOS BPF only has microsecond timestamps
        assert 'precision' in str(e)
        assert h.get_tstamp_precision() == pypcap3.TSTAMP_PRECISION_MICRO
    else:
        assert h.get_tstamp_precision() == pypcap3.TSTAMP_PRECISION_NANO
    for entry in h.list_tstamp_types():
        assert len(entry) == 3 and isinstance(entry[0], int)
    h.close()


def test_unsupported_tstamp_type_warns():
    h = pypcap3.create('nosuch0')
    assert isinstance(h.set_tstamp_type(pypcap3.TSTAMP_ADAPTER_UNSYNCED), str)
    h.close()


def test_setting_requires_int():
    with pytest.raises(pypcap3.error, match='timeout must be an integer'):
        pypcap3.create('nosuch0').set_timeout('100')


@pytest.mark.parametrize('setter', [
    'set_snaplen', 'set_promisc', 'set_timeout', 'set_immediate_mode', 'set_buffer_size',
    'set_rfmon', 'set_tstamp_type', 'set_tstamp_precision',
])
def test_settings_after_activation_raise(handle, setter):
    with pytest.raises(pypcap3.error, match='activated'):
        getattr(handle, setter)(0)


def test_only_devices_can_rfmon(handle):
    # libpcap itself crashes if asked on a file or open_dead() handle
    assert handle.can_set_rfmon() is False
    assert pypcap3.open_dead().can_set_rfmon() is False


# find() details


def test_find_details():
    for name, device in pypcap3.find().items():
        assert device['description'] is None or isinstance(device['description'], str)
        assert isinstance(device['flags'], int)
        for address in device['addresses']:
            assert address['family'] in (socket.AF_INET, socket.AF_INET6)
            for key in ('addr', 'netmask', 'broadcast', 'dstaddr'):
                if address[key] is not None:
                    ipaddress.ip_address(address[key])


@pytest.mark.skipif(sys.platform == 'win32', reason='loopback interface name')
def test_find_loopback():
    loopback = pypcap3.find()['lo0' if sys.platform == 'darwin' else 'lo']
    assert loopback['flags'] & pypcap3.IF_LOOPBACK
    assert loopback['flags'] & pypcap3.IF_UP
    ipv4 = [a for a in loopback['addresses'] if a['family'] == socket.AF_INET]
    assert {'family': socket.AF_INET, 'addr': '127.0.0.1', 'netmask': '255.0.0.0',
            'broadcast': None, 'dstaddr': None} in ipv4
    # the original flat keys are still there
    assert (loopback['ip'], loopback['netmask']) == ('127.0.0.1', '255.0.0.0')
    for address in loopback['addresses']:
        if address['addr'] == '::1':
            assert address['netmask'] == 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'


# file objects, descriptors and pipes


def test_dump_to_file_object(handle, packets, tmp_path):
    path = tmp_path / 'object.pcap'
    with open(path, 'wb') as f:
        with handle.dump_open(f) as dumper:
            handle.loop(dumper)
        # the dumper wrote through its own copy of the descriptor, so f is still open
        assert not f.closed
        f.write(b'')
    assert [record[3] for record in read_pcap(path)[2]] == packets


def test_dump_to_descriptor_and_read_back(packets, tmp_path):
    path = tmp_path / 'fd.pcap'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    with pypcap3.open_dead().dump_open(fd) as dumper:
        for pkt in packets:
            dumper.write(pkt, ts=1)
    os.fstat(fd)  # still open
    os.close(fd)

    fd = os.open(path, os.O_RDONLY)
    h = pypcap3.open_file(fd)
    assert [h.next() for _ in packets] == packets
    h.close()
    os.fstat(fd)
    os.close(fd)


def test_read_from_file_object(make_pcap, packets):
    with open(make_pcap(packets), 'rb') as f:
        h = pypcap3.open_file(f, precision=pypcap3.TSTAMP_PRECISION_NANO)
        assert h.get_tstamp_precision() == pypcap3.TSTAMP_PRECISION_NANO
        assert [h.next() for _ in packets] == packets
        h.close()
        assert not f.closed


def test_pipe_between_dumper_and_reader(packets):
    rfd, wfd = os.pipe()
    with pypcap3.open_dead().dump_open(wfd) as dumper:
        for pkt in packets:
            dumper.write(pkt)
    os.close(wfd)
    h = pypcap3.open_file(rfd)
    assert [h.next() for _ in packets] + [h.next()] == packets + [None]
    h.close()
    os.close(rfd)


def test_read_from_subprocess(make_pcap, packets):
    # the way you would read `tcpdump -w -`
    child = subprocess.Popen(
        [sys.executable, '-c', 'import sys; sys.stdout.buffer.write(open(sys.argv[1], "rb").read())',
         make_pcap(packets)],
        stdout=subprocess.PIPE)
    h = pypcap3.open_file(child.stdout)
    seen = []
    h.loop(seen.append)
    h.close()
    child.stdout.close()
    assert child.wait() == 0
    assert seen == packets


@pytest.mark.skipif(sys.platform == 'win32', reason='needs mkfifo')
def test_open_file_on_fifo_releases_gil(tmp_path, packets):
    # open_file blocks until the writer thread opens the FIFO and sends the
    # header; if it held the GIL the writer could never run. faulthandler's
    # watchdog runs without the GIL, so a regression fails instead of hanging.
    fifo = tmp_path / 'capture.fifo'
    os.mkfifo(fifo)

    def writer():
        time.sleep(0.2)
        with open(fifo, 'wb') as f:
            f.write(pcap_bytes(packets))

    thread = threading.Thread(target=writer)
    thread.start()
    faulthandler.dump_traceback_later(10, exit=True)
    try:
        h = pypcap3.open_file(str(fifo))
        seen = []
        h.loop(seen.append)
        h.close()
    finally:
        faulthandler.cancel_dump_traceback_later()
        thread.join()
    assert seen == packets


def test_append_needs_a_path(handle, tmp_path):
    with open(tmp_path / 'append.pcap', 'wb') as f:
        with pytest.raises(pypcap3.error, match='append needs a path'):
            handle.dump_open(f, append=True)


def test_bad_descriptor(handle):
    with pytest.raises(pypcap3.error):
        handle.dump_open(-1)
    with pytest.raises(pypcap3.error):
        pypcap3.open_file(-1)


# compiled program text


def test_instructions():
    program = pypcap3.open_dead().compile('udp port 53')
    lines = program.instructions()
    assert len(program) == len(lines) > 2
    assert lines[0] == '(000) ldh      [12]'
    assert lines[-1].startswith(f'({len(lines) - 1:03d}) ret ')
    assert pypcap3.open_dead().compile('').instructions() == ['(000) ret      #65535']


def test_compile_without_handle():
    packet = ipv4_udp(53)
    assert pypcap3.compile('udp port 53').match(ether(packet)) is True
    assert pypcap3.compile('udp port 53', DLT_RAW).match(packet) is True
    assert pypcap3.compile('udp port 53', linktype=DLT_RAW).match(ether(packet)) is False
    assert list(pypcap3.compile('udp port 53')) == list(pypcap3.open_dead().compile('udp port 53'))
    assert pypcap3.compile('', snaplen=1500).instructions() == ['(000) ret      #1500']
    assert pypcap3.compile('ip broadcast', netmask='255.255.255.0').match(ether(ipv4_udp(53, dst='10.0.0.255'))) is True
    # unlike pcap_compile_nopcap, libpcap's error text comes through
    with pytest.raises(pypcap3.error, match='syntax error'):
        pypcap3.compile('udp port')
    with pytest.raises(pypcap3.error, match='netmask'):
        pypcap3.compile('ip broadcast')


# instructions as `tcpdump -ddd -y EN10MB arp` prints them, with its default snaplen
TCPDUMP_ARP = '''4
40 0 0 12
21 0 1 2054
6 0 0 262144
6 0 0 0
'''


def test_bpf_program_from_instructions(make_pcap, mixed):
    program = pypcap3.bpf_program(tuple(map(int, line.split())) for line in TCPDUMP_ARP.splitlines()[1:])
    assert list(program) == list(pypcap3.compile('arp', snaplen=262144))
    assert len(program) == 4
    assert program[0] == (0x28, 0, 0, 12)  # ldh [12]
    assert program[-1] == (6, 0, 0, 0)     # ret #0
    with pytest.raises(IndexError):
        program[4]
    assert [program.match(frame) for frame in mixed] == [False, False, True, False, False]

    h = pypcap3.open_file(make_pcap(mixed))
    h.setfilter(program)
    assert list(h) == [mixed[2]]
    h.close()

    copy = pypcap3.bpf_program(program)
    assert list(copy) == list(program)
    assert copy.instructions() == program.instructions()
    assert pypcap3.bpf_program([[6, 0, 0, 65535]]).match(b'x') is True


@pytest.mark.parametrize('instructions, message', [
    ([(6, 0, 0)], 'instruction 0 must be'),
    ([(6, 0, 0, 0), (6, 0, 0, -1)], 'instruction 1 must be'),
    ([(6, 0, 0, 2**32)], 'instruction 0 must be'),
    ([(6, 256, 0, 0)], 'instruction 0 must be'),
    ([(0x10000, 0, 0, 0)], 'instruction 0 must be'),
    ([(6, 0, 0, '0')], 'instruction 0 must be'),
    (['6000'], 'instruction 0 must be'),
    ([], 'invalid BPF program'),
    ([(0x28, 0, 0, 12)], 'invalid BPF program'),                # no return at the end
    ([(0x15, 5, 0, 1), (6, 0, 0, 0)], 'invalid BPF program'),   # jumps past the end
])
def test_invalid_bpf_program(instructions, message):
    with pytest.raises(pypcap3.error, match=message):
        pypcap3.bpf_program(instructions)


def test_bpf_program_needs_instructions():
    with pytest.raises(TypeError):
        pypcap3.bpf_program()
    with pytest.raises(TypeError, match='iterable'):
        pypcap3.bpf_program(5)


# link types, timestamp names and file details


def test_datalink_lookups():
    assert pypcap3.datalink_name_to_val('EN10MB') == 1
    assert pypcap3.datalink_name_to_val('en10mb') == 1
    assert pypcap3.datalink_name_to_val('RAW') == DLT_RAW
    assert pypcap3.datalink_val_to_name(1) == 'EN10MB'
    assert pypcap3.datalink_val_to_description(1) == 'Ethernet'
    assert pypcap3.datalink_val_to_name(999) is None
    assert pypcap3.datalink_val_to_description(999) is None
    for dlt, name, description in pypcap3.open_dead().list_datalinks():
        assert pypcap3.datalink_name_to_val(name) == dlt
    with pytest.raises(pypcap3.error, match="unknown link type 'nonsense'"):
        pypcap3.datalink_name_to_val('nonsense')
    with pytest.raises(pypcap3.error, match='must be a string'):
        pypcap3.datalink_name_to_val(1)
    with pytest.raises(pypcap3.error, match='must be an integer'):
        pypcap3.datalink_val_to_name('EN10MB')


def test_tstamp_type_lookups():
    assert pypcap3.tstamp_type_name_to_val('host') == pypcap3.TSTAMP_HOST
    assert pypcap3.tstamp_type_name_to_val('adapter') == pypcap3.TSTAMP_ADAPTER
    assert pypcap3.tstamp_type_val_to_name(pypcap3.TSTAMP_ADAPTER_UNSYNCED) == 'adapter_unsynced'
    assert pypcap3.tstamp_type_val_to_name(99) is None
    with pytest.raises(pypcap3.error, match="unknown timestamp type"):
        pypcap3.tstamp_type_name_to_val('sundial')


def test_set_datalink():
    dead = pypcap3.open_dead()
    assert dead.set_datalink(1) is None
    with pytest.raises(pypcap3.error, match='not one of the DLTs'):
        dead.set_datalink(DLT_RAW)
    assert dead.datalink()[0] == 1


@pytest.mark.parametrize('endian', ['<', '>'], ids=['little', 'big'])
def test_file_details(tmp_path, packets, endian):
    path = tmp_path / 'endian.pcap'
    path.write_bytes(pcap_bytes(packets, endian=endian))
    h = pypcap3.open_file(str(path))
    assert (h.major_version(), h.minor_version()) == (2, 4)
    assert h.is_swapped() is (endian != ('<' if sys.byteorder == 'little' else '>'))
    assert [h.next() for _ in packets] == packets
    h.close()


def test_file_details_unactivated():
    h = pypcap3.create('nosuch0')
    for method in (h.major_version, h.minor_version, h.is_swapped):
        with pytest.raises(pypcap3.error, match='not been activated'):
            method()


def test_dumper_tell(tmp_path):
    with pypcap3.open_dead().dump_open(tmp_path / 'tell.pcap') as dumper:
        assert dumper.tell() == 24  # the file header
        dumper.write(b'\x00' * 60, ts=1)
        assert dumper.tell() == 24 + 16 + 60
        dumper.write(b'\x00' * 100, ts=2)
        assert dumper.tell() == 24 + 2 * 16 + 60 + 100
    assert (tmp_path / 'tell.pcap').stat().st_size == 24 + 2 * 16 + 60 + 100


@pytest.mark.skipif(sys.platform == 'win32', reason='ftell on a Windows pipe is undefined')
def test_dumper_tell_on_pipe():
    rfd, wfd = os.pipe()
    try:
        with pypcap3.open_dead().dump_open(wfd) as dumper:
            with pytest.raises(pypcap3.error):
                dumper.tell()
    finally:
        os.close(rfd)
        os.close(wfd)


# iteration, context managers and the module's types


def test_iterate_handle(handle, packets):
    assert list(handle) == packets
    assert list(handle) == []  # at the end of the file


def test_iterate_with_header(handle, packets):
    seen = list(handle.packets(header=True))
    assert [data for data, _, _ in seen] == packets
    assert seen[1][1] == pytest.approx(1700000001.001007, abs=1e-6)
    assert all(orig_len == len(data) for data, _, orig_len in seen)


def test_iteration_interleaves_with_next(handle, packets):
    packet_iter = iter(handle)
    assert next(packet_iter) == packets[0]
    assert handle.next() == packets[1]
    assert next(packet_iter) == packets[2]


def test_iteration_respects_filter_and_close(make_pcap, mixed):
    h = pypcap3.open_file(make_pcap(mixed))
    h.setfilter('udp port 53')
    packet_iter = iter(h)
    assert next(packet_iter) == mixed[0]
    h.close()
    with pytest.raises(pypcap3.error, match='no device opened'):
        next(packet_iter)


def test_iterate_closed_handle(handle):
    handle.close()
    with pytest.raises(pypcap3.error, match='no device opened'):
        iter(handle)


def test_handle_context_manager(make_pcap, packets):
    with pypcap3.open_file(make_pcap(packets)) as h:
        assert h.next() == packets[0]
    with pytest.raises(pypcap3.error, match='no device opened'):
        h.next()

    with pytest.raises(ValueError):
        with pypcap3.open_file(make_pcap(packets)) as h:
            raise ValueError
    with pytest.raises(pypcap3.error, match='no device opened'):
        h.next()


def test_module_types(handle, tmp_path):
    assert isinstance(handle, pypcap3.handle)
    assert isinstance(handle.compile('udp'), pypcap3.bpf_program)
    assert isinstance(iter(handle), pypcap3.packet_iterator)
    with handle.dump_open(tmp_path / 'types.pcap') as dumper:
        assert isinstance(dumper, pypcap3.dumper)
    assert repr(handle).startswith('<pypcap3.handle object')
    assert pypcap3.packet_iterator[bytes].__origin__ is pypcap3.packet_iterator
    # a handle made directly has no device behind it
    with pytest.raises(pypcap3.error, match='no device opened'):
        pypcap3.handle().next()
    for cls in (pypcap3.dumper, pypcap3.packet_iterator):
        with pytest.raises(TypeError):
            cls()


def test_write_orig_len_none(tmp_path):
    with pypcap3.open_dead().dump_open(tmp_path / 'none.pcap') as dumper:
        dumper.write(b'\x00' * 60, 1.0, None)
    assert read_pcap(tmp_path / 'none.pcap')[2][0][2] == 60


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux only')
def test_set_protocol_linux(handle):
    h = pypcap3.create('nosuch0')
    assert h.set_protocol_linux(0x0806) is None
    h.close()
    with pytest.raises(pypcap3.error, match='activated'):
        handle.set_protocol_linux(0x0806)


# Npcap's rpcap active mode; never run, since CI can't install Npcap


@pytest.mark.skipif(sys.platform != 'win32', reason='Npcap only')
def test_remoteact_without_connections():
    assert pypcap3.remoteact_list() == []
    with pytest.raises(pypcap3.error):
        pypcap3.remoteact_close('192.0.2.1')
    assert pypcap3.remoteact_cleanup() is None  # nothing is waiting


@pytest.mark.skipif(sys.platform != 'win32', reason='Npcap only')
def test_remoteact_cleanup_stops_accept():
    errors = []

    def accept():
        try:
            pypcap3.remoteact_accept('127.0.0.1', '0')
        except pypcap3.error as e:
            errors.append(str(e))

    thread = threading.Thread(target=accept)
    thread.start()
    # cleanup only stops an accept that is already listening, so repeat it
    deadline = time.monotonic() + 10
    while thread.is_alive() and time.monotonic() < deadline:
        pypcap3.remoteact_cleanup()
        thread.join(0.1)
    assert not thread.is_alive()
    assert errors == ['remoteact_accept() was stopped by remoteact_cleanup()']


# type stubs


STUB = pathlib.Path(__file__).resolve().parent.parent / 'pypcap3-stubs' / '__init__.pyi'
# dunders compared between the stub and the module; others such as __init__ aren't
DUNDERS = {'__enter__', '__exit__', '__iter__', '__next__', '__len__', '__getitem__'}


def _stub_platform(test):
    # the stub branches only on `sys.platform == "..."` and `!=`
    assert ast.unparse(test.left) == 'sys.platform', ast.unparse(test)
    value = test.comparators[0].value
    return sys.platform == value if isinstance(test.ops[0], ast.Eq) else sys.platform != value


def _stub_names(body):
    names = {}
    for node in body:
        if isinstance(node, ast.If):
            names.update(_stub_names(node.body if _stub_platform(node.test) else node.orelse))
        elif isinstance(node, ast.AnnAssign):
            names[node.target.id] = node
        elif isinstance(node, ast.Assign):
            names.update((target.id, node) for target in node.targets)
        elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names[node.name] = node
    return names


def _compared(names):
    return {name for name in names if not name.startswith('_') or name in DUNDERS}


def test_stubs_match_module():
    stub = _stub_names(ast.parse(STUB.read_text()).body)
    assert _compared(stub) == _compared(dir(pypcap3))
    for name, node in stub.items():
        if isinstance(node, ast.ClassDef) and not name.startswith('_') and name != 'error':
            assert _compared(_stub_names(node.body)) == _compared(vars(getattr(pypcap3, name))), name
