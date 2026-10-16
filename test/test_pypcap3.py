import os
import signal
import struct
import sys
import threading
import time

import pytest

import pypcap3

LINKTYPE_ETHERNET = 1


def pcap_bytes(packets, linktype=LINKTYPE_ETHERNET, snaplen=65535):
    """A classic little-endian pcap file holding the given frames."""
    out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, linktype)]
    for idx, pkt in enumerate(packets):
        out.append(struct.pack('<IIII', 1700000000 + idx, 0, len(pkt), len(pkt)))
        out.append(pkt)
    return b''.join(out)

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
], ids=['close', 'next', 'loop'])
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
