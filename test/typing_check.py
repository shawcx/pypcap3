"""Checked by `mypy --strict test/typing_check.py` in CI, never run: the types
the stubs give common calls. pytest doesn't collect it."""

from typing import assert_type

import pypcap3


def check(h: pypcap3.handle, dumper: pypcap3.dumper) -> None:
    assert_type(pypcap3.open_file('capture.pcap'), pypcap3.handle)
    assert_type(h.next(), bytes | None)
    assert_type(h.next(header=True), tuple[bytes, float, int] | None)
    for packet in h:
        assert_type(packet, bytes)
    for data, ts, orig_len in h.packets(header=True):
        assert_type(ts, float)
    h.loop(dumper)
    h.loop(dumper.write, header=True)
    h.loop(lambda packet, ts, orig_len: None, header=True)
    assert_type(h.dispatch(lambda packet: None), int)
    assert_type(pypcap3.find()['lo']['addresses'][0]['netmask'], str | None)
    assert_type(h.compile('udp', netmask='255.255.255.0').match(b''), bool)
    assert_type(len(h.compile('udp')), int)
    program = pypcap3.bpf_program(list(pypcap3.compile('udp', linktype=1)))
    assert_type(program[0], tuple[int, int, int, int])
    for code, jt, jf, k in program:
        assert_type(k, int)
    assert_type(h.bufsize(), int)
    with h.dump_open('copy.pcap') as out:
        assert_type(out, pypcap3.dumper)
