# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`pypcap3` is a single-file CPython C extension wrapping libpcap (Linux, macOS, Windows/WinPcap-Npcap). There is no Python package layer: the build compiles `src/pypcap.c` into the top-level extension module `pypcap3`.

## Packaging

- **`pyproject.toml`** holds all project metadata, including the version and the SPDX license (which is why it needs `setuptools>=77`). It also sets `packages = []`, because otherwise setuptools treats `src/` as a src-layout package directory and writes `egg-info` into it.
- **`setup.py`** only declares the extension, because the `define_macros` and `libraries` depend on `sys.platform`. Declaring `src/pypcap.h` in `depends` makes header edits trigger a rebuild.
- **`MANIFEST.in`** ships `src/*.c`, `src/*.h` and `README.rst` in the sdist, which the Debian package is built from (`deb_dist/` is the gitignored output).

## Build and run

Needs libpcap headers (Linux: `libpcap-dev`; macOS: the SDK's libpcap; Windows: the WinPcap/Npcap SDK, linked as `wpcap`).

```sh
pip install -e .                         # editable: builds pypcap3.*.so into the repo root (gitignored)
pip wheel --no-deps -w dist .            # build a wheel
PYTHONPATH=. python3 test/simple.py      # list interfaces that have an IPv4 address
sudo PYTHONPATH=. python3 test/simple.py en0   # capture and hexdump packets until Ctrl-C
```

Run `python -m build` from outside the repo root: there, the gitignored `build/` directory shadows the `build` package.

After a C edit, rerun `pip install -e .` (or `python3 setup.py build_ext --inplace`) to rebuild. There is no linter. `test/simple.py` is a manual smoke test, and live capture needs root (or BPF device access on macOS).

## Tests

```sh
pip install --group test                 # pytest, from [dependency-groups] in pyproject.toml
PYTHONPATH=. pytest                      # whole suite, after building in place
PYTHONPATH=. pytest -k loop              # tests matching a name
```

`test/test_pypcap3.py` needs no root or network:

- It builds frames with `ether()` and `ipv4_udp()`, writes them as captures with `pcap_bytes()`, and reads them through `open_file`.
- It checks written files byte for byte with `read_pcap()`, a small parser that also covers the timestamps and original lengths that `next()` doesn't return.
- It uses unactivated `create('nosuch0')` handles for the live-capture error paths.

Two tests rely on threads and signals:

- **`test_sigint_interrupts_blocked_loop`** feeds a pipe through `/dev/fd/N`, then sends SIGINT while `loop()` is blocked on it. If `loop()` stops releasing the GIL, this test hangs.
- **`test_loops_run_concurrently_in_threads`** uses a barrier, so it fails if two threads can't run loops at the same time.

Opening a FIFO with `open_file` deadlocks such tests, because `open_file` holds the GIL while libpcap reads the header.

## Architecture

- **`src/pypcap.h` holds the Python-facing surface:** every function prototype, the `PyMethodDef` tables, the `PyModuleDef`, the three type objects (`PyPCAP_Type` for handles, `PyBPF_Type` for compiled filters, `PyDumper_Type` for file writers), and the defaults (`DEFAULT_SNAPLEN`, `DEFAULT_PROMISC`, `DEFAULT_TO_MS`). `src/pypcap.c` holds only the implementations. Adding a method means adding a prototype and a table entry in the header plus the body in the `.c` file.
- **Module functions** (`find`, `mac`, `version`, `lookupnet`, `open_live`, `open_file`/`open_offline`, `create`, `open_dead`) are the only way to get a capture handle. `PyPCAP_Type` is not added to the module, so handles can't be constructed directly. Each handle wraps one `pcap_t *pd`. Handle methods start with the `CTXCHECK` macro, which raises if `pd` is NULL (for example after `close()`). Any new method that touches `pd` needs it too, or it crashes on a closed handle.
- **Busy handles:** `loop()` and `next()` set `self->busy` while the GIL is released.
  - The `BUSYCHECK` macro makes `close()`, `loop()`, `next()` and `setfilter()` raise while it is set, so the `pcap_t` can't be closed, re-entered or refiltered from another thread or from inside the callback.
  - `breakloop()` is deliberately not guarded.
- **Filters:**
  - `setfilter()` accepts an expression or a program from `compile()`. `bpf_program.match()` runs `pcap_offline_filter` on raw bytes.
  - Both compile against a handle's link type, so use `open_dead(linktype, snaplen)` to compile without a device.
  - `parse_netmask` converts the dotted netmask to host byte order, because `pcap_compile` needs that for `ip broadcast` to match. `pcap_lookupnet` returns network byte order, and `lookupnet()` converts that to dotted strings, so callers never see the mismatch.
- **Capture files:**
  - `dump_open()` returns a dumper whose file header takes the handle's link type and snaplen.
  - `write()` truncates data to that snaplen but records the full length, and timestamps default to now.
  - `loop(dumper)` passes `pcap_dump` straight to `pcap_loop`, with no Python call per packet, so packets keep their capture timestamps.
  - The dumper's own `busy` flag stops `write()` and `close()` during that loop, because `pcap_dump` makes two separate `fwrite`s per packet that could interleave.
- **Names:** the extension, `.m_name` and exception are all `pypcap3`, and the init function is `PyInit_pypcap3`; only the handle's `tp_name` still says `pypcap`. If you rename the module, the `PyInit_` symbol must match the `Extension` name in `setup.py`.
- **Errors:** all failures raise the module's single exception, `pypcap3.error`, usually with libpcap's error buffer or `pcap_statustostr` text. Every error path must set an exception before returning NULL; otherwise Python raises `SystemError`.
- **Capture paths:**
  - `loop(callback, cnt=-1)` releases the GIL for `pcap_loop`. `pypcap_handler` takes the GIL back for each packet through the `loop_ctx` passed as libpcap's `user` pointer.
  - In `loop()`, an exception from the callback, or a pending signal, calls `pcap_breakloop` and is raised from `loop()`. After `breakloop()`, `loop()` returns `None`.
  - Ctrl-C: the first loop to start (`_g_pd` is NULL) installs a C SIGINT hook. The hook calls `pcap_breakloop` and then chains to the previous handler (Python's), so a blocked loop wakes up and `loop()` raises `KeyboardInterrupt`. Other loops running at the same time work, but can only be stopped with `breakloop()`.
  - `next()` releases the GIL around `pcap_next_ex`. It returns packet bytes only (no header or timestamp), or `None` on timeout or EOF.
- **Platform splits** (`setup.py` defines `MACOS` on Darwin and `WIN32`/`WPCAP` on Windows):
  - `mac()` uses a `sysctl` `NET_RT_IFLIST` query on macOS, the `SIOCGIFHWADDR` ioctl on Linux, and returns `None` on Windows.
  - On Windows, `find()` returns friendly connection names and `open_live()` accepts them. The two map to `\Device\NPF_{GUID}` through registry lookups (`get_canonical` and `get_guid`).
  - `setdirection` is a no-op on Windows, and `getevent` exists only there.
- **`find()`** returns `{ifname: {"ip", "netmask", "broadcast"}}` and reports IPv4 only; IPv6 is a TODO.
