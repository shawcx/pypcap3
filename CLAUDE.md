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

After a C edit, rerun `pip install -e .` (or `python3 setup.py build_ext --inplace`) to rebuild. There is no test suite or linter. `test/simple.py` is a manual smoke test, and live capture needs root (or BPF device access on macOS).

## Architecture

- **`src/pypcap.h` holds the Python-facing surface:** every function prototype, both `PyMethodDef` tables (module-level and handle methods), the `PyModuleDef`, the `PyPCAP_Type` object, and the defaults (`DEFAULT_SNAPLEN`, `DEFAULT_PROMISC`, `DEFAULT_TO_MS`). `src/pypcap.c` holds only the implementations. Adding a method means adding a prototype and a table entry in the header plus the body in the `.c` file.
- **Module functions** (`find`, `mac`, `version`, `open_live`, `open_file`/`open_offline`, `create`) are the only way to get a capture handle. `PyPCAP_Type` is not added to the module, so handles can't be constructed directly. Each handle wraps one `pcap_t *pd`, and handle methods start with the `CTXCHECK` macro, which raises if `pd` is NULL (for example after `close()`).
- **Names:** the extension is `pypcap3` and its init function is `PyInit_pypcap3`. The `.m_name`, `tp_name`, and exception name still say `pypcap`. If you rename the module, the `PyInit_` symbol must match the `Extension` name in `setup.py`.
- **Errors:** all failures raise the module's single exception, `pypcap3.error`, usually with libpcap's error buffer or `pcap_statustostr` text.
- **Capture paths:**
  - `loop(callback, cnt=-1)` runs `pcap_loop` holding the GIL. It allows one loop per process (the global `_g_pd`) and installs a temporary C `SIGINT` handler that calls `pcap_breakloop`, so Ctrl-C stops the loop. Exceptions raised in the callback are printed and swallowed, not propagated.
  - `next()` releases the GIL around `pcap_next_ex`. It returns packet bytes only (no header or timestamp), or `None` on timeout or EOF.
- **Platform splits** (`setup.py` defines `MACOS` on Darwin and `WIN32`/`WPCAP` on Windows):
  - `mac()` uses a `sysctl` `NET_RT_IFLIST` query on macOS, the `SIOCGIFHWADDR` ioctl on Linux, and returns `None` on Windows.
  - On Windows, `find()` returns friendly connection names and `open_live()` accepts them. The two map to `\Device\NPF_{GUID}` through registry lookups (`get_canonical` and `get_guid`).
  - `setdirection` is a no-op on Windows, and `getevent` exists only there.
- **`find()`** returns `{ifname: {"ip", "netmask", "broadcast"}}` and reports IPv4 only; IPv6 is a TODO. BPF filters are not wrapped yet (README TODO).
