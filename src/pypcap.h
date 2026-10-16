#ifndef __PYPCAP_H__
#define __PYPCAP_H__

#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <structmember.h>
#include <pcap.h>
#include <signal.h>
#include <time.h>

#ifdef WIN32
 #include <io.h>
 #include <ws2tcpip.h>
#else
 #include <arpa/inet.h>
 #include <net/if.h>
#ifdef MACOS
 #include <net/if_dl.h>
 #include <sys/sysctl.h>
#endif
 #include <netinet/in.h>
 #include <sys/ioctl.h>
 #include <sys/socket.h>
 #include <sys/time.h>
 #include <sys/types.h>
 #include <errno.h>
#endif

#define  DEFAULT_SNAPLEN  65535
#define  DEFAULT_PROMISC  1
#define  DEFAULT_TO_MS    100

#define  DOC_MOD  "Python wrapper for libpcap"

#ifndef FALSE
#define FALSE 0
#endif

PyMODINIT_FUNC PyInit_pypcap3(void);

typedef struct {
    PyObject_HEAD
    pcap_t *pd;
    int busy;      // set while loop() or next() runs with the GIL released
    int live;      // from open_live() or create(), not a file or open_dead()
} PyPCAP;

typedef struct {
    PyObject_HEAD
    struct bpf_program program;
} PyBPF;

typedef struct {
    PyObject_HEAD
    pcap_dumper_t *dumper;
    int snaplen;   // packets longer than this are truncated, as a capture would
    int nano;      // the file stores nanoseconds rather than microseconds
    int busy;      // set while loop() writes to it with the GIL released
} PyDumper;

static PyObject * pypcap_version   (PyObject * self);
static PyObject * pypcap_find      (PyObject * self);
static PyObject * pypcap_mac       (PyObject * self, PyObject * interface);

static PyPCAP * pypcap_open_live (PyObject * self, PyObject * arguments);
static PyPCAP * pypcap_open_file (PyObject * self, PyObject * arguments, PyObject * keywords);
static PyPCAP * pypcap_create    (PyObject * self, PyObject * interface);
static PyPCAP * pypcap_open_dead (PyObject * self, PyObject * arguments, PyObject * keywords);

static PyObject * pypcap_lookupnet (PyObject * self, PyObject * interface);

static PyMethodDef PyPCAP_methods[] = {
    { "version",      (PyCFunction)pypcap_version,   METH_NOARGS,  "return the version"                },
    { "find",         (PyCFunction)pypcap_find,      METH_NOARGS,
      "{name: {description, flags, addresses, ...}} for each capture device" },
    { "mac",          (PyCFunction)pypcap_mac,       METH_O,       "MAC address of an interface"       },
    { "open_live",    (PyCFunction)pypcap_open_live, METH_VARARGS, "open an interface"                 },
    { "open_file",    (PyCFunction)pypcap_open_file, METH_VARARGS | METH_KEYWORDS,
      "open_file(file, precision=TSTAMP_PRECISION_MICRO): read a capture from a path, file object or descriptor" },
    { "open_offline", (PyCFunction)pypcap_open_file, METH_VARARGS | METH_KEYWORDS,
      "open_offline(file, precision=TSTAMP_PRECISION_MICRO): read a capture from a path, file object or descriptor" },
    { "create",       (PyCFunction)pypcap_create,    METH_O,       "create a live capture handle"      },
    { "open_dead",    (PyCFunction)pypcap_open_dead, METH_VARARGS | METH_KEYWORDS,
      "open_dead(linktype=1, snaplen=65535, precision=TSTAMP_PRECISION_MICRO): a handle with no device, "
      "for compiling filters and writing files" },
    { "lookupnet",    (PyCFunction)pypcap_lookupnet, METH_O,       "(network, netmask) of an interface" },
    { NULL }
};

static PyModuleDef PyPCAP_module = {
    PyModuleDef_HEAD_INIT,
    .m_name    = "pypcap3",
    .m_doc     = NULL,
    .m_size    = -1,
    .m_methods = PyPCAP_methods
};


static int  pypcap_init   (PyPCAP*, PyObject*, PyObject*);
static void pypcap_dealloc(PyPCAP *self);

static PyObject * pypcap_activate       (PyPCAP *self);
static PyObject * pypcap_snapshot       (PyPCAP *self);
static PyObject * pypcap_close          (PyPCAP *self);
static PyObject * pypcap_stats          (PyPCAP *self);
static PyObject * pypcap_geterr         (PyPCAP *self);
static PyObject * pypcap_list_datalinks (PyPCAP *self);
static PyObject * pypcap_datalink       (PyPCAP *self);
static PyObject * pypcap_set_snaplen    (PyPCAP *self, PyObject *snaplen);
static PyObject * pypcap_set_promisc    (PyPCAP *self, PyObject *promisc);
static PyObject * pypcap_setnonblock    (PyPCAP *self, PyObject *blocking);
static PyObject * pypcap_getnonblock    (PyPCAP *self);
static PyObject * pypcap_setdirection   (PyPCAP *self, PyObject *direction);
static PyObject * pypcap_loop           (PyPCAP *self, PyObject *arguments, PyObject *keywords);
static PyObject * pypcap_dispatch       (PyPCAP *self, PyObject *arguments, PyObject *keywords);
static PyObject * pypcap_breakloop      (PyPCAP *self);
static PyObject * pypcap_next           (PyPCAP *self, PyObject *arguments, PyObject *keywords);
static PyObject * pypcap_fileno         (PyPCAP *self);
#ifndef WIN32
static PyObject * pypcap_get_selectable_fd           (PyPCAP *self);
static PyObject * pypcap_get_required_select_timeout (PyPCAP *self);
#endif // WIN32
static PyObject * pypcap_set_timeout           (PyPCAP *self, PyObject *value);
static PyObject * pypcap_set_immediate_mode    (PyPCAP *self, PyObject *value);
static PyObject * pypcap_set_buffer_size       (PyPCAP *self, PyObject *value);
static PyObject * pypcap_set_rfmon             (PyPCAP *self, PyObject *value);
static PyObject * pypcap_can_set_rfmon         (PyPCAP *self);
static PyObject * pypcap_set_tstamp_type       (PyPCAP *self, PyObject *value);
static PyObject * pypcap_list_tstamp_types     (PyPCAP *self);
static PyObject * pypcap_set_tstamp_precision  (PyPCAP *self, PyObject *value);
static PyObject * pypcap_get_tstamp_precision  (PyPCAP *self);
static PyObject * pypcap_inject         (PyPCAP *self, PyObject *packet);
static PyObject * pypcap_setfilter      (PyPCAP *self, PyObject *arguments, PyObject *keywords);
static PyObject * pypcap_compile        (PyPCAP *self, PyObject *arguments, PyObject *keywords);
static PyObject * pypcap_dump_open      (PyPCAP *self, PyObject *arguments, PyObject *keywords);
#ifdef WIN32
static PyObject * pypcap_getevent       (PyPCAP *self);
#endif // WIN32

static PyMethodDef PyPCAP_Type_methods[] = {
    { "activate",      (PyCFunction)pypcap_activate,       METH_NOARGS,  "activate an interface"              },
    { "snapshot",      (PyCFunction)pypcap_snapshot,       METH_NOARGS,  "get the snaplen"                    },
    { "close",         (PyCFunction)pypcap_close,          METH_NOARGS,  "close an interface"                 },
    { "stats",         (PyCFunction)pypcap_stats,          METH_NOARGS,  "get stats from a sessions"          },
    { "geterr",        (PyCFunction)pypcap_geterr,         METH_NOARGS,  "print the last error"               },
    { "list_datalinks",(PyCFunction)pypcap_list_datalinks, METH_NOARGS,  "return list of supported datalinks" },
    { "datalink",      (PyCFunction)pypcap_datalink,       METH_NOARGS,  "get datalink"                       },
    { "set_snaplen",   (PyCFunction)pypcap_set_snaplen,    METH_O,       "set snaplen"                        },
    { "set_promisc",   (PyCFunction)pypcap_set_promisc,    METH_O,       "set promiscuous mode"               },
    { "setnonblock",   (PyCFunction)pypcap_setnonblock,    METH_O,       "set blocking or non-blocking"       },
    { "getnonblock",   (PyCFunction)pypcap_getnonblock,    METH_NOARGS,  "get blocking state"                 },
    { "setdirection",  (PyCFunction)pypcap_setdirection,   METH_O,       "set the direction of a capture"     },
    { "loop",          (PyCFunction)pypcap_loop,           METH_VARARGS | METH_KEYWORDS,
      "loop(callback, cnt=-1, *, header=False): call callback(packet), or callback(packet, ts, orig_len) "
      "with header=True, for each packet; a dumper is written to directly" },
    { "dispatch",      (PyCFunction)pypcap_dispatch,       METH_VARARGS | METH_KEYWORDS,
      "dispatch(callback, cnt=-1, *, header=False): like loop() for one buffer of packets; returns how many" },
    { "breakloop",     (PyCFunction)pypcap_breakloop,      METH_NOARGS,  "cancel the callback function"       },
    { "next",          (PyCFunction)pypcap_next,           METH_VARARGS | METH_KEYWORDS,
      "next(*, header=False): the next packet, (packet, ts, orig_len) with header=True, or None" },
    { "fileno",        (PyCFunction)pypcap_fileno,         METH_NOARGS,  "fetch file descriptor"              },
#ifndef WIN32
    { "get_selectable_fd",           (PyCFunction)pypcap_get_selectable_fd,           METH_NOARGS,
      "descriptor to wait on with select/poll/asyncio, or -1" },
    { "get_required_select_timeout", (PyCFunction)pypcap_get_required_select_timeout, METH_NOARGS,
      "seconds a select() must time out after on this handle, or None" },
#endif // WIN32
    { "set_timeout",          (PyCFunction)pypcap_set_timeout,          METH_O,      "set the read timeout in ms, before activate()"  },
    { "set_immediate_mode",   (PyCFunction)pypcap_set_immediate_mode,   METH_O,      "deliver packets as they arrive, before activate()" },
    { "set_buffer_size",      (PyCFunction)pypcap_set_buffer_size,      METH_O,      "set the buffer size in bytes, before activate()" },
    { "set_rfmon",            (PyCFunction)pypcap_set_rfmon,            METH_O,      "set Wi-Fi monitor mode, before activate()"     },
    { "can_set_rfmon",        (PyCFunction)pypcap_can_set_rfmon,        METH_NOARGS, "whether monitor mode is available"             },
    { "set_tstamp_type",      (PyCFunction)pypcap_set_tstamp_type,      METH_O,      "set a TSTAMP_* source, before activate()"      },
    { "list_tstamp_types",    (PyCFunction)pypcap_list_tstamp_types,    METH_NOARGS, "(type, name, description) of each timestamp source" },
    { "set_tstamp_precision", (PyCFunction)pypcap_set_tstamp_precision, METH_O,      "set TSTAMP_PRECISION_MICRO or _NANO, before activate()" },
    { "get_tstamp_precision", (PyCFunction)pypcap_get_tstamp_precision, METH_NOARGS, "TSTAMP_PRECISION_MICRO or _NANO"               },
    { "inject",        (PyCFunction)pypcap_inject,         METH_O,       "send a packet on the interface"     },
    { "setfilter",     (PyCFunction)pypcap_setfilter,      METH_VARARGS | METH_KEYWORDS,
      "setfilter(filter, optimize=True, netmask=None): apply a BPF expression or a compiled program" },
    { "compile",       (PyCFunction)pypcap_compile,        METH_VARARGS | METH_KEYWORDS,
      "compile(expression, optimize=True, netmask=None): compile a BPF expression for this handle" },
    { "dump_open",     (PyCFunction)pypcap_dump_open,      METH_VARARGS | METH_KEYWORDS,
      "dump_open(file, append=False): write packets to a path, file object or descriptor" },
#ifdef WIN32
    { "getevent",      (PyCFunction)pypcap_getevent,       METH_NOARGS,  "get an event handle"                },
#endif // WIN32
    { NULL }
};

static PyTypeObject PyPCAP_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name      = "pypcap",
    .tp_doc       = "pypcap Class",
    .tp_basicsize = sizeof(PyPCAP),
    .tp_new       = PyType_GenericNew,
    .tp_init      = (initproc)pypcap_init,
    .tp_dealloc   = (destructor)pypcap_dealloc,
    .tp_flags     = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_methods   = PyPCAP_Type_methods,
};


static void       pypcap_bpf_dealloc      (PyBPF *self);
static PyObject * pypcap_bpf_match        (PyBPF *self, PyObject *packet);
static PyObject * pypcap_bpf_instructions (PyBPF *self);
static Py_ssize_t pypcap_bpf_len          (PyBPF *self);

static PyMethodDef PyBPF_Type_methods[] = {
    { "match",         (PyCFunction)pypcap_bpf_match,        METH_O,       "True if the filter accepts the packet" },
    { "instructions",  (PyCFunction)pypcap_bpf_instructions, METH_NOARGS,  "the program as text, one line per instruction, like tcpdump -d" },
    { NULL }
};

static PySequenceMethods PyBPF_Type_sequence = {
    .sq_length    = (lenfunc)pypcap_bpf_len,
};

static PyTypeObject PyBPF_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name      = "pypcap3.bpf_program",
    .tp_doc       = "compiled BPF filter, from compile()",
    .tp_basicsize = sizeof(PyBPF),
    .tp_dealloc   = (destructor)pypcap_bpf_dealloc,
    .tp_as_sequence = &PyBPF_Type_sequence,
    .tp_flags     = Py_TPFLAGS_DEFAULT,
    .tp_methods   = PyBPF_Type_methods,
};


static void       pypcap_dumper_dealloc (PyDumper *self);
static PyObject * pypcap_dumper_write   (PyDumper *self, PyObject *arguments, PyObject *keywords);
static PyObject * pypcap_dumper_flush   (PyDumper *self);
static PyObject * pypcap_dumper_close   (PyDumper *self);
static PyObject * pypcap_dumper_enter   (PyDumper *self);
static PyObject * pypcap_dumper_exit    (PyDumper *self, PyObject *arguments);

static PyMethodDef PyDumper_Type_methods[] = {
    { "write",         (PyCFunction)pypcap_dumper_write,   METH_VARARGS | METH_KEYWORDS,
      "write(packet, ts=None, orig_len=None): ts defaults to now, orig_len to len(packet)" },
    { "flush",         (PyCFunction)pypcap_dumper_flush,   METH_NOARGS,  "flush buffered packets to the file" },
    { "close",         (PyCFunction)pypcap_dumper_close,   METH_NOARGS,  "flush and close the file"           },
    { "__enter__",     (PyCFunction)pypcap_dumper_enter,   METH_NOARGS,  NULL                                 },
    { "__exit__",      (PyCFunction)pypcap_dumper_exit,    METH_VARARGS, NULL                                 },
    { NULL }
};

static PyTypeObject PyDumper_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name      = "pypcap3.dumper",
    .tp_doc       = "capture file writer, from dump_open()",
    .tp_basicsize = sizeof(PyDumper),
    .tp_dealloc   = (destructor)pypcap_dumper_dealloc,
    .tp_flags     = Py_TPFLAGS_DEFAULT,
    .tp_methods   = PyDumper_Type_methods,
};

#ifdef WIN32
static int get_canonical(char *guid, char *name);
static int get_guid(char *name, char *guid);
#endif // WIN32

#endif // __PYPCAP_H__
