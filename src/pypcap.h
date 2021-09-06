#ifndef __PYPCAP_H__
#define __PYPCAP_H__

#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <structmember.h>
#include <pcap.h>

#define  DEFAULT_SNAPLEN  65535
#define  DEFAULT_PROMISC  1
#define  DEFAULT_TO_MS    100

#define  DOC_MOD  "Python wrapper for libpcap"

#ifndef FALSE
#define FALSE 0
#endif

PyMODINIT_FUNC PyInit_pypcap(void);

typedef struct {
    PyObject_HEAD
    pcap_t *pd;
} PyPCAP;

static PyObject * pypcap_version   (PyObject * self);
static PyObject * pypcap_find      (PyObject * self);
static PyObject * pypcap_mac       (PyObject * self, PyObject * pyoInterface);

static PyPCAP * pypcap_open_live (PyObject * self, PyObject * pyoParams);
static PyPCAP * pypcap_open_file (PyObject * self, PyObject * pyoParams);
static PyPCAP * pypcap_create    (PyObject * self, PyObject * pyoParams);

static PyMethodDef PyPCAP_methods[] = {
    { "version",   (PyCFunction)pypcap_version,   METH_NOARGS,  "return the version"                },
    { "find",      (PyCFunction)pypcap_find,      METH_NOARGS,  "find suitable devices in a system" },
    { "mac",       (PyCFunction)pypcap_mac,       METH_O,       "MAC address of an interface"       },
    { "open_live", (PyCFunction)pypcap_open_live, METH_VARARGS, "open an interface"                 },
    { "open_file", (PyCFunction)pypcap_open_file, METH_O,       "open a file"                       },
    { "create",    (PyCFunction)pypcap_create,    METH_O,       "create a live capture handle"      },
    { NULL }
};

static PyModuleDef PyPCAP_module = {
    PyModuleDef_HEAD_INIT,
    .m_name    = "pypcap",
    .m_doc     = NULL,
    .m_size    = -1,
    .m_methods = PyPCAP_methods
};


static int  pypcap_init   (PyPCAP*, PyObject*, PyObject*);
static void pypcap_dealloc(PyPCAP *self);

static PyObject * pypcap_activate       (PyPCAP *self);
static PyObject * pypcap_close          (PyPCAP *self);
static PyObject * pypcap_stats          (PyPCAP *self);
static PyObject * pypcap_geterr         (PyPCAP *self);
static PyObject * pypcap_list_datalinks (PyPCAP *self);
static PyObject * pypcap_datalink       (PyPCAP *self);
static PyObject * pypcap_setnonblock    (PyPCAP *self, PyObject *pyoBlocking);
static PyObject * pypcap_getnonblock    (PyPCAP *self);
static PyObject * pypcap_setdirection   (PyPCAP *self, PyObject *pyoDirection);
static PyObject * pypcap_loop           (PyPCAP *self, PyObject *pyoParams);
static PyObject * pypcap_breakloop      (PyPCAP *self);
static PyObject * pypcap_next           (PyPCAP *self);
static PyObject * pypcap_fileno         (PyPCAP *self);
static PyObject * pypcap_inject         (PyPCAP *self, PyObject *pyoPacket);
#ifdef WIN32
static PyObject * pypcap_getevent       (PyPCAP *self);
#endif // WIN32

static PyMethodDef PyPCAP_Type_methods[] = {
    { "activate",      (PyCFunction)pypcap_activate,       METH_NOARGS,  "activate an interface"              },
    { "close",         (PyCFunction)pypcap_close,          METH_NOARGS,  "close an interface"                 },
    { "stats",         (PyCFunction)pypcap_stats,          METH_NOARGS,  "get stats from a sessions"          },
    { "geterr",        (PyCFunction)pypcap_geterr,         METH_NOARGS,  "print the last error"               },
    { "list_datalinks",(PyCFunction)pypcap_list_datalinks, METH_NOARGS,  "return list of supported datalinks" },
    { "datalink",      (PyCFunction)pypcap_datalink,       METH_NOARGS,  "get datalink"                       },
    { "setnonblock",   (PyCFunction)pypcap_setnonblock,    METH_O,       "set blocking or non-blocking"       },
    { "getnonblock",   (PyCFunction)pypcap_getnonblock,    METH_NOARGS,  "get blocking state"                 },
    { "setdirection",  (PyCFunction)pypcap_setdirection,   METH_O,       "set the direction of a capture"     },
    { "loop",          (PyCFunction)pypcap_loop,           METH_VARARGS, "call a callback function on packet" },
    { "breakloop",     (PyCFunction)pypcap_breakloop,      METH_NOARGS,  "cancel the callback function"       },
    { "next",          (PyCFunction)pypcap_next,           METH_NOARGS,  "read the next packet"               },
    { "fileno",        (PyCFunction)pypcap_fileno,         METH_NOARGS,  "fetch file descriptor"              },
    { "inject",        (PyCFunction)pypcap_inject,         METH_O,       "send a packet on the interface"     },
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

#ifdef WIN32
static int get_canonical(char *guid, char *name);
static int get_guid(char *name, char *guid);
#endif // WIN32

#endif // __PYPCAP_H__
