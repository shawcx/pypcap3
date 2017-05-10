#ifndef __PYPCAP_H__
#define __PYPCAP_H__

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
} PyPCAP_Object;

static PyObject * PyPCAP_version   (PyObject * self);
static PyObject * PyPCAP_find      (PyObject * self);
static PyObject * PyPCAP_mac       (PyObject * self, PyObject * pyoInterface);

static PyPCAP_Object * PyPCAP_open_live (PyObject * self, PyObject * pyoParams);
static PyPCAP_Object * PyPCAP_open_file (PyObject * self, PyObject * pyoParams);

static PyMethodDef PyPCAP_methods[] = {
    { "version",   (PyCFunction)PyPCAP_version,   METH_NOARGS,  "return the version"                },
    { "find",      (PyCFunction)PyPCAP_find,      METH_NOARGS,  "find suitable devices in a system" },
    { "mac",       (PyCFunction)PyPCAP_mac,       METH_O,       "MAC address of an interface"       },
    { "open_live", (PyCFunction)PyPCAP_open_live, METH_VARARGS, "open an interface"                 },
    { "open_file", (PyCFunction)PyPCAP_open_file, METH_VARARGS, "open a file"                       },
    { NULL }
};

static PyModuleDef PyPCAP_module = {
    PyModuleDef_HEAD_INIT,
    "pypcap",
    NULL,
    -1,
    PyPCAP_methods
};


static void PyPCAP_dealloc(PyPCAP_Object *self);

static PyObject * pypcap_close        (PyPCAP_Object *self);
static PyObject * pypcap_geterr       (PyPCAP_Object *self);
static PyObject * pypcap_setnonblock  (PyPCAP_Object *self, PyObject *pyoBlocking);
static PyObject * pypcap_getnonblock  (PyPCAP_Object *self);
static PyObject * pypcap_setdirection (PyPCAP_Object *self, PyObject *pyoDirection);
static PyObject * pypcap_loop         (PyPCAP_Object *self, PyObject *pyoParams);
static PyObject * pypcap_breakloop    (PyPCAP_Object *self);
static PyObject * pypcap_next         (PyPCAP_Object *self);
static PyObject * pypcap_fileno       (PyPCAP_Object *self);
static PyObject * pypcap_sendpacket   (PyPCAP_Object *self, PyObject *pyoPacket);
#ifdef WIN32
static PyObject * pypcap_getevent     (PyPCAP_Object *self);
#endif // WIN32

static PyMethodDef PyPCAP_Object_methods[] = {
    { "close",        (PyCFunction)pypcap_close,        METH_NOARGS,  "close an interface"                 },
    { "geterr",       (PyCFunction)pypcap_geterr,       METH_NOARGS,  "print the last error"               },
    { "setnonblock",  (PyCFunction)pypcap_setnonblock,  METH_O,       "set blocking or non-blocking"       },
    { "getnonblock",  (PyCFunction)pypcap_getnonblock,  METH_NOARGS,  "get blocking state"                 },
    { "setdirection", (PyCFunction)pypcap_setdirection, METH_O,       "set the direction of a capture"     },
    { "loop",         (PyCFunction)pypcap_loop,         METH_VARARGS, "call a callback function on packet" },
    { "breakloop",    (PyCFunction)pypcap_breakloop,    METH_NOARGS,  "cancel the callback function"       },
    { "next",         (PyCFunction)pypcap_next,         METH_NOARGS,  "read the next packet"               },
    { "fileno",       (PyCFunction)pypcap_fileno,       METH_NOARGS,  "fetch file descriptor"              },
    { "sendpacket",   (PyCFunction)pypcap_sendpacket,   METH_O,       "send a packet on the interface"     },
#ifdef WIN32
    { "getevent",     (PyCFunction)pypcap_getevent,     METH_NOARGS,  "get an event handle"                },
#endif // WIN32
    { NULL }
};

static PyTypeObject PyPCAP_Type = {
    PyVarObject_HEAD_INIT(0, 0)
    "pypcap",                        // name
    sizeof(PyPCAP_Object),           // basicsize
    0,                               // itemsize
    (destructor)PyPCAP_dealloc,      // dealloc
    0,                               // print
    0,                               // getattr
    0,                               // setattr
    0,                               // compare
    0,                               // repr
    0,                               // as_number
    0,                               // as_sequence
    0,                               // as_mapping
    0,                               // hash
    0,                               // call
    0,                               // str
    0,                               // getattro
    0,                               // setattro
    0,                               // as_buffer
    Py_TPFLAGS_DEFAULT,              // flags
    "PyPCAP Class",                  // doc
    0,                               // traverse
    0,                               // clear
    0,                               // richcompare
    0,                               // weaklistoffset
    0,                               // iter
    0,                               // iternext
    PyPCAP_Object_methods
};

#ifdef WIN32
static int get_canonical(char *guid, char *name);
static int get_guid(char *name, char *guid);
#endif // WIN32

#endif // __PYPCAP_H__
