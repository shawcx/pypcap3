#ifdef WIN32
// #include <Windows.h>
#else // !WIN32
 #include <arpa/inet.h>
 #include <net/if.h>
 #include <net/if_dl.h>
 #include <netinet/in.h>
 #include <sys/ioctl.h>
 #include <sys/socket.h>
 #include <sys/sysctl.h>
 #include <sys/types.h>
 #include <errno.h>
 #include <signal.h>
#endif // WIN32

#include "pypcap.h"

#define CTXCHECK if(NULL == self->pd) { PyErr_SetString(PyExc_IOError, "No device opened"); return NULL; }

PyMODINIT_FUNC PyInit_pypcap() {
    PyObject *mod;
    int ok;

    ok = PyType_Ready(&PyPCAP_Type);
    if(0 > ok) {
        return NULL;
    }

    mod = PyModule_Create(&PyPCAP_module);
    if(NULL == mod) {
        return NULL;
    }

    Py_INCREF(&PyPCAP_Type);

    // PCAP DIRECTIONS
    PyModule_AddIntConstant(mod, "D_IN",    PCAP_D_IN);
    PyModule_AddIntConstant(mod, "D_OUT",   PCAP_D_OUT);
    PyModule_AddIntConstant(mod, "D_INOUT", PCAP_D_INOUT);

    return mod;
}

/*
 *  PyPCAP Module Functions
 */

static PyObject * PyPCAP_version(PyObject *self) {
    return PyUnicode_FromString(pcap_lib_version());
}

static PyObject * PyPCAP_find(PyObject *self) {
    PyObject *pyoDevDict;
    PyObject *pyoAddrDict;
    PyObject *pyoNameString;
    PyObject *pyoValueString;

    pcap_if_t *devices;
    pcap_if_t *current;
    pcap_addr_t *address;
    struct sockaddr *sa;
    struct sockaddr_in *sai;

    char szErrBuf[PCAP_ERRBUF_SIZE];
    int ok;

#ifdef WIN32
    char canonical[MAX_PATH];
#endif // WIN32

    // Returns a linked list of all devices in the system
    ok = pcap_findalldevs(&devices, szErrBuf);
    if(0 > ok) {
        PyErr_SetString(PyExc_IOError, szErrBuf);
        return NULL;
    }

    // Create empty dictionary
    pyoDevDict = PyDict_New();

    // Iterate through all devices
    current = devices;
    while(current) {
        // Create an empty dictionary for all the addresses associated with an interface
        pyoAddrDict = PyDict_New();

        // TODO: create list of addresses
        address = current->addresses;
        while(address) {
            sa = address->addr;
            if(AF_INET == sa->sa_family) {
                sai = (struct sockaddr_in *)address->addr;
                if(NULL != sai) {
                    pyoValueString = PyUnicode_FromString(inet_ntoa(sai->sin_addr));
                    PyDict_SetItemString(pyoAddrDict, "ip", pyoValueString);
                    Py_DECREF(pyoValueString);
                }

                sai = (struct sockaddr_in *)address->netmask;
                if(NULL != sai) {
                    pyoValueString = PyUnicode_FromString(inet_ntoa(sai->sin_addr));
                    PyDict_SetItemString(pyoAddrDict, "netmask", pyoValueString);
                    Py_DECREF(pyoValueString);
                }

                sai = (struct sockaddr_in *)address->broadaddr;
                if(NULL != sai) {
                    pyoValueString = PyUnicode_FromString(inet_ntoa(sai->sin_addr));
                    PyDict_SetItemString(pyoAddrDict, "broadcast", pyoValueString);
                    Py_DECREF(pyoValueString);
                }
            }

            if(AF_INET6 == sa->sa_family) {
                // TODO: ipv6
            }

            address = address->next;
        }

#ifdef WIN32
        if(0 > get_canonical(current->name + 12, canonical)) {
            current = current->next;
            continue;
        }
        pyoNameString = PyUnicode_FromString(canonical);
#else
        pyoNameString = PyUnicode_FromString(current->name);
#endif // WIN32
        PyDict_SetItem(pyoDevDict, pyoNameString, pyoAddrDict);
        Py_DECREF(pyoNameString);
        Py_DECREF(pyoAddrDict);

        current = current->next;
    }

    // Free the linked list
    pcap_freealldevs(devices);

    // Return the dictionary of devices
    return pyoDevDict;
}

static PyObject * PyPCAP_mac(PyObject *self, PyObject *pyoInterface) {
    int ok;

    ok = PyUnicode_Check(pyoInterface);
    if(FALSE == ok) {
        PyErr_SetString(PyExc_TypeError, "Value must be a string.");
        return NULL;
    }

#ifdef WIN32
    Py_RETURN_NONE;
#endif // WIN32

#ifdef MACOS
    int mib[6];
    size_t len;
    char * buff;
    uint8_t * ptr;
    struct if_msghdr   * ifm;
    struct sockaddr_dl * sdl;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_LINK;
    mib[4] = NET_RT_IFLIST;
    mib[5] = if_nametoindex(PyUnicode_AsUTF8(pyoInterface));
    if(mib[5] == 0) {
        //perror("if_nametoindex error");
        Py_RETURN_NONE;
    }

    ok = sysctl(mib, 6, NULL, &len, NULL, 0);
    if(0 > ok) {
        Py_RETURN_NONE;
    }

    buff = malloc(len);
    if(buff == NULL) {
        Py_RETURN_NONE;
    }

    ok = sysctl(mib, 6, buff, &len, NULL, 0);
    if(0 > ok) {
        free(buff);
        Py_RETURN_NONE;
    }

    ifm = (struct if_msghdr *)buff;
    sdl = (struct sockaddr_dl *)(ifm + 1);
    ptr = (uint8_t *)LLADDR(sdl);

    free(buff);

    return PyBytes_FromStringAndSize((char *)ptr, 6);
#endif // MACOS

#ifdef LINUX
    struct ifreq ifr;
    int fd;

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, PyUnicode_AsUTF8(pyoInterface), IFNAMSIZ-1);
    ifr.ifr_name[IFNAMSIZ-1] = 0;

    Py_DECREF(pyoAscii);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(0 > fd) {
        return NULL;
    }

    ok = ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);

    if(0 > ok) {
        PyErr_SetString(PyExc_IOError, "Error calling ioctl");
        return NULL;
    }

    return PyBytes_FromStringAndSize((char *)ifr.ifr_hwaddr.sa_data, 6);
#endif // LINUX

}

static PyPCAP_Object * PyPCAP_open_live(PyObject *self, PyObject *pyoParams) {
    PyPCAP_Object *pypcap;

    char *szDevice = NULL;
    int snaplen = DEFAULT_SNAPLEN;
    int promisc = DEFAULT_PROMISC;
    int to_ms = DEFAULT_TO_MS;
    char szErrBuf[PCAP_ERRBUF_SIZE];
    int ok;
#ifdef WIN32
    char guid[MAX_PATH];
#endif // WIN32

    ok = PyArg_ParseTuple(pyoParams, "s|iii", &szDevice, &snaplen, &promisc, &to_ms);
    if(FALSE == ok) {
        PyErr_SetString(PyExc_TypeError, "");
        return NULL;
    }

#ifdef WIN32
    if(0 > get_guid(szDevice, guid)) {
        PyErr_SetString(PyExc_IOError, "Cannot find interface");
        return NULL;
    }
#endif // WIN32

    pypcap = PyObject_New(PyPCAP_Object, &PyPCAP_Type);
    if(NULL == pypcap) {
        return NULL;
    }

#ifdef WIN32
    pypcap->pd = pcap_open_live(guid, snaplen, promisc, to_ms, szErrBuf);
#else
    pypcap->pd = pcap_open_live(szDevice, snaplen, promisc, to_ms, szErrBuf);
#endif
    if(NULL == pypcap->pd) {
        PyErr_SetString(PyExc_IOError, szErrBuf);
        return NULL;
    }

    //printf("??? %d\n", pcap_set_timeout(pypcap->pd, 100));

#ifdef WIN32
    pcap_setmintocopy(pypcap->pd, 14);
#endif // WIN32

    return pypcap;
}

static PyPCAP_Object * PyPCAP_open_file(PyObject *self, PyObject *pyoParams) {
    PyPCAP_Object *pypcap;

    char *szFileName = NULL;
    char szErrBuf[PCAP_ERRBUF_SIZE];
    int ok;

    ok = PyArg_ParseTuple(pyoParams, "s", &szFileName);
    if(FALSE == ok) {
        PyErr_SetString(PyExc_TypeError, "String expected");
        return NULL;
    }

    pypcap = PyObject_New(PyPCAP_Object, &PyPCAP_Type);
    if(NULL == pypcap) {
        return NULL;
    }

    pypcap->pd = pcap_open_offline(szFileName, szErrBuf);
    if(NULL == pypcap->pd) {
        PyErr_SetString(PyExc_IOError, szErrBuf);
        return NULL;
    }

    return pypcap;
}

/*
 *  PyPCAP Object Functions
 */


static void PyPCAP_dealloc(PyPCAP_Object *self) {
    if(NULL != self->pd) {
        pcap_close(self->pd);
        self->pd = NULL;
    }
    PyObject_Del(self);
}

static PyObject * pypcap_close(PyPCAP_Object *self) {
    if(NULL != self->pd) {
        pcap_close(self->pd);
        self->pd = NULL;
    }
    Py_RETURN_NONE;
}

static PyObject * pypcap_geterr(PyPCAP_Object *self) {
    return PyUnicode_FromString(pcap_geterr(self->pd));
}

static PyObject * pypcap_setnonblock(PyPCAP_Object *self, PyObject *pyoBlocking) {
    char szErrBuf[PCAP_ERRBUF_SIZE];
    long block;
    int ok;

    CTXCHECK;

    ok = PyLong_Check(pyoBlocking);
    if(FALSE == ok) {
        PyErr_SetString(PyExc_TypeError, "Value must be a boolean or integer.");
        return NULL;
    }

    block = (int)PyLong_AsLong(pyoBlocking);
    ok = pcap_setnonblock(self->pd, block, szErrBuf);
    if(0 > ok) {
        PyErr_SetString(PyExc_IOError, szErrBuf);
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject * pypcap_getnonblock(PyPCAP_Object *self) {
    char szErrBuf[PCAP_ERRBUF_SIZE];
    int block;

    CTXCHECK;

    block = pcap_getnonblock(self->pd, szErrBuf);
    if(0 > block) {
        PyErr_SetString(PyExc_IOError, szErrBuf);
        return NULL;
    }

    return Py_BuildValue("i", block);
}

static PyObject * pypcap_setdirection(PyPCAP_Object *self, PyObject *pyoDirection) {
#ifdef WIN32
    Py_RETURN_FALSE;
#else // !WIN32
    long nDirection;
    int ok;

    CTXCHECK;

    ok = PyLong_Check(pyoDirection);
    if(FALSE == ok) {
        PyErr_SetString(PyExc_TypeError, "Value must be an integer.");
        return NULL;
    }

    nDirection = (int)PyLong_AsLong(pyoDirection);
    pcap_setdirection(self->pd, nDirection);

    Py_RETURN_TRUE;
#endif // WIN32
}

void pypcap_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data) {
    Py_DECREF(PyObject_CallFunction((PyObject *)user, "y#", pkt_data, pkt_header->caplen));
}

//
// Used by pypcap_loop to break immediately on Ctrl-C
//
typedef void (*sigfunc)(int);
static pcap_t *_g_pd;

void sig_handler(int signo) {
    if(signo == SIGINT) {
        pcap_breakloop(_g_pd);
    }
}

static PyObject * pypcap_loop(PyPCAP_Object *self, PyObject *pyoParams) {
    PyObject *pyoCallback;
    int cnt = -1;
    int ok;

    CTXCHECK;

    ok = PyArg_ParseTuple(pyoParams, "O|i", &pyoCallback, &cnt);
    if(FALSE == ok) {
        PyErr_SetString(PyExc_TypeError, "Bad args");
        return NULL;
    }

    ok = PyCallable_Check(pyoCallback);
    if(FALSE == ok) {
        PyErr_SetString(PyExc_TypeError, "The callback needs to be a function");
        return NULL;
    }

    _g_pd = self->pd;
    // install temporary signal handler
    sigfunc *_pyhandler;
    _pyhandler = signal(SIGINT, sig_handler);
    ok = pcap_loop(self->pd, cnt, pypcap_handler, (u_char *)pyoCallback);
    signal(SIGINT, _pyhandler);

    Py_RETURN_NONE;
}

static PyObject * pypcap_breakloop(PyPCAP_Object *self) {
    CTXCHECK;
    pcap_breakloop(self->pd);
    Py_RETURN_NONE;
}

static PyObject * pypcap_next(PyPCAP_Object *self) {
    struct pcap_pkthdr *hdr;
    const u_char *data;
    int ok;

    Py_BEGIN_ALLOW_THREADS
        ok = pcap_next_ex(self->pd, &hdr, &data);
    Py_END_ALLOW_THREADS

    switch(ok) {
    case 1:
        // TODO: do something more with the header...
        return Py_BuildValue("y#", data, hdr->caplen);
    case 0:
    case -2:
        // case 0 and -2 should be mutually exclusive, so None has the same meaning...
        Py_RETURN_NONE;
    case -1:
        PyErr_SetString(PyExc_IOError, "Problem reading from pcap descriptor.");
        return NULL;
    }

    // Should never be reached...
    return NULL;
}

static PyObject * pypcap_fileno(PyPCAP_Object *self) {
    CTXCHECK;
    return Py_BuildValue("i", pcap_fileno(self->pd));
}

static PyObject * pypcap_sendpacket(PyPCAP_Object *self, PyObject *pyoPacket) {
    char *data;
    ssize_t len;
    int ok;

    ok = PyBytes_AsStringAndSize(pyoPacket, &data, &len);
    if(0 > ok) {
        return NULL;
    }

    ok = pcap_inject(self->pd, (u_char *)data, len);
    if(0 > ok) {
        PyErr_SetString(PyExc_IOError, pcap_geterr(self->pd));
        return NULL;
    }

    return Py_BuildValue("i", ok);
}

#ifdef WIN32
static PyObject * pypcap_getevent(PyPCAP_Object *self) {
    CTXCHECK;
    return Py_BuildValue("i", pcap_getevent(self->pd));
}

// Code that allows you to open a device by the name (e.g. Local Area Connection) instead of a GUID on Windows
#define REG_NETWORK_CANON "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

static int get_canonical(char *guid, char *name) {
    HKEY hkey;
    HRESULT hr;
    char path[MAX_PATH];
    DWORD len;

    sprintf(path, REG_NETWORK_CANON "\\%s\\Connection", guid);

    hr = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE, &hkey);
    if(hr != ERROR_SUCCESS) {
        return -1;
    }

    len = MAX_PATH;

    hr = RegQueryValueEx(
        hkey,
        "Name",
        NULL,
        NULL,
        (BYTE *)name,
        &len
        );

    RegCloseKey(hkey);

    return hr != ERROR_SUCCESS ? -1 : 0;
}

static int get_guid(char *name, char *guid) {
    HKEY hkey_base;
    HKEY hkey_connection;
    HRESULT hr;
    char path[514];
    char cannon[260];
    char uid[256];
    int idx;
    DWORD klen;
    DWORD vlen;

    hr = RegOpenKeyEx(HKEY_LOCAL_MACHINE, REG_NETWORK_CANON, 0, KEY_ENUMERATE_SUB_KEYS, &hkey_base);
    if(hr != ERROR_SUCCESS) {
        return -1;
    }

    idx = 0;
    while(1) {
        klen = 256;

        hr = RegEnumKeyEx(hkey_base, idx++, guid, &klen, NULL, NULL, NULL, NULL);
        if(hr != ERROR_SUCCESS && hr != ERROR_MORE_DATA) {
            break;
        }

        if(klen != 38 || guid[0] != '{') {
            continue;
        }

        sprintf(path, "%s\\Connection", guid);

        hr = RegOpenKeyEx(hkey_base, path, 0, KEY_QUERY_VALUE, &hkey_connection);
        if(hr != ERROR_SUCCESS) {
            break;
        }

        vlen = 260;

        hr = RegQueryValueEx(hkey_connection, "Name", NULL, NULL, (BYTE *)cannon, &vlen);
        if(hr != ERROR_SUCCESS) {
            break;
        }

        RegCloseKey(hkey_connection);

        if(!stricmp(cannon, name)) {
            sprintf(uid, "\\Device\\NPF_%s", guid);
            strcpy(guid, uid);
            RegCloseKey(hkey_base);
            return 0;
        }
    }

    RegCloseKey(hkey_base);
    return -1;
}

#endif // WIN32
