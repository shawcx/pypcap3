#include "pypcap.h"

#define CTXCHECK if(NULL == self->pd) { PyErr_SetString(pypcap_error, "no device opened"); return NULL; }


PyObject *pypcap_error;


PyMODINIT_FUNC PyInit_pypcap() {
    int ok;

    PyObject *mod = PyModule_Create(&PyPCAP_module);
    if(NULL == mod) {
        return NULL;
    }

    pypcap_error = PyErr_NewException("pypcap.error", NULL, NULL);
    Py_INCREF(pypcap_error);
    PyModule_AddObject(mod, "error", pypcap_error);

    ok = PyType_Ready(&PyPCAP_Type);
    if(0 > ok) {
        return NULL;
    }

    Py_INCREF(&PyPCAP_Type);

    // PCAP DIRECTIONS
    PyModule_AddIntConstant(mod, "D_IN",    PCAP_D_IN);
    PyModule_AddIntConstant(mod, "D_OUT",   PCAP_D_OUT);
    PyModule_AddIntConstant(mod, "D_INOUT", PCAP_D_INOUT);

    return mod;
}


static PyObject * pypcap_version(PyObject *self) {
    return PyUnicode_FromString(pcap_lib_version());
}


static PyObject * pypcap_find(PyObject *self) {
    PyObject *name;
    PyObject *value;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ok;

#ifdef WIN32
    char canonical[MAX_PATH];
#endif // WIN32

    // Returns a linked list of all interfaces in the system
    pcap_if_t *interfaces;
    ok = pcap_findalldevs(&interfaces, errbuf);
    if(0 > ok) {
        PyErr_SetString(pypcap_error, errbuf);
        return NULL;
    }

    // Create empty dictionary
    PyObject *pyoDevDict = PyDict_New();

    // Iterate through all interfaces
    pcap_if_t *current = interfaces;
    while(current) {
        // Create an empty dictionary for all the addresses associated with an interface
        PyObject *dict = PyDict_New();

        // TODO: create list of addresses
        pcap_addr_t *address = current->addresses;
        while(address) {
            struct sockaddr *sa = address->addr;
            struct sockaddr_in *sai;
            if(AF_INET == sa->sa_family) {
                sai = (struct sockaddr_in *)address->addr;
                if(NULL != sai) {
                    value = PyUnicode_FromString(inet_ntoa(sai->sin_addr));
                    PyDict_SetItemString(dict, "ip", value);
                    Py_DECREF(value);
                }

                sai = (struct sockaddr_in *)address->netmask;
                if(NULL != sai) {
                    value = PyUnicode_FromString(inet_ntoa(sai->sin_addr));
                    PyDict_SetItemString(dict, "netmask", value);
                    Py_DECREF(value);
                }

                sai = (struct sockaddr_in *)address->broadaddr;
                if(NULL != sai) {
                    value = PyUnicode_FromString(inet_ntoa(sai->sin_addr));
                    PyDict_SetItemString(dict, "broadcast", value);
                    Py_DECREF(value);
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
        name = PyUnicode_FromString(canonical);
#else
        name = PyUnicode_FromString(current->name);
#endif // WIN32
        PyDict_SetItem(pyoDevDict, name, dict);
        Py_DECREF(name);
        Py_DECREF(dict);

        current = current->next;
    }

    // Free the linked list
    pcap_freealldevs(interfaces);

    // Return the dictionary of interfaces
    return pyoDevDict;
}


static PyObject * pypcap_mac(PyObject *self, PyObject *interface) {
    int ok;

    ok = PyUnicode_Check(interface);
    if(FALSE == ok) {
        PyErr_SetString(pypcap_error, "interface must be a string");
        return NULL;
    }

#ifdef WIN32
    Py_RETURN_NONE;
#endif // WIN32

#ifdef MACOS
    int mib[6];
    size_t len;
    char *buff;
    uint8_t *ptr;
    struct if_msghdr   *ifm;
    struct sockaddr_dl *sdl;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_LINK;
    mib[4] = NET_RT_IFLIST;
    mib[5] = if_nametoindex(PyUnicode_AsUTF8(interface));
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
#else // LINUX
    struct ifreq ifr;

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, PyUnicode_AsUTF8(interface), IFNAMSIZ-1);
    ifr.ifr_name[IFNAMSIZ-1] = 0;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(0 > fd) {
        return NULL;
    }

    ok = ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);

    if(0 > ok) {
        PyErr_SetString(pypcap_error, strerror(errno));
        return NULL;
    }

    return PyBytes_FromStringAndSize((char *)ifr.ifr_hwaddr.sa_data, 6);
#endif // LINUX

}


static PyPCAP * pypcap_open_live(PyObject *self, PyObject *arguments) {
    char *inteface = NULL;
    int snaplen = DEFAULT_SNAPLEN;
    int promisc = DEFAULT_PROMISC;
    int to_ms   = DEFAULT_TO_MS;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ok;

    ok = PyArg_ParseTuple(arguments, "s|iii", &inteface, &snaplen, &promisc, &to_ms);
    if(FALSE == ok) {
        return NULL;
    }

#ifdef WIN32
    char guid[MAX_PATH];
    if(0 > get_guid(inteface, guid)) {
        PyErr_SetString(pypcap_error, "unknown interface");
        return NULL;
    }
#endif // WIN32

    PyPCAP *pypcap = (PyPCAP *)PyObject_CallObject((PyObject *)&PyPCAP_Type, NULL);
    if(NULL == pypcap) {
        return NULL;
    }

#ifdef WIN32
    pypcap->pd = pcap_open_live(guid, snaplen, promisc, to_ms, errbuf);
#else
    pypcap->pd = pcap_open_live(inteface, snaplen, promisc, to_ms, errbuf);
#endif
    if(NULL == pypcap->pd) {
        PyErr_SetString(pypcap_error, errbuf);
        return NULL;
    }

#ifdef WIN32
    pcap_setmintocopy(pypcap->pd, 14);
#endif // WIN32

    return pypcap;
}


static PyPCAP * pypcap_open_file(PyObject *self, PyObject *filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    int ok;

    ok = PyUnicode_Check(filename);
    if(FALSE == ok) {
        PyErr_SetString(pypcap_error, "filename must be a string");
        return NULL;
    }

    PyPCAP *pypcap = (PyPCAP *)PyObject_CallObject((PyObject *)&PyPCAP_Type, NULL);
    if(NULL == pypcap) {
        return NULL;
    }

    pypcap->pd = pcap_open_offline(PyUnicode_AsUTF8(filename), errbuf);
    if(NULL == pypcap->pd) {
        PyErr_SetString(pypcap_error, errbuf);
        return NULL;
    }

    return pypcap;
}


static PyPCAP * pypcap_create(PyObject *self, PyObject *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    int ok;

    ok = PyUnicode_Check(interface);
    if(FALSE == ok) {
        PyErr_SetString(pypcap_error, "interface must be a string");
        return NULL;
    }

    PyPCAP *pypcap = (PyPCAP *)PyObject_CallObject((PyObject *)&PyPCAP_Type, NULL);
    if(NULL == pypcap) {
        return NULL;
    }

    pypcap->pd = pcap_create(PyUnicode_AsUTF8(interface), errbuf);
    if(NULL == pypcap->pd) {
        PyErr_SetString(pypcap_error, errbuf);
        return NULL;
    }

    return pypcap;
}


static int pypcap_init(PyPCAP *self, PyObject *args, PyObject *kwds) {
    self->pd = NULL;
    return 0;
}


static void pypcap_dealloc(PyPCAP *self) {
    if(NULL != self->pd) {
        pcap_close(self->pd);
        self->pd = NULL;
    }
    PyObject_Del(self);
}


static PyObject * pypcap_activate(PyPCAP *self) {
    CTXCHECK

    int ok = pcap_activate(self->pd);
    if(0 > ok) {
        PyErr_SetString(pypcap_error, pcap_statustostr(ok));
        return NULL;
    }
    else if(0 < ok) {
        return PyUnicode_FromString(pcap_statustostr(ok));

    }
    Py_RETURN_NONE;
}


static PyObject * pypcap_snapshot(PyPCAP *self) {
    CTXCHECK
    int snaplen = pcap_snapshot(self->pd);
    if(0 > snaplen) {
        PyErr_SetString(pypcap_error, pcap_statustostr(snaplen));
        return NULL;
    }
    return PyLong_FromLong(snaplen);
}


static PyObject * pypcap_close(PyPCAP *self) {
    if(NULL != self->pd) {
        pcap_close(self->pd);
        self->pd = NULL;
    }
    Py_RETURN_NONE;
}


static PyObject * pypcap_stats(PyPCAP *self) {
    struct pcap_stat ps;

    CTXCHECK

    if(-1 == pcap_stats(self->pd, &ps)) {
        PyErr_SetString(pypcap_error, pcap_geterr(self->pd));
        return NULL;
    }

    return Py_BuildValue("III", ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
}


static PyObject * pypcap_geterr(PyPCAP *self) {
    return PyUnicode_FromString(pcap_geterr(self->pd));
}


static PyObject * pypcap_list_datalinks(PyPCAP *self) {
    int *dlts;

    CTXCHECK

    int len = pcap_list_datalinks(self->pd, &dlts);
    if(0 > len) {
        PyErr_SetString(pypcap_error, pcap_geterr(self->pd));
        return NULL;
    }

    PyObject *links = PyList_New(len);

    for(int idx = 0; idx < len; ++idx) {
        PyObject *value = PyTuple_New(3);
        PyTuple_SET_ITEM(value, 0, PyLong_FromLong(dlts[idx]));
        PyTuple_SET_ITEM(value, 1, PyUnicode_FromString(pcap_datalink_val_to_name(dlts[idx])));
        PyTuple_SET_ITEM(value, 2, PyUnicode_FromString(pcap_datalink_val_to_description(dlts[idx])));
        PyList_SET_ITEM(links, idx, value);
    }

    pcap_free_datalinks(dlts);

    return links;
}


static PyObject * pypcap_datalink(PyPCAP *self) {
    CTXCHECK
    int dlt = pcap_datalink(self->pd);
    return Py_BuildValue("iss", dlt, pcap_datalink_val_to_name(dlt), pcap_datalink_val_to_description(dlt));
}


static PyObject * pypcap_set_snaplen(PyPCAP *self, PyObject *snaplen) {
    int ok;

    CTXCHECK

    ok = PyLong_Check(snaplen);
    if(FALSE == ok) {
        PyErr_SetString(pypcap_error, "snaplen must be an integer");
        return NULL;
    }

    ok = pcap_set_snaplen(self->pd, PyLong_AsLong(snaplen));
    if(0 > ok) {
        PyErr_SetString(pypcap_error, pcap_statustostr(ok));
        return NULL;
    }

    Py_RETURN_NONE;
}


static PyObject * pypcap_set_promisc(PyPCAP *self, PyObject *promisc) {
    int ok;

    CTXCHECK

    ok = PyLong_Check(promisc);
    if(FALSE == ok) {
        PyErr_SetString(pypcap_error, "promisc must be boolean or integer");
        return NULL;
    }

    ok = pcap_set_promisc(self->pd, PyLong_AsLong(promisc));
    if(0 > ok) {
        PyErr_SetString(pypcap_error, pcap_statustostr(ok));
        return NULL;
    }

    Py_RETURN_NONE;
}


static PyObject * pypcap_setnonblock(PyPCAP *self, PyObject *blocking) {
    char errbuf[PCAP_ERRBUF_SIZE];
    int ok;

    CTXCHECK

    ok = PyLong_Check(blocking);
    if(FALSE == ok) {
        PyErr_SetString(pypcap_error, "blocking must be boolean or integer");
        return NULL;
    }

    ok = pcap_setnonblock(self->pd, PyLong_AsLong(blocking), errbuf);
    if(0 > ok) {
        PyErr_SetString(pypcap_error, errbuf);
        return NULL;
    }

    Py_RETURN_NONE;
}


static PyObject * pypcap_getnonblock(PyPCAP *self) {
    char errbuf[PCAP_ERRBUF_SIZE];

    CTXCHECK

    int block = pcap_getnonblock(self->pd, errbuf);
    if(0 > block) {
        PyErr_SetString(pypcap_error, errbuf);
        return NULL;
    }

    return PyLong_FromLong(block);
}


static PyObject * pypcap_setdirection(PyPCAP *self, PyObject *direction) {
#ifdef WIN32
    Py_RETURN_FALSE;
#else // !WIN32
    int ok;

    CTXCHECK

    ok = PyLong_Check(direction);
    if(FALSE == ok) {
        PyErr_SetString(pypcap_error, "direction must be an integer.");
        return NULL;
    }

    pcap_setdirection(self->pd, PyLong_AsLong(direction));

    Py_RETURN_TRUE;
#endif // WIN32
}


static void pypcap_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data) {
    PyObject *retval = PyObject_CallFunction((PyObject *)user, "y#", pkt_data, pkt_header->caplen);
    if(retval) {
        Py_DECREF(retval);
    } else {
        PyErr_Print();
        PyErr_Clear();
    }
}

//
// Used by pypcap_loop to break immediately on Ctrl-C
//
typedef void (*sigfunc)(int);
static pcap_t *_g_pd = NULL;

static void sig_handler(int signo) {
    if(signo == SIGINT) {
        pcap_breakloop(_g_pd);
    }
}


static PyObject * pypcap_loop(PyPCAP *self, PyObject *arguments) {
    PyObject *callback;
    int cnt = -1;
    int ok;

    CTXCHECK

    ok = PyArg_ParseTuple(arguments, "O|i", &callback, &cnt);
    if(FALSE == ok) {
        return NULL;
    }

    ok = PyCallable_Check(callback);
    if(FALSE == ok) {
        PyErr_SetString(pypcap_error, "callback needs to be callable");
        return NULL;
    }

    if(NULL != _g_pd) {
        PyErr_SetString(pypcap_error, "only one pcap_loop can run at a time");
        return NULL;
    }

    _g_pd = self->pd;
    // install temporary signal handler
    sigfunc _pyhandler;
    _pyhandler = signal(SIGINT, sig_handler);
    ok = pcap_loop(self->pd, cnt, pypcap_handler, (u_char *)callback);
    signal(SIGINT, _pyhandler);
    _g_pd = NULL;

    Py_RETURN_NONE;
}


static PyObject * pypcap_breakloop(PyPCAP *self) {
    CTXCHECK
    pcap_breakloop(self->pd);
    Py_RETURN_NONE;
}


static PyObject * pypcap_next(PyPCAP *self) {
    struct pcap_pkthdr *hdr;
    const u_char *data;
    int ok;

    Py_BEGIN_ALLOW_THREADS
        ok = pcap_next_ex(self->pd, &hdr, &data);
    Py_END_ALLOW_THREADS

    switch(ok) {
    case 1:
        // TODO: do something more with the header...
        return PyBytes_FromStringAndSize((const char *)data, hdr->caplen);
    case 0:
    case -2:
        // case 0 and -2 should be mutually exclusive, so None has the same meaning...
        Py_RETURN_NONE;
    case -1:
        PyErr_SetString(pypcap_error, "problem reading from pcap descriptor");
        return NULL;
    }

    // Should never be reached...
    return NULL;
}


static PyObject * pypcap_fileno(PyPCAP *self) {
    CTXCHECK
    return PyLong_FromLong(pcap_fileno(self->pd));
}


static PyObject * pypcap_inject(PyPCAP *self, PyObject *packet) {
    uint8_t *data;
    ssize_t len;
    int ok;

    ok = PyBytes_AsStringAndSize(packet, (char **)&data, &len);
    if(0 > ok) {
        return NULL;
    }

    ok = pcap_inject(self->pd, data, len);
    if(0 > ok) {
        PyErr_SetString(pypcap_error, pcap_geterr(self->pd));
        return NULL;
    }

    return PyLong_FromLong(ok);
}

#ifdef WIN32

static PyObject * pypcap_getevent(PyPCAP *self) {
    CTXCHECK
    return PyLong_FromLong(pcap_getevent(self->pd));
}

// Code that allows you to open a device by the name (e.g. Local Area Connection) instead of a GUID on Windows
#define REG_NETWORK_CANON "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

static int get_canonical(char *guid, char *name) {
    HKEY hkey;
    HRESULT hr;
    char path[MAX_PATH+1];
    DWORD len;

    snprintf(path, MAX_PATH, REG_NETWORK_CANON "\\%s\\Connection", guid);

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
    char path[MAX_PATH+1];
    char cannon[MAX_PATH+1];
    char uid[MAX_PATH+1];
    int idx;
    DWORD klen;
    DWORD vlen;

    hr = RegOpenKeyEx(HKEY_LOCAL_MACHINE, REG_NETWORK_CANON, 0, KEY_ENUMERATE_SUB_KEYS, &hkey_base);
    if(hr != ERROR_SUCCESS) {
        return -1;
    }

    idx = 0;
    while(1) {
        klen = MAX_PATH;

        hr = RegEnumKeyEx(hkey_base, idx++, guid, &klen, NULL, NULL, NULL, NULL);
        if(hr != ERROR_SUCCESS && hr != ERROR_MORE_DATA) {
            break;
        }

        if(klen != 38 || guid[0] != '{') {
            continue;
        }

        snprintf(path, MAX_PATH, "%s\\Connection", guid);

        hr = RegOpenKeyEx(hkey_base, path, 0, KEY_QUERY_VALUE, &hkey_connection);
        if(hr != ERROR_SUCCESS) {
            break;
        }

        vlen = MAX_PATH;

        hr = RegQueryValueEx(hkey_connection, "Name", NULL, NULL, (BYTE *)cannon, &vlen);
        if(hr != ERROR_SUCCESS) {
            break;
        }

        RegCloseKey(hkey_connection);

        if(!stricmp(cannon, name)) {
            snprintf(uid, MAX_PATH, "\\Device\\NPF_%s", guid);
            strcpy(guid, uid);
            RegCloseKey(hkey_base);
            return 0;
        }
    }

    RegCloseKey(hkey_base);
    return -1;
}

#endif // WIN32
