#include "pypcap.h"

#define CTXCHECK if(NULL == self->pd) { PyErr_SetString(pypcap_error, "no device opened"); return NULL; }
#define BUSYCHECK if(self->busy) { PyErr_SetString(pypcap_error, "handle is busy in loop() or next()"); return NULL; }


PyObject *pypcap_error;


PyMODINIT_FUNC PyInit_pypcap3(void) {
    int ok;

    PyObject *mod = PyModule_Create(&PyPCAP_module);
    if(NULL == mod) {
        return NULL;
    }

    pypcap_error = PyErr_NewException("pypcap3.error", NULL, NULL);
    Py_INCREF(pypcap_error);
    PyModule_AddObject(mod, "error", pypcap_error);

    ok = PyType_Ready(&PyPCAP_Type);
    if(0 <= ok) {
        ok = PyType_Ready(&PyBPF_Type);
    }
    if(0 <= ok) {
        ok = PyType_Ready(&PyDumper_Type);
    }
    if(0 > ok) {
        Py_DECREF(mod);
        return NULL;
    }

    Py_INCREF(&PyPCAP_Type);

    // PCAP DIRECTIONS
    PyModule_AddIntConstant(mod, "D_IN",    PCAP_D_IN);
    PyModule_AddIntConstant(mod, "D_OUT",   PCAP_D_OUT);
    PyModule_AddIntConstant(mod, "D_INOUT", PCAP_D_INOUT);

    // INTERFACE FLAGS, FROM find()
    PyModule_AddIntConstant(mod, "IF_LOOPBACK",          PCAP_IF_LOOPBACK);
    PyModule_AddIntConstant(mod, "IF_UP",                PCAP_IF_UP);
    PyModule_AddIntConstant(mod, "IF_RUNNING",           PCAP_IF_RUNNING);
    PyModule_AddIntConstant(mod, "IF_WIRELESS",          PCAP_IF_WIRELESS);
    PyModule_AddIntConstant(mod, "IF_CONNECTION_STATUS", PCAP_IF_CONNECTION_STATUS);
    PyModule_AddIntConstant(mod, "IF_CONNECTION_STATUS_UNKNOWN",        PCAP_IF_CONNECTION_STATUS_UNKNOWN);
    PyModule_AddIntConstant(mod, "IF_CONNECTION_STATUS_CONNECTED",      PCAP_IF_CONNECTION_STATUS_CONNECTED);
    PyModule_AddIntConstant(mod, "IF_CONNECTION_STATUS_DISCONNECTED",   PCAP_IF_CONNECTION_STATUS_DISCONNECTED);
    PyModule_AddIntConstant(mod, "IF_CONNECTION_STATUS_NOT_APPLICABLE", PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE);

    // TIMESTAMP PRECISIONS AND SOURCES
    PyModule_AddIntConstant(mod, "TSTAMP_PRECISION_MICRO",  PCAP_TSTAMP_PRECISION_MICRO);
    PyModule_AddIntConstant(mod, "TSTAMP_PRECISION_NANO",   PCAP_TSTAMP_PRECISION_NANO);
    PyModule_AddIntConstant(mod, "TSTAMP_HOST",             PCAP_TSTAMP_HOST);
    PyModule_AddIntConstant(mod, "TSTAMP_HOST_LOWPREC",     PCAP_TSTAMP_HOST_LOWPREC);
    PyModule_AddIntConstant(mod, "TSTAMP_HOST_HIPREC",      PCAP_TSTAMP_HOST_HIPREC);
    PyModule_AddIntConstant(mod, "TSTAMP_ADAPTER",          PCAP_TSTAMP_ADAPTER);
    PyModule_AddIntConstant(mod, "TSTAMP_ADAPTER_UNSYNCED", PCAP_TSTAMP_ADAPTER_UNSYNCED);
#ifdef PCAP_TSTAMP_HOST_HIPREC_UNSYNCED
    PyModule_AddIntConstant(mod, "TSTAMP_HOST_HIPREC_UNSYNCED", PCAP_TSTAMP_HOST_HIPREC_UNSYNCED);
#endif

    return mod;
}


static PyObject * pypcap_version(PyObject *self) {
    return PyUnicode_FromString(pcap_lib_version());
}


// text form of an IPv4 or IPv6 address, read as the given family (a netmask's
// own sa_family isn't always set). BSDs trim trailing zero bytes from netmasks,
// so sa_len can be 5 for 255.0.0.0; libpcap copies them at the address's size,
// so the bytes past sa_len are whatever followed in getifaddrs()'s buffer.
// Copy only sa_len bytes into zeroed storage so those bytes count as zero.
static PyObject * address_string(int family, const struct sockaddr *sa) {
    struct sockaddr_storage copy;
    char text[INET6_ADDRSTRLEN];
    const void *addr;

    if(NULL == sa) {
        Py_RETURN_NONE;
    }

    memset(&copy, 0, sizeof(copy));
#ifdef SIN6_LEN
    memcpy(&copy, sa, sa->sa_len < sizeof(copy) ? sa->sa_len : sizeof(copy));
#else
    memcpy(&copy, sa, AF_INET6 == family ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
#endif // SIN6_LEN

    if(AF_INET6 == family) {
        addr = &((struct sockaddr_in6 *)&copy)->sin6_addr;
    }
    else {
        addr = &((struct sockaddr_in *)&copy)->sin_addr;
    }

    if(NULL == inet_ntop(family, addr, text, sizeof(text))) {
        Py_RETURN_NONE;
    }

    return PyUnicode_FromString(text);
}


// {"description", "flags", "addresses": [{"family", "addr", "netmask",
// "broadcast", "dstaddr"}, ...]}, plus the original flat "ip", "netmask" and
// "broadcast" keys, taken from the device's last IPv4 address
static PyObject * describe_device(pcap_if_t *device) {
    PyObject *entry = NULL;
    PyObject *addresses = PyList_New(0);
    PyObject *result = Py_BuildValue("{s:z,s:I,s:O}",
        "description", device->description,
        "flags",       (unsigned int)device->flags,
        "addresses",   addresses ? addresses : Py_None);
    if(NULL == addresses || NULL == result) {
        goto error;
    }

    for(pcap_addr_t *address = device->addresses; address; address = address->next) {
        if(NULL == address->addr) {
            continue;
        }
        int family = address->addr->sa_family;
        if(AF_INET != family && AF_INET6 != family) {
            continue;
        }

        entry = Py_BuildValue("{s:i,s:N,s:N,s:N,s:N}",
            "family",    family,
            "addr",      address_string(family, address->addr),
            "netmask",   address_string(family, address->netmask),
            "broadcast", address_string(family, address->broadaddr),
            "dstaddr",   address_string(family, address->dstaddr));
        if(NULL == entry || 0 > PyList_Append(addresses, entry)) {
            goto error;
        }

        if(AF_INET == family) {
            static const char *flat[][2] = { { "addr", "ip" }, { "netmask", "netmask" }, { "broadcast", "broadcast" } };
            for(int idx = 0; idx < 3; ++idx) {
                PyObject *value = PyDict_GetItemString(entry, flat[idx][0]);
                if(Py_None != value && 0 > PyDict_SetItemString(result, flat[idx][1], value)) {
                    goto error;
                }
            }
        }

        Py_CLEAR(entry);
    }

    Py_DECREF(addresses);
    return result;

error:
    Py_XDECREF(entry);
    Py_XDECREF(addresses);
    Py_XDECREF(result);
    return NULL;
}


static PyObject * pypcap_find(PyObject *self) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;
    int ok;

#ifdef WIN32
    char canonical[MAX_PATH];
#endif // WIN32

    ok = pcap_findalldevs(&interfaces, errbuf);
    if(0 > ok) {
        PyErr_SetString(pypcap_error, errbuf);
        return NULL;
    }

    PyObject *devices = PyDict_New();
    if(NULL == devices) {
        pcap_freealldevs(interfaces);
        return NULL;
    }

    for(pcap_if_t *current = interfaces; current; current = current->next) {
#ifdef WIN32
        // name devices by their connection name, skipping any without one
        if(0 > get_canonical(current->name + 12, canonical)) {
            continue;
        }
        const char *name = canonical;
#else
        const char *name = current->name;
#endif // WIN32

        PyObject *device = describe_device(current);
        if(NULL == device || 0 > PyDict_SetItemString(devices, name, device)) {
            Py_XDECREF(device);
            Py_DECREF(devices);
            pcap_freealldevs(interfaces);
            return NULL;
        }
        Py_DECREF(device);
    }

    pcap_freealldevs(interfaces);

    return devices;
}


static PyObject * pypcap_mac(PyObject *self, PyObject *interface) {
    int ok;

    ok = PyUnicode_Check(interface);
    if(FALSE == ok) {
        PyErr_SetString(pypcap_error, "interface must be a string");
        return NULL;
    }

#if defined(WIN32)
    Py_RETURN_NONE;
#elif defined(MACOS)
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

    PyObject *mac = PyBytes_FromStringAndSize((char *)ptr, 6);
    free(buff);

    return mac;
#else // LINUX
    struct ifreq ifr;

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, PyUnicode_AsUTF8(interface), IFNAMSIZ-1);
    ifr.ifr_name[IFNAMSIZ-1] = 0;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(0 > fd) {
        PyErr_SetString(pypcap_error, strerror(errno));
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
        Py_DECREF(pypcap);
        return NULL;
    }

#ifdef WIN32
    pcap_setmintocopy(pypcap->pd, 14);
#endif // WIN32

    pypcap->live = 1;

    return pypcap;
}


//
// open_file() and dump_open() take a path (str, bytes or os.PathLike), a file
// object with fileno(), or a descriptor such as a pipe from subprocess. A path
// sets *path to a bytes object; otherwise *path is NULL and *fd is set.
//
static int parse_target(PyObject *target, PyObject **path, int *fd) {
    *path = NULL;
    *fd   = -1;

    if(PyLong_Check(target) || PyObject_HasAttrString(target, "fileno")) {
#ifdef WIN32
        // the FILE would belong to a different C runtime than wpcap.dll's
        PyErr_SetString(pypcap_error, "file objects and descriptors aren't supported on Windows; pass a path");
        return -1;
#else
        PyObject *number = PyLong_Check(target) ? (Py_INCREF(target), target) : PyObject_CallMethod(target, "fileno", NULL);
        if(NULL == number) {
            return -1;
        }
        long value = PyLong_AsLong(number);
        Py_DECREF(number);
        if(-1 == value && PyErr_Occurred()) {
            return -1;
        }
        *fd = (int)value;
        return 0;
#endif // WIN32
    }

    if(0 == PyUnicode_FSConverter(target, path)) {
        if(PyErr_ExceptionMatches(PyExc_TypeError)) {
            PyErr_SetString(pypcap_error, "expected a path, a file object or a file descriptor");
        }
        return -1;
    }

    return 0;
}


#ifndef WIN32
// a FILE on a duplicate of fd, so closing the handle or dumper leaves the
// caller's descriptor open. It bypasses any buffering in a Python file object.
static FILE * dup_file(int fd, const char *mode) {
    int copy = dup(fd);
    if(0 > copy) {
        PyErr_SetString(pypcap_error, strerror(errno));
        return NULL;
    }

    FILE *fp = fdopen(copy, mode);
    if(NULL == fp) {
        PyErr_SetString(pypcap_error, strerror(errno));
        close(copy);
        return NULL;
    }

    return fp;
}
#endif // WIN32


static PyPCAP * pypcap_open_file(PyObject *self, PyObject *arguments, PyObject *keywords) {
    static char *kwlist[] = { "file", "precision", NULL };
    PyObject *target;
    PyObject *path;
    int precision = PCAP_TSTAMP_PRECISION_MICRO;
    FILE *fp = NULL;
    pcap_t *pd;
    char errbuf[PCAP_ERRBUF_SIZE];
    int fd;
    int ok;

    ok = PyArg_ParseTupleAndKeywords(arguments, keywords, "O|i", kwlist, &target, &precision);
    if(FALSE == ok) {
        return NULL;
    }

    if(0 > parse_target(target, &path, &fd)) {
        return NULL;
    }

#ifndef WIN32
    if(NULL == path) {
        fp = dup_file(fd, "rb");
        if(NULL == fp) {
            return NULL;
        }
    }
#endif // WIN32

    PyPCAP *pypcap = (PyPCAP *)PyObject_CallObject((PyObject *)&PyPCAP_Type, NULL);
    if(NULL == pypcap) {
        Py_XDECREF(path);
        if(NULL != fp) {
            fclose(fp);
        }
        return NULL;
    }

    // Reading the file header blocks on a pipe or FIFO until the writer sends
    // it, and the writer may be another thread here, so release the GIL.
    // libpcap scales the file's timestamps to the requested precision.
    const char *name = path ? PyBytes_AS_STRING(path) : NULL;
    Py_BEGIN_ALLOW_THREADS
#ifndef WIN32
    if(NULL != fp) {
        pd = pcap_fopen_offline_with_tstamp_precision(fp, precision, errbuf);
    }
    else
#endif // WIN32
    {
        pd = pcap_open_offline_with_tstamp_precision(name, precision, errbuf);
    }
    Py_END_ALLOW_THREADS
    Py_XDECREF(path);

    if(NULL == pd) {
        // on success pcap_close() closes the FILE; on failure it is still ours
        if(NULL != fp) {
            fclose(fp);
        }
        PyErr_SetString(pypcap_error, errbuf);
        Py_DECREF(pypcap);
        return NULL;
    }

    pypcap->pd = pd;
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
        Py_DECREF(pypcap);
        return NULL;
    }

    pypcap->live = 1;

    return pypcap;
}


static PyPCAP * pypcap_open_dead(PyObject *self, PyObject *arguments, PyObject *keywords) {
    static char *kwlist[] = { "linktype", "snaplen", "precision", NULL };
    int linktype  = DLT_EN10MB;
    int snaplen   = DEFAULT_SNAPLEN;
    int precision = PCAP_TSTAMP_PRECISION_MICRO;
    int ok;

    ok = PyArg_ParseTupleAndKeywords(arguments, keywords, "|iii", kwlist, &linktype, &snaplen, &precision);
    if(FALSE == ok) {
        return NULL;
    }

    PyPCAP *pypcap = (PyPCAP *)PyObject_CallObject((PyObject *)&PyPCAP_Type, NULL);
    if(NULL == pypcap) {
        return NULL;
    }

    pypcap->pd = pcap_open_dead_with_tstamp_precision(linktype, snaplen, precision);
    if(NULL == pypcap->pd) {
        Py_DECREF(pypcap);
        PyErr_NoMemory();
        return NULL;
    }

    return pypcap;
}


static PyObject * pypcap_lookupnet(PyObject *self, PyObject *interface) {
    bpf_u_int32 net;
    bpf_u_int32 mask;
    struct in_addr addr;
    char network[INET_ADDRSTRLEN];
    char netmask[INET_ADDRSTRLEN];
    char errbuf[PCAP_ERRBUF_SIZE];
    int ok;

    ok = PyUnicode_Check(interface);
    if(FALSE == ok) {
        PyErr_SetString(pypcap_error, "interface must be a string");
        return NULL;
    }

    const char *name = PyUnicode_AsUTF8(interface);
    if(NULL == name) {
        return NULL;
    }

#ifdef WIN32
    char guid[MAX_PATH];
    if(0 > get_guid((char *)name, guid)) {
        PyErr_SetString(pypcap_error, "unknown interface");
        return NULL;
    }
    name = guid;
#endif // WIN32

    ok = pcap_lookupnet(name, &net, &mask, errbuf);
    if(0 > ok) {
        PyErr_SetString(pypcap_error, errbuf);
        return NULL;
    }

    // both come back in network byte order, ready for inet_ntop
    addr.s_addr = net;
    inet_ntop(AF_INET, &addr, network, sizeof(network));
    addr.s_addr = mask;
    inet_ntop(AF_INET, &addr, netmask, sizeof(netmask));

    return Py_BuildValue("ss", network, netmask);
}


//
// Name <-> number lookups for link types and timestamp sources
//

static int int_argument(PyObject *value, const char *what, int *number) {
    if(!PyLong_Check(value)) {
        PyErr_Format(pypcap_error, "%s must be an integer", what);
        return -1;
    }
    long result = PyLong_AsLong(value);
    if(-1 == result && PyErr_Occurred()) {
        return -1;
    }
    *number = (int)result;
    return 0;
}


static const char * str_argument(PyObject *value, const char *what) {
    if(!PyUnicode_Check(value)) {
        PyErr_Format(pypcap_error, "%s must be a string", what);
        return NULL;
    }
    return PyUnicode_AsUTF8(value);
}


static PyObject * str_or_none(const char *text) {
    if(NULL == text) {
        Py_RETURN_NONE;
    }
    return PyUnicode_FromString(text);
}


static PyObject * pypcap_datalink_name_to_val(PyObject *self, PyObject *name) {
    const char *text = str_argument(name, "name");
    if(NULL == text) {
        return NULL;
    }

    // names as in datalink(), case-insensitive, without the DLT_ prefix
    int value = pcap_datalink_name_to_val(text);
    if(0 > value) {
        PyErr_Format(pypcap_error, "unknown link type '%s'", text);
        return NULL;
    }

    return PyLong_FromLong(value);
}


static PyObject * pypcap_datalink_val_to_name(PyObject *self, PyObject *value) {
    int number;
    if(0 > int_argument(value, "link type", &number)) {
        return NULL;
    }
    return str_or_none(pcap_datalink_val_to_name(number));
}


static PyObject * pypcap_datalink_val_to_description(PyObject *self, PyObject *value) {
    int number;
    if(0 > int_argument(value, "link type", &number)) {
        return NULL;
    }
    return str_or_none(pcap_datalink_val_to_description(number));
}


static PyObject * pypcap_tstamp_type_name_to_val(PyObject *self, PyObject *name) {
    const char *text = str_argument(name, "name");
    if(NULL == text) {
        return NULL;
    }

    int value = pcap_tstamp_type_name_to_val(text);
    if(0 > value) {
        PyErr_Format(pypcap_error, "unknown timestamp type '%s'", text);
        return NULL;
    }

    return PyLong_FromLong(value);
}


static PyObject * pypcap_tstamp_type_val_to_name(PyObject *self, PyObject *value) {
    int number;
    if(0 > int_argument(value, "timestamp type", &number)) {
        return NULL;
    }
    return str_or_none(pcap_tstamp_type_val_to_name(number));
}


static int pypcap_init(PyPCAP *self, PyObject *args, PyObject *kwds) {
    self->pd   = NULL;
    self->busy = 0;
    self->live = 0;
    return 0;
}


static void pypcap_dealloc(PyPCAP *self) {
    if(NULL != self->pd) {
        pcap_close(self->pd);
        self->pd = NULL;
    }
    Py_TYPE(self)->tp_free((PyObject *)self);
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
    BUSYCHECK
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
    CTXCHECK
    return PyUnicode_FromString(pcap_geterr(self->pd));
}


// (dlt, name, description); libpcap returns NULL names for DLTs it doesn't know, which become None
static PyObject * datalink_tuple(int dlt) {
    return Py_BuildValue("izz", dlt, pcap_datalink_val_to_name(dlt), pcap_datalink_val_to_description(dlt));
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
    if(NULL == links) {
        pcap_free_datalinks(dlts);
        return NULL;
    }

    for(int idx = 0; idx < len; ++idx) {
        PyObject *value = datalink_tuple(dlts[idx]);
        if(NULL == value) {
            Py_DECREF(links);
            pcap_free_datalinks(dlts);
            return NULL;
        }
        PyList_SET_ITEM(links, idx, value);
    }

    pcap_free_datalinks(dlts);

    return links;
}


static PyObject * pypcap_datalink(PyPCAP *self) {
    CTXCHECK
    int dlt = pcap_datalink(self->pd);
    if(0 > dlt) {
        PyErr_SetString(pypcap_error, pcap_statustostr(dlt));
        return NULL;
    }
    return datalink_tuple(dlt);
}


static PyObject * pypcap_set_datalink(PyPCAP *self, PyObject *value) {
    int dlt;

    CTXCHECK

    if(0 > int_argument(value, "link type", &dlt)) {
        return NULL;
    }

    if(0 > pcap_set_datalink(self->pd, dlt)) {
        PyErr_SetString(pypcap_error, pcap_geterr(self->pd));
        return NULL;
    }

    Py_RETURN_NONE;
}


// pcap_major_version() and friends describe a capture file; on a live handle
// libpcap returns values that mean nothing, or an error if it isn't activated
static PyObject * file_property(PyPCAP *self, int (*getter)(pcap_t *), int as_bool) {
    CTXCHECK

    int value = getter(self->pd);
    if(0 > value) {
        PyErr_SetString(pypcap_error, pcap_statustostr(value));
        return NULL;
    }

    return as_bool ? PyBool_FromLong(value) : PyLong_FromLong(value);
}


static PyObject * pypcap_major_version(PyPCAP *self) {
    return file_property(self, pcap_major_version, 0);
}


static PyObject * pypcap_minor_version(PyPCAP *self) {
    return file_property(self, pcap_minor_version, 0);
}


static PyObject * pypcap_is_swapped(PyPCAP *self) {
    return file_property(self, pcap_is_swapped, 1);
}


// the pcap_set_* options taken before activate(): an int in, None out, or
// the text of a warning such as an unsupported timestamp type
static PyObject * set_option(PyPCAP *self, PyObject *value, int (*setter)(pcap_t *, int), const char *name) {
    int ok;

    CTXCHECK

    ok = PyLong_Check(value);
    if(FALSE == ok) {
        PyErr_Format(pypcap_error, "%s must be an integer", name);
        return NULL;
    }

    long number = PyLong_AsLong(value);
    if(-1 == number && PyErr_Occurred()) {
        return NULL;
    }

    ok = setter(self->pd, (int)number);
    if(0 > ok) {
        PyErr_SetString(pypcap_error, pcap_statustostr(ok));
        return NULL;
    }
    if(0 < ok) {
        return PyUnicode_FromString(pcap_statustostr(ok));
    }

    Py_RETURN_NONE;
}


static PyObject * pypcap_set_snaplen(PyPCAP *self, PyObject *value) {
    return set_option(self, value, pcap_set_snaplen, "snaplen");
}


static PyObject * pypcap_set_promisc(PyPCAP *self, PyObject *value) {
    return set_option(self, value, pcap_set_promisc, "promisc");
}


static PyObject * pypcap_set_timeout(PyPCAP *self, PyObject *value) {
    return set_option(self, value, pcap_set_timeout, "timeout");
}


static PyObject * pypcap_set_immediate_mode(PyPCAP *self, PyObject *value) {
    return set_option(self, value, pcap_set_immediate_mode, "immediate mode");
}


static PyObject * pypcap_set_buffer_size(PyPCAP *self, PyObject *value) {
    return set_option(self, value, pcap_set_buffer_size, "buffer size");
}


static PyObject * pypcap_set_rfmon(PyPCAP *self, PyObject *value) {
    return set_option(self, value, pcap_set_rfmon, "rfmon");
}


static PyObject * pypcap_set_tstamp_type(PyPCAP *self, PyObject *value) {
    return set_option(self, value, pcap_set_tstamp_type, "timestamp type");
}


static PyObject * pypcap_set_tstamp_precision(PyPCAP *self, PyObject *value) {
    return set_option(self, value, pcap_set_tstamp_precision, "timestamp precision");
}


static PyObject * pypcap_can_set_rfmon(PyPCAP *self) {
    CTXCHECK

    // libpcap only implements this for devices; it crashes on files and open_dead() handles
    if(!self->live) {
        Py_RETURN_FALSE;
    }

    int ok = pcap_can_set_rfmon(self->pd);
    if(0 > ok) {
        PyErr_SetString(pypcap_error, PCAP_ERROR == ok ? pcap_geterr(self->pd) : pcap_statustostr(ok));
        return NULL;
    }

    return PyBool_FromLong(ok);
}


static PyObject * pypcap_list_tstamp_types(PyPCAP *self) {
    int *types;

    CTXCHECK

    int len = pcap_list_tstamp_types(self->pd, &types);
    if(0 > len) {
        PyErr_SetString(pypcap_error, pcap_geterr(self->pd));
        return NULL;
    }

    PyObject *list = PyList_New(len);
    if(NULL == list) {
        pcap_free_tstamp_types(types);
        return NULL;
    }

    for(int idx = 0; idx < len; ++idx) {
        PyObject *value = Py_BuildValue("izz", types[idx],
            pcap_tstamp_type_val_to_name(types[idx]), pcap_tstamp_type_val_to_description(types[idx]));
        if(NULL == value) {
            Py_DECREF(list);
            pcap_free_tstamp_types(types);
            return NULL;
        }
        PyList_SET_ITEM(list, idx, value);
    }

    pcap_free_tstamp_types(types);

    return list;
}


static PyObject * pypcap_get_tstamp_precision(PyPCAP *self) {
    CTXCHECK
    return PyLong_FromLong(pcap_get_tstamp_precision(self->pd));
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

    ok = pcap_setdirection(self->pd, PyLong_AsLong(direction));
    if(0 > ok) {
        PyErr_SetString(pypcap_error, pcap_geterr(self->pd));
        return NULL;
    }

    Py_RETURN_TRUE;
#endif // WIN32
}


//
// loop() and dispatch() run libpcap with the GIL released; the handler takes it
// back for each packet. An exception from the callback, or a pending signal
// such as Ctrl-C, stops the loop and is raised from loop() or dispatch().
//
typedef struct {
    PyObject      *callback;
    pcap_t        *pd;
    PyThreadState *tstate;
    pcap_dumper_t *dumper;   // write here instead of calling a callback
    int            header;   // call callback(packet, ts, orig_len) instead of callback(packet)
    int            nano;     // the handle's timestamps are in nanoseconds
    int            failed;
    int            count;    // packets handled; dispatch() returns it
} loop_ctx;

static int is_nano(pcap_t *pd) {
    return PCAP_TSTAMP_PRECISION_NANO == pcap_get_tstamp_precision(pd);
}

// seconds since the epoch; with nanosecond precision libpcap keeps nanoseconds in tv_usec
static double timestamp_seconds(const struct timeval *ts, int nano) {
    return (double)ts->tv_sec + (double)ts->tv_usec / (nano ? 1e9 : 1e6);
}

static void pypcap_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data) {
    loop_ctx *ctx = (loop_ctx *)user;
    PyObject *retval;

    // libpcap may still deliver the rest of the current buffer after pcap_breakloop
    if(ctx->failed) {
        return;
    }

    PyEval_RestoreThread(ctx->tstate);

    ctx->count++;
    if(ctx->header) {
        retval = PyObject_CallFunction(ctx->callback, "y#dI", pkt_data, (Py_ssize_t)pkt_header->caplen,
            timestamp_seconds(&pkt_header->ts, ctx->nano), (unsigned int)pkt_header->len);
    }
    else {
        retval = PyObject_CallFunction(ctx->callback, "y#", pkt_data, (Py_ssize_t)pkt_header->caplen);
    }
    Py_XDECREF(retval);
    if(NULL == retval || 0 > PyErr_CheckSignals()) {
        ctx->failed = 1;
        pcap_breakloop(ctx->pd);
    }

    ctx->tstate = PyEval_SaveThread();
}

// loop(dumper): no Python per packet, so the GIL stays released
static void dump_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data) {
    loop_ctx *ctx = (loop_ctx *)user;
    ctx->count++;
    pcap_dump((u_char *)ctx->dumper, pkt_header, pkt_data);
}

//
// SIGINT hook so Ctrl-C breaks a loop(), dispatch() or next() that is blocked
// waiting for packets. It calls pcap_breakloop and then chains to the previous
// handler (normally Python's), so the call can raise KeyboardInterrupt. Only
// one call at a time holds the hook; calls made while it is taken can be
// stopped with breakloop().
//
static pcap_t * volatile _g_pd = NULL;

#ifdef WIN32
typedef void (*sigfunc)(int);
static sigfunc _g_prev_handler;

static void sig_handler(int signo) {
    if(NULL != _g_pd) {
        pcap_breakloop(_g_pd);
    }
    if(SIG_DFL != _g_prev_handler && SIG_IGN != _g_prev_handler && SIG_ERR != _g_prev_handler) {
        _g_prev_handler(signo);
    }
}

static void hook_sigint(void)   { _g_prev_handler = signal(SIGINT, sig_handler); }
static void unhook_sigint(void) { signal(SIGINT, _g_prev_handler); }
#else // !WIN32
static struct sigaction _g_prev_action;

static void sig_handler(int signo, siginfo_t *info, void *context) {
    if(NULL != _g_pd) {
        pcap_breakloop(_g_pd);
    }
    if(_g_prev_action.sa_flags & SA_SIGINFO) {
        _g_prev_action.sa_sigaction(signo, info, context);
    }
    else if(SIG_DFL != _g_prev_action.sa_handler && SIG_IGN != _g_prev_action.sa_handler) {
        _g_prev_action.sa_handler(signo);
    }
}

static void hook_sigint(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = sig_handler;
    action.sa_flags     = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, &_g_prev_action);
}

static void unhook_sigint(void) {
    sigaction(SIGINT, &_g_prev_action, NULL);
}
#endif // WIN32

// take the hook for pd unless another call holds it; returns whether it was taken
static int acquire_sigint(pcap_t *pd) {
    if(NULL != _g_pd) {
        return 0;
    }
    _g_pd = pd;
    hook_sigint();
    return 1;
}

static void release_sigint(int hooked) {
    if(hooked) {
        unhook_sigint();
        _g_pd = NULL;
    }
}


static PyObject * run_loop(PyPCAP *self, PyObject *arguments, PyObject *keywords, int dispatch) {
    static char *kwlist[] = { "callback", "cnt", "header", NULL };
    PyObject *callback;
    int cnt = -1;
    int header = 0;
    int ok;

    CTXCHECK
    BUSYCHECK

    ok = PyArg_ParseTupleAndKeywords(arguments, keywords, "O|i$p", kwlist, &callback, &cnt, &header);
    if(FALSE == ok) {
        return NULL;
    }

    loop_ctx ctx = { callback, self->pd, NULL, NULL, header, is_nano(self->pd), 0, 0 };
    pcap_handler handler = pypcap_handler;

    // packets for a dumper go straight to pcap_dump, keeping their capture timestamps
    PyDumper *dumper = NULL;
    if(PyObject_TypeCheck(callback, &PyDumper_Type)) {
        dumper = (PyDumper *)callback;
        if(NULL == dumper->dumper) {
            PyErr_SetString(pypcap_error, "dumper is closed");
            return NULL;
        }
        if(dumper->busy) {
            PyErr_SetString(pypcap_error, "dumper is busy in loop()");
            return NULL;
        }
        handler    = dump_handler;
        ctx.dumper = dumper->dumper;
    }
    else {
        ok = PyCallable_Check(callback);
        if(FALSE == ok) {
            PyErr_SetString(pypcap_error, "callback needs to be callable");
            return NULL;
        }
    }

    int hooked = acquire_sigint(self->pd);

    self->busy = 1;
    if(dumper) {
        dumper->busy = 1;
    }
    ctx.tstate = PyEval_SaveThread();
    if(dispatch) {
        ok = pcap_dispatch(self->pd, cnt, handler, (u_char *)&ctx);
    }
    else {
        ok = pcap_loop(self->pd, cnt, handler, (u_char *)&ctx);
    }
    PyEval_RestoreThread(ctx.tstate);
    self->busy = 0;
    if(dumper) {
        dumper->busy = 0;
    }

    release_sigint(hooked);

    if(ctx.failed) {
        // the callback raised, or a signal handler did
        return NULL;
    }

    // Ctrl-C ends the loop with PCAP_ERROR_BREAK, or with PCAP_ERROR when it
    // interrupts a blocking read; either way, raise KeyboardInterrupt instead
    if(0 > ok && 0 > PyErr_CheckSignals()) {
        return NULL;
    }

    switch(ok) {
    case PCAP_ERROR_BREAK:
        // breakloop() before any packets were processed
        break;
    case PCAP_ERROR:
        PyErr_SetString(pypcap_error, pcap_geterr(self->pd));
        return NULL;
    default:
        if(0 > ok) {
            PyErr_SetString(pypcap_error, pcap_statustostr(ok));
            return NULL;
        }
    }

    // count packets here rather than trust pcap_dispatch's return value: on a
    // file, macOS's libpcap 1.10.1 returns 0 when it reaches the end, even
    // after handling packets
    if(dispatch) {
        return PyLong_FromLong(ctx.count);
    }
    Py_RETURN_NONE;
}


static PyObject * pypcap_loop(PyPCAP *self, PyObject *arguments, PyObject *keywords) {
    return run_loop(self, arguments, keywords, 0);
}


static PyObject * pypcap_dispatch(PyPCAP *self, PyObject *arguments, PyObject *keywords) {
    return run_loop(self, arguments, keywords, 1);
}


static PyObject * pypcap_breakloop(PyPCAP *self) {
    CTXCHECK
    pcap_breakloop(self->pd);
    Py_RETURN_NONE;
}


static PyObject * pypcap_next(PyPCAP *self, PyObject *arguments, PyObject *keywords) {
    static char *kwlist[] = { "header", NULL };
    struct pcap_pkthdr *hdr;
    const u_char *data;
    int header = 0;
    int ok;

    CTXCHECK
    BUSYCHECK

    ok = PyArg_ParseTupleAndKeywords(arguments, keywords, "|$p", kwlist, &header);
    if(FALSE == ok) {
        return NULL;
    }

    int hooked = acquire_sigint(self->pd);
    self->busy = 1;
    Py_BEGIN_ALLOW_THREADS
        ok = pcap_next_ex(self->pd, &hdr, &data);
    Py_END_ALLOW_THREADS
    self->busy = 0;
    release_sigint(hooked);

    // as in loop(): Ctrl-C during a blocked read raises KeyboardInterrupt
    if(0 > ok && 0 > PyErr_CheckSignals()) {
        return NULL;
    }

    switch(ok) {
    case 1:
        if(header) {
            return Py_BuildValue("y#dI", data, (Py_ssize_t)hdr->caplen,
                timestamp_seconds(&hdr->ts, is_nano(self->pd)), (unsigned int)hdr->len);
        }
        return PyBytes_FromStringAndSize((const char *)data, hdr->caplen);
    case 0:
    case PCAP_ERROR_BREAK:
        // timeout on a live capture, or end of a file: both mean no packet
        Py_RETURN_NONE;
    case PCAP_ERROR:
        PyErr_SetString(pypcap_error, pcap_geterr(self->pd));
        return NULL;
    default:
        PyErr_SetString(pypcap_error, pcap_statustostr(ok));
        return NULL;
    }
}

static PyObject * pypcap_fileno(PyPCAP *self) {
    CTXCHECK
    return PyLong_FromLong(pcap_fileno(self->pd));
}

#ifndef WIN32

static PyObject * pypcap_get_selectable_fd(PyPCAP *self) {
    CTXCHECK
    return PyLong_FromLong(pcap_get_selectable_fd(self->pd));
}


// some platforms can't wake select() when packets arrive, so it must time out
// this often and then call dispatch(); None when there is no such limit
static PyObject * pypcap_get_required_select_timeout(PyPCAP *self) {
    CTXCHECK

    const struct timeval *timeout = pcap_get_required_select_timeout(self->pd);
    if(NULL == timeout) {
        Py_RETURN_NONE;
    }

    return PyFloat_FromDouble((double)timeout->tv_sec + (double)timeout->tv_usec / 1e6);
}

#endif // WIN32


static PyObject * pypcap_inject(PyPCAP *self, PyObject *packet) {
    uint8_t *data;
    Py_ssize_t len;
    int ok;

    CTXCHECK

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


//
// Filters
//

// pcap_compile's netmask: None means unknown, otherwise a dotted IPv4 string.
// pcap_compile wants it in host byte order ('ip broadcast' only matches that
// way), even though pcap_lookupnet returns network byte order.
static int parse_netmask(PyObject *netmask, bpf_u_int32 *mask) {
    struct in_addr addr;

    if(Py_None == netmask) {
        *mask = PCAP_NETMASK_UNKNOWN;
        return 0;
    }

    const char *text = PyUnicode_Check(netmask) ? PyUnicode_AsUTF8(netmask) : NULL;
    if(NULL == text || 1 != inet_pton(AF_INET, text, &addr)) {
        PyErr_SetString(pypcap_error, "netmask must be a dotted IPv4 string or None");
        return -1;
    }

    *mask = ntohl(addr.s_addr);
    return 0;
}


static int compile_filter(PyPCAP *self, const char *expression, int optimize, PyObject *netmask, struct bpf_program *program) {
    bpf_u_int32 mask;

    if(0 > parse_netmask(netmask, &mask)) {
        return -1;
    }

    if(0 > pcap_compile(self->pd, program, expression, optimize, mask)) {
        PyErr_SetString(pypcap_error, pcap_geterr(self->pd));
        return -1;
    }

    return 0;
}


static PyObject * pypcap_setfilter(PyPCAP *self, PyObject *arguments, PyObject *keywords) {
    static char *kwlist[] = { "filter", "optimize", "netmask", NULL };
    PyObject *filter;
    int optimize = 1;
    PyObject *netmask = Py_None;
    struct bpf_program program;
    int ok;

    CTXCHECK
    BUSYCHECK

    ok = PyArg_ParseTupleAndKeywords(arguments, keywords, "O|pO", kwlist, &filter, &optimize, &netmask);
    if(FALSE == ok) {
        return NULL;
    }

    if(PyObject_TypeCheck(filter, &PyBPF_Type)) {
        ok = pcap_setfilter(self->pd, &((PyBPF *)filter)->program);
    }
    else if(PyUnicode_Check(filter)) {
        const char *expression = PyUnicode_AsUTF8(filter);
        if(NULL == expression) {
            return NULL;
        }
        if(0 > compile_filter(self, expression, optimize, netmask, &program)) {
            return NULL;
        }
        // libpcap keeps its own copy, so the program can be freed straight away
        ok = pcap_setfilter(self->pd, &program);
        pcap_freecode(&program);
    }
    else {
        PyErr_SetString(pypcap_error, "filter must be a string or a compiled program");
        return NULL;
    }

    if(0 > ok) {
        PyErr_SetString(pypcap_error, pcap_geterr(self->pd));
        return NULL;
    }

    Py_RETURN_NONE;
}


static PyObject * pypcap_compile(PyPCAP *self, PyObject *arguments, PyObject *keywords) {
    static char *kwlist[] = { "expression", "optimize", "netmask", NULL };
    const char *expression;
    int optimize = 1;
    PyObject *netmask = Py_None;
    int ok;

    CTXCHECK

    ok = PyArg_ParseTupleAndKeywords(arguments, keywords, "s|pO", kwlist, &expression, &optimize, &netmask);
    if(FALSE == ok) {
        return NULL;
    }

    PyBPF *bpf = PyObject_New(PyBPF, &PyBPF_Type);
    if(NULL == bpf) {
        return NULL;
    }
    bpf->program.bf_len   = 0;
    bpf->program.bf_insns = NULL;

    if(0 > compile_filter(self, expression, optimize, netmask, &bpf->program)) {
        Py_DECREF(bpf);
        return NULL;
    }

    return (PyObject *)bpf;
}


static void pypcap_bpf_dealloc(PyBPF *self) {
    pcap_freecode(&self->program);
    Py_TYPE(self)->tp_free((PyObject *)self);
}


static PyObject * pypcap_bpf_match(PyBPF *self, PyObject *packet) {
    Py_buffer buffer;
    struct pcap_pkthdr header;

    if(0 > PyObject_GetBuffer(packet, &buffer, PyBUF_SIMPLE)) {
        return NULL;
    }

    memset(&header, 0, sizeof(header));
    header.caplen = (bpf_u_int32)buffer.len;
    header.len    = (bpf_u_int32)buffer.len;

    int matched = pcap_offline_filter(&self->program, &header, buffer.buf);
    PyBuffer_Release(&buffer);

    return PyBool_FromLong(matched);
}


static PyObject * pypcap_bpf_instructions(PyBPF *self) {
    PyObject *lines = PyList_New(self->program.bf_len);
    if(NULL == lines) {
        return NULL;
    }

    for(u_int idx = 0; idx < self->program.bf_len; ++idx) {
        // bpf_image formats one instruction as "(000) ldh      [12]"
        PyObject *line = PyUnicode_FromString(bpf_image(&self->program.bf_insns[idx], (int)idx));
        if(NULL == line) {
            Py_DECREF(lines);
            return NULL;
        }
        PyList_SET_ITEM(lines, idx, line);
    }

    return lines;
}


static Py_ssize_t pypcap_bpf_len(PyBPF *self) {
    return self->program.bf_len;
}


//
// Capture files
//

#define DUMPCHECK if(NULL == self->dumper) { PyErr_SetString(pypcap_error, "dumper is closed"); return NULL; }
#define DUMPBUSYCHECK if(self->busy) { PyErr_SetString(pypcap_error, "dumper is busy in loop()"); return NULL; }


static PyObject * pypcap_dump_open(PyPCAP *self, PyObject *arguments, PyObject *keywords) {
    static char *kwlist[] = { "file", "append", NULL };
    PyObject *target;
    PyObject *path;
    int append = 0;
    int fd;
    int ok;

    CTXCHECK

    ok = PyArg_ParseTupleAndKeywords(arguments, keywords, "O|p", kwlist, &target, &append);
    if(FALSE == ok) {
        return NULL;
    }

    // an unactivated handle has no link type or snaplen for the file header yet
    int snaplen = pcap_snapshot(self->pd);
    if(0 > snaplen) {
        PyErr_SetString(pypcap_error, pcap_statustostr(snaplen));
        return NULL;
    }

    if(0 > parse_target(target, &path, &fd)) {
        return NULL;
    }

    if(append && NULL == path) {
        PyErr_SetString(pypcap_error, "append needs a path");
        return NULL;
    }

    PyDumper *dumper = PyObject_New(PyDumper, &PyDumper_Type);
    if(NULL == dumper) {
        Py_XDECREF(path);
        return NULL;
    }
    dumper->dumper  = NULL;
    dumper->snaplen = snaplen;
    dumper->nano    = is_nano(self->pd);
    dumper->busy    = 0;

    // the file header takes its link type and snaplen from this handle
    if(NULL == path) {
#ifndef WIN32
        FILE *fp = dup_file(fd, "wb");
        if(NULL == fp) {
            Py_DECREF(dumper);
            return NULL;
        }
        // on failure libpcap may already have closed fp, so it isn't closed
        // here; at worst that leaks the duplicate descriptor
        dumper->dumper = pcap_dump_fopen(self->pd, fp);
#endif // WIN32
    }
    else if(append) {
        dumper->dumper = pcap_dump_open_append(self->pd, PyBytes_AS_STRING(path));
    }
    else {
        dumper->dumper = pcap_dump_open(self->pd, PyBytes_AS_STRING(path));
    }
    Py_XDECREF(path);

    if(NULL == dumper->dumper) {
        PyErr_SetString(pypcap_error, pcap_geterr(self->pd));
        Py_DECREF(dumper);
        return NULL;
    }

    return (PyObject *)dumper;
}


static void pypcap_dumper_dealloc(PyDumper *self) {
    if(NULL != self->dumper) {
        pcap_dump_close(self->dumper);
        self->dumper = NULL;
    }
    Py_TYPE(self)->tp_free((PyObject *)self);
}


static void timestamp_now(struct timeval *tv) {
#ifdef WIN32
    struct timespec now;
    timespec_get(&now, TIME_UTC);
    tv->tv_sec  = (long)now.tv_sec;
    tv->tv_usec = now.tv_nsec / 1000;
#else
    gettimeofday(tv, NULL);
#endif // WIN32
}


static PyObject * pypcap_dumper_write(PyDumper *self, PyObject *arguments, PyObject *keywords) {
    static char *kwlist[] = { "packet", "ts", "orig_len", NULL };
    Py_buffer packet;
    PyObject *ts = Py_None;
    Py_ssize_t orig_len = -1;
    struct pcap_pkthdr header;
    int ok;

    DUMPCHECK
    DUMPBUSYCHECK

    ok = PyArg_ParseTupleAndKeywords(arguments, keywords, "y*|On", kwlist, &packet, &ts, &orig_len);
    if(FALSE == ok) {
        return NULL;
    }

    if(0 <= orig_len && orig_len < packet.len) {
        PyBuffer_Release(&packet);
        PyErr_SetString(pypcap_error, "orig_len is shorter than the packet");
        return NULL;
    }

    // a nanosecond file keeps nanoseconds in tv_usec
    long scale = self->nano ? 1000000000 : 1000000;

    if(Py_None == ts) {
        timestamp_now(&header.ts);
        if(self->nano) {
            header.ts.tv_usec *= 1000;
        }
    }
    else {
        double seconds = PyFloat_AsDouble(ts);
        if(-1.0 == seconds && PyErr_Occurred()) {
            PyBuffer_Release(&packet);
            return NULL;
        }
        double whole = floor(seconds);
        long fraction = (long)((seconds - whole) * scale + 0.5);
        if(scale <= fraction) {
            whole    += 1;
            fraction -= scale;
        }
        header.ts.tv_sec  = (long)whole;
        header.ts.tv_usec = fraction;
    }

    // like a capture: store at most snaplen bytes, but record the full length
    header.len    = (bpf_u_int32)(0 <= orig_len ? orig_len : packet.len);
    header.caplen = (bpf_u_int32)(packet.len < self->snaplen ? packet.len : self->snaplen);

    pcap_dump((u_char *)self->dumper, &header, packet.buf);
    PyBuffer_Release(&packet);

    Py_RETURN_NONE;
}


static PyObject * pypcap_dumper_flush(PyDumper *self) {
    DUMPCHECK

    if(0 > pcap_dump_flush(self->dumper)) {
        PyErr_SetString(pypcap_error, strerror(errno));
        return NULL;
    }

    Py_RETURN_NONE;
}


// where the next packet goes, so a caller can start a new file at some size;
// fails on a pipe
static PyObject * pypcap_dumper_tell(PyDumper *self) {
    DUMPCHECK

    int64_t position = pcap_dump_ftell64(self->dumper);
    if(0 > position) {
        PyErr_SetString(pypcap_error, strerror(errno));
        return NULL;
    }

    return PyLong_FromLongLong(position);
}


static PyObject * pypcap_dumper_close(PyDumper *self) {
    DUMPBUSYCHECK

    if(NULL == self->dumper) {
        Py_RETURN_NONE;
    }

    // pcap_dump_close doesn't report errors, so flush first to catch a failed write
    int flushed = pcap_dump_flush(self->dumper);
    int error = errno;
    pcap_dump_close(self->dumper);
    self->dumper = NULL;

    if(0 > flushed) {
        PyErr_SetString(pypcap_error, strerror(error));
        return NULL;
    }

    Py_RETURN_NONE;
}


static PyObject * pypcap_dumper_enter(PyDumper *self) {
    DUMPCHECK
    Py_INCREF(self);
    return (PyObject *)self;
}


static PyObject * pypcap_dumper_exit(PyDumper *self, PyObject *arguments) {
    return pypcap_dumper_close(self);
}

#ifdef WIN32

static PyObject * pypcap_getevent(PyPCAP *self) {
    CTXCHECK
    // a HANDLE is a pointer, too wide for a long on 64-bit Windows
    return PyLong_FromVoidPtr(pcap_getevent(self->pd));
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

        if(!_stricmp(cannon, name)) {
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
