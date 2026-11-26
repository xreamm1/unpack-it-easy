/* Static analysis fixture only; this is not a loadable CPython extension. */
int _fltused = 0;
__declspec(dllimport) void *PyObject_GetAttr(void *, void *);
__declspec(dllimport) void *PyNumber_Add(void *, void *);
__declspec(dllimport) void *PyFloat_FromDouble(double);
__declspec(dllimport) void *PyBytes_FromStringAndSize(const char *, long long);
__declspec(dllexport) void *PyInit_owned_api(void *object, void *attribute) {
    void *value = PyObject_GetAttr(object, attribute);
    return PyNumber_Add(value, PyFloat_FromDouble(8.0));
}
__declspec(dllexport) void *owned_bytes(void) {
    return PyBytes_FromStringAndSize("uie", 3);
}
