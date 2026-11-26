/* Owned static-analysis fixture, not a loadable CPython extension. Never loaded as a DLL. */
typedef void Object;
typedef long long Count;
typedef struct {
    const char *name;
    void *function;
    unsigned int flags;
    const char *doc;
} Method;
static Object *one(Object *self, Object *arg) { return arg ? arg : self; }
static Object *fast(Object *self, Object *const *args, Count nargs) {
    return nargs > 0 ? args[0] : self;
}
static Object *keywords(Object *self, Object *const *args, Count nargs, Object *names) {
    return names ? names : (nargs > 0 ? args[0] : self);
}
__declspec(dllexport) Method fixture_methods[] = {
    {"one", (void *)one, 8, "owned METH_O fixture"},
    {"fast", (void *)fast, 128, "owned FASTCALL fixture"},
    {"keywords", (void *)keywords, 130, "owned FASTCALL KEYWORDS fixture"},
    {0, 0, 0, 0}
};
/* Export is a static format marker for the test; no Python runtime is started. */
__declspec(dllexport) void *PyInit_owned(void) { return fixture_methods; }
