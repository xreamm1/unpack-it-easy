/* Owned UIE fixture. No runtime, file, process or network operations. */
__declspec(dllexport) unsigned long long scalar_sum(unsigned long long a, unsigned long long b) {
    return a + b;
}
__declspec(dllexport) unsigned long long scalar_mix(unsigned long long a, unsigned long long b) {
    return (a * 10 + b * 3) ^ 0x13579;
}
__declspec(dllexport) unsigned int scalar_wrap(unsigned int a, unsigned int b) {
    return (a + b) * 17;
}
__declspec(dllexport) unsigned long long scalar_neg(unsigned long long a) {
    return -a;
}
__declspec(dllexport) unsigned long long scalar_shift(unsigned long long a) {
    return (a >> 13) ^ (a << 7);
}
__declspec(dllexport) unsigned long long scalar_rotate_left(unsigned long long a) {
    return (a << 9) | (a >> (64 - 9));
}
__declspec(dllexport) unsigned int scalar_rotate_right32(unsigned int a) {
    return (a >> 5) | (a << (32 - 5));
}
__declspec(dllexport) unsigned long long scalar_rotate_variable(unsigned long long a, unsigned long long b) {
    unsigned int shift = (unsigned int)b & 63;
    return (a << shift) | (a >> ((64 - shift) & 63));
}
__declspec(dllexport) unsigned long long scalar_mask(unsigned long long a, unsigned long long b) {
    return (a & 0xff00ff00ff00ff00ULL) | (b ^ 0x123);
}
__declspec(dllexport) unsigned long long unsupported_memory(const unsigned long long *p) {
    return *p;
}
__declspec(dllexport) unsigned long long unsupported_branch(unsigned long long a, unsigned long long b) {
    return a < b ? b - a : a - b;
}
