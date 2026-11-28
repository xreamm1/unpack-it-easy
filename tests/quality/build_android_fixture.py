"""Authored DEX/APK fixture: one class, integer addition and a literal string.

Builds bytes only; never executes Dalvik code. Layout follows the AOSP DEX format.
https://source.android.com/docs/core/runtime/dex-format
"""
import hashlib
import sys
import struct
import zipfile
import zlib
from pathlib import Path

root = Path(sys.argv[1]).resolve()
root.mkdir(parents=True, exist_ok=False)
strings = sorted(['Hello.java', 'I', 'III', 'L', 'Ljava/lang/Object;', 'Ljava/lang/String;',
                  'Luie/fixture/Hello;', 'add', 'message', 'uie owned fixture'])
string_ids = {text: index for index, text in enumerate(strings)}
types = ['I', 'Ljava/lang/Object;', 'Ljava/lang/String;', 'Luie/fixture/Hello;']
u32 = lambda *values: struct.pack('<'+'I'*len(values), *values)
def uleb(value):
    out = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        out.append(byte | (128 if value else 0))
        if not value:
            return out

string_off = 112
type_off = string_off + 4*len(strings)
proto_off = type_off + 4*len(types)
method_off = proto_off + 24
class_off = method_off + 16
data_off = class_off + 32
data = bytearray(data_off)
def align():
    while len(data) % 4:
        data.append(0)
params_off = len(data)
data += u32(2) + struct.pack('<HH', 0, 0)
string_data_off = len(data)
for index, text in enumerate(strings):
    struct.pack_into('<I', data, string_off + 4*index, len(data))
    encoded = text.encode('ascii')
    data += uleb(len(text)) + encoded + b'\0'
align()
add_code = len(data)
data += struct.pack('<HHHHII', 3, 2, 0, 0, 0, 3)
data += struct.pack('<HHH', 0x0090, 0x0201, 0x000f)  # add-int v0,v1,v2; return v0
align()
message_code = len(data)
data += struct.pack('<HHHHII', 1, 0, 0, 0, 0, 3)
data += struct.pack('<HHH', 0x001a, string_ids['uie owned fixture'], 0x0011)
class_data_off = len(data)
data += uleb(0) + uleb(0) + uleb(2) + uleb(0)
data += uleb(0) + uleb(9) + uleb(add_code)
data += uleb(1) + uleb(9) + uleb(message_code)
align()
map_off = len(data)
items = [(0, 1, 0), (1, len(strings), string_off), (2, 4, type_off), (3, 2, proto_off),
         (5, 2, method_off), (6, 1, class_off), (0x1001, 1, params_off),
         (0x2002, len(strings), string_data_off), (0x2001, 2, add_code),
         (0x2000, 1, class_data_off), (0x1000, 1, map_off)]
data += u32(len(items))
for kind, count, offset in sorted(items, key=lambda item: item[2]):
    data += struct.pack('<HHII', kind, 0, count, offset)
for index, descriptor in enumerate(types):
    struct.pack_into('<I', data, type_off + index*4, string_ids[descriptor])
data[proto_off:proto_off+24] = u32(string_ids['III'], 0, params_off, string_ids['L'], 2, 0)
data[method_off:method_off+16] = struct.pack('<HHIHHI', 3, 0, string_ids['add'], 3, 1, string_ids['message'])
data[class_off:class_off+32] = u32(3, 1, 1, 0, string_ids['Hello.java'], 0, class_data_off, 0)
data[:8] = b'dex\n035\0'
data[32:112] = u32(len(data), 112, 0x12345678, 0, 0, map_off, len(strings), string_off,
                   len(types), type_off, 2, proto_off, 0, 0, 2, method_off, 1, class_off,
                   len(data)-data_off, data_off)
data[12:32] = hashlib.sha1(data[32:]).digest()
data[8:12] = u32(zlib.adler32(data[12:]))
(root/'hello.dex').write_bytes(data)

# Minimal binary AXML manifest with one string attribute: package="uie.fixture".
names = ['manifest', 'package', 'uie.fixture']
pool = bytearray()
offsets = []
for text in names:
    offsets.append(len(pool))
    pool += bytes([len(text), len(text)]) + text.encode() + b'\0'
while len(pool) % 4:
    pool.append(0)
pool_size = 28 + 4*len(names) + len(pool)
string_pool = struct.pack('<HHI', 1, 28, pool_size) + u32(len(names), 0, 0x100, 28+4*len(names), 0)
string_pool += u32(*offsets) + pool
node = lambda kind, size: struct.pack('<HHI', kind, 16, size) + u32(1, 0xffffffff)
start = node(0x102, 56) + u32(0xffffffff, 0) + struct.pack('<HHHHHH', 20, 20, 1, 0, 0, 0)
start += u32(0xffffffff, 1, 2) + struct.pack('<HBBI', 8, 0, 3, 2)
end = node(0x103, 24) + u32(0xffffffff, 0)
manifest = struct.pack('<HHI', 3, 8, 8+len(string_pool)+len(start)+len(end)) + string_pool + start + end
with zipfile.ZipFile(root/'hello.apk', 'x', zipfile.ZIP_DEFLATED) as archive:
    for name, content in [('AndroidManifest.xml', manifest), ('classes.dex', data),
                          ('assets/uie.txt', b'owned static-analysis fixture\n')]:
        entry = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
        entry.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(entry, content)

assert data[:8] == b"dex\n035\0"
assert hashlib.sha1(data[32:]).digest() == data[12:32]
print("Authored hello.dex and hello.apk built")
