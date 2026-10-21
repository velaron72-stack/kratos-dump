#!/usr/bin/env python3
"""Creates damaged, protected-like and non-ELF variants of the generated fixtures, and APK containers."""
import os
import random
import struct
import sys
import zipfile

out = sys.argv[1]


def rd(name):
    with open(os.path.join(out, name), "rb") as f:
        return bytearray(f.read())


def wr(name, data):
    with open(os.path.join(out, name), "wb") as f:
        f.write(bytes(data))


def hdr(b):
    is64 = b[4] == 2
    if is64:
        shoff, = struct.unpack_from("<Q", b, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", b, 0x3A)
        phoff, = struct.unpack_from("<Q", b, 0x20)
    else:
        shoff, = struct.unpack_from("<I", b, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", b, 0x2E)
        phoff, = struct.unpack_from("<I", b, 0x1C)
    return is64, phoff, shoff, shentsize, shnum, shstrndx


def drop_sections(b):
    is64, phoff, shoff, shentsize, shnum, shstrndx = hdr(b)
    if is64:
        struct.pack_into("<Q", b, 0x28, 0)
        struct.pack_into("<HHH", b, 0x3A, 0, 0, 0)
    else:
        struct.pack_into("<I", b, 0x20, 0)
        struct.pack_into("<HHH", b, 0x2E, 0, 0, 0)
    return b


def sections(b):
    is64, phoff, shoff, shentsize, shnum, shstrndx = hdr(b)
    res = []
    for i in range(shnum):
        o = shoff + i * shentsize
        if is64:
            name, typ, flags, addr, off, size, link, info, align, ent = struct.unpack_from("<IIQQQQIIQQ", b, o)
        else:
            name, typ, flags, addr, off, size, link, info, align, ent = struct.unpack_from("<IIIIIIIIII", b, o)
        res.append(dict(name=name, type=typ, flags=flags, addr=addr, off=off, size=size, link=link, info=info))
    return res, shstrndx


def sec_name(b, secs, shstrndx, s):
    base = secs[shstrndx]["off"] + s["name"]
    end = b.index(b"\0", base)
    return b[base:end].decode()


for arch in ("sample_arm64", "sample_arm", "sample_x86_64"):
    src = arch + ".so"
    if not os.path.exists(os.path.join(out, src)):
        continue
    b = rd(src)
    wr(arch + "_nosections.so", drop_sections(bytearray(b)))
    # Section table present in the header but zeroed in the file
    c = bytearray(b)
    is64, phoff, shoff, shentsize, shnum, shstrndx = hdr(c)
    for i in range(shoff, min(len(c), shoff + shentsize * shnum)):
        c[i] = 0
    wr(arch + "_zeroedsections.so", c)
    # Section header offset beyond the end of the file
    c = bytearray(b)
    if is64:
        struct.pack_into("<Q", c, 0x28, len(c) + 0x1000)
    else:
        struct.pack_into("<I", c, 0x20, len(c) + 0x1000)
    wr(arch + "_badshoff.so", c)
    # Wrong program header offset: the standard position must be assumed
    c = drop_sections(bytearray(b))
    if is64:
        struct.pack_into("<Q", c, 0x20, 0x7fffff00)
    else:
        struct.pack_into("<I", c, 0x1C, 0x7fffff00)
    wr(arch + "_badphoff.so", c)
    wr(arch + "_truncated.so", b[: int(len(b) * 0.55)])
    wr(arch + "_appended.so", b + bytes(random.Random(7).getrandbits(8) for _ in range(4096)))
    # Obfuscated symbol names (same length, in place)
    c = bytearray(b)
    secs, shstr = sections(c)
    n = 0
    for s in secs:
        if s["type"] in (2, 11):  # symtab, dynsym
            strsec = secs[s["link"]]
            region = c[strsec["off"]: strsec["off"] + strsec["size"]]
            idx = 0
            while True:
                j = region.find(b"kratos_", idx)
                if j < 0:
                    break
                k = region.index(b"\0", j)
                for t in range(j, k):
                    region[t] = ord("I") if (t - j) % 2 == 0 else ord("l")
                n += 1
                idx = k
            c[strsec["off"]: strsec["off"] + strsec["size"]] = region
    wr(arch + "_obfnames.so", c)

# Packed-like: random bytes in the code segment, UPX marker, no usable section names
if os.path.exists(os.path.join(out, "sample_arm64.so")):
    b = rd("sample_arm64.so")
    secs, shstr = sections(b)
    rng = random.Random(1234)
    for s in secs:
        nm = sec_name(b, secs, shstr, s)
        if nm in (".text", ".rodata", ".eh_frame", ".eh_frame_hdr"):
            for i in range(s["off"], s["off"] + s["size"]):
                b[i] = rng.getrandbits(8)
    marker = b"UPX! packed-like marker"
    secs2 = [s for s in secs if sec_name(b, secs, shstr, s) == ".text"]
    if secs2 and secs2[0]["size"] > 64:
        b[secs2[0]["off"] + 16: secs2[0]["off"] + 16 + len(marker)] = marker
    wr("sample_arm64_packedlike.so", drop_sections(b))

wr("not_elf.so", bytes(random.Random(99).getrandbits(8) for _ in range(5000)))
wr("empty.so", b"")
b = rd("sample_arm64.so")
wr("elf_header_only.so", b[:64])
wr("elf_ident_only.so", b[:16])
c = bytearray(b)
c[4] = 7  # invalid class
wr("bad_class.so", c)
# Big-endian flag on a little-endian body
c = bytearray(b)
c[5] = 2
wr("bad_endian.so", c)

# ---------------------------------------------------------------- IL2CPP-like metadata
def il2cpp_metadata(version=29, strings=("UnityEngine", "System.Void", "<Module>", "Assembly-CSharp", "GameManager", "get_Player")):
    sdata = b"".join(s.encode() + b"\0" for s in strings)
    header_size = 0x108
    # (offset, size) pairs; strings at 0x18/0x1c style positions: literal tables first, string table after the header
    fields = [0] * ((header_size - 8) // 4)
    # stringLiteral (offset,size), stringLiteralData (offset,size), string (offset,size)
    lit = b"\x08\x00\x00\x00\x00\x00\x00\x00"
    litdata = b"HelloIL2CPP"
    off = header_size
    fields[0], fields[1] = off, len(lit)
    off += len(lit)
    fields[2], fields[3] = off, len(litdata)
    off += len(litdata)
    fields[4], fields[5] = off, len(sdata)
    body = lit + litdata + sdata
    blob = struct.pack("<II", 0xFAB11BAF, version) + struct.pack("<%dI" % len(fields), *fields) + body
    return blob


wr("global-metadata.dat", il2cpp_metadata())
wr("global-metadata-badversion.dat", il2cpp_metadata(version=7))
wr("global-metadata-badmagic.dat", b"\x00" * 64)
wr("global-metadata-truncated.dat", il2cpp_metadata()[:90])


# ---------------------------------------------------------------- APK containers
def apk(name, entries, comp=zipfile.ZIP_DEFLATED):
    with zipfile.ZipFile(os.path.join(out, name), "w", comp) as z:
        for ent, data, c in entries:
            zi = zipfile.ZipInfo(ent, date_time=(2024, 1, 1, 0, 0, 0))
            zi.compress_type = c if c is not None else comp
            zi.external_attr = 0o644 << 16
            z.writestr(zi, data)


def read(name):
    with open(os.path.join(out, name), "rb") as f:
        return f.read()


manifest = b"\x03\x00\x08\x00fake-binary-manifest"
dex = b"dex\n035\0" + b"\0" * 100
meta = read("global-metadata.dat")
files = {k: read(k + ".so") for k in ("sample_arm64", "sample_arm", "sample_x86_64", "sample_x86") if os.path.exists(os.path.join(out, k + ".so"))}

apk("sample_multi_abi.apk", [
    ("AndroidManifest.xml", manifest, None),
    ("classes.dex", dex, None),
    ("lib/arm64-v8a/libsample.so", files["sample_arm64"], None),
    ("lib/armeabi-v7a/libsample.so", files["sample_arm"], None),
    ("lib/x86_64/libsample.so", files["sample_x86_64"], None),
    ("lib/x86/libsample.so", files["sample_x86"], None),
    ("assets/bin/Data/Managed/Metadata/global-metadata.dat", meta, None),
    ("assets/data.bin", bytes(range(256)) * 8, None),
])
apk("sample_stored_libs.apk", [
    ("AndroidManifest.xml", manifest, None),
    ("lib/arm64-v8a/libsample.so", files["sample_arm64"], zipfile.ZIP_STORED),
    ("lib/arm64-v8a/libother.so", read("sample_arm64_stripped.so"), zipfile.ZIP_STORED),
    ("assets/bin/Data/Managed/Metadata/global-metadata.dat", meta, zipfile.ZIP_STORED),
])
apk("sample_no_libs.apk", [("AndroidManifest.xml", manifest, None), ("classes.dex", dex, None), ("res/raw/data.txt", b"plain", None)])
apk("sample_bad_lib.apk", [
    ("AndroidManifest.xml", manifest, None),
    ("lib/arm64-v8a/libbroken.so", read("sample_arm64_truncated.so"), None),
    ("lib/arm64-v8a/libnotelf.so", read("not_elf.so"), None),
    ("lib/armeabi-v7a/libsample.so", files["sample_arm"], None),
])
apk("sample_bad_metadata.apk", [
    ("AndroidManifest.xml", manifest, None),
    ("lib/arm64-v8a/libsample.so", files["sample_arm64"], None),
    ("assets/bin/Data/Managed/Metadata/global-metadata.dat", read("global-metadata-badmagic.dat"), None),
])
inner = os.path.join(out, "_inner.apk")
apk("_inner.apk", [("lib/arm64-v8a/libinner.so", files["sample_arm64"], None), ("AndroidManifest.xml", manifest, None)])
apk("sample_nested.apk", [
    ("AndroidManifest.xml", manifest, None),
    ("assets/split_config.apk", read("_inner.apk"), zipfile.ZIP_STORED),
    ("lib/arm64-v8a/libsample.so", files["sample_arm64"], None),
])
os.remove(inner)
# Corrupt containers
good = read("sample_multi_abi.apk")
with open(os.path.join(out, "corrupt_truncated.apk"), "wb") as f:
    f.write(good[: len(good) // 2])
c = bytearray(good)
c[-20:-4] = b"\xff" * 16  # damages the end-of-central-directory record
with open(os.path.join(out, "corrupt_eocd.apk"), "wb") as f:
    f.write(c)
with open(os.path.join(out, "not_a_zip.apk"), "wb") as f:
    f.write(b"this is not a zip archive" * 100)
# Unsupported ABI only (mips-like directory name with an x86 library)
apk("sample_odd_abi.apk", [("AndroidManifest.xml", manifest, None), ("lib/mips/libsample.so", files["sample_x86"], None)])
# Archive with a bad CRC in a library
raw = bytearray(read("sample_stored_libs.apk"))
pos = raw.find(b"\x7fELF")
raw[pos + 100] ^= 0xFF
with open(os.path.join(out, "sample_bad_crc.apk"), "wb") as f:
    f.write(raw)
print("variants created")
