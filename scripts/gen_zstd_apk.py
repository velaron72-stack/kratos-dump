#!/usr/bin/env python3
"""Builds sample_zstd.apk: a ZIP archive whose library entry uses compression method 93 (Zstandard).

Python's zipfile cannot write method 93, so the local headers, the central directory and the end record are written here.
The compressed frame comes from the system libzstd through ctypes (any 1.4 or newer works; the frame format is stable).

Usage: gen_zstd_apk.py <fixtures dir>
Input: sample_arm64.so and sample_x86_64.so in that directory. Output: sample_zstd.apk next to them.
"""
import ctypes
import ctypes.util
import struct
import sys
import zlib
from pathlib import Path


def load_zstd():
    for name in (ctypes.util.find_library("zstd"), "libzstd.so.1", "libzstd.dylib"):
        if name:
            try:
                return ctypes.CDLL(name)
            except OSError:
                continue
    sys.exit("libzstd was not found: install it (for example the libzstd1 package)")


def zstd_compress(data: bytes) -> bytes:
    lib = load_zstd()
    lib.ZSTD_compressBound.restype = ctypes.c_size_t
    lib.ZSTD_compressBound.argtypes = [ctypes.c_size_t]
    lib.ZSTD_compress.restype = ctypes.c_size_t
    lib.ZSTD_compress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    lib.ZSTD_isError.restype = ctypes.c_uint
    lib.ZSTD_isError.argtypes = [ctypes.c_size_t]
    out = ctypes.create_string_buffer(lib.ZSTD_compressBound(len(data)))
    n = lib.ZSTD_compress(out, len(out), data, len(data), 19)
    if lib.ZSTD_isError(n):
        sys.exit("ZSTD_compress failed")
    return out.raw[:n]


def build_zip(entries):
    """entries: list of (name, method, uncompressed bytes). Returns the archive bytes."""
    blob = bytearray()
    central = bytearray()
    for name, method, data in entries:
        nm = name.encode()
        payload = zstd_compress(data) if method == 93 else data
        crc = zlib.crc32(data) & 0xFFFFFFFF
        need = 63 if method == 93 else 10
        offset = len(blob)
        blob += struct.pack("<IHHHHHIIIHH", 0x04034B50, need, 0, method, 0, 0x21, crc, len(payload), len(data), len(nm), 0) + nm + payload
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 0x031E, need, 0, method, 0, 0x21, crc, len(payload), len(data), len(nm), 0, 0, 0, 0, 0, offset) + nm
    cd_off = len(blob)
    blob += central
    blob += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(central), cd_off, 0)
    return bytes(blob)


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    d = Path(sys.argv[1])
    arm64 = (d / "sample_arm64.so").read_bytes()
    x86_64 = (d / "sample_x86_64.so").read_bytes()
    apk = build_zip([
        ("AndroidManifest.xml", 0, b"stub manifest for the zstd fixture\n"),
        ("lib/arm64-v8a/libsample.so", 93, arm64),
        ("lib/x86_64/libsample.so", 0, x86_64),
    ])
    (d / "sample_zstd.apk").write_bytes(apk)
    print("wrote", d / "sample_zstd.apk", len(apk), "bytes")


if __name__ == "__main__":
    main()
