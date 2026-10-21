#!/usr/bin/env python3
"""Creates core/tests/fixtures/sample_arm64_strings.so from sample_arm64.so.
Each string is written over a run of zero padding inside the file, so the ELF stays valid and no offset moves.
Contents: UTF-8 Cyrillic and CJK text, UTF-16LE (Latin and Cyrillic) and UTF-16BE text."""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "core/tests/fixtures/sample_arm64.so")
DST = os.path.join(ROOT, "core/tests/fixtures/sample_arm64_strings.so")
MIN_OFFSET = 0x300  # the program header table of the source file ends at 0x2a8

PIECES = [
    ("Привет, мир! Проверка".encode("utf-8") + b"\0", 1),
    ("你好，世界，这是一个测试字符串".encode("utf-8") + b"\0", 1),
    ("Wide text".encode("utf-16-le") + b"\0\0", 2),
    ("Широкая строка UTF-16".encode("utf-16-le") + b"\0\0", 2),
    ("Big endian".encode("utf-16-be") + b"\0\0", 2),
]


def main():
    data = bytearray(open(SRC, "rb").read())
    used = []
    for blob, align in sorted(PIECES, key=lambda p: -len(p[0])):
        placed = False
        # Only padding after the program header table and before the end of the file is used.
        runs = sorted(((m.start(), m.end() - m.start()) for m in re.finditer(rb"\0{20,}", bytes(data)) if m.start() >= MIN_OFFSET), key=lambda r: r[1])
        for start, length in runs:
            off = start + 2
            if off % align:
                off += 1
            if off + len(blob) + 2 <= start + length and all(off + len(blob) + 2 <= u[0] or off >= u[1] for u in used):
                data[off:off + len(blob)] = blob
                used.append((off, off + len(blob)))
                placed = True
                break
        if not placed:
            print("no room for", blob[:20], file=sys.stderr)
            return 1
    open(DST, "wb").write(bytes(data))
    print("written", DST, "size", len(data), "placements", used)
    return 0


if __name__ == "__main__":
    sys.exit(main())
