#!/usr/bin/env python3
"""Writes app/src/main/assets/THIRD_PARTY_NOTICES.txt from the license files of the third-party sources that are built into the app.
Run it after the pinned sources are in place (scripts/fetch_third_party.sh)."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "app/src/main/assets/THIRD_PARTY_NOTICES.txt")

COMPONENTS = [
    ("zlib 1.3.2", "zlib License", "https://github.com/madler/zlib", ["third_party/zlib/LICENSE"]),
    ("Zstandard 1.5.7", "BSD-3-Clause (the BSD alternative of the dual license is used)", "https://github.com/facebook/zstd", ["third_party/zstd/LICENSE"]),
    ("Capstone 5.0.9", "BSD-3-Clause; parts derived from LLVM under the LLVM license", "https://github.com/capstone-engine/capstone",
     ["third_party/capstone/LICENSE.TXT", "third_party/capstone/LICENSE_LLVM.TXT"]),
    ("ELFIO 3.12", "MIT", "https://github.com/serge1/ELFIO", ["third_party/ELFIO/LICENSE.txt"]),
]


def main():
    parts = ["KRATOS DUMP uses the following open-source components. Their license texts follow.\n"]
    for name, lic, url, files in COMPONENTS:
        parts.append("=" * 78 + f"\n{name}\nLicense: {lic}\nSource: {url}\n" + "=" * 78 + "\n")
        for rel in files:
            path = os.path.join(ROOT, rel)
            if not os.path.isfile(path):
                print("missing license file:", rel, file=sys.stderr)
                return 1
            with open(path, encoding="utf-8", errors="replace") as f:
                parts.append(f"--- {os.path.basename(rel)} ---\n{f.read().strip()}\n")
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))
    print("written", OUT, os.path.getsize(OUT), "bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
