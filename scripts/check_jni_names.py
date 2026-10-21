#!/usr/bin/env python3
"""Checks that the native method declarations agree in three places:
app Native.kt, core/jni/kratos_jni.cpp, and the host-test twin core/tests/jni/com/kratos/dump/Native.java.
A name or type mismatch would only show up at run time on a device (UnsatisfiedLinkError), so it is checked here."""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

KT_TYPES = {"Int": "int", "Long": "long", "String": "String", "NativeListener?": "Object", "NativeListener": "Object"}
JAVA_TYPES = {"int": "int", "long": "long", "String": "String", "Object": "Object", "void": "void"}
JNI_TYPES = {"jint": "int", "jlong": "long", "jstring": "String", "jobject": "Object", "void": "void"}


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def kotlin():
    out = {}
    for m in re.finditer(r"external fun (\w+)\(([^)]*)\)\s*(?::\s*(\w+))?", read("app/src/main/java/com/kratos/dump/Native.kt")):
        name, params, ret = m.group(1), m.group(2), m.group(3) or "Unit"
        types = [KT_TYPES[p.split(":")[1].strip()] for p in params.split(",") if p.strip()]
        out[name] = (("void" if ret == "Unit" else KT_TYPES[ret]), types)
    return out


def java():
    out = {}
    for m in re.finditer(r"public static native (\w+) (\w+)\(([^)]*)\);", read("core/tests/jni/com/kratos/dump/Native.java")):
        ret, name, params = m.group(1), m.group(2), m.group(3)
        types = [JAVA_TYPES[p.strip().split()[0]] for p in params.split(",") if p.strip()]
        out[name] = (JAVA_TYPES[ret], types)
    return out


def jni():
    out = {}
    for m in re.finditer(r"JNIEXPORT (\w+) JNICALL Java_com_kratos_dump_Native_(\w+)\(([^)]*)\)", read("core/jni/kratos_jni.cpp")):
        ret, name, params = m.group(1), m.group(2), m.group(3)
        parts = [p.strip() for p in params.split(",")]
        parts = parts[2:]  # JNIEnv*, jclass
        types = [JNI_TYPES[p.split()[0]] for p in parts if p]
        out[name] = (JNI_TYPES[ret], types)
    return out


def main():
    kt, jv, jn = kotlin(), java(), jni()
    problems = []
    if not kt:
        problems.append("no external functions found in Native.kt")
    for name in sorted(set(kt) | set(jv) | set(jn)):
        sigs = {"Native.kt": kt.get(name), "Native.java": jv.get(name), "kratos_jni.cpp": jn.get(name)}
        missing = [k for k, v in sigs.items() if v is None]
        if missing:
            problems.append(f"{name}: missing in {', '.join(missing)}")
            continue
        if len({repr(v) for v in sigs.values()}) != 1:
            problems.append(f"{name}: signatures differ: {sigs}")
    for p in problems:
        print("FAIL", p)
    print(f"{len(kt)} native functions checked, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
