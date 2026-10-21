#!/bin/bash
# Builds the JNI bridge for the host, loads it into a real JVM and runs JniSmokeTest.
# usage: run_jni_test.sh [build_dir]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CORE="$(cd "$HERE/../.." && pwd)"
B="${1:-$CORE/build-jni}"
cmake -S "$CORE" -B "$B" -G Ninja -DCMAKE_BUILD_TYPE=Release -DKRATOS_BUILD_JNI=ON -DKRATOS_BUILD_TESTS=OFF >/dev/null
cmake --build "$B" --target kratos_jni
CLS="$B/jni_test_classes"
rm -rf "$CLS" && mkdir -p "$CLS"
javac -d "$CLS" "$HERE/com/kratos/dump/Native.java" "$HERE/JniSmokeTest.java"
OUT="$B/jni_test_out"
rm -rf "$OUT" && mkdir -p "$OUT"
java -Xcheck:jni --add-opens java.base/java.io=ALL-UNNAMED -cp "$CLS" JniSmokeTest "$B/libkratos_jni.so" "$CORE/tests/fixtures" "$OUT"
