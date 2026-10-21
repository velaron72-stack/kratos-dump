#!/usr/bin/env bash
# Builds the analysis fixtures (ELF libraries for ARM64, ARM32, x86-64, x86 and damaged variants) with clang/lld.
# Needs: clang, ld.lld, llvm-strip, llvm-objcopy, python3. No Android NDK is required: the samples are freestanding.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
src="$here/core/tests/fixtures/src"
out="${1:-$here/core/tests/fixtures}"
mkdir -p "$out"
LDFLAGS="-fuse-ld=lld -shared -nostdlib -Wl,--build-id=sha1 -Wl,-soname,libsample.so"
CF="-O1 -fPIC -ffreestanding -fno-stack-protector -fno-unwind-tables -g0"
CFU="-O1 -fPIC -ffreestanding -fno-stack-protector -funwind-tables -g0"

build() { # name target extra-cflags extra-ldflags
  local name=$1 target=$2 cf=$3 lf=${4:-}
  clang --target="$target" $CFU $cf -c "$src/sample.c" -o "$out/_$name.o"
  clang --target="$target" $LDFLAGS $lf "$out/_$name.o" -o "$out/$name.so"
  rm -f "$out/_$name.o"
}

build sample_arm64 aarch64-linux-android21 ""
build sample_x86_64 x86_64-linux-android21 ""
build sample_x86 i686-linux-android21 ""
# ARM32: mixed ARM/Thumb. sample.c in Thumb, the second unit in ARM.
clang --target=armv7a-linux-androideabi21 $CFU -mthumb -c "$src/sample.c" -o "$out/_t.o"
clang --target=armv7a-linux-androideabi21 $CFU -marm -c "$src/sample_mode.c" -o "$out/_a.o"
clang --target=armv7a-linux-androideabi21 $LDFLAGS "$out/_t.o" "$out/_a.o" -o "$out/sample_arm.so"
rm -f "$out/_t.o" "$out/_a.o"

# Relocation encodings
build sample_arm64_packed aarch64-linux-android21 "" "-Wl,--pack-dyn-relocs=android"
build sample_arm64_relr aarch64-linux-android21 "" "-Wl,--pack-dyn-relocs=relr"
clang --target=armv7a-linux-androideabi21 $CFU -mthumb -c "$src/sample.c" -o "$out/_t.o"
clang --target=armv7a-linux-androideabi21 $LDFLAGS -Wl,--pack-dyn-relocs=android "$out/_t.o" -o "$out/sample_arm_packed.so"
rm -f "$out/_t.o"

# Compressed debug sections (SHF_COMPRESSED): zlib (ELFCOMPRESS_ZLIB) and zstd (ELFCOMPRESS_ZSTD)
for algo in zlib zstd; do
  clang --target=aarch64-linux-android21 -O1 -fPIC -ffreestanding -fno-stack-protector -funwind-tables -g -fdebug-prefix-map="$src"=src \
    -c "$src/sample.c" -o "$out/_c.o"
  clang --target=aarch64-linux-android21 $LDFLAGS -Wl,--compress-debug-sections=$algo "$out/_c.o" -o "$out/sample_arm64_${algo}sec.so"
  rm -f "$out/_c.o"
done

# Stripped (no .symtab, no debug), without unwind tables
llvm-strip --strip-all "$out/sample_arm64.so" -o "$out/sample_arm64_stripped.so"
llvm-strip --strip-all "$out/sample_arm.so" -o "$out/sample_arm_stripped.so"
llvm-strip --strip-all "$out/sample_x86_64.so" -o "$out/sample_x86_64_stripped.so"
clang --target=aarch64-linux-android21 $CF -c "$src/sample.c" -o "$out/_n.o"
clang --target=aarch64-linux-android21 $LDFLAGS "$out/_n.o" -o "$out/_n.so"
llvm-strip --strip-all "$out/_n.so" -o "$out/sample_arm64_nounwind.so"
rm -f "$out/_n.o" "$out/_n.so"

python3 "$here/scripts/damage_fixtures.py" "$out"
python3 "$here/scripts/gen_zstd_apk.py" "$out"
echo "fixtures written to $out"
