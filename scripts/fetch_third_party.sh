#!/usr/bin/env bash
# Restores the third-party sources at the exact pinned versions and verifies the commit of each one.
# usage: scripts/fetch_third_party.sh [--full] [--reference]
#   --full       clone with the complete history instead of a single commit
#   --reference  also fetch LIEF and Unicorn, which are NOT part of the build (kept only for reference; see DEPENDENCIES.md)
# A directory that already holds the pinned commit is left alone.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TP="$ROOT/third_party"
FULL=0
REFERENCE=0
for a in "$@"; do
  case "$a" in
    --full) FULL=1 ;;
    --reference) REFERENCE=1 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

# name url tag commit
PINNED=(
  "zlib https://github.com/madler/zlib v1.3.2 da607da739fa6047df13e66a2af6b8bec7c2a498"
  "zstd https://github.com/facebook/zstd v1.5.7 f8745da6ff1ad1e7bab384bd1f9d742439278e99"
  "capstone https://github.com/capstone-engine/capstone 5.0.9 022575848782a4801fd150fdbc927effcbca0864"
  "ELFIO https://github.com/serge1/ELFIO Release_3.12 8ae6cec5d60495822ecd57d736f66149da9b1830"
)
REFERENCE_ONLY=(
  "LIEF https://github.com/lief-project/LIEF 1.0.0 d05b3499b6934137e917c009a4df0a9dc8cb11c5"
  "unicorn https://github.com/unicorn-engine/unicorn 2.1.4 8028ec436f2d9376525352dd38ed9ed6b9f6be10"
)

fetch_one() {
  local name="$1" url="$2" tag="$3" want="$4" dir="$TP/$1"
  if [ -d "$dir/.git" ] || [ -f "$dir/.git" ]; then
    local have
    have="$(git -C "$dir" rev-parse HEAD 2>/dev/null || true)"
    if [ "$have" = "$want" ]; then
      echo "ok      $name $tag ($want)"
      return 0
    fi
    echo "wrong commit in $dir (have ${have:-none}); it is not touched. Remove the directory to fetch it again." >&2
    return 1
  fi
  if [ -d "$dir" ] && [ -n "$(ls -A "$dir" 2>/dev/null)" ]; then
    echo "$dir exists, is not a git checkout and is not empty: cannot verify it" >&2
    return 1
  fi
  rm -rf "$dir"
  if [ "$FULL" = 1 ]; then
    git clone --recurse-submodules --branch "$tag" "$url" "$dir"
  else
    git clone --depth 1 --recurse-submodules --shallow-submodules --branch "$tag" "$url" "$dir"
  fi
  local got
  got="$(git -C "$dir" rev-parse HEAD)"
  if [ "$got" != "$want" ]; then
    echo "$name $tag resolved to $got, expected $want" >&2
    return 1
  fi
  echo "fetched $name $tag ($want)"
}

status=0
for line in "${PINNED[@]}"; do
  read -r n u t c <<<"$line"
  fetch_one "$n" "$u" "$t" "$c" || status=1
done
if [ "$REFERENCE" = 1 ]; then
  for line in "${REFERENCE_ONLY[@]}"; do
    read -r n u t c <<<"$line"
    fetch_one "$n" "$u" "$t" "$c" || status=1
  done
fi
exit $status
