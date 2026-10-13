#!/usr/bin/env bash
# Run inside the selected pinned DDK image via the manual workflow.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
: "${KDIR:?The selected DDK image must provide KDIR}"
: "${DDK_IMAGE_ID:?Run this helper through the image-recording workflow}"
: "${VARIANT:?Select one of the eight pinned KMI variants}"
OUT="$ROOT/${OUTPUT_DIR:-artifacts/$VARIANT}"
mkdir -p "$OUT"
for tool in make clang llvm-strip llvm-nm llvm-readelf llvm-objdump modinfo python3; do
  command -v "$tool" >/dev/null || { echo "Missing build tool: $tool" >&2; exit 1; }
done
python3 tools/verify-samsung.py source --variant "$VARIANT" --root "$ROOT" --out "$OUT" --reuse-record
{
  printf 'DDK_IMAGE_TAG=%s\nDDK_IMAGE_ID=%s\nKDIR=%s\n' "$DDK_IMAGE_TAG" "$DDK_IMAGE_ID" "$KDIR"
  clang --version
  make --version
  printf '\nKernel release:\n'
  cat "$KDIR/include/config/kernel.release"
  printf '\nRelevant build configuration:\n'
  grep -E '^(CONFIG_(ARM64|64BIT|KPROBES|MODULES|MODVERSIONS|CFI|LTO|KASAN|ARM64_BTI|ARM64_PTR_AUTH)[A-Z0-9_]*=|# CONFIG_(CFI|LTO)[A-Z0-9_]* is not set)' "$KDIR/.config" || true
} > "$OUT/build-environment.txt"
cp "$KDIR/include/config/kernel.release" "$OUT/kernel.release.txt"
FAMILY="${VARIANT#*-}"
case "$(cat "$OUT/kernel.release.txt")" in
  "$FAMILY".*) ;;
  *) echo "Selected DDK kernel release does not match $VARIANT" >&2; exit 1 ;;
esac
# This is the actual kbuild command used by the Samsung payload workflow,
# adjusted only from susfs-src/kernel to the already checked-out fork's kernel.
make -C "$KDIR" M="$ROOT/kernel" \
  ARCH=arm64 CC=clang LLVM=1 LLVM_IAS=1 \
  -j"$(nproc)" modules 2>&1 | tee "$OUT/build.log"
SOURCE="$ROOT/kernel/susfs_guard_lkm.ko"
FULL="$OUT/susfs_guard_lkm-$VARIANT.unstripped.ko"
MODULE="$OUT/susfs_guard_lkm-$VARIANT.ko"
test -s "$SOURCE"
cp "$SOURCE" "$FULL"
cp "$SOURCE" "$MODULE"
# -d removes debug info only; the official loader requires .symtab.
llvm-strip -d "$MODULE"
llvm-readelf --file-header --sections --symbols --relocations "$MODULE" > "$OUT/elf-report.txt"
llvm-nm --undefined-only "$MODULE" > "$OUT/imports.txt"
llvm-nm --defined-only "$MODULE" > "$OUT/defined-symbols.txt"
modinfo "$MODULE" > "$OUT/modinfo.txt"
llvm-objdump -d --disassemble-symbols=susfs_pre_handler "$MODULE" > "$OUT/pre-handler-disassembly.txt"
# Keep the complete disassembly to review inlined/outlined CFI bridges too.
llvm-objdump -d "$MODULE" > "$OUT/disassembly.txt"
# Retain the official cross-family LLVM-CFI/KCFI call-site gate.
python3 tools/cfi_sites.py --allow init_module,susfs_layers_down,susfs_tw_func "$MODULE" \
  2>&1 | tee "$OUT/cfi-sites.txt"
python3 tools/verify-samsung.py elf --variant "$VARIANT" --module "$MODULE" --out "$OUT"
python3 tools/verify-samsung.py finalize --variant "$VARIANT" --root "$ROOT" --out "$OUT"
printf '\nBuild and static checks complete. Device runtime status: NOT TESTED.\n'
