#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Derived from matsuzaka-yuki/susfs-lkm-module commit
# 170c672ebff5a35ea30a7bee3949cc67a96c9710; Samsung build packaging adaptation.
MODDIR=${0%/*}
[ ! -f "$MODDIR/disable" ] && [ ! -f "$MODDIR/remove" ] || exit 0
umask 077
exec > "$MODDIR/load.log" 2>&1
echo "SUSFS Samsung loader patcher1: $(date)"
[ ! -r "$MODDIR/build-info/source-commit.txt" ] || { printf "Source commit: "; cat "$MODDIR/build-info/source-commit.txt"; }
# Read the real release: uname may already be spoofed by another SUSFS implementation.
REAL_KERNEL=$(cat /proc/sys/kernel/osrelease) || exit 1
. "$MODDIR/kmi.sh" || { echo "Missing KMI selector."; exit 1; }
KMI=$(select_kmi "$REAL_KERNEL" "$MODDIR") \
  || { echo "Refusing unrecognized kernel release (no packaged KMI matches): $REAL_KERNEL"; exit 1; }
LKM="$MODDIR/lib/susfs_guard_lkm-$KMI.ko"
[ -s "$LKM" ] || { echo "Missing packaged LKM for $KMI."; exit 1; }
echo "Selected kernel KMI: $KMI"
"$MODDIR/bin/susfs_probe"
RESULT=$?
case "$RESULT" in
  0) echo "SUSFS already detected; leaving it untouched."; exit 0 ;;
  10) ;;
  *) echo "Cannot safely establish SUSFS absence (probe=$RESULT); refusing load."; exit 1 ;;
esac
# The upstream loader performs kallsyms relocation and its own checks. No fallback plain insmod,
# forced unload, rule mutation, global clearing or changes to /data/adb/ksu are performed here.
"$MODDIR/bin/susfs_insmod" "$LKM" expose_proc=1
RESULT=$?
[ "$RESULT" = 0 ] || { echo "Upstream loader failed: $RESULT"; exit "$RESULT"; }
"$MODDIR/bin/susfs_probe" || { echo "Load returned success but protocol probe failed."; exit 1; }
echo "SUSFS detected after loading. No rules were applied by this module."
