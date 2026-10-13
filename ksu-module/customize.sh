#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Derived from matsuzaka-yuki/susfs-lkm-module commit
# 170c672ebff5a35ea30a7bee3949cc67a96c9710; Samsung build packaging adaptation.
[ "$KSU" = true ] || abort "KernelSU-compatible managers only; Magisk is not supported."
[ "$ARCH" = arm64 ] || abort "Only arm64 is packaged."
REAL_KERNEL=$(cat /proc/sys/kernel/osrelease) || abort "Cannot read real kernel release."
. "$MODPATH/kmi.sh" || abort "Missing KMI selector."
KMI=$(select_kmi "$REAL_KERNEL" "$MODPATH") \
  || abort "Unrecognized kernel release: $REAL_KERNEL. No packaged KMI matches it; refusing to guess."
[ -s "$MODPATH/lib/susfs_guard_lkm-$KMI.ko" ] || abort "Missing packaged LKM for $KMI."
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
set_perm "$MODPATH/bin/susfs_probe" 0 0 0755
set_perm "$MODPATH/bin/susfs_insmod" 0 0 0755
touch "$MODPATH/skip_mount"
ui_print "- Installs loader only; does not load anything during installation."
ui_print "- Selected kernel KMI: $KMI (arm64). Vendor ABI compatibility is not guaranteed."
ui_print "- Reboot to activate. Disable/remove also takes effect after reboot."
ui_print "- Existing SUSFS is never replaced or unloaded."
ui_print "- FolkSU dynamic kstat pre-mount snapshots are NOT supported by this loading stage."
