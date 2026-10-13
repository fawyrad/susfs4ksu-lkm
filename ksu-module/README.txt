Samsung SUSFS LKM Loader -- KernelSU installation

Install the generated ZIP through the KernelSU manager, not recovery.
Installation selects a matching ARM64 Android/KMI but does not load kernel code.
Reboot manually to activate. Disable/uninstall also takes effect after reboot;
this package never attempts live rmmod.

The module ID remains susfs_lkm_loader, so this replaces the earlier wrapper.
Disable other SUSFS loader modules before activation. The read-only protocol
probe detects responding built-in/existing SUSFS and leaves it untouched;
ambiguous replies also stop loading. No rules are added or changed.

Selection uses /proc/sys/kernel/osrelease and the exact Android/KMI pair.
There is no tagless, nearest-version, or Android-OS-property fallback.
Supported pairs are listed in kmis. A matching KMI does not prove every vendor
kernel has the same internal ABI. Individual device runtime testing remains.

The standard post-fs-data.sh stage uses bin/susfs_insmod with expose_proc=1.
Check load.log inside the installed module directory after reboot. A zero
loader exit alone is followed by a protocol probe before success is reported.
No sepolicy, initrc, global boot scripts, or system partitions are modified.
This stage is too late for FolkSU pre-mount dynamic-kstat snapshots.

All eight modules and both userspace binaries were supplied by the same build
workflow; the package builder downloads no binary. See provenance.json, the
per-KMI manifests and source/matching-source.tar.gz for reproducibility.

FIX1: versionCode 8. Disable/remove the old susfs_guard_lkm loader before
rebooting with this package. load.log identifies FIX1 and the built source commit.
The userspace loader is checked for unsupported runtime relocations; it retains
the upstream loading behavior and kernel-only symbol-matching correction.
