# SPDX-License-Identifier: GPL-2.0-only
# Derived from matsuzaka-yuki/susfs-lkm-module commit
# 170c672ebff5a35ea30a7bee3949cc67a96c9710; strict canonical KMI selection.
# Match the real kernel release, not the Android OS version or spoofable uname.
# The packaged KMIs are listed in "$2/kmis" (one <android-os>-<kver> per line),
# so a new upstream KMI needs no change here.
#
# A release is selected only on the canonical GKI shape
#   <kver>.<numeric patch>[-<kmi generation>...][-<build id>...]
# i.e. a purely numeric patch level directly followed by the Android tag. The patch
# level is parsed out first (a glob "*" would happily swallow a "-vendor" token) so a
# reordered release like 6.6.118-vendor-android15-8, a malformed one like
# 6.6.118.android15-8, or a release with no Android tag at all is refused instead of
# guessed: the upstream loader may patch vermagic, so a wrong pick would look like a
# successful load rather than a clean failure.
select_kmi() {
  rel="$1"
  while IFS= read -r kmi; do
    [ -n "$kmi" ] || continue
    os="${kmi%-*}"
    kver="${kmi#*-}"
    case "$rel" in
      "$kver".*) ;;
      *) continue ;;
    esac
    # $rel is guaranteed to start with "<kver>." now, so these expansions strip it.
    patch="${rel#"$kver".}"
    tag="${patch#*-}"
    patch="${patch%%-*}"
    # The patch level must be digits and nothing else: 118 yes, 118-vendor no.
    case "$patch" in
      ''|*[!0-9]*) continue ;;
    esac
    case "$tag" in
      "$os" | "$os"-*) echo "$kmi"; return 0 ;;
    esac
  done < "$2/kmis"
  return 1
}
