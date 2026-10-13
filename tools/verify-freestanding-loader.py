#!/usr/bin/env python3
"""Reject AArch64 static PIE loaders that need unsupported runtime relocation.

susfs_insmod has its own _start, with neither a dynamic interpreter nor a
self-relocation pass. Inspect program headers and PT_DYNAMIC, not section names:
stripping section headers must not hide a relocation dependency from this gate.
Only the Python standard library is required. This is a structural check, not a
device execution or module-loading test.
"""

import argparse
import hashlib
from pathlib import Path
import struct
import sys


class InvalidLoader(ValueError):
    pass


# A nonzero address, byte count, or relocation count means a relocation consumer
# would be required. Include Android packed tables and legacy Android RELR tags.
RELOCATION_TAGS = {
    2: "DT_PLTRELSZ", 7: "DT_RELA", 8: "DT_RELASZ",
    17: "DT_REL", 18: "DT_RELSZ", 23: "DT_JMPREL",
    35: "DT_RELRSZ", 36: "DT_RELR",
    0x6000000F: "DT_ANDROID_REL", 0x60000010: "DT_ANDROID_RELSZ",
    0x60000011: "DT_ANDROID_RELA", 0x60000012: "DT_ANDROID_RELASZ",
    0x6FFFE000: "DT_ANDROID_RELR", 0x6FFFE001: "DT_ANDROID_RELRSZ",
    0x6FFFFFF9: "DT_RELACOUNT", 0x6FFFFFFA: "DT_RELCOUNT",
}
ENTRY_SIZE_TAGS = {9: 24, 19: 16, 37: 8, 0x6FFFE003: 8}


def inspect_loader(data):
    """Return structural facts, or raise InvalidLoader for invalid input."""
    if len(data) < 64:
        raise InvalidLoader("truncated ELF64 header")
    ident = data[:16]
    if ident[:4] != b"\x7fELF":
        raise InvalidLoader("missing ELF magic")
    if ident[4:7] != bytes((2, 1, 1)):
        raise InvalidLoader("expected ELF64 little-endian version 1")
    fields = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    (etype, machine, version, entry, phoff, _shoff, _flags, ehsize,
     phentsize, phnum, _shentsize, _shnum, _shstrndx) = fields
    if etype != 3 or machine != 183 or version != 1:
        raise InvalidLoader("expected ELF64 AArch64 ET_DYN version 1")
    if ehsize != 64 or phentsize != 56 or phnum in (0, 0xFFFF):
        raise InvalidLoader("invalid or unsupported program-header layout")
    if phoff < 64 or phoff + phnum * 56 > len(data):
        raise InvalidLoader("program-header table is outside the file")

    loads, dynamics = [], []
    for index in range(phnum):
        ptype, flags, offset, vaddr, _paddr, filesz, memsz, align = (
            struct.unpack_from("<IIQQQQQQ", data, phoff + index * 56))
        if offset + filesz > len(data):
            raise InvalidLoader("program segment is outside the file")
        if vaddr + memsz > 1 << 64:
            raise InvalidLoader("program segment address overflows ELF64")
        if ptype == 3:  # PT_INTERP
            raise InvalidLoader("PT_INTERP requires a dynamic interpreter")
        if ptype in (1, 2) and filesz > memsz:
            raise InvalidLoader("segment file size exceeds memory size")
        if ptype == 1:  # PT_LOAD
            if align > 1 and (align & (align - 1) or
                              offset % align != vaddr % align):
                raise InvalidLoader("invalid PT_LOAD alignment")
            loads.append((flags, offset, vaddr, filesz, memsz))
        if ptype == 2:  # PT_DYNAMIC
            dynamics.append((offset, vaddr, filesz))
    if not loads:
        raise InvalidLoader("no PT_LOAD segment")
    if not any(flags & 1 and vaddr <= entry < vaddr + filesz
               for flags, _off, vaddr, filesz, _memsz in loads):
        raise InvalidLoader("entry point is not file-backed executable PT_LOAD")
    if len(dynamics) > 1:
        raise InvalidLoader("multiple PT_DYNAMIC segments")

    tags = {}
    for offset, vaddr, size in dynamics:
        if size == 0 or size % 16:
            raise InvalidLoader("invalid PT_DYNAMIC size")
        if not any(off <= offset and offset + size <= off + filesz and
                   va + offset - off == vaddr
                   for _fl, off, va, filesz, _ms in loads):
            raise InvalidLoader("PT_DYNAMIC is not file-backed by PT_LOAD")
        terminated = False
        for pos in range(offset, offset + size, 16):
            tag, value = struct.unpack_from("<qQ", data, pos)
            if tag == 0:  # DT_NULL terminates the runtime table
                terminated = True
                break
            if tag in tags:
                raise InvalidLoader("duplicate dynamic tag 0x%x" % tag)
            tags[tag] = value
        if not terminated:
            raise InvalidLoader("PT_DYNAMIC has no DT_NULL terminator")
    needed = [(RELOCATION_TAGS[tag], value) for tag, value in tags.items()
              if tag in RELOCATION_TAGS and value]
    if needed:
        raise InvalidLoader("runtime relocations required: " + ", ".join(
            "%s=0x%x" % item for item in needed))
    if 1 in tags:  # DT_NEEDED
        raise InvalidLoader("DT_NEEDED requires a shared-library loader")
    for tag, expected in ENTRY_SIZE_TAGS.items():
        if tag in tags and tags[tag] not in (0, expected):
            raise InvalidLoader("invalid relocation entry size for tag 0x%x" % tag)
    if 20 in tags and tags[20] not in (0, 7, 17):
        raise InvalidLoader("invalid DT_PLTREL")
    return {"program_headers": phnum, "dynamic_segments": len(dynamics),
            "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("loader", type=Path)
    args = parser.parse_args()
    try:
        result = inspect_loader(args.loader.read_bytes())
    except (OSError, InvalidLoader) as exc:
        print("FAIL: %s: %s" % (args.loader, exc), file=sys.stderr)
        return 1
    print("PASS: %s: ELF64 AArch64 ET_DYN; no PT_INTERP; no runtime relocations"
          % args.loader)
    print("SHA256: %s" % result["sha256"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
