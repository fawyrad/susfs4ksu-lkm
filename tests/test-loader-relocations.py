#!/usr/bin/env python3
"""Stdlib regression tests; optional --legacy-loader checks a preserved binary."""

import argparse
import importlib.util
from pathlib import Path
import struct
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "loader_validator", ROOT / "tools" / "verify-freestanding-loader.py")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)
LEGACY_LOADER = None
SOURCE_ROOT = ROOT


def elf(tags=(), interpreter=False, dynamic=True, terminate=True):
    """Make a sectionless, file-backed synthetic ELF; no executable is run."""
    data = bytearray(1024)
    data[:16] = b"\x7fELF" + bytes((2, 1, 1)) + bytes(9)
    phnum = 1 + int(dynamic) + int(interpreter)
    struct.pack_into("<HHIQQQIHHHHHH", data, 16,
                     3, 183, 1, 0x180, 64, 0, 0, 64, 56, phnum, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64,
                     1, 5, 0, 0, 0, len(data), len(data), 0x1000)
    phpos = 120
    if dynamic:
        entries = list(tags) + ([(0, 0)] if terminate else [])
        for index, (tag, value) in enumerate(entries):
            struct.pack_into("<qQ", data, 0x200 + index * 16, tag, value)
        size = len(entries) * 16
        struct.pack_into("<IIQQQQQQ", data, phpos,
                         2, 4, 0x200, 0x200, 0x200, size, size, 8)
        phpos += 56
    if interpreter:
        struct.pack_into("<IIQQQQQQ", data, phpos,
                         3, 4, 0x300, 0x300, 0x300, 8, 8, 1)
        data[0x300:0x308] = b"/linker\0"
    return bytes(data)


class LoaderValidationTests(unittest.TestCase):
    def rejects(self, data, message):
        with self.assertRaisesRegex(VALIDATOR.InvalidLoader, message):
            VALIDATOR.inspect_loader(data)

    def test_sectionless_no_relocations(self):
        self.assertEqual(VALIDATOR.inspect_loader(elf())["dynamic_segments"], 1)

    def test_static_pie_without_dynamic_segment(self):
        self.assertEqual(VALIDATOR.inspect_loader(elf(dynamic=False))[
            "dynamic_segments"], 0)

    def test_zero_sized_relocation_metadata(self):
        VALIDATOR.inspect_loader(elf([(7, 0), (8, 0), (9, 24)]))

    def test_all_runtime_relocation_tags(self):
        for tag, name in VALIDATOR.RELOCATION_TAGS.items():
            with self.subTest(tag=name):
                self.rejects(elf([(tag, 0x300)]), name)

    def test_rela_pointer_and_size(self):
        self.rejects(elf([(7, 0x300), (8, 192), (9, 24)]), "DT_RELA")

    def test_interpreter(self):
        self.rejects(elf(interpreter=True), "PT_INTERP")

    def test_shared_library(self):
        self.rejects(elf([(1, 0)]), "DT_NEEDED")

    def test_truncated_header(self):
        self.rejects(elf()[:63], "truncated")

    def test_missing_magic(self):
        self.rejects(b"bad!" + elf()[4:], "magic")

    def test_wrong_class_endianness_ident_version(self):
        for index in (4, 5, 6):
            with self.subTest(index=index):
                data = bytearray(elf())
                data[index] = 0
                self.rejects(data, "ELF64 little-endian")

    def test_wrong_type_machine_version(self):
        for offset, fmt in ((16, "<H"), (18, "<H"), (20, "<I")):
            with self.subTest(offset=offset):
                data = bytearray(elf())
                struct.pack_into(fmt, data, offset, 0)
                self.rejects(data, "ET_DYN")

    def test_bad_header_sizes_counts(self):
        for offset, value in ((52, 0), (54, 0), (56, 0), (56, 65535)):
            with self.subTest(offset=offset, value=value):
                data = bytearray(elf())
                struct.pack_into("<H", data, offset, value)
                self.rejects(data, "program-header layout")

    def test_program_table_out_of_bounds(self):
        data = bytearray(elf())
        struct.pack_into("<Q", data, 32, 1020)
        self.rejects(data, "program-header table")

    def test_segment_out_of_bounds(self):
        data = bytearray(elf())
        struct.pack_into("<Q", data, 64 + 32, 1025)
        self.rejects(data, "segment is outside")

    def test_segment_address_overflow(self):
        data = bytearray(elf())
        struct.pack_into("<Q", data, 64 + 16, (1 << 64) - 1)
        self.rejects(data, "overflows")

    def test_file_size_exceeds_memory(self):
        data = bytearray(elf())
        struct.pack_into("<Q", data, 64 + 40, 1023)
        self.rejects(data, "exceeds memory")

    def test_bad_load_alignment(self):
        data = bytearray(elf())
        struct.pack_into("<Q", data, 64 + 48, 3)
        self.rejects(data, "alignment")

    def test_entry_not_executable(self):
        data = bytearray(elf())
        struct.pack_into("<I", data, 64 + 4, 4)
        self.rejects(data, "entry point")

    def test_no_load_segment(self):
        data = bytearray(elf())
        struct.pack_into("<I", data, 64, 0)
        self.rejects(data, "no PT_LOAD")

    def test_duplicate_dynamic_segment(self):
        data = bytearray(elf(interpreter=True))
        data[176:232] = data[120:176]
        self.rejects(data, "multiple PT_DYNAMIC")

    def test_unmapped_dynamic_table(self):
        data = bytearray(elf())
        struct.pack_into("<Q", data, 120 + 16, 0x201)
        self.rejects(data, "PT_DYNAMIC is not file-backed")

    def test_bad_dynamic_size(self):
        for size in (0, 15):
            with self.subTest(size=size):
                data = bytearray(elf())
                struct.pack_into("<Q", data, 120 + 32, size)
                self.rejects(data, "PT_DYNAMIC size")

    def test_unterminated_dynamic_table(self):
        self.rejects(elf([(9, 24)], terminate=False), "DT_NULL")

    def test_duplicate_dynamic_tags(self):
        self.rejects(elf([(7, 0), (7, 0)]), "duplicate dynamic tag")

    def test_bad_relocation_metadata(self):
        for tag in VALIDATOR.ENTRY_SIZE_TAGS:
            with self.subTest(tag=tag):
                self.rejects(elf([(tag, 1)]), "entry size")
        self.rejects(elf([(20, 1)]), "DT_PLTREL")

    def test_loader_uses_inline_diagnostic_strings(self):
        source = (SOURCE_ROOT / "tools" / "susfs_insmod.c").read_text(encoding="utf-8")
        self.assertTrue("static const char kmsg_interesting[][32]" in source,
                        "kmsg_interesting must store strings inline")
        self.assertFalse("static const char *const kmsg_interesting[]" in source,
                         "diagnostic pointer table requires runtime relocation")

    def test_preserved_legacy_loader(self):
        if LEGACY_LOADER is None:
            self.skipTest("supply --legacy-loader to check preserved binary")
        self.rejects(LEGACY_LOADER.read_bytes(), "runtime relocations required.*DT_RELA")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-loader", type=Path)
    parser.add_argument("--source-root", type=Path, default=ROOT,
                        help="source tree to check (supports baseline comparison)")
    args = parser.parse_args()
    LEGACY_LOADER = args.legacy_loader
    SOURCE_ROOT = args.source_root
    unittest.main(argv=[sys.argv[0]], verbosity=2)
