#!/usr/bin/env python3
"""Independent synthetic-ELF regression tests; these do not compile/load a module.

Usage: python test-multikmi.py /path/to/tools/verify-samsung.py
"""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
import shutil


EXPECTED = {
    "android12-5.10": "5.10",
    "android13-5.10": "5.10",
    "android13-5.15": "5.15",
    "android14-5.15": "5.15",
    "android14-6.1": "6.1",
    "android15-6.6": "6.6",
    "android16-6.12": "6.12",
    "android17-6.18": "6.18",
}


def elf_fixture(release, marker, module_size=1024, imports=None,
                with_handler=True, with_symtab=True, namespace=True,
                machine=183, kind=1, module_name="susfs_guard_lkm"):
    """Create a small ELF-shaped input for the parser, not runnable kernel code."""
    if imports is None:
        imports = ["register_kprobe", "unregister_kprobe"]
    if isinstance(marker, str):
        marker = marker.encode()
    names = ["", ".text", ".rodata", ".modinfo",
             ".gnu.linkonce.this_module", ".strtab", ".symtab", ".shstrtab"]
    if not with_symtab:
        names[6] = ".missing_symtab"
    shnames = bytearray(b"\0")
    name_offsets = {"": 0}
    for name in names[1:]:
        name_offsets[name] = len(shnames)
        shnames.extend(name.encode() + b"\0")
    symstrings = bytearray(b"\0")
    symbol_names = (["susfs_pre_handler"] if with_handler else []) + list(imports)
    offsets = {}
    for name in symbol_names:
        offsets[name] = len(symstrings)
        symstrings.extend(name.encode() + b"\0")
    symbols = bytearray(24)
    if with_handler:
        symbols.extend(struct.pack("<IBBHQQ", offsets["susfs_pre_handler"],
                                   0x12, 0, 1, 16, 8))
    for name in imports:
        symbols.extend(struct.pack("<IBBHQQ", offsets[name], 0x10, 0, 0, 0, 0))
    modinfo = ("name=" + module_name + "\0vermagic=" + release +
               " SMP preempt mod_unload modversions aarch64\0").encode()
    if namespace:
        modinfo += b"import_ns=ANDROID_GKI_VFS_EXPORT_ONLY\0"
    contents = [b"", b"\0" * 16 + b"\x1f\x20\x03\xd5" * 2,
                marker + b"\0", modinfo, b"\0" * module_size,
                bytes(symstrings), bytes(symbols), bytes(shnames)]
    # Section zero is NULL; other sections are PROGBITS except the two string
    # tables and the symbol table. Text's flags are ALLOC|EXECINSTR.
    section_types = [0, 1, 1, 1, 1, 3, 2, 3]
    data = bytearray(64)
    section_headers = []
    for index, content in enumerate(contents):
        while len(data) % 8:
            data.append(0)
        at = len(data) if index else 0
        data.extend(content)
        section_headers.append(struct.pack(
            "<IIQQQQIIQQ", name_offsets[names[index]], section_types[index],
            6 if index == 1 else 0, 0, at, len(content),
            5 if index == 6 else 0, 1 if index == 6 else 0,
            8 if index else 0, 24 if index == 6 else 0))
    while len(data) % 8:
        data.append(0)
    shoff = len(data)
    data.extend(b"".join(section_headers))
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, kind, machine, 1,
                         0, 0, shoff, 0, 64, 0, 0, 64, len(names), 7)
    data[:64] = header
    return bytes(data)


class MultiKmiTests(unittest.TestCase):
    verifier = None

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="susfs-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.counter = 0

    def run_elf(self, variant="android15-6.6", release=None,
                recorded_release=None, **options):
        self.counter += 1
        out = self.root / str(self.counter)
        out.mkdir()
        family = EXPECTED.get(variant, "6.6")
        release = release or family + ".123-synthetic"
        (out / "kernel.release.txt").write_text(
            (recorded_release if recorded_release is not None else release) + "\n",
            encoding="utf-8")
        module = out / ("susfs_guard_lkm-" + variant + ".ko")
        marker = options.pop("marker", self.verifier.MARKER)
        module.write_bytes(elf_fixture(release, marker, **options))
        with contextlib.redirect_stdout(io.StringIO()):
            self.verifier.inspect_elf(module, out, variant)
        return json.loads((out / "module-manifest.json").read_text(encoding="utf-8"))

    def assert_rejected(self, **options):
        with self.assertRaises((ValueError, KeyError)):
            self.run_elf(**options)

    def test_exact_eight_variant_contract(self):
        self.assertEqual(set(self.verifier.TARGETS), set(EXPECTED))
        for variant, family in EXPECTED.items():
            with self.subTest(variant=variant):
                self.assertEqual(self.verifier.TARGETS[variant]["kernel_family"], family)
                self.assertEqual(self.verifier.TARGETS[variant]["ddk_image_tag"],
                                 "ghcr.io/ylarod/ddk-min:" + variant + "-20260828")

    def test_all_eight_matching_elf_records(self):
        sizes = [1024, 1088, 1152, 1280, 1408, 1536, 1664, 1792]
        for (variant, family), size in zip(EXPECTED.items(), sizes):
            with self.subTest(variant=variant, module_size=size):
                release = family + ".123-synthetic"
                report = self.run_elf(variant, release, module_size=size)
                self.assertTrue(report["vermagic"].startswith(release + " "))
                self.assertEqual(report["this_module_size"], size)
                self.assertTrue(report["symtab_retained"])
                if "variant" in report:
                    self.assertEqual(report["variant"], variant)

    def test_wrong_family_rejected_for_every_variant(self):
        for variant, family in EXPECTED.items():
            other = "6.1" if family != "6.1" else "6.6"
            with self.subTest(variant=variant):
                self.assert_rejected(variant=variant, release=other + ".123-synthetic")

    def test_exact_release_mismatch_rejected(self):
        self.assert_rejected(release="6.6.123-one", recorded_release="6.6.123-two")

    def test_unknown_variant_rejected(self):
        self.assert_rejected(variant="android99-6.6")

    def test_symtab_required(self):
        self.assert_rejected(with_symtab=False)

    def test_kprobe_imports_required_individually(self):
        for imports in (["register_kprobe"], ["unregister_kprobe"], []):
            with self.subTest(imports=imports):
                self.assert_rejected(imports=imports)

    def test_allocation_store_imports_rejected(self):
        for extra in ("xa_store", "__xa_store"):
            with self.subTest(extra=extra):
                self.assert_rejected(imports=["register_kprobe", "unregister_kprobe", extra])

    def test_handler_and_marker_required_individually(self):
        self.assert_rejected(with_handler=False)
        self.assert_rejected(marker=b"unreviewed marker")

    def test_namespace_import_required(self):
        self.assert_rejected(namespace=False)

    def test_kallsyms_link_dependencies_rejected(self):
        for extra in ("kallsyms_lookup_name", "kallsyms_lookup",
                      "kallsyms_lookup_size_offset", "kallsyms_on_each_symbol",
                      "kallsyms_on_each_match_symbol"):
            with self.subTest(extra=extra):
                self.assert_rejected(imports=["register_kprobe", "unregister_kprobe", extra])

    def test_empty_module_structure_rejected(self):
        self.assert_rejected(module_size=0)

    def test_non_arm64_or_executable_rejected(self):
        self.assert_rejected(machine=62)
        self.assert_rejected(kind=2)

    def test_module_name_rejected(self):
        self.assert_rejected(module_name="wrong_module")

    def test_malformed_elf_rejected(self):
        for blob in (b"", b"not ELF", b"\x7fELF\x02\x01" + b"\0" * 58):
            with self.subTest(length=len(blob)):
                with self.assertRaises(ValueError):
                    self.verifier.elf_data(blob)
        valid = bytearray(elf_fixture("6.6.123-synthetic", self.verifier.MARKER))
        struct.pack_into("<Q", valid, 40, len(valid) + 1)
        with self.assertRaises(ValueError):
            self.verifier.elf_data(bytes(valid))

    def collector_fixture(self):
        artifacts = self.root / "artifacts"
        artifacts.mkdir()
        expected_commit = "1" * 40
        for variant, family in EXPECTED.items():
            target = artifacts / ("evidence-" + variant) / variant
            target.mkdir(parents=True)
            name = "susfs_guard_lkm-" + variant + ".ko"
            data = elf_fixture(family + ".123-synthetic", self.verifier.MARKER)
            (target / name).write_bytes(data)
            identity = {
                "target_kmi": variant,
                "fork_commit": expected_commit,
                "official_base_commit": self.verifier.BASE_COMMIT,
                "overlay_sha256": self.verifier.OVERLAY_SHA256,
                "ddk_image_tag": self.verifier.TARGETS[variant]["ddk_image_tag"],
            }
            source = dict(identity)
            module = {"file": name, "sha256": hashlib.sha256(data).hexdigest()}
            build = dict(identity, build_status="COMPILED_AND_STATIC_CHECKED",
                         runtime_status="NOT_TESTED", module=module)
            for filename, record in (("source-manifest.json", source),
                                     ("module-manifest.json", module),
                                     ("build-manifest.json", build)):
                (target / filename).write_text(json.dumps(record), encoding="utf-8")
        return artifacts, self.root / "collected", expected_commit

    def rewrite_manifest(self, path, field, value):
        record = json.loads(path.read_text(encoding="utf-8"))
        record[field] = value
        path.write_text(json.dumps(record), encoding="utf-8")

    def test_collector_all_eight(self):
        artifacts, out, commit = self.collector_fixture()
        with contextlib.redirect_stdout(io.StringIO()):
            self.verifier.collect(artifacts, out, commit)
        actual = {p.name for p in (out / "modules").glob("*.ko")}
        self.assertEqual(actual, {"susfs_guard_lkm-" + v + ".ko" for v in EXPECTED})

    def test_collector_missing_variant(self):
        artifacts, out, commit = self.collector_fixture()
        next(artifacts.rglob("build-manifest.json")).unlink()
        with self.assertRaises(ValueError):
            self.verifier.collect(artifacts, out, commit)

    def test_collector_duplicate_variant(self):
        artifacts, out, commit = self.collector_fixture()
        first = next(artifacts.rglob("build-manifest.json")).parent
        shutil.copytree(first, artifacts / "duplicate")
        with self.assertRaises(ValueError):
            self.verifier.collect(artifacts, out, commit)

    def test_collector_wrong_commit(self):
        artifacts, out, commit = self.collector_fixture()
        with self.assertRaises(ValueError):
            self.verifier.collect(artifacts, out, "2" * 40)

    def test_collector_wrong_hash(self):
        artifacts, out, commit = self.collector_fixture()
        first = next(artifacts.rglob("*.ko"))
        first.write_bytes(first.read_bytes() + b"changed")
        with self.assertRaises(ValueError):
            self.verifier.collect(artifacts, out, commit)

    def test_collector_mismatched_source_identity(self):
        artifacts, out, commit = self.collector_fixture()
        first = next(artifacts.rglob("source-manifest.json"))
        self.rewrite_manifest(first, "fork_commit", "2" * 40)
        with self.assertRaises(ValueError):
            self.verifier.collect(artifacts, out, commit)

    def test_collector_wrong_build_status(self):
        artifacts, out, commit = self.collector_fixture()
        first = next(artifacts.rglob("build-manifest.json"))
        self.rewrite_manifest(first, "build_status", "BUILD_NOT_RUN")
        with self.assertRaises(ValueError):
            self.verifier.collect(artifacts, out, commit)

    def test_collector_wrong_image_tag(self):
        artifacts, out, commit = self.collector_fixture()
        first = next(artifacts.rglob("build-manifest.json"))
        self.rewrite_manifest(first, "ddk_image_tag", "ghcr.io/other/ddk:wrong")
        with self.assertRaises(ValueError):
            self.verifier.collect(artifacts, out, commit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("verifier", type=Path)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("samsung_verifier_under_test", args.verifier)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    MultiKmiTests.verifier = verifier
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(MultiKmiTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.wasSuccessful():
        print("SYNTHETIC_ELF_PASS: all 8 variants; varying module sizes; malformed, mismatched and incomplete ELF rejection; no kernel compilation or device execution")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
