#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Package this workflow's eight compiled modules; no downloads or device operations."""
import argparse
import gzip
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tarfile
import zipfile

BASE_COMMIT = "85ef920ccf27682a2a9089b4676547f691b92828"
REVIEWED_LOADER_SHA256 = "663b55f719c5d559bc0220098822b687715ad3c0ac40b568ec05d551700f2db0"
WRAPPER_COMMIT = "170c672ebff5a35ea30a7bee3949cc67a96c9710"
TARGETS = (
    "android12-5.10", "android13-5.10", "android13-5.15", "android14-5.15",
    "android14-6.1", "android15-6.6", "android16-6.12", "android17-6.18",
)
TEMPLATES = ("module.prop", "customize.sh", "post-fs-data.sh", "kmi.sh", "NOTICE.txt", "README.txt")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def git(root, *args):
    return subprocess.check_output(["git", "-c", "safe.directory=" + str(root), "-C", str(root), *args])


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def elf(data, label, executable):
    require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01", label + ": expected ELF64 little-endian")
    kind, machine, version = struct.unpack_from("<HHI", data, 16)
    require(machine == 183 and version == 1, label + ": expected AArch64 ELF version 1")
    require(kind in ((2, 3) if executable else (1,)), label + ": unexpected ELF file type")
    require(struct.unpack_from("<H", data, 52)[0] == 64, label + ": invalid ELF header size")
    if executable:
        entry, phoff = struct.unpack_from("<QQ", data, 24)
        phentsize, phnum = struct.unpack_from("<HH", data, 54)
        require(phnum > 0 and phentsize == 56 and phoff + phnum * phentsize <= len(data),
                label + ": invalid ELF program headers")
        entry_ok = False
        for i in range(phnum):
            typ, flags, offset, vaddr, _, filesz, memsz, _ = struct.unpack_from("<IIQQQQQQ", data, phoff + i * phentsize)
            require(offset + filesz <= len(data), label + ": truncated ELF segment")
            if typ == 1:
                require(filesz <= memsz, label + ": invalid load segment")
                if flags & 1 and vaddr <= entry < vaddr + filesz:
                    entry_ok = True
        require(entry_ok, label + ": entry point is not in an executable load segment")
    return {"sha256": digest(data), "size": len(data), "architecture": "AArch64",
            "elf_type": {1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN"}[kind]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--collection", type=Path, required=True)
    parser.add_argument("--loader", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--build-info", type=Path, help="Recorded NDK/compiler versions and exact build commands")
    args = parser.parse_args()
    root, collection = args.root.resolve(), args.collection.resolve()
    expected = args.expected_commit
    require(re.fullmatch(r"[0-9a-f]{40}", expected) is not None, "Expected commit must be a full lowercase SHA-1")
    require(git(root, "rev-parse", "HEAD").decode().strip() == expected, "Checkout differs from dispatched commit")
    require(not git(root, "diff", "--name-only", "HEAD", "--").strip(), "Tracked source differs from HEAD")
    required_sources = ["tools/susfs_insmod.c", "tools/verify-freestanding-loader.py", "tools/susfs_probe.c", "tools/package-samsung-ksu.py",
                        "kernel/lsm_hook.c", "LICENSE"] + ["ksu-module/" + name for name in TEMPLATES]
    for name in required_sources:
        require(git(root, "show", "HEAD:" + name) == (root / name).read_bytes(), "Source differs from archived HEAD: " + name)
    require(digest((root / "tools/susfs_insmod.c").read_bytes()) == REVIEWED_LOADER_SHA256,
            "Loader source differs from the reviewed kernel-only symbol matcher plus relocation-free diagnostics")
    overlay = digest((root / "kernel/lsm_hook.c").read_bytes())
    matrix = read_json(collection / "BUILD_MATRIX.json")
    identity = {"fork_commit": expected, "official_base_commit": BASE_COMMIT, "overlay_sha256": overlay}
    for key, value in identity.items():
        require(matrix.get(key) == value, "Collection identity mismatch: " + key)
    require(matrix.get("module_count") == 8 and sorted(matrix.get("targets", [])) == sorted(TARGETS),
            "Collection must contain exactly all eight targets")
    module_names = {"susfs_guard_lkm-" + target + ".ko" for target in TARGETS}
    require({p.name for p in (collection / "modules").iterdir()} == module_names,
            "Collection modules directory differs from the exact eight expected filenames")
    require({p.name for p in (collection / "manifests").iterdir()} == {t + ".json" for t in TARGETS},
            "Collection manifests directory differs from the exact eight expected filenames")
    payload, modes, module_records = {}, {}, {}
    for name in TEMPLATES:
        data = (root / "ksu-module" / name).read_bytes()
        require(b"\r" not in data and b"\x00" not in data, "Wrapper text must use LF: " + name)
        payload[name] = data
        modes[name] = 0o755 if name.endswith(".sh") else 0o644
    payload["kmis"] = ("\n".join(TARGETS) + "\n").encode()
    payload["skip_mount"] = b""
    payload["LICENSE"] = (root / "LICENSE").read_bytes()
    for target in TARGETS:
        manifest = read_json(collection / "manifests" / (target + ".json"))
        required = dict(identity, target_kmi=target, build_status="COMPILED_AND_STATIC_CHECKED",
                        ddk_image_tag="ghcr.io/ylarod/ddk-min:" + target + "-20260828")
        for key, value in required.items():
            require(manifest.get(key) == value, target + ": manifest mismatch: " + key)
        name = "susfs_guard_lkm-" + target + ".ko"
        data = (collection / "modules" / name).read_bytes()
        require(manifest.get("module", {}).get("file") == name, target + ": module filename mismatch")
        require(manifest["module"].get("sha256") == digest(data), target + ": module SHA-256 mismatch")
        module_records[target] = dict(elf(data, name, False), file="lib/" + name)
        payload["lib/" + name] = data
        payload["manifests/" + target + ".json"] = json_bytes(manifest)
    payload["BUILD_MATRIX.json"] = json_bytes(matrix)
    payload["build-info/source-commit.txt"] = (expected + "\n").encode()
    loader_data, probe_data = args.loader.read_bytes(), args.probe.read_bytes()
    userspace = {"susfs_insmod": elf(loader_data, "susfs_insmod", True),
                 "susfs_probe": elf(probe_data, "susfs_probe", True)}
    loader_spec = importlib.util.spec_from_file_location("loader_elf_gate", root / "tools/verify-freestanding-loader.py")
    loader_gate = importlib.util.module_from_spec(loader_spec)
    loader_spec.loader.exec_module(loader_gate)
    userspace["susfs_insmod"]["freestanding_check"] = loader_gate.inspect_loader(loader_data)
    userspace["susfs_insmod"]["source_sha256"] = REVIEWED_LOADER_SHA256
    userspace["susfs_probe"]["source_sha256"] = digest((root / "tools/susfs_probe.c").read_bytes())
    payload["bin/susfs_insmod"], payload["bin/susfs_probe"] = loader_data, probe_data
    modes["bin/susfs_insmod"] = modes["bin/susfs_probe"] = 0o755
    source_tar = git(root, "archive", "--format=tar", "HEAD")
    with tarfile.open(fileobj=io.BytesIO(source_tar), mode="r:") as source:
        for member in source.getmembers():
            require(".git" not in Path(member.name).parts, "Source archive unexpectedly includes .git")
    source_gz = gzip.compress(source_tar, compresslevel=9, mtime=0)
    payload["source/matching-source.tar.gz"] = source_gz
    provenance = dict(identity, supported_kmis=list(TARGETS), architecture="arm64",
                      module_count=8, module_id="susfs_lkm_loader", wrapper_version_code=8,
                      wrapper_repository="https://github.com/matsuzaka-yuki/susfs-lkm-module",
                      wrapper_commit=WRAPPER_COMMIT, wrapper_license="GPL-2.0-only",
                      binary_origin="current workflow run only; package builder performs no downloads",
                      github_repository=os.environ.get("GITHUB_REPOSITORY"),
                      github_run_id=os.environ.get("GITHUB_RUN_ID"),
                      github_run_attempt=os.environ.get("GITHUB_RUN_ATTEMPT"),
                      modules=module_records, userspace=userspace,
                      source_archive={"file": "source/matching-source.tar.gz", "sha256": digest(source_gz)},
                      runtime_status="NOT_TESTED_BY_PACKAGER")
    if args.build_info:
        build_info = args.build_info.read_bytes()
        require(bool(build_info), "Userspace build-info log is empty")
        payload["build-info/userspace-build.log"] = build_info
        provenance["userspace_build_info"] = {"file": "build-info/userspace-build.log", "sha256": digest(build_info)}
    payload["provenance.json"] = json_bytes(provenance)
    payload["SHA256SUMS"] = "".join(digest(data) + "  " + name + "\n" for name, data in sorted(payload.items())).encode()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    zip_path = out / ("susfs-samsung-patcher1-" + expected[:12] + "-arm64-multi-kmi.zip")
    require(not zip_path.exists(), "Output already exists; choose an empty output directory")
    with zipfile.ZipFile(zip_path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(payload.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (0o100000 | modes.get(name, 0o644)) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    with zipfile.ZipFile(zip_path) as archive:
        require(archive.testzip() is None, "ZIP CRC verification failed")
        require(len(archive.namelist()) == len(payload) and set(archive.namelist()) == set(payload), "ZIP file list mismatch")
        for name, data in payload.items():
            require(archive.read(name) == data, "ZIP byte mismatch: " + name)
            require(archive.getinfo(name).external_attr >> 16 == 0o100000 | modes.get(name, 0o644),
                    "ZIP Unix permission mismatch: " + name)
        for target, record in module_records.items():
            require(digest(archive.read(record["file"])) == record["sha256"], "ZIP module digest mismatch: " + target)
    zip_sha = digest(zip_path.read_bytes())
    (out / (zip_path.name + ".sha256")).write_text(zip_sha + "  " + zip_path.name + "\n", encoding="utf-8")
    (out / "PACKAGE_VERIFICATION.json").write_bytes(json_bytes({"result": "PACKAGE_PASS", "zip": zip_path.name,
        "sha256": zip_sha, "files_checked": len(payload), "module_count": 8,
        "fork_commit": expected, "crc_verified": True, "all_bytes_verified": True,
        "unix_permissions_verified": True, "runtime_status": "NOT_TESTED_BY_PACKAGER"}))
    print("PACKAGE_PASS: eight current-run modules; ARM64 loader/probe; matching source; ZIP CRC, bytes and Unix permissions verified")
    print(str(zip_path))
    print("SHA256: " + zip_sha)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError, zipfile.BadZipFile) as exc:
        print("PACKAGE_FAILED: " + str(exc), file=sys.stderr)
        sys.exit(1)
