#!/usr/bin/env python3
"""Offline source/ELF evidence checks for the pinned Samsung eight-KMI build.

No phone operations; successful checks mean build/static validation, not runtime support.
"""
import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
import struct
import subprocess
import sys

BASE_COMMIT = "85ef920ccf27682a2a9089b4676547f691b92828"
OVERLAY_SHA256 = "7211f345f991bae282343d9c2f8d8ab6922ad53f1bf8ea6ee67d5496fe76d581"
TARGETS = {
    "android12-5.10": {"kernel_family": "5.10",
        "ddk_image_tag": "ghcr.io/ylarod/ddk-min:android12-5.10-20260828"},
    "android13-5.10": {"kernel_family": "5.10",
        "ddk_image_tag": "ghcr.io/ylarod/ddk-min:android13-5.10-20260828"},
    "android13-5.15": {"kernel_family": "5.15",
        "ddk_image_tag": "ghcr.io/ylarod/ddk-min:android13-5.15-20260828"},
    "android14-5.15": {"kernel_family": "5.15",
        "ddk_image_tag": "ghcr.io/ylarod/ddk-min:android14-5.15-20260828"},
    "android14-6.1": {"kernel_family": "6.1",
        "ddk_image_tag": "ghcr.io/ylarod/ddk-min:android14-6.1-20260828"},
    "android15-6.6": {"kernel_family": "6.6",
        "ddk_image_tag": "ghcr.io/ylarod/ddk-min:android15-6.6-20260828"},
    "android16-6.12": {"kernel_family": "6.12",
        "ddk_image_tag": "ghcr.io/ylarod/ddk-min:android16-6.12-20260828"},
    "android17-6.18": {"kernel_family": "6.18",
        "ddk_image_tag": "ghcr.io/ylarod/ddk-min:android17-6.18-20260828"},
}


def get_target(variant):
    if variant not in TARGETS:
        raise ValueError("Unknown target KMI: " + str(variant))
    return TARGETS[variant]
MARKER = b"multi-KMI entry-return; no handler allocation"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def git(root, *args):
    result = subprocess.run(["git", "-c", "safe.directory=" + str(root), "-C", str(root), *args],
                            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode("utf-8").strip()


def source(root, out, reuse, variant):
    target = get_target(variant)
    root = root.resolve()
    head = git(root, "rev-parse", "HEAD")
    git(root, "cat-file", "-e", BASE_COMMIT + "^{commit}")
    # Uploaded-source repositories can have unrelated history. Compare the
    # immutable endpoint trees below; do not require inherited ancestry.
    # Permit ONLY the reviewed hook replacement within the official kernel tree.
    changed = git(root, "diff", "--name-only", BASE_COMMIT, "HEAD", "--", "kernel")
    if set(changed.splitlines()) != {"kernel/lsm_hook.c"}:
        raise ValueError("Kernel changes must be exactly kernel/lsm_hook.c on the pinned base: " + changed)
    if git(root, "diff", "HEAD", "--", "kernel"):
        raise ValueError("Tracked kernel sources differ from the checked-out commit")
    # This runs before kbuild in a fresh checkout: reject ignored extras too.
    if git(root, "ls-files", "--others", "--", "kernel"):
        raise ValueError("Untracked kernel inputs are not part of the reviewed source contract")
    actual = sha((root / "kernel/lsm_hook.c").read_bytes())
    if actual != OVERLAY_SHA256:
        raise ValueError("kernel/lsm_hook.c differs from the reviewed overlay: " + actual)
    expected = os.environ.get("GITHUB_SHA")
    if expected and expected != head:
        raise ValueError("Checkout HEAD differs from the dispatched immutable commit")
    paths = git(root, "ls-files", "--", "kernel").splitlines()
    hashes = {p: sha((root / p).read_bytes()) for p in sorted(paths)}
    record = {"official_base_commit": BASE_COMMIT, "fork_commit": head,
              "target_kmi": variant, "expected_kernel_family": target["kernel_family"],
              "source_comparison": "pinned_commit_tree_not_ancestry",
              "fork_repository": os.environ.get("GITHUB_REPOSITORY"),
              "github_run_id": os.environ.get("GITHUB_RUN_ID"),
              "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
              "overlay_sha256": actual, "source_sha256": hashes,
              "source_tree_digest": sha(json.dumps(hashes, sort_keys=True).encode()),
              "ddk_image_tag": target["ddk_image_tag"], "runtime_status": "NOT_TESTED"}
    record_path = out / "source-manifest.json"
    if reuse:
        previous = json.loads(record_path.read_text(encoding="utf-8"))
        for key in ("official_base_commit", "fork_commit", "overlay_sha256", "source_sha256",
                    "target_kmi", "ddk_image_tag", "expected_kernel_family"):
            if previous[key] != record[key]:
                raise ValueError("Source changed between host preflight and container: " + key)
    else:
        save(record_path, record)
    print("SOURCE_PASS: exact reviewed overlay; other kernel files match pinned official base")


def elf_data(data):
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("Expected ELF64 little-endian")
    kind, machine = struct.unpack_from("<HH", data, 16)
    if kind != 1 or machine != 183:
        raise ValueError("Expected AArch64 ET_REL module")
    shoff = struct.unpack_from("<Q", data, 40)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 58)
    if shentsize != 64 or not 0 < shstrndx < shnum or shoff + shnum * 64 > len(data):
        raise ValueError("Invalid ELF section table")
    sections = []
    for i in range(shnum):
        fields = struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * 64)
        name, stype, flags, addr, offset, size, link, info, align, entsize = fields
        if stype != 8 and offset + size > len(data):
            raise ValueError("Section exceeds file")
        sections.append(dict(index=i, name_offset=name, type=stype, offset=offset,
                             size=size, link=link, info=info, entsize=entsize))
    strings = sections[shstrndx]
    names = data[strings["offset"]:strings["offset"] + strings["size"]]
    def cstring(buf, at):
        if at >= len(buf):
            raise ValueError("String offset exceeds string table")
        end = buf.find(b"\0", at)
        if end < 0:
            raise ValueError("Unterminated ELF string")
        return buf[at:end].decode("utf-8", errors="replace")
    for sec in sections:
        sec["name"] = cstring(names, sec["name_offset"])
    named = {s["name"]: s for s in sections}
    if ".symtab" not in named:
        raise ValueError("Missing .symtab: official loader needs it")
    symtab = named[".symtab"]
    if symtab["entsize"] != 24 or symtab["size"] % 24:
        raise ValueError("Unexpected symbol table format")
    string_sec = sections[symtab["link"]]
    strings = data[string_sec["offset"]:string_sec["offset"] + string_sec["size"]]
    symbols = []
    for off in range(symtab["offset"], symtab["offset"] + symtab["size"], 24):
        name, info, other, index, value, size = struct.unpack_from("<IBBHQQ", data, off)
        symbols.append(dict(name=cstring(strings, name), section=index, value=value, size=size, info=info))
    return sections, named, symbols


def inspect_elf(path, out, variant):
    target = get_target(variant)
    data = path.read_bytes()
    sections, named, symbols = elf_data(data)
    modinfo = named[".modinfo"]
    entries = data[modinfo["offset"]:modinfo["offset"] + modinfo["size"]].split(b"\0")
    values = {}
    for entry in entries:
        if b"=" in entry:
            key, value = entry.split(b"=", 1)
            values.setdefault(key.decode(), []).append(value.decode(errors="replace"))
    vermagic = values.get("vermagic", [""])[0]
    release = (out / "kernel.release.txt").read_text().strip()
    if not release.startswith(target["kernel_family"] + "."):
        raise ValueError("DDK kernel release does not match target KMI: " + release)
    if not vermagic.split() or vermagic.split()[0] != release or "aarch64" not in vermagic:
        raise ValueError("Unexpected vermagic: " + vermagic)
    if values.get("name") != ["susfs_guard_lkm"]:
        raise ValueError("Unexpected module name")
    module_size = named[".gnu.linkonce.this_module"]["size"]
    if module_size <= 0:
        raise ValueError("Missing/empty module structure section")
    # Record per-DDK layout; 1536 was one phone observation, not an eight-KMI ABI.
    if not values.get("import_ns"):
        raise ValueError("Expected module namespace import missing")
    imports = sorted({s["name"] for s in symbols if s["section"] == 0 and s["name"]})
    if any(name.startswith("kallsyms_") for name in imports):
        raise ValueError("Unexpected link-time kallsyms import")
    for required in ("register_kprobe", "unregister_kprobe"):
        if required not in imports:
            raise ValueError("Expected kprobe import missing: " + required)
    if any(name in imports for name in ("xa_store", "__xa_store")):
        raise ValueError("Unexpected XArray store import; reviewed allocation-free guard was not preserved")
    handler = next((s for s in symbols if s["name"] == "susfs_pre_handler" and s["section"]), None)
    if not handler or MARKER not in data:
        raise ValueError("Reviewed Samsung handler/marker missing")
    text = sections[handler["section"]]
    at = text["offset"] + handler["value"]
    # Capture, do not certify, compiler-emitted incoming CFI information. A word
    # before a function is not by itself proof of the expected type hash.
    prefix = data[max(text["offset"], at - 16):at].hex()
    report = {"file": path.name, "size": len(data), "sha256": sha(data),
              "target_kmi": variant, "kernel_release": release,
              "elf": "ELF64 little-endian AArch64 ET_REL", "vermagic": vermagic,
              "this_module_size": module_size, "imports": imports,
              "symtab_retained": True, "handler": handler,
              "cfi_inspection": {"handler_prefix_hex": prefix,
                                 "kcfi_sections": [s["name"] for s in sections if "cfi" in s["name"].lower()],
                                 "review": "Review prefix/type hash and pre-handler-disassembly.txt; not runtime verification"},
              "runtime_status": "NOT_TESTED"}
    save(out / "module-manifest.json", report)
    print("ELF_PASS: " + variant + "; exact DDK release; .symtab retained; kprobe handler present")


def finalize(root, out, variant):
    target = get_target(variant)
    source_record = json.loads((out / "source-manifest.json").read_text())
    module = json.loads((out / "module-manifest.json").read_text())
    images = json.loads((out / "ddk-image-inspect.json").read_text())
    if len(images) != 1 or images[0]["Id"] != os.environ.get("DDK_IMAGE_ID"):
        raise ValueError("Container image ID differs from recorded Docker image")
    if os.environ.get("DDK_IMAGE_TAG") != target["ddk_image_tag"]:
        raise ValueError("Unexpected DDK tag")
    if source_record["target_kmi"] != variant or module["target_kmi"] != variant:
        raise ValueError("Source/module KMI differs from selected target")
    if source_record["ddk_image_tag"] != target["ddk_image_tag"]:
        raise ValueError("Source manifest DDK differs from selected target")
    if git(root.resolve(), "rev-parse", "HEAD") != source_record["fork_commit"]:
        raise ValueError("Source commit changed during build")
    expected_name = "susfs_guard_lkm-" + variant + ".ko"
    if module["file"] != expected_name or sha((out / expected_name).read_bytes()) != module["sha256"]:
        raise ValueError("Module changed after ELF inspection")
    result = {"official_base_commit": BASE_COMMIT, "fork_commit": source_record["fork_commit"],
              "overlay_sha256": source_record["overlay_sha256"], "target_kmi": variant,
              "kernel_release": module["kernel_release"],
              "ddk_image_tag": target["ddk_image_tag"], "ddk_image_id": images[0]["Id"],
              "ddk_repo_digests": images[0].get("RepoDigests", []),
              "module": module, "build_status": "COMPILED_AND_STATIC_CHECKED",
              "runtime_status": "NOT_TESTED", "loader_included": False}
    save(out / "build-manifest.json", result)
    files = sorted(p for p in out.iterdir() if p.is_file() and p.name not in ("SHA256SUMS", "container.log"))
    (out / "SHA256SUMS").write_text("".join(sha(p.read_bytes()) + "  " + p.name + "\n" for p in files))
    print("FINAL_PASS: " + variant + "; image/source/output recorded; runtime NOT_TESTED")


def collect(artifacts, out, expected_commit):
    if len(expected_commit) != 40 or any(c not in "0123456789abcdef" for c in expected_commit):
        raise ValueError("Expected a full immutable commit SHA")
    manifests = sorted(artifacts.rglob("build-manifest.json"))
    if len(manifests) != len(TARGETS):
        raise ValueError("Require exactly eight successful build manifests")
    found = {}
    for manifest in manifests:
        record = json.loads(manifest.read_text())
        variant = record["target_kmi"]
        target = get_target(variant)
        if variant in found:
            raise ValueError("Duplicate target: " + variant)
        if record["build_status"] != "COMPILED_AND_STATIC_CHECKED":
            raise ValueError("Incomplete target build: " + variant)
        source_record = json.loads((manifest.parent / "source-manifest.json").read_text())
        required = {"target_kmi": variant, "fork_commit": expected_commit,
                    "official_base_commit": BASE_COMMIT, "overlay_sha256": OVERLAY_SHA256,
                    "ddk_image_tag": target["ddk_image_tag"]}
        for key, value in required.items():
            if record[key] != value or source_record[key] != value:
                raise ValueError("Build/source identity mismatch: " + variant + ":" + key)
        module = record["module"]
        name = "susfs_guard_lkm-" + variant + ".ko"
        if module["file"] != name:
            raise ValueError("Unexpected module filename: " + variant)
        binary = manifest.parent / name
        if sha(binary.read_bytes()) != module["sha256"]:
            raise ValueError("Module hash differs from build manifest: " + variant)
        found[variant] = (binary, record)
    if set(found) != set(TARGETS):
        raise ValueError("Missing or unexpected KMI target")
    if out.exists() and any(out.iterdir()):
        raise ValueError("Collector output directory must be empty")
    (out / "modules").mkdir(parents=True, exist_ok=True)
    (out / "manifests").mkdir(parents=True, exist_ok=True)
    for variant, (binary, record) in sorted(found.items()):
        shutil.copy2(binary, out / "modules" / binary.name)
        save(out / "manifests" / (variant + ".json"), record)
    save(out / "BUILD_MATRIX.json", {"fork_commit": expected_commit,
         "official_base_commit": BASE_COMMIT, "overlay_sha256": OVERLAY_SHA256,
         "targets": sorted(found), "module_count": 8, "runtime_status": "NOT_TESTED"})
    files = sorted(p for p in out.rglob("*") if p.is_file())
    (out / "SHA256SUMS").write_text("".join(sha(p.read_bytes()) + "  " + p.relative_to(out).as_posix() + "\n" for p in files))
    print("COLLECT_PASS: exactly 8 locally built KMI modules; hashes and source commit match")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("source", "elf", "finalize", "collect", "self-test"))
    parser.add_argument("--variant", choices=sorted(TARGETS))
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--out", type=Path, default=Path("artifacts/samsung"))
    parser.add_argument("--module", type=Path)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--reuse-record", action="store_true")
    args = parser.parse_args()
    if args.mode == "self-test":
        for invalid in (b"", b"not an elf", b"\x7fELF\x02\x01" + b"\0" * 58):
            try:
                elf_data(invalid)
            except ValueError:
                continue
            raise ValueError("Malformed ELF was accepted")
        assert len(BASE_COMMIT) == 40 and len(OVERLAY_SHA256) == 64 and len(TARGETS) == 8
        print("SELF_TEST_PASS: malformed ELF rejection and eight-target fixed-pin format")
        return
    if args.mode == "collect":
        if args.artifacts is None or args.expected_commit is None:
            parser.error("collect requires --artifacts and --expected-commit")
        collect(args.artifacts, args.out, args.expected_commit)
        return
    if args.variant is None:
        parser.error("source/elf/finalize require --variant")
    args.out.mkdir(parents=True, exist_ok=True)
    if args.mode == "source":
        source(args.root, args.out, args.reuse_record, args.variant)
    elif args.mode == "elf":
        if args.module is None:
            parser.error("elf requires --module")
        inspect_elf(args.module, args.out, args.variant)
    else:
        finalize(args.root, args.out, args.variant)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, IndexError, struct.error, subprocess.CalledProcessError) as exc:
        print("CHECK_FAILED: " + str(exc), file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            print(exc.stderr.decode(errors="replace"), file=sys.stderr)
        sys.exit(1)
