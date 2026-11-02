#!/usr/bin/env python3
"""Regenerate pre-code evidence and exercise static admission boundaries only."""

import argparse
import gzip
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

from bind import HERE, REPO, Image, admit_image, authenticate, derive, native, read_json, require, rows, sha, write_json


def inventory(directory):
    return {str(p.relative_to(directory)): sha(p.read_bytes())
            for p in sorted(directory.rglob("*")) if p.is_file()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=REPO)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    require(not args.out.exists(), "fresh output required")
    require(not (args.repo / "src/visor-child-args").exists(), "production source already exists")
    pins = read_json(HERE / "BASIS-PINS.json")
    image = authenticate(args.repo, pins)
    frames = native(["/opt/homebrew/opt/binutils/bin/readelf", "--debug-dump=frames",
                     pins["target"]["path"]], args.repo)
    baseline = derive(image, pins, frames)
    require(baseline["child_name"]["hex"] == b"child-args".hex(), "selected name differs")
    controls = []

    def reject(name, category, operation, reason):
        try:
            operation()
        except ValueError as error:
            require(reason in str(error), "unexpected rejection in " + name)
            controls.append(dict(name=name, category=category, rejected=str(error)))
        else:
            raise ValueError("negative control accepted: " + name)

    def changed(address):
        data = bytearray(image.data)
        data[image.offset(address, 1)] ^= 1
        return bytes(data)

    reject("whole-image-mutation", "outer identity only",
           lambda: admit_image(changed(0x49b560), pins["target"]), "target identity")
    reject("truncated-image", "outer identity only",
           lambda: admit_image(image.data[:-1], pins["target"]), "target identity")
    reject("body-below-outer-hash", "body integrity only",
           lambda: derive(Image(changed(0x49b560)), pins, frames), "body identity")
    reject("caller-below-outer-hash", "body integrity only",
           lambda: derive(Image(changed(0x5b9238)), pins, frames), "body identity")
    for slot in ("0x7e6aa0", "0x7e4b68"):
        record = next(x for x in baseline["relas"] if x["slot"] == slot)
        altered = bytearray(image.data)
        altered[record["file_offset"] + 16] ^= 1
        reject("relocation-" + slot, "actual binding check below outer hash",
               lambda raw=bytes(altered): derive(Image(raw), pins, frames), "selected binding")
    fde = int(baseline["ranges"][0]["fde_va"], 16)
    reject("fde-size", "raw FDE arithmetic below outer hash",
           lambda: derive(Image(changed(fde + 12)), pins, frames), "FDE size")
    reject("fde-cie-pointer", "raw CIE reference below outer hash",
           lambda: derive(Image(changed(fde + 4)), pins, frames), "CIE reference")
    reject("lead-table", "table identity only",
           lambda: derive(Image(changed(0x8047e)), pins, frames), "lead table")
    symtab, strings = image.sections[".dynsym"], image.sections[".dynstr"]
    name = struct.unpack_from("<I", image.data, symtab[4] + 6 * 24)[0]
    altered = bytearray(image.data)
    altered[strings[4] + name] ^= 1
    reject("copy-symbol-name", "dynamic symbol name below outer hash",
           lambda: derive(Image(bytes(altered)), pins, frames), "copy symbol")
    text = gzip.decompress((HERE / "observed/validator.llvm.txt.gz").read_bytes()).decode()
    require(len(rows(text, image, 0x49b560, 0x49b757)) == 143, "positive decoder input")
    reject("native-byte-change", "native export byte check",
           lambda: rows(text.replace("41 57", "40 57", 1), image, 0x49b560, 0x49b757),
           "native row differs")
    lines = text.splitlines(keepends=True)
    first = next(x for x in lines if x.lstrip().startswith("49b560:"))
    reject("native-missing-row", "native export complete partition",
           lambda: rows(text.replace(first, "", 1), image, 0x49b560, 0x49b757), "do not tile")
    reject("native-duplicate-row", "native export complete partition",
           lambda: rows(text + first, image, 0x49b560, 0x49b757), "do not tile")
    args.out.mkdir(parents=True)
    commands = []
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    for script, label, committed in [("bind.py", "native", "observed"),
                                      ("corpus.py", "corpus", "frozen")]:
        command = [sys.executable, str(HERE / script), "--repo", str(args.repo),
                   "--out", str(args.out / label)]
        completed = subprocess.run(command, env=env, cwd=args.repo, capture_output=True,
                                   text=True, timeout=180)
        require(completed.returncode == 0 and not completed.stderr, "regeneration failed: " + script)
        left, right = inventory(HERE / committed), inventory(args.out / label)
        require(left == right, "regeneration differs: " + script)
        commands.append(dict(argv=["<PYTHON>", "<PACKET>/" + script, "--repo", "<SOURCE_ROOT>",
                                   "--out", "<OUTPUT_DIR>/" + label],
                             exit_code=completed.returncode, stdout=completed.stdout,
                             stderr=completed.stderr, byte_identical_files=len(left)))
    source_files = ["BASIS-PINS.json", "bind.py", "corpus.py", "verify_precode.py", "CONTRACT.md",
                    "BRIDGE.md", "README.md", "VALIDATION-PLAN.md", ".gitattributes"]
    receipt = dict(status="PASS: pre-code only", controls=controls, regenerations=commands,
                   source_identities={name: sha((HERE / name).read_bytes()) for name in source_files},
                   current_source_absent=not (args.repo / "src/visor-child-args").exists(),
                   python_version=sys.version, synthetic_private_paths="Command placeholders map to the invoking --repo/--out; no user data in streams.",
                   initial_pre_freeze_failure="First native parser required a space after the last raw byte; LLVM's tab-delimited movabs failed complete tiling. Accepting space or tab fixed formatting only; full raw-byte/partition checks remain mandatory. No prior freeze or success receipt existed.",
                   scope="Static byte/FDE/binding admission and independent mathematical regeneration. No target execution, Rust compilation, runtime observation or new native semantic proof.")
    write_json(args.out / "receipt.json", receipt)
    print(json.dumps(dict(status=receipt["status"], controls=len(controls),
                          byte_identical_files=sum(x["byte_identical_files"] for x in commands),
                          source_absent=receipt["current_source_absent"])))


if __name__ == "__main__":
    main()
