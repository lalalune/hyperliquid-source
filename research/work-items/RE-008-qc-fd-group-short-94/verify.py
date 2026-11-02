#!/usr/bin/env python3
"""Reproduce the bounded native group/row error relation without executing it."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import unwind_index
from fde_extents import eh_frame_records

FREEZE_SHA = "01c42296db4d8eb2d213631b820391be40fe508d1ff9be5b045cbffc5a902198"
RX = re.compile(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}[ \t]+)+)(\S.*)$", re.M)
MASK = (1 << 64) - 1


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Image:
    def __init__(self, data, patches=None):
        self.data, self.patches = data, patches or {}
        ph = struct.unpack_from("<Q", data, 32)[0]
        self.loads = [struct.unpack_from("<IIQQQQQQ", data, ph + i * 56)
                      for i in range(struct.unpack_from("<H", data, 56)[0])]

    def read(self, va, count):
        found = [r[2] + va - r[3] for r in self.loads if r[0] == 1 and r[3] <= va and va + count <= r[3] + r[5]]
        need(len(found) == 1, "unique file-backed mapping")
        data = bytearray(self.data[found[0]:found[0] + count])
        for at, value in self.patches.items():
            if va <= at < va + count:
                data[at - va] = value
        return bytes(data)


def parameters(image):
    def exact(va, code):
        code = bytes.fromhex(code)
        need(image.read(va, len(code)) == code, f"native operation {va:#x}")

    def operand(va, prefix):
        exact(va, prefix)
        return image.read(va + len(bytes.fromhex(prefix)), 1)[0]

    exact(0x466BF6E, "4989f64889fb833e01")
    exact(0x466BF79, "498b46204883f8df7715")
    exact(0x466BF83, "498b4e084d8d6620")
    reserve = operand(0x466BF8B, "488d50")
    exact(0x466BF8F, "498914244839ca7616")
    initial = operand(0x466BFAE, "4883c0")
    exact(0x466BFB2, "49890424")
    scalar = operand(0x466BD24, "4883c0")
    exact(0x466BD11, "833e017523488b46204883f8f77711")
    exact(0x466BD28, "488946204839c87608")
    exact(0x466BD3D, "4883f808766e")
    exact(0x466BDB1, "4883c6104889fb31d2ff1520881001")
    exact(0x466D981, "488b46084885c0742b488b0e")
    step = operand(0x466D98D, "4c8d49")
    exact(0x466D991, "4c8d50ff440fb6014c890e4c895608")
    exact(0x466D9B5, "c6070048c74708010000004889f85bc3")
    exact(0x466D9C5, "4181c005ffffff4183f803")
    table = struct.unpack("<iiii", image.read(0x6F6ED8, 16))
    need(0x6F6ED8 + table[2] == 0x466D9F4, "FD Reader table entry")
    exact(0x466D9F4, "4883f8097321b9")
    short_base = struct.unpack("<I", image.read(0x466D9FB, 4))[0]
    exact(0x466D9FF, "eb0b")
    exact(0x466DA0C, "4829c1c6070048894f084889f85bc3")
    stops, refunds = [], []
    for call, check, branch, dest in [(0x466BFBE, 0x466BFD5, 0x466BFD7, 0x466C0AC),
                                     (0x466C001, 0x466C018, 0x466C01A, 0x466C0B3),
                                     (0x466C044, 0x466C05B, 0x466C05D, 0x466C0BD),
                                     (0x466C083, 0x466C09A, 0x466C09C, 0x466C0C7)]:
        exact(call - 8, "488d7c24084c89f6e8")
        need(call + 5 + struct.unpack("<i", image.read(call + 1, 4))[0] == 0x466BD10, "wrapper call target")
        exact(check, "3c12")
        code = image.read(branch, 2)
        if code[0] == 0x0F:
            need(code[1] in (0x84, 0x85), "near stop branch")
            target = branch + 6 + struct.unpack("<i", image.read(branch + 2, 4))[0]
            stops.append(code[1] == 0x85)
        else:
            need(code[0] in (0x74, 0x75), "short stop branch")
            target = branch + 2 + struct.unpack("b", image.read(branch + 1, 1))[0]
            stops.append(code[0] == 0x75)
        need(target == dest, "failure join target")
    for check in (0x466BFC8, 0x466C00B, 0x466C04E, 0x466C08D):
        exact(check, "3c130f84")
        need(check + 8 + struct.unpack("<i", image.read(check + 4, 4))[0] == 0x466C125, "special13 panic branch")
    for guard, add in [(0x466BFDD, 0x466BFF1), (0x466C020, 0x466C034), (0x466C05F, 0x466C073)]:
        exact(guard, "49833e007416498b04244883f8080f82")
        exact(add, "4883c0")
        refunds.append(struct.unpack("b", image.read(add + 3, 1))[0])
        exact(add + 4, "49890424")
    for va, code in [(0x466BFD0, "4c8b7c2410"), (0x466C013, "4c8b6c2410"),
                     (0x466C056, "488b6c2410"), (0x466C095, "488b4c2410"),
                     (0x466C0B8, "4d89efeb12"), (0x466C0C2, "4989efeb08"),
                     (0x466C0CC, "4989cf"), (0x466C0E9, "bf01000000"),
                     (0x466C0F6, "4d89fd48893b48c1e6080fb6c04809f048894308"),
                     (0x466C0A5, "31ff4489f8eb4d"),
                     (0x4C7E41A, "488d7c24284c89f6e839db9eff"),
                     (0x4C7E427, "0fb6442430"), (0x4C7E43C, "488b4c2438"),
                     (0x4C7E456, "488d542450488d7424204989cf89c5"),
                     (0x4C7E47D, "4c89fa89ee"), (0x4C7E4B8, "40887308"),
                     (0x4C7E4DA, "b8010000004889034889d8"), (0x4C7E4F2, "c3")]:
        exact(va, code)
    group_need = operand(0x466C10A, "4c896b")
    row_need = operand(0x4C7E4CA, "488953")
    exact(0x4C7E44B, "807c2428000f")
    row_branch = image.read(0x4C7E451, 1)[0]
    need(row_branch in (0x84, 0x85), "row status branch")
    return dict(reserve=reserve, initial=initial, scalar=scalar, refunds=refunds,
                stop_on_short=stops, marker_step=step, short_base=short_base,
                group_need_slot=group_need, row_need_slot=row_need, row_takes_error=row_branch == 0x84)


def relation(p, row):
    """Bounded algebraic consequence; not a CPU or instruction evaluator."""
    wire = b"" if row["wire_hex"] == "-" else bytes.fromhex(row["wire_hex"])
    c, limit = int(row["charge"]), int(row["limit"])
    need(c + p["reserve"] <= MASK and c + p["reserve"] <= limit, "admitted native domain")
    cursor = 0
    for k in range(1, 5):
        n = len(wire) - cursor
        if n == 0:
            missing, remaining = 1, 0
            break
        need(wire[cursor] == 0xFD, "FD-only domain")
        if n < 9:
            missing, remaining = p["short_base"] - n, n - 1
            cursor += p["marker_step"]
            break
        cursor += 9
    else:
        raise ValueError("outside selected short-input domain")
    attempts = k
    group_tag = 1
    if not p["stop_on_short"][k - 1]:
        need(n == 1, "control witness limited to FD with no payload")
        if k == 4:
            group_tag = 0
        else:
            attempts += 1
            missing = 1  # The next wrapper sees physical EOF and stops normally.
    trace = [c + p["reserve"], c + p["initial"]]
    for i in range(attempts):
        trace.append(trace[-1] + p["scalar"])
        if i < attempts - 1:
            trace.append(trace[-1] + p["refunds"][i])
    result = dict(id=row["id"], charge=str(trace[-1]), pointer_advance=str(cursor), remaining=str(remaining),
                  suffix_hex=wire[cursor:cursor + remaining].hex() or "-", group_tag=str(group_tag),
                  wrapper_attempts=attempts, charge_relative_to_C=trace[-1] - c,
                  row_error_route=group_tag == 1 and p["row_takes_error"])
    if group_tag == 1:
        # Displaced-need controls explicitly premise initialized-zero old slots.
        group_missing = missing if p["group_need_slot"] == 16 else 0
        result.update(group_kind_byte="0", group_need_u64=str(group_missing))
        if p["row_takes_error"]:
            result.update(row_tag="1", row_kind_byte="0", row_need_u64=str(group_missing if p["row_need_slot"] == 16 else 0))
    return result, trace


def rows(path):
    with path.open() as f:
        return list(csv.DictReader(f, delimiter="\t"))


def check_control_prediction(edit, actual):
    for field, expected in edit["predicted_difference"].items():
        if field in ("premise", "note"):
            continue
        if field == "row_error_route":
            need(actual[field] is False, "frozen changed route")
        else:
            need(int(actual[field]) == expected, "frozen control result " + field)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--llvm", default=os.environ.get("LLVM_OBJDUMP") or shutil.which("llvm-objdump"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    need(args.llvm, "supply --llvm or LLVM_OBJDUMP or llvm-objdump on PATH")
    frozen_bytes = (HERE / "PRE-RUST-FREEZE.json").read_bytes()
    need(sha(frozen_bytes) == FREEZE_SHA, "pre-Rust native freeze")
    freeze = json.loads(frozen_bytes)
    data = args.target.read_bytes()
    need(len(data) == freeze["target"]["size"] and sha(data) == freeze["target"]["sha256"], "authenticated node94")
    image = Image(data)
    _, fdes = eh_frame_records(data)
    _, index = unwind_index(data)
    for f in freeze["functions"]:
        s, e = int(f["start"], 16), int(f["end"], 16)
        found = [x for x in fdes if x["start"] == s]
        need(len(found) == 1 and found[0]["end"] == e and found[0]["lsda"] is None, "complete FDE")
        need(sum(x["start"] == s and x["fde"] == found[0]["fde"] for x in index) == 1, "unique unwind index")
        off = int(f["fde"]["fde"], 16)
        need(data[off:off + len(bytes.fromhex(f["fde_hex"]))].hex() == f["fde_hex"], "full FDE bytes")
        need(sha(image.read(s, e - s)) == f["body_sha256"], "full body hash")
    for path, digest in freeze["reuse_dependencies"].items():
        need(sha((ROOT / path).read_bytes()) == digest, "reused evidence identity")
    rel = freeze["Reader_RELA"]
    off = int(rel["file_offset"], 16)
    need(data[off:off + 24].hex() == rel["hex"] and struct.unpack("<QQq", data[off:off + 24]) == (0x57745E0, 8, 0x466D980), "Reader RELA binding")
    need(image.read(0x57745E0, 8).hex() == rel["slot_hex"], "Reader slot bytes")
    for name, pin in freeze["fixtures"].items():
        need(sha((HERE / name).read_bytes()) == pin["sha256"], "pre-Rust fixture")
    inputs, expected = rows(HERE / "inputs.tsv"), rows(HERE / "expected.tsv")
    params = parameters(image)
    for case, wanted in zip(inputs, expected, strict=True):
        got, trace = relation(params, case)
        need({k: got[k] for k in wanted} == wanted, "frozen active state " + case["id"])
        need(got["wrapper_attempts"] == freeze["case_domains"][case["id"]]["failed_position"] and got["row_error_route"], "first-error route")
    # Original native exports only; no patched image is executed or emulated.
    for _ in range(2):
        for label, tool, flags in [("gnu", "objdump", ["-d", "-M", "intel", "--insn-width=16"]),
                                   ("llvm", args.llvm, ["-d", "--x86-asm-syntax=intel"])]:
            parts = []
            for window in freeze["new_native_ranges"]:
                s, e = int(window["start"], 16), int(window["end"], 16)
                text = subprocess.check_output([tool, *flags, f"--start-address={s}", f"--stop-address={e}", str(args.target)], text=True)
                cursor = s
                for m in RX.finditer(text):
                    va, code = int(m[1], 16), bytes.fromhex(m[2])
                    need(va == cursor and image.read(va, len(code)) == code, "complete instruction partition")
                    cursor += len(code)
                need(cursor == e, "complete native end")
                parts.append(text.replace(str(args.target), "artifacts/node/94/hl-node"))
            need("".join(parts) == (HERE / f"native.{label}.txt").read_text(), "exact native regeneration")
    controls = []
    for edit in freeze["native_controls"]:
        va = int(edit["va"], 16)
        need(image.read(va, 1).hex() == edit["before"], "control origin")
        changed = Image(data, {va: int(edit["after"], 16)})
        case = next(x for x in inputs if x["id"] == edit["witness"])
        got, _ = relation(parameters(changed), case)
        baseline, _ = relation(params, case)
        need(got != baseline, "operative native-site distinction")
        check_control_prediction(edit, got)
        controls.append({"name": edit["name"], "witness": case["id"], "changed_fields": sorted(k for k in got if got.get(k) != baseline.get(k)),
                         "classification": "static algebraic/CFG witness, not captured execution"})
    report = {"target": freeze["target"], "native_freeze_sha256": FREEZE_SHA, "cases": 36, "parameters": params,
              "controls": controls, "native_regenerations": 2, "captured_execution": False,
              "limits": "Only active byte/qword error fields and state/route; no inactive image, runtime equivalence or full QC reachability"}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("PASS:36 frozen active states;10 operative static controls;two exact GNU/LLVM generations")


if __name__ == "__main__":
    main()
