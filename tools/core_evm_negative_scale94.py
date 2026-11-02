#!/usr/bin/env python3
"""RE-004: core-to-EVM scaling for negative evm_extra_wei_decimals in node #94 (static).

Three handler copies (0x2715320, 0x4d0a6d0, 0x4d0bfa0) load the record byte at
+0xd1 (evm_extra_wei_decimals, stride 0xe8, flag +0xbc == 1) and, when the byte
is negative as i8, run the same square-and-multiply pow10 ladder and then divide
the core amount by 10^|d|, requiring an exact division:

    d in -19..-1 : q = amount / 10^|d|, success only when amount % 10^|d| == 0
    d <= -20     : the ladder overflows (10^20 > u64::MAX) or misses its bound,
                   and the fragment leaves the divide for the 0xba-tagged path
    d >= 0       : a different path (not mapped here); the byte is kept as r15

The ladder immediates are 10, 100, 10^4, 10^8, 10^16. Only the final multiply is
checked (mul + seto); the earlier imul steps cannot overflow for |d| <= 19
because 10^15 < 2^64. The divide uses a 64-bit div, or a 32-bit div when
(amount | pow10) has no bit above bit 31.

This tool never executes the node and never calls a disassembler. It verifies
the target SHA-256, reads FDE bounds from the repository unwind index, checks
anchor byte strings at fixed virtual addresses, transcribes the fragment
windows, and computes the ladder/divide tables arithmetically. It writes only
to the directory given by --out.

    python3 tools/core_evm_negative_scale94.py --out <dir>
    python3 tools/core_evm_negative_scale94.py --out <dir> --binary <path>

--allow-digest-mismatch is test-only: it lets the tamper controls prove the
anchor checks fail on their own, instead of failing at the digest check.
Production runs must never use it.


writes evidence.json, sites.tsv, ladder.tsv, cases.tsv, divide_cases.tsv and
fragment-bytes.txt. Only the Python standard library is used.
"""

import argparse
import bisect
import csv
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import elf_index  # noqa: E402  (repository shared ELF section parser)

DEFAULT_BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
U64MAX = (1 << 64) - 1

RECORD_STRIDE = 0xE8
FLAG_OFFSET = 0xBC
DECIMALS_OFFSET = 0xD1
FALLBACK_FIELD_OFFSET = 0x49
FLOAT_TABLE = 0x584B08
FLOAT_CONST_A = 0x203E80
FLOAT_CONST_B = 0x202EA0
FLAG_ERROR_TAG = 0x14A
FALLBACK_TAG = 0xBA

# Per-copy anchor addresses. Every anchor is verified byte-for-byte; the
# tamper controls in the tests flip one byte of each anchor class and must
# make this tool fail.
COPIES = [
    {
        "id": "copy-1",
        "fde": (0x2715320, 0x2716BC0),
        "scan": 0x271563A,
        "load": 0x271568D,
        "sign": 0x2715694,
        "positive": 0x2715756,
        "divide": 0x2715724,
        "div64": 0x271573B,
        "small": 0x271627D,
        "decision": 0x2716284,
        "success": 0x27163E8,
        "fallback": 0x271628D,
        "flag_err": 0x2715746,
        "native10": 0x271574F,
        "amount_slot": 0x58,
        "save_slot": 0x40,
        "fragment": (0x271563A, 0x2715741),
        "decision_window": (0x271627D, 0x27163E8),
        "fallback_window": (0x271628D, 0x27162E4),
    },
    {
        "id": "copy-2",
        "fde": (0x4D0A6D0, 0x4D0BFA0),
        "scan": 0x4D0A9F0,
        "load": 0x4D0AA43,
        "sign": 0x4D0AA4A,
        "positive": 0x4D0AB0C,
        "divide": 0x4D0AADA,
        "div64": 0x4D0AAF1,
        "small": 0x4D0B680,
        "decision": 0x4D0B687,
        "success": 0x4D0B7E8,
        "fallback": 0x4D0B690,
        "flag_err": 0x4D0AAFC,
        "native10": 0x4D0AB05,
        "amount_slot": 0x48,
        "save_slot": 0x30,
        "fragment": (0x4D0A9F0, 0x4D0AAF7),
        "decision_window": (0x4D0B680, 0x4D0B7E8),
        "fallback_window": (0x4D0B690, 0x4D0B6E8),
    },
    {
        "id": "copy-3",
        "fde": (0x4D0BFA0, 0x4D0D870),
        "scan": 0x4D0C2C0,
        "load": 0x4D0C313,
        "sign": 0x4D0C31A,
        "positive": 0x4D0C3DC,
        "divide": 0x4D0C3AA,
        "div64": 0x4D0C3C1,
        "small": 0x4D0CF50,
        "decision": 0x4D0CF57,
        "success": 0x4D0D0B8,
        "fallback": 0x4D0CF60,
        "flag_err": 0x4D0C3CC,
        "native10": 0x4D0C3D5,
        "amount_slot": 0x48,
        "save_slot": 0x30,
        "fragment": (0x4D0C2C0, 0x4D0C3C7),
        "decision_window": (0x4D0CF50, 0x4D0D0B8),
        "fallback_window": (0x4D0CF60, 0x4D0CFB8),
    },
]

# Anchor byte strings shared by all three copies (relative offsets are the
# same because the ladder code is identical; only the surrounding register
# allocation differs, which these anchors do not touch).
SHARED_ANCHORS = [
    ("flag_cmp", "4280bc33bc00000001"),      # cmpb $0x1, 0xbc(%base,%index,1)
    ("decimals_load", "0fb693d1000000"),     # movzbl 0xd1(%rbx), %edx
    ("neg_seq", "89d0f6d8b901000000"),       # mov %edx,%eax; neg %al; mov $1,%ecx
    ("bit0_mul", "b90a000000"),              # mov $10, %ecx
    ("bit1_mul", "486bc964"),                # imul $100, %rcx
    ("bit2_mul", "4869c910270000"),          # imul $10000, %rcx
    ("bit3_mul", "4869c900e1f505"),          # imul $100000000, %rcx
    ("bit4_mul", "48ba0000c16ff2862300"),    # movabs $10^16, %rdx
    ("checked_mul", "48f7e2"),               # mul %rdx
    ("checked_seto", "0f90c2"),              # seto %dl
    ("div64", "48f7f1"),                     # div %rcx
    ("div32", "f7f1"),                       # div %ecx
    ("remainder_test", "4885d2"),            # test %rdx, %rdx
    ("fallback_field", "0fb6440849"),        # movzbl 0x49(%rax,%rcx,1), %eax
    ("fallback_divsd", "f20f5e0cc1"),        # divsd (%rcx,%rax,8), %xmm1
    ("fallback_tag", "66bbba00"),            # mov $0xba, %bx
    ("flag_error_tag", "66bb4a01"),          # mov $0x14a, %bx
]

# Per-copy anchor VAs: (anchor_name, copy_field) for anchors whose address
# differs per copy. The byte strings come from SHARED_ANCHORS by name.
PER_COPY_ANCHORS = [
    ("flag_cmp", "scan", 7),        # scan imul is 7 bytes; flag cmp follows it
    ("decimals_load", "load", 0),
    ("neg_seq", "sign", 8),         # sign test (2) + jns (6) precede the neg seq
    ("bit0_mul", "load", 0x1C),     # load + 28: verified against the dumps
    ("bit1_mul", "load", 0x2D),
    ("bit2_mul", "load", 0x3F),
    ("bit3_mul", "load", 0x54),
    ("bit4_mul", "load", 0x6D),
    ("checked_mul", "load", 0x7A),
    ("checked_seto", "load", 0x7D),
    ("div64", "div64", 0),
    ("div32", "small", 2),          # xor %edx,%edx (2) precedes div %ecx
    ("remainder_test", "decision", 0),
    ("fallback_field", "fallback", 0x30),
    ("fallback_divsd", "fallback", 0x48),
    ("fallback_tag", "fallback", 0x53),
    ("flag_error_tag", "flag_err", 0),
]


class CheckError(Exception):
    pass


def fail(message):
    raise CheckError(message)


def va_to_offset(data, sections, va):
    for section in sections:
        if section["type"] == 8:
            continue
        start = section["address"]
        end = start + section["size"]
        if start <= va < end:
            return section["offset"] + (va - start)
    fail(f"VA {va:#x} has no file mapping")


def read_at(data, sections, va, size):
    offset = va_to_offset(data, sections, va)
    chunk = data[offset:offset + size]
    if len(chunk) != size:
        fail(f"short read at VA {va:#x}")
    return chunk


def check_anchor(data, sections, va, expected_hex, name):
    actual = read_at(data, sections, va, len(expected_hex) // 2).hex()
    if actual != expected_hex:
        fail(f"anchor {name} at {va:#x}: expected {expected_hex}, got {actual}")


def lea_target(insn_va, insn_bytes):
    # 48 8d 0d disp32: RIP-relative LEA, target = next instruction + disp32.
    if len(insn_bytes) != 7 or insn_bytes[:3] != bytes.fromhex("488d0d"):
        fail(f"not a RIP-relative LEA at {insn_va:#x}")
    disp = struct.unpack_from("<i", insn_bytes, 3)[0]
    return insn_va + 7 + disp


def load_unwind_index(root):
    for candidate in ("work/node-94-unwind.tsv", "work/index/node-94-unwind.tsv"):
        path = root / candidate
        if path.exists():
            bounds = {}
            with open(path, newline="") as handle:
                for row in csv.DictReader(handle, delimiter="\t"):
                    bounds[int(row["start_va"], 16)] = int(
                        row["next_index_upper_bound_va"], 16
                    )
            return bounds
    fail("node #94 unwind index not found under work/")


def ladder_model(al):
    """Return (verdict, pow10_or_reason) for the ladder's byte value al.

    al is the negated decimals byte (1..127 on the negative path). The walk
    below mirrors the instruction order: early exits after bits 0..3, the
    bit-4 gate, the checked final multiply, and the (al & 0xf0) == 0x10 gate.
    """
    rcx = 1
    if al & 1:
        rcx = 10
        if al == 1:
            return ("divide", rcx)
    if al & 2:
        rcx *= 100
        if (al & ~1) == 2:
            return ("divide", rcx)
    if al & 4:
        rcx *= 10 ** 4
        if (al & ~3) == 4:
            return ("divide", rcx)
    if al & 8:
        rcx *= 10 ** 8
        if (al & ~7) == 8:
            return ("divide", rcx)
    if not (al & 16):
        return ("error", "ladder-bound")
    rcx *= 10 ** 16
    if (al & 0xF0) != 0x10:
        return ("error", "ladder-bound")
    if rcx > U64MAX:
        return ("error", "pow10-overflow")
    return ("divide", rcx)


def scan_decimals_loads(data, sections, bounds):
    """Reproduce the census of +0xd1 byte loads over .text.

    A plain load is 0F B6/BE with modrm mod=10 and disp32 == 0xd1. One load
    in this binary is genuinely REX-prefixed (0x3baf4ad: 44 0f b6 ...), so a
    plain-only scan reports its tail at 0x3baf4ae; that tail is accounted for
    explicitly below instead of being mistaken for a seventh load. A plain
    scan cannot mistake the byte before 0x330668f for a prefix, because it
    never treats a bare 0x40..0x4f byte as a prefix at all.
    """
    text = None
    for section in sections:
        if section["name"] == ".text":
            text = (section["address"], section["offset"], section["size"])
            break
    if text is None:
        fail(".text section not found")
    base_va, base_off, size = text
    blob = data[base_off:base_off + size]
    starts = sorted(bounds)
    hits = []
    i = 0
    while i < len(blob) - 7:
        if (
            blob[i] == 0x0F
            and blob[i + 1] in (0xB6, 0xBE)
            and 0x80 <= blob[i + 2] <= 0xBF
            and blob[i + 3:i + 7] == b"\xd1\x00\x00\x00"
        ):
            hits.append(base_va + i)
        i += 1
    expected_plain = {
        0x271568D, 0x330668F, 0x3BAF4AE, 0x3BAF6FF, 0x4D0AA43, 0x4D0C313,
    }
    if set(hits) != expected_plain:
        fail(f"+0xd1 plain-scan mismatch: {[hex(h) for h in hits]}")
    # Verify the true instruction bytes at the six census VAs, including the
    # one genuine REX prefix.
    true_loads = {
        0x271568D: "0fb693d1000000",
        0x330668F: "0fb695d1000000",
        0x3BAF4AD: "440fb6b9d1000000",
        0x3BAF6FF: "0fb698d1000000",
        0x4D0AA43: "0fb693d1000000",
        0x4D0C313: "0fb693d1000000",
    }
    for va, expected in true_loads.items():
        if expected is None:
            continue
        actual = read_at(data, sections, va, len(expected) // 2).hex()
        if actual != expected:
            fail(f"+0xd1 load at {va:#x}: expected {expected}, got {actual}")
    out = []
    for va in sorted(true_loads):
        pos = bisect.bisect_right(starts, va) - 1
        fde = (starts[pos], bounds[starts[pos]]) if pos >= 0 else None
        if fde is None or not (fde[0] <= va < fde[1]):
            fail(f"+0xd1 load at {va:#x} has no enclosing FDE")
        out.append({"va": va, "fde_start": fde[0], "fde_end": fde[1]})
    return out


def build(binary_path, out_dir, allow_digest_mismatch=False):
    data = Path(binary_path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        if not allow_digest_mismatch:
            fail(f"target SHA-256 mismatch: {digest}")
        print(f"core_evm_negative_scale94: WARNING: digest mismatch "
              f"({digest}), continuing for tamper-control purposes only",
              file=sys.stderr)
    sections = elf_index.sections(data)
    bounds = load_unwind_index(ROOT)

    shared = dict(SHARED_ANCHORS)
    copies_out = []
    windows_out = []
    for copy in COPIES:
        fde_start, fde_end = copy["fde"]
        if bounds.get(fde_start) != fde_end:
            fail(f"FDE bound mismatch for {copy['id']}: "
                 f"expected {fde_end:#x}, got {bounds.get(fde_start)}")
        anchors = {}
        for name, field, delta in PER_COPY_ANCHORS:
            if field == "scan":
                va = copy["scan"] + delta
            elif field == "load":
                va = copy["load"] + delta
            elif field == "sign":
                va = copy["sign"] + delta
            else:
                va = copy[field] + delta
            check_anchor(data, sections, va, shared[name], f"{copy['id']}:{name}")
            anchors[name] = {"va": hex(va), "hex": shared[name]}
        # Sign-test displacement must land on the positive path entry.
        sign_bytes = read_at(data, sections, copy["sign"], 8)
        if sign_bytes[:2] != bytes.fromhex("84d2") or sign_bytes[2] != 0x0F \
                or sign_bytes[3] != 0x89:
            fail(f"{copy['id']}: sign test shape mismatch")
        disp = struct.unpack_from("<i", sign_bytes, 4)[0]
        if copy["sign"] + 8 + disp != copy["positive"]:
            fail(f"{copy['id']}: jns target is not the positive entry")
        # Native-token default: the null-pointer branch saves the input and
        # forces dl = 10 before joining the positive entry.
        slot = copy["save_slot"]
        nat_expected = bytes.fromhex(f"48895424{slot:02x}b20a")
        check_anchor(data, sections, copy["native10"], nat_expected.hex(),
                     f"{copy['id']}:native10")
        # Fallback float-table LEA targets (computed from raw bytes).
        fb = copy["fallback"]
        fb_window = read_at(data, sections, fb, 0x60)
        lea_pos = fb_window.find(bytes.fromhex("488d0d"))
        if lea_pos < 0:
            fail(f"{copy['id']}: fallback float-table LEA not found")
        table_target = lea_target(fb + lea_pos, fb_window[lea_pos:lea_pos + 7])
        if table_target != FLOAT_TABLE:
            fail(f"{copy['id']}: float table is {table_target:#x}, "
                 f"expected {FLOAT_TABLE:#x}")
        # The two float constants are RIP-relative loads in the fallback.
        const_targets = []
        for opcode in ("0f1405", "660f5c05"):
            op = bytes.fromhex(opcode)
            pos = fb_window.find(op)
            if pos < 0:
                fail(f"{copy['id']}: float constant load {opcode} not found")
            size = 7 if opcode == "0f1405" else 8
            disp = struct.unpack_from("<i", fb_window, pos + size - 4)[0]
            const_targets.append(fb + pos + size + disp)
        if const_targets != [FLOAT_CONST_A, FLOAT_CONST_B]:
            fail(f"{copy['id']}: float constants are {const_targets}, "
                 f"expected {[FLOAT_CONST_A, FLOAT_CONST_B]}")
        for label, (start, end) in (
            ("fragment", copy["fragment"]),
            ("decision", copy["decision_window"]),
            ("fallback", copy["fallback_window"]),
        ):
            raw = read_at(data, sections, start, end - start)
            windows_out.append({
                "copy": copy["id"],
                "window": label,
                "start": hex(start),
                "end": hex(end),
                "length": end - start,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "hex": raw.hex(),
            })
        copies_out.append({
            "id": copy["id"],
            "fde_start": hex(fde_start),
            "fde_end": hex(fde_end),
            "fde_size": fde_end - fde_start,
            "scan_va": hex(copy["scan"]),
            "load_va": hex(copy["load"]),
            "sign_va": hex(copy["sign"]),
            "positive_va": hex(copy["positive"]),
            "divide_va": hex(copy["divide"]),
            "div64_va": hex(copy["div64"]),
            "small_divide_va": hex(copy["small"]),
            "decision_va": hex(copy["decision"]),
            "success_va": hex(copy["success"]),
            "fallback_va": hex(copy["fallback"]),
            "flag_error_va": hex(copy["flag_err"]),
            "native10_va": hex(copy["native10"]),
            "amount_slot": hex(copy["amount_slot"]),
            "float_table": hex(FLOAT_TABLE),
            "float_constants": [hex(t) for t in const_targets],
            "anchors": anchors,
        })

    census = scan_decimals_loads(data, sections, bounds)
    expected_census = {0x271568D, 0x330668F, 0x3BAF4AD, 0x3BAF6FF, 0x4D0AA43, 0x4D0C313}
    if {hit["va"] for hit in census} != expected_census:
        fail(f"+0xd1 census mismatch: {[hex(h['va']) for h in census]}")

    ladder_rows = []
    for bit, immediate in ((0, 10), (1, 100), (2, 10 ** 4), (3, 10 ** 8), (4, 10 ** 16)):
        # Cumulative power after processing bits 0..bit with all of them set.
        cumulative = 1
        for b in range(bit + 1):
            cumulative *= (10, 100, 10 ** 4, 10 ** 8, 10 ** 16)[b]
        ladder_rows.append({
            "bit": bit,
            "immediate": immediate,
            "immediate_hex": hex(immediate),
            "cumulative_pow10": cumulative,
        })

    case_rows = []
    for d in range(-128, 0):
        dl = d & 0xFF
        al = (-dl) & 0xFF
        verdict, value = ladder_model(al)
        case_rows.append({
            "d": d,
            "dl_hex": f"{dl:#04x}",
            "al": al,
            "verdict": verdict,
            "pow10": value if verdict == "divide" else "",
            "reason": "" if verdict == "divide" else value,
        })

    divide_rows = []
    amounts = [0, 1, 9, 10, 99, 100, 101, 10 ** 19 - 1, 10 ** 19,
               12345678901234567890, (1 << 64) - 2, (1 << 64) - 1]
    for d in (-1, -2, -19):
        pow10 = 10 ** (-d)
        for amount in amounts:
            q, r = divmod(amount, pow10)
            path = "div32" if ((amount | pow10) >> 32) == 0 else "div64"
            divide_rows.append({
                "d": d,
                "pow10": pow10,
                "amount": amount,
                "quotient": q,
                "remainder": r,
                "exact": r == 0,
                "path": path,
                "outcome": "success-join" if r == 0 else "fallback-0xba",
            })

    evidence = {
        "component": "RE-004",
        "work_item": "RE-004-core-evm-negative-decimals-scale-94",
        "target": "node #94",
        "target_sha256": SHA256,
        "target_size": len(data),
        "record": {
            "stride": RECORD_STRIDE,
            "flag_offset": FLAG_OFFSET,
            "flag_required": 1,
            "flag_error_tag": FLAG_ERROR_TAG,
            "decimals_offset": DECIMALS_OFFSET,
            "fallback_field_offset": FALLBACK_FIELD_OFFSET,
            "fallback_tag": FALLBACK_TAG,
        },
        "copies": copies_out,
        "windows": windows_out,
        "decimals_load_census": [
            {"va": hex(hit["va"]), "fde_start": hex(hit["fde_start"]),
             "fde_end": hex(hit["fde_end"])}
            for hit in census
        ],
    }

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    def write_json(name, obj):
        (out / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n",
                                encoding="utf-8")

    def write_tsv(name, rows, columns):
        lines = ["\t".join(columns)]
        for row in rows:
            lines.append("\t".join(str(row[col]) for col in columns))
        (out / name).write_text("\n".join(lines) + "\n", encoding="utf-8")

    write_json("evidence.json", evidence)
    site_rows = []
    for copy in copies_out:
        site_rows.append({
            "copy": copy["id"], "role": "scaling-fragment",
            "fde_start": copy["fde_start"], "fde_end": copy["fde_end"],
            "scan_va": copy["scan_va"], "load_va": copy["load_va"],
            "positive_va": copy["positive_va"], "success_va": copy["success_va"],
            "fallback_va": copy["fallback_va"],
        })
    for hit in census:
        if hit["va"] in (0x3BAF4AD, 0x3BAF6FF):
            site_rows.append({
                "copy": "-", "role": "evm-to-core-call-site",
                "fde_start": hex(hit["fde_start"]), "fde_end": hex(hit["fde_end"]),
                "scan_va": "", "load_va": hex(hit["va"]),
                "positive_va": "", "success_va": "", "fallback_va": "",
            })
        elif hit["va"] == 0x330668F:
            site_rows.append({
                "copy": "-", "role": "struct-copy-conditional",
                "fde_start": hex(hit["fde_start"]), "fde_end": hex(hit["fde_end"]),
                "scan_va": "", "load_va": hex(hit["va"]),
                "positive_va": "", "success_va": "", "fallback_va": "",
            })
    write_tsv("sites.tsv", site_rows,
              ["copy", "role", "fde_start", "fde_end", "scan_va", "load_va",
               "positive_va", "success_va", "fallback_va"])
    write_tsv("ladder.tsv", ladder_rows,
              ["bit", "immediate", "immediate_hex", "cumulative_pow10"])
    write_tsv("cases.tsv", case_rows,
              ["d", "dl_hex", "al", "verdict", "pow10", "reason"])
    write_tsv("divide_cases.tsv", divide_rows,
              ["d", "pow10", "amount", "quotient", "remainder", "exact", "path",
               "outcome"])
    frag_lines = []
    for window in windows_out:
        frag_lines.append(
            f"{window['copy']} {window['window']} "
            f"{window['start']}..{window['end']} "
            f"len={window['length']} sha256={window['sha256']}")
        frag_lines.append(window["hex"])
    (out / "fragment-bytes.txt").write_text("\n".join(frag_lines) + "\n",
                                            encoding="utf-8")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="RE-004 core-to-EVM "
                                     "negative-decimals scale transcription")
    parser.add_argument("--out", required=True, help="output directory")
    parser.add_argument("--binary", default=str(DEFAULT_BINARY),
                        help="node #94 binary (default: repository artifact)")
    parser.add_argument("--allow-digest-mismatch", action="store_true",
                        help="TEST ONLY: continue past a digest mismatch so "
                             "anchor checks can fail on their own")
    args = parser.parse_args(argv)
    try:
        return build(args.binary, args.out, args.allow_digest_mismatch)
    except CheckError as exc:
        print(f"core_evm_negative_scale94: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
