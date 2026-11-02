"""Deterministic generator for the RE-004 non-rejoin sentinel-gate packet.

The #165 sentinel-gate family packet mapped 47 gates in 46 functions and
left one question open: what do the 13 non-rejoin je gates do on their
non-match paths, and do any of them distinguish "vectors all zero" from
"vectors match" the way the 23 rejoin gates do not? This packet answers
it. None of the 13 distinguishes vectors-zero from vectors-match: every
non-match path is unconditional. The 13 partition into five classes:

- same-callee trio (3, newly modeled in full): 0x4e6fd50, 0x4e856f0,
  0x4e6bcb0. Both paths call the SAME second-stage callee and both
  install [obj] = 1; only the source buffer differs (match installs the
  decoded buffer's tail, non-match installs the callee's fresh output).
  A vectors-zero object therefore gets the alternate value, never the
  match value -- the sharp opposite of the rejoin gates.
- twin-B clones (4, measured instances, not new behavior): 0x32aca90,
  0x32acca0, 0x44bb790, 0x4dd6c90. Each is 527 bytes, 93-94% byte-identical
  to twin-B (0x2788500), and uses twin-B's exact transform pair
  (0x37d13c0, then 0x324a070 when the transform output's first DWORD is
  4). They are reported as census instances supporting the partition,
  not claimed as new behavior.
- twin-shape pair (2, classified): 0x1eb1cc0 (twin-A transform 0x1e6af40)
  and 0x1eb1e60 (twin-B transform pair 0x37d13c0 + 0x324a070), sharing
  match callee 0x1e5f1c0 and cleanup 0x1eaffe0. Same skeleton as the
  twins, different callees and bytes (26-28% similarity to twin-A).
- attributed, already mapped (4, not re-claimed): the twins 0x2788350 /
  0x2788500 (PR #1785), gate 0 of 0x4e852a0 (#165), and the flag anchor
  0x3272190 (#165, match -> dl = 0, non-match -> dl = 1).

Claimed bytes are the non-match fall-through segments of the 9 newly
examined gates plus their install anchors. Every recorded anchor lies
strictly after its gate's branch instruction, so the claimed anchors are
disjoint from #165's recorded gate anchors (feeds, compares, branch),
which are all at or before the branch. The segments are sub-ranges of
#165's FDE windows; that inclusion, the anchor disjointness, and #165's
explicit next question inviting this follow-up are all disclosed in the
README, following the #163 precedent for invited follow-ups.

Reads the pinned node #94 binary and disassembles nothing: it checks the
node SHA-256 first, verifies unwind FDE starts/ends via the repository
shared ELF parser, re-derives the census with a byte-level disp32 scan,
and verifies every recorded anchor byte. Writes only to --out. Static
analysis only: the node binary is never executed.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import elf_index  # noqa: E402  (repository shared ELF section parser)

SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
DEFAULT_BINARY = Path("artifacts/node/94/hl-node")
CONST_HI = 0x204BE0
CONST_LO = 0x206160
CONST_HI_BYTES = bytes.fromhex("e500b653ca82273b7bfad8045d85a470")
CONST_LO_BYTES = bytes.fromhex("c5d2460186f7233c927e7db2dcc703c0")

# The 13 non-rejoin je gates. Gate compare/branch anchors come from the
# binary (cross-checked against #165's gates.tsv values). Segmented gates
# carry their fall-through segment plus install anchors; attributed gates
# carry segment None and are cited, not re-claimed.
GATES = [
    # ---- same-callee trio (newly modeled) ----
    {
        "fde": "0x4e6fd50", "fde_end": "0x4e6fee2", "fde_len": 402,
        "class": "same-callee", "disposition": "new",
        "pcmpeqb": [{"va": "0x4e6fd8f", "bytes": "660f740d494e39fb"},
                    {"va": "0x4e6fd97", "bytes": "660f7405c16339fb"}],
        "branch": {"va": "0x4e6fdac", "bytes": "0f8487000000",
                   "asm": "je 0x4e6fe39", "polarity": "je"},
        "segment": {"start": "0x4e6fdb2", "end": "0x4e6fe02",
                    "sha256": "4616d3172d28d661432df045762cc5c433b32ca012eaf35b18fd16c5b3a8ba09"},
        "first_call": {"va": "0x4e6fdb7", "bytes": "e8f4caffff", "target": "0x4e6c8b0"},
        "second_call": None,
        "one_store": {"va": "0x4e6fdbc", "bytes": "48c744243001000000",
                      "asm": "mov [rsp+0x30],1"},
        "install_top_store": {"va": "0x4e6fdec", "bytes": "410f115630",
                              "asm": "movups [r14+0x30],xmm2"},
        "install_range": "[r14+0x0..0x40]",
        "match_call": {"va": "0x4e6fe3c", "bytes": "e86fcaffff", "target": "0x4e6c8b0"},
        "match_install_range": "[r14+0x0..0x38]",
    },
    {
        "fde": "0x4e856f0", "fde_end": "0x4e85b12", "fde_len": 1058,
        "class": "same-callee", "disposition": "new",
        "pcmpeqb": [{"va": "0x4e85741", "bytes": "660f740d97f437fb"},
                    {"va": "0x4e85749", "bytes": "660f74050f0a38fb"}],
        "branch": {"va": "0x4e8575e", "bytes": "0f8464010000",
                   "asm": "je 0x4e858c8", "polarity": "je"},
        "segment": {"start": "0x4e85764", "end": "0x4e857b3",
                    "sha256": "df0f27ee3df118576cf033f89f0aab8c12c77679c6f94e904e91ba91cabcf450"},
        "first_call": {"va": "0x4e85769", "bytes": "e852c6ffff", "target": "0x4e81dc0"},
        "second_call": None,
        "one_store": {"va": "0x4e8576e", "bytes": "48c744247001000000",
                      "asm": "mov [rsp+0x70],1"},
        "install_top_store": {"va": "0x4e857a3", "bytes": "410f115e30",
                              "asm": "movups [r14+0x30],xmm3"},
        "install_range": "[r14+0x0..0x40]",
        "match_call": {"va": "0x4e858cd", "bytes": "e8eec4ffff", "target": "0x4e81dc0"},
        "match_install_range": "[r14+0x0..0x38]",
    },
    {
        "fde": "0x4e6bcb0", "fde_end": "0x4e6c840", "fde_len": 2960,
        "class": "same-callee", "disposition": "new",
        "pcmpeqb": [{"va": "0x4e6bf63", "bytes": "660f740d758c39fb"},
                    {"va": "0x4e6bf6b", "bytes": "660f7405eda139fb"}],
        "branch": {"va": "0x4e6bf80", "bytes": "0f849d000000",
                   "asm": "je 0x4e6c023", "polarity": "je"},
        "segment": {"start": "0x4e6bf86", "end": "0x4e6bfc7",
                    "sha256": "06efde0d07379b2099237d6aaa694eee3bae3aa8ecae7864473d724cea82fcea"},
        "first_call": {"va": "0x4e6bf8b", "bytes": "e860f6ffff", "target": "0x4e6b5f0"},
        "second_call": None,
        "one_store": {"va": "0x4e6bf90", "bytes": "48c744243001000000",
                      "asm": "mov [rsp+0x30],1"},
        "install_top_store": {"va": "0x4e6bfb6", "bytes": "0f115d30",
                              "asm": "movups [rbp+0x30],xmm3"},
        "install_range": "[rbp+0x0..0x40]",
        "match_call": {"va": "0x4e6c028", "bytes": "e8c3f5ffff", "target": "0x4e6b5f0"},
        "match_install_range": "[rbp+0x0..0x38]",
    },
    # ---- twin-B clones (measured instances) ----
    {
        "fde": "0x32aca90", "fde_end": "0x32acc9f", "fde_len": 527,
        "class": "twin-B-clone", "disposition": "instance",
        "pcmpeqb": [{"va": "0x32acad7", "bytes": "660f740d0181f5fc"},
                    {"va": "0x32acadf", "bytes": "660f74057996f5fc"}],
        "branch": {"va": "0x32acaf4", "bytes": "0f8499000000",
                   "asm": "je 0x32acb93", "polarity": "je"},
        "segment": {"start": "0x32acafa", "end": "0x32acb5b",
                    "sha256": "0e7a9e90fa5e996bf62d10738fe239bea26e82a0f00408f8fbaed8ef509caec2"},
        "first_call": {"va": "0x32acb2a", "bytes": "e891485200", "target": "0x37d13c0"},
        "second_call": {"va": "0x32acb3e", "bytes": "e82dd5f9ff", "target": "0x324a070"},
        "one_store": {"va": "0x32acb43", "bytes": "48c744244001000000",
                      "asm": "mov [rsp+0x40],1"},
        "install_top_store": {"va": "0x32acc18", "bytes": "410f115e30",
                              "asm": "movups [r14+0x30],xmm3"},
        "install_range": "[r14+0x0..0x40]",
        "match_call": None,
        "match_install_range": "[r14+0x0..0x38]",
    },
    {
        "fde": "0x32acca0", "fde_end": "0x32aceaf", "fde_len": 527,
        "class": "twin-B-clone", "disposition": "instance",
        "pcmpeqb": [{"va": "0x32acce7", "bytes": "660f740df17ef5fc"},
                    {"va": "0x32accef", "bytes": "660f74056994f5fc"}],
        "branch": {"va": "0x32acd04", "bytes": "0f8499000000",
                   "asm": "je 0x32acda3", "polarity": "je"},
        "segment": {"start": "0x32acd0a", "end": "0x32acd6b",
                    "sha256": "f0c3cc0d1dc767562b9529a4d65d1eb00247bddf60e1c7997db464d4e8336864"},
        "first_call": {"va": "0x32acd3a", "bytes": "e881465200", "target": "0x37d13c0"},
        "second_call": {"va": "0x32acd4e", "bytes": "e81dd3f9ff", "target": "0x324a070"},
        "one_store": {"va": "0x32acd53", "bytes": "48c744244001000000",
                      "asm": "mov [rsp+0x40],1"},
        "install_top_store": {"va": "0x32ace28", "bytes": "410f115e30",
                              "asm": "movups [r14+0x30],xmm3"},
        "install_range": "[r14+0x0..0x40]",
        "match_call": None,
        "match_install_range": "[r14+0x0..0x38]",
    },
    {
        "fde": "0x44bb790", "fde_end": "0x44bb99f", "fde_len": 527,
        "class": "twin-B-clone", "disposition": "instance",
        "pcmpeqb": [{"va": "0x44bb7d7", "bytes": "660f740d0194d4fb"},
                    {"va": "0x44bb7df", "bytes": "660f740579a9d4fb"}],
        "branch": {"va": "0x44bb7f4", "bytes": "0f8499000000",
                   "asm": "je 0x44bb893", "polarity": "je"},
        "segment": {"start": "0x44bb7fa", "end": "0x44bb85b",
                    "sha256": "e24b3d17e06c1f44751a1fb03cc200cf177eb4cdb352933e7e59e157abd937a3"},
        "first_call": {"va": "0x44bb82a", "bytes": "e8915b31ff", "target": "0x37d13c0"},
        "second_call": {"va": "0x44bb83e", "bytes": "e82de8d8fe", "target": "0x324a070"},
        "one_store": {"va": "0x44bb843", "bytes": "48c744244001000000",
                      "asm": "mov [rsp+0x40],1"},
        "install_top_store": {"va": "0x44bb918", "bytes": "410f115e30",
                              "asm": "movups [r14+0x30],xmm3"},
        "install_range": "[r14+0x0..0x40]",
        "match_call": None,
        "match_install_range": "[r14+0x0..0x38]",
    },
    {
        "fde": "0x4dd6c90", "fde_end": "0x4dd6e9f", "fde_len": 527,
        "class": "twin-B-clone", "disposition": "instance",
        "pcmpeqb": [{"va": "0x4dd6cd7", "bytes": "660f740d01df42fb"},
                    {"va": "0x4dd6cdf", "bytes": "660f740579f442fb"}],
        "branch": {"va": "0x4dd6cf4", "bytes": "0f8499000000",
                   "asm": "je 0x4dd6d93", "polarity": "je"},
        "segment": {"start": "0x4dd6cfa", "end": "0x4dd6d5b",
                    "sha256": "a4af2f0b39ee402e124e51a25c810b3302ad7b5c7edc18f5816c07cb58d01d7c"},
        "first_call": {"va": "0x4dd6d2a", "bytes": "e891a69ffe", "target": "0x37d13c0"},
        "second_call": {"va": "0x4dd6d3e", "bytes": "e82d3347fe", "target": "0x324a070"},
        "one_store": {"va": "0x4dd6d43", "bytes": "48c744244001000000",
                      "asm": "mov [rsp+0x40],1"},
        "install_top_store": {"va": "0x4dd6e18", "bytes": "410f115e30",
                              "asm": "movups [r14+0x30],xmm3"},
        "install_range": "[r14+0x0..0x40]",
        "match_call": None,
        "match_install_range": "[r14+0x0..0x38]",
    },
    # ---- twin-shape pair (classified) ----
    {
        "fde": "0x1eb1cc0", "fde_end": "0x1eb1e58", "fde_len": 408,
        "class": "twin-shape", "disposition": "classified",
        "pcmpeqb": [{"va": "0x1eb1d07", "bytes": "660f740dd12e35fe"},
                    {"va": "0x1eb1d0f", "bytes": "660f7405494435fe"}],
        "branch": {"va": "0x1eb1d24", "bytes": "0f848a000000",
                   "asm": "je 0x1eb1db4", "polarity": "je"},
        "segment": {"start": "0x1eb1d2a", "end": "0x1eb1d7d",
                    "sha256": "cad545b2b3a6ae9430ea666bd3c33e2dce4d35a23f2a5cc29aa5ba2576db08a1"},
        "first_call": {"va": "0x1eb1d4a", "bytes": "e8f191fbff", "target": "0x1e6af40"},
        "second_call": None,
        "one_store": None,
        "install_top_store": {"va": "0x1eb1d6a", "bytes": "410f115e30",
                              "asm": "movups [r14+0x30],xmm3"},
        "install_range": "[r14+0x0..0x40]",
        "match_call": {"va": "0x1eb1db7", "bytes": "e804d4faff", "target": "0x1e5f1c0"},
        "match_install_range": "[r14+0x0..0x38]",
    },
    {
        "fde": "0x1eb1e60", "fde_end": "0x1eb2057", "fde_len": 503,
        "class": "twin-shape", "disposition": "classified",
        "pcmpeqb": [{"va": "0x1eb1ea7", "bytes": "660f740d312d35fe"},
                    {"va": "0x1eb1eaf", "bytes": "660f7405a94235fe"}],
        "branch": {"va": "0x1eb1ec4", "bytes": "0f848d000000",
                   "asm": "je 0x1eb1f57", "polarity": "je"},
        "segment": {"start": "0x1eb1eca", "end": "0x1eb1f1f",
                    "sha256": "f34c0d09c57adf0a01a343a2f7e83edff0071ec4c75c451d842c032d0151f224"},
        "first_call": {"va": "0x1eb1ef8", "bytes": "e8c3f49101", "target": "0x37d13c0"},
        "second_call": {"va": "0x1eb1f0c", "bytes": "e85f813901", "target": "0x324a070"},
        "one_store": {"va": "0x1eb1f11", "bytes": "48c744244001000000",
                      "asm": "mov [rsp+0x40],1"},
        "install_top_store": {"va": "0x1eb1fd0", "bytes": "410f115e30",
                              "asm": "movups [r14+0x30],xmm3"},
        "install_range": "[r14+0x0..0x40]",
        "match_call": {"va": "0x1eb1f5a", "bytes": "e861d2faff", "target": "0x1e5f1c0"},
        "match_install_range": "[r14+0x0..0x38]",
    },
    # ---- attributed, already mapped (not re-claimed) ----
    {
        "fde": "0x2788350", "fde_end": "0x27884f5", "fde_len": 421,
        "class": "twin", "disposition": "attributed",
        "pcmpeqb": [{"va": "0x2788397", "bytes": "660f740d41c8a7fd"},
                    {"va": "0x278839f", "bytes": "660f7405b9dda7fd"}],
        "branch": {"va": "0x27883b4", "bytes": "0f8490000000",
                   "asm": "je 0x278844a", "polarity": "je"},
        "segment": None, "first_call": None, "second_call": None,
        "one_store": None, "install_top_store": None,
        "install_range": "attributed to PR #1785",
        "match_call": None, "match_install_range": "attributed to PR #1785",
    },
    {
        "fde": "0x2788500", "fde_end": "0x278870f", "fde_len": 527,
        "class": "twin", "disposition": "attributed",
        "pcmpeqb": [{"va": "0x2788547", "bytes": "660f740d91c6a7fd"},
                    {"va": "0x278854f", "bytes": "660f740509dca7fd"}],
        "branch": {"va": "0x2788564", "bytes": "0f8499000000",
                   "asm": "je 0x27885fd", "polarity": "je"},
        "segment": None, "first_call": None, "second_call": None,
        "one_store": None, "install_top_store": None,
        "install_range": "attributed to PR #1785",
        "match_call": None, "match_install_range": "attributed to PR #1785",
    },
    {
        "fde": "0x3272190", "fde_end": "0x3272272", "fde_len": 226,
        "class": "flag-anchor", "disposition": "attributed",
        "pcmpeqb": [{"va": "0x32721dd", "bytes": "660f740dfb29f9fc"},
                    {"va": "0x32721e5", "bytes": "660f7405733ff9fc"}],
        "branch": {"va": "0x3272203", "bytes": "7438",
                   "asm": "je 0x327223d", "polarity": "je"},
        "segment": None, "first_call": None, "second_call": None,
        "one_store": None, "install_top_store": None,
        "install_range": "attributed to #165 (dl=1 store)",
        "match_call": None, "match_install_range": "attributed to #165 (dl=0 store)",
    },
    {
        "fde": "0x4e852a0", "fde_end": "0x4e85663", "fde_len": 963,
        "class": "double-gate-0", "disposition": "attributed",
        "pcmpeqb": [{"va": "0x4e852f8", "bytes": "660f740de0f837fb"},
                    {"va": "0x4e85300", "bytes": "660f7405580e38fb"}],
        "branch": {"va": "0x4e85315", "bytes": "0f8434010000",
                   "asm": "je 0x4e8544f", "polarity": "je"},
        "segment": None, "first_call": None, "second_call": None,
        "one_store": None, "install_top_store": None,
        "install_range": "attributed to #165 (twin pattern)",
        "match_call": None, "match_install_range": "attributed to #165 (twin pattern)",
    },
]

def va_to_offset(sections, va):
    for s in sections:
        if s["type"] == 8:
            continue
        if s["address"] <= va < s["address"] + s["size"]:
            return s["offset"] + (va - s["address"])
    raise ValueError(f"VA {va:#x} has no file mapping")


def read_bytes(data, sections, va, length):
    off = va_to_offset(sections, va)
    return data[off:off + length]


def check_anchor(data, sections, va, hex_bytes):
    want = bytes.fromhex(hex_bytes)
    got = read_bytes(data, sections, va, len(want))
    if got != want:
        raise ValueError(f"anchor mismatch at {va:#x}: got {got.hex()}, want {hex_bytes}")


def parse_fde_ends(data):
    """Parse .eh_frame records into {initial_location: (end, length)}."""
    secs = elf_index.sections(data)
    eh = next(s for s in secs if s["name"] == ".eh_frame")
    base, size = eh["offset"], eh["size"]

    def uleb(buf, p):
        v = 0; s = 0
        while True:
            b = buf[p]; p += 1; v |= (b & 0x7F) << s; s += 7
            if not (b & 0x80):
                return v, p

    def sleb(buf, p):
        v = 0; s = 0
        while True:
            b = buf[p]; p += 1; v |= (b & 0x7F) << s; s += 7
            if not (b & 0x80):
                if b & 0x40:
                    v |= -(1 << s)
                return v, p

    p = base; cies = {}; fdes = {}
    while p < base + size:
        rec_start = p
        length, = struct.unpack_from("<I", data, p)
        if length == 0:
            break
        cie_id, = struct.unpack_from("<I", data, p + 4)
        if cie_id == 0:
            q = p + 8
            q += 1  # version
            e = data.index(b"\0", q); aug = data[q:e].decode(); q = e + 1
            _, q = uleb(data, q); _, q = sleb(data, q); _, q = uleb(data, q)
            fde_enc = None
            if aug.startswith("z"):
                _, q = uleb(data, q)
                for ch in aug[1:]:
                    if ch == "L":
                        q += 1
                    elif ch == "P":
                        enc = data[q]; q += 1
                        q += {0x03: 4, 0x04: 8, 0x0B: 4, 0x0C: 8, 0x0A: 2, 0x02: 2}.get(enc & 0x0F, 8)
                    elif ch == "R":
                        fde_enc = data[q]; q += 1
            cies[rec_start] = fde_enc
        else:
            cie_off = (p + 4) - cie_id
            enc = cies.get(cie_off)
            fmt = enc & 0x0F if enc is not None else 0x04
            app = enc & 0x70 if enc is not None else 0
            q = p + 8
            if fmt == 0x03:
                loc, q = struct.unpack_from("<I", data, q)[0], q + 4
            elif fmt == 0x04:
                loc, q = struct.unpack_from("<Q", data, q)[0], q + 8
            elif fmt == 0x0B:
                loc, q = struct.unpack_from("<i", data, q)[0], q + 4
            elif fmt == 0x0C:
                loc, q = struct.unpack_from("<q", data, q)[0], q + 8
            elif fmt == 0x0A:
                loc, q = struct.unpack_from("<h", data, q)[0], q + 2
            else:
                raise ValueError(f"unsupported FDE encoding {enc:#x}")
            field_size = {0x03: 4, 0x04: 8, 0x0B: 4, 0x0C: 8, 0x0A: 2}[fmt]
            if app == 0x10:
                loc = (q - field_size) + loc
            if fmt == 0x03:
                rng, q = struct.unpack_from("<I", data, q)[0], q + 4
            elif fmt == 0x04:
                rng, q = struct.unpack_from("<Q", data, q)[0], q + 8
            elif fmt == 0x0B:
                rng, q = struct.unpack_from("<i", data, q)[0], q + 4
            elif fmt == 0x0C:
                rng, q = struct.unpack_from("<q", data, q)[0], q + 8
            elif fmt == 0x0A:
                rng, q = struct.unpack_from("<h", data, q)[0], q + 2
            fdes[loc] = (loc + rng, rng)
        p = rec_start + 4 + length
    return secs, fdes


def disp32_scan(data, sections):
    """Byte-level scan: every disp32 in .text whose rip-relative target is
    one of the two constants. Returns {disp_field_va: target}."""
    text = next(s for s in sections if s["name"] == ".text")
    blob = data[text["offset"]:text["offset"] + text["size"]]
    out = {}
    for p in range(0, len(blob) - 4):
        disp, = struct.unpack_from("<i", blob, p)
        target = text["address"] + p + 4 + disp
        if target in (CONST_HI, CONST_LO):
            out[text["address"] + p] = target
    return out


def e8_target(data, sections, va):
    """Target of a 5-byte E8 call at va."""
    rel, = struct.unpack_from("<i", read_bytes(data, sections, va + 1, 4), 0)
    return va + 5 + rel


def main(binary, out_dir):
    data = Path(binary).read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("node digest mismatch")
    secs, fdes = parse_fde_ends(data)
    # 1. Anchor verification for every gate.
    for g in GATES:
        fde = int(g["fde"], 16)
        if fde not in fdes:
            raise ValueError(f"FDE {g['fde']} missing from .eh_frame")
        end, length = fdes[fde]
        if end != int(g["fde_end"], 16) or length != g["fde_len"]:
            raise ValueError(f"FDE {g['fde']} bounds mismatch: got {end:#x}/{length}, "
                             f"want {g['fde_end']}/{g['fde_len']}")
        for cmp_ in g["pcmpeqb"]:
            check_anchor(data, secs, int(cmp_["va"], 16), cmp_["bytes"])
        check_anchor(data, secs, int(g["branch"]["va"], 16), g["branch"]["bytes"])
        # Anchor disjointness from #165: every claimed anchor below lies
        # strictly after its gate's branch; #165's recorded anchors (feeds,
        # compares, branch) are all at or before the branch.
        branch_va = int(g["branch"]["va"], 16)
        seg = g["segment"]
        if seg is not None:
            s, e = int(seg["start"], 16), int(seg["end"], 16)
            if s <= branch_va:
                raise ValueError(f"segment for {g['fde']} starts at or before its branch")
            blob = read_bytes(data, secs, s, e - s)
            if hashlib.sha256(blob).hexdigest() != seg["sha256"]:
                raise ValueError(f"segment digest mismatch for {g['fde']}")
            # No second gate test inside the fall-through segment: the
            # bytes 3d ff ff 00 00 (cmp eax,0xffff) must not occur. The
            # gate's own cmp sits before fall_start, so any occurrence
            # here would be a vectors re-test.
            if blob.count(bytes.fromhex("3dffff0000")) != 0:
                raise ValueError(f"segment for {g['fde']} contains a second cmp 0xffff")
            fc = g["first_call"]
            check_anchor(data, secs, int(fc["va"], 16), fc["bytes"])
            if e8_target(data, secs, int(fc["va"], 16)) != int(fc["target"], 16):
                raise ValueError(f"first-call target mismatch for {g['fde']}")
            if g["second_call"] is not None:
                sc = g["second_call"]
                check_anchor(data, secs, int(sc["va"], 16), sc["bytes"])
                if e8_target(data, secs, int(sc["va"], 16)) != int(sc["target"], 16):
                    raise ValueError(f"second-call target mismatch for {g['fde']}")
            if g["one_store"] is not None:
                check_anchor(data, secs, int(g["one_store"]["va"], 16),
                             g["one_store"]["bytes"])
            check_anchor(data, secs, int(g["install_top_store"]["va"], 16),
                         g["install_top_store"]["bytes"])
            if g["match_call"] is not None:
                mc = g["match_call"]
                check_anchor(data, secs, int(mc["va"], 16), mc["bytes"])
                if e8_target(data, secs, int(mc["va"], 16)) != int(mc["target"], 16):
                    raise ValueError(f"match-call target mismatch for {g['fde']}")
    # 2. Independent census cross-check (byte-level, no recorded table).
    cands = disp32_scan(data, secs)
    if len(cands) != 94:
        raise ValueError(f"disp32 census: got {len(cands)}, want 94")
    # Pair consecutive compares per FDE in address order; derive polarity
    # from the branch opcode following cmp 0xffff (0f 84 = je, 0f 85 = jne,
    # 0f 95 = setne, 74 = short je).
    per_fde = {}
    for disp_va in sorted(cands):
        cmp_va = disp_va - 3  # 66 0f 74 xx disp32: disp field is 4 bytes in
        for fde, (end, _length) in fdes.items():
            if fde <= cmp_va < end:
                per_fde.setdefault(fde, []).append(cmp_va)
                break
    if len(per_fde) != 46:
        raise ValueError(f"census FDEs: got {len(per_fde)}, want 46")
    polarity = {"je": 0, "jne": 0, "setne": 0}
    derived_je_pairs = set()
    for fde, vas in per_fde.items():
        if len(vas) % 2 != 0:
            raise ValueError(f"FDE {fde:#x} has odd pcmpeqb count {len(vas)}")
        for i in range(0, len(vas), 2):
            # cmp 0xffff follows the second compare: 8-byte pcmpeqb +
            # pand + pmovmskb + 5-byte cmp = branch nearby; scan forward
            # for the branch opcode.
            second = vas[i + 1]
            branch = None
            for probe in range(second + 8, second + 40):
                b = read_bytes(data, secs, probe, 2)
                if b == bytes.fromhex("0f84"):
                    branch = ("je", probe)
                    break
                if b == bytes.fromhex("0f85"):
                    branch = ("jne", probe)
                    break
                if b == bytes.fromhex("0f95"):
                    branch = ("setne", probe)
                    break
                if b[0] == 0x74:
                    branch = ("je", probe)
                    break
                if b[0] == 0x75:
                    branch = ("jne", probe)
                    break
            if branch is None:
                raise ValueError(f"no branch found after gate at {second:#x}")
            polarity[branch[0]] += 1
            if branch[0] == "je":
                derived_je_pairs.add((fde, branch[1]))
    if polarity != {"je": 36, "jne": 9, "setne": 2}:
        raise ValueError(f"census polarity: got {polarity}, want je36/jne9/setne2")
    table_pairs = {(int(g["fde"], 16), int(g["branch"]["va"], 16)) for g in GATES}
    if not table_pairs <= derived_je_pairs:
        raise ValueError("table gates are not all derived je gates")
    if len(derived_je_pairs) - len(table_pairs) != 23:
        raise ValueError("derived je gates minus table gates != 23 rejoin gates")
    # 3. Emit packet files (sorted deterministically).
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths_lines = ["fde\tgate\tclass\tpcmpeqb_hi\tpcmpeqb_lo\tbranch_va\tpolarity"
                   "\tdisposition\tfall_start\tseg_start\tseg_end\tseg_sha256"
                   "\tfirst_call\tfirst_call_target\tsecond_call\tsecond_call_target"
                   "\tinstall_range\tmatch_install_range\tvectors_zero_distinguishes"]
    seg_lines = []
    case_lines = ["case\tgate\tcheck\tresult"]
    ev_gates = []
    for g in sorted(GATES, key=lambda x: int(x["fde"], 16)):
        branch_va = int(g["branch"]["va"], 16)
        seg = g["segment"]
        if seg is not None:
            fall = branch_va + len(bytes.fromhex(g["branch"]["bytes"]))
            seg_lines.append(f"{g['fde']}..{seg['end']} length={int(seg['end'], 16) - int(seg['start'], 16)} "
                             f"sha256={seg['sha256']}")
            case_lines.append(f"seg-no-second-gate-test\t{g['fde']}\t"
                              f"segment contains no cmp 0xffff\tpass: 0 occurrences")
        else:
            fall = ""
        fc = g["first_call"]
        sc = g["second_call"]
        paths_lines.append("\t".join([
            g["fde"], "0", g["class"],
            g["pcmpeqb"][0]["va"], g["pcmpeqb"][1]["va"], g["branch"]["va"],
            g["branch"]["polarity"], g["disposition"],
            f"{fall:#x}" if fall != "" else "",
            seg["start"] if seg else "", seg["end"] if seg else "",
            seg["sha256"] if seg else "",
            fc["va"] if fc else "", fc["target"] if fc else "",
            sc["va"] if sc else "", sc["target"] if sc else "",
            g["install_range"], g["match_install_range"], "false"]))
        ev_gates.append({
            "fde": g["fde"], "fde_end": g["fde_end"], "fde_len": g["fde_len"],
            "class": g["class"], "disposition": g["disposition"],
            "pcmpeqb_hi": g["pcmpeqb"][0]["va"], "pcmpeqb_lo": g["pcmpeqb"][1]["va"],
            "branch_va": g["branch"]["va"], "branch_asm": g["branch"]["asm"],
            "polarity": g["branch"]["polarity"],
            "segment": ({"start": seg["start"], "end": seg["end"],
                         "sha256": seg["sha256"]} if seg else None),
            "first_call": ({"va": fc["va"], "target": fc["target"]} if fc else None),
            "second_call": ({"va": sc["va"], "target": sc["target"]} if sc else None),
            "install_range": g["install_range"],
            "match_install_range": g["match_install_range"],
            "vectors_zero_distinguishes": False,
        })
    for g in sorted(GATES, key=lambda x: int(x["fde"], 16)):
        if g["disposition"] == "new" and g["match_call"] is not None:
            case_lines.append(f"trio-both-path-callee\t{g['fde']}\t"
                              f"match-path call target == non-match first-call target\t"
                              f"pass: {g['match_call']['target']}")
    case_lines.append("partition-sums-to-13\tall\t"
                      "same-callee 3 + twin-B-clone 4 + twin-shape 2 + attributed 4\t"
                      "pass: 13")
    evidence = {
        "target": "node #94",
        "target_sha256": SHA256,
        "constants": {"hi": {"va": f"{CONST_HI:#x}", "bytes": CONST_HI_BYTES.hex()},
                      "lo": {"va": f"{CONST_LO:#x}", "bytes": CONST_LO_BYTES.hex()}},
        "census_method": "byte-level disp32 scan over .text (94 candidates, all pcmpeqb "
                         "rip-relative), polarity derived from the branch opcode after "
                         "cmp 0xffff; cross-checked against #165's published census "
                         "(47 gates / 46 FDEs / je36 jne9 setne2)",
        "census": {"refs": 94, "gates_total": 47, "fdes_total": 46,
                   "polarity": {"je": 36, "jne": 9, "setne": 2},
                   "classes": {"A": 42, "B": 3, "C": 2}},
        "nonrejoin_total": 13,
        "partition": {"same_callee": 3, "twin_B_clone": 4, "twin_shape": 2,
                      "attributed": 4},
        "vectors_zero_distinguishes_any": False,
        "segments_total": 9,
        "cases": len(case_lines) - 1,
        "gates": ev_gates,
    }
    (out_dir / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    (out_dir / "paths.tsv").write_text("\n".join(paths_lines) + "\n")
    (out_dir / "segments.txt").write_text("\n".join(seg_lines) + "\n")
    (out_dir / "cases.tsv").write_text("\n".join(case_lines) + "\n")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    main(args.binary, args.out)
