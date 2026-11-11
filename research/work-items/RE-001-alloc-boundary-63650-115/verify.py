"""Checker for the RE-001-alloc-boundary-63650-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-alloc-boundary-63650-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary
(objdump splits a few long instructions across two lines; the
parser accumulates those continuations); spot instructions
byte-for-byte against a fresh objdump run and the raw binary;
the FDE ranges in frames.txt against a fresh frame dump; the
four GOT-slot RELATIVE records against a fresh relocation dump
(and that no RELATIVE addend names the routine itself); census
consistency (callers.tsv against a fresh scan: 732 direct
calls, 0 tail jumps, no stored qwords, no RELATIVE addends,
0 internal calls, 0 internal tail jumps, 4 internal indirect
calls, 0 internal indirect tail jumps) and each callers.tsv
caller function against the smallest enclosing FDE range from
a fresh frame dump; the semantic records; and the model tests.
Prints ALL CHECKS PASSED on success, else raises.
"""

import ast
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = [
    ("main.txt", 0x5963650, 0x5963739),
]

EXPECTED_CALLS = {
    0x5963650: [
    "0x4d73edd", "0x4d73f5b", "0x4d73fa4", "0x4d75ebd",
    "0x4d8116c", "0x4d8129e", "0x4d81b15", "0x4d9ccc2",
    "0x4e0d5f2", "0x4e0e15c", "0x4e0f18a", "0x4e2a6a6",
    "0x4e2a6e6", "0x4e37ef5", "0x4e37f83", "0x4e38154",
    "0x4e381e3", "0x4e38813", "0x4e389f7", "0x4e38a87",
    "0x4e38b51", "0x4e38c36", "0x4e38cc5", "0x4e38d7b",
    "0x4e38e22", "0x4ec7e51", "0x4ec7e9b", "0x4ed031f",
    "0x4ed034a", "0x4ed054e", "0x4ed0599", "0x4ed070e",
    "0x4ed0759", "0x4ed08b8", "0x4ed08e3", "0x4ed0abf",
    "0x4ed0aea", "0x4ed0cc8", "0x4ed0cf3", "0x4ed0e98",
    "0x4ed0ec3", "0x4ed1073", "0x4ed10a1", "0x4ed129e",
    "0x4ed12e9", "0x4ed1448", "0x4ed1473", "0x4ed162e",
    "0x4ed1679", "0x4ed17ee", "0x4ed1839", "0x4ed1998",
    "0x4ed19c3", "0x4ed1bee", "0x4ed1c39", "0x4ed1dae",
    "0x4ed1df9", "0x4ed1f6e", "0x4ed1fb9", "0x4ed2118",
    "0x4ed2143", "0x4ed235e", "0x4ed23a9", "0x4ed251e",
    "0x4ed2569", "0x4ed26de", "0x4ed2729", "0x4ed2888",
    "0x4ed28b3", "0x4ed2abe", "0x4ed2b09", "0x4ed2c68",
    "0x4ed2c93", "0x4ed2e9e", "0x4ed2ee9", "0x4ed305e",
    "0x4ed30a9", "0x4ed321e", "0x4ed3269", "0x4ed33de",
    "0x4ed3429", "0x4ed359e", "0x4ed35e9", "0x4ed375e",
    "0x4ed37a9", "0x4ed3922", "0x4ed394d", "0x4ef1537",
    "0x4ef157b", "0x4ef4fb4", "0x4ef5058", "0x4ef5325",
    "0x4ef5440", "0x4ef5705", "0x4ef5820", "0x4ef5b7d",
    "0x4ef5bfa", "0x4ef5fc4", "0x4ef6079", "0x4ef635a",
    "0x4ef6455", "0x4f00064", "0x50b4591", "0x50c07d8",
    "0x50c0e15", "0x50c165a", "0x50c2245", "0x50c932d",
    "0x50c9a29", "0x50ca947", "0x50cb2ce", "0x50cb4d9",
    "0x50cc420", "0x50ceb03", "0x50d50ec", "0x50d6874",
    "0x50dab31", "0x50dac05", "0x50dac63", "0x50de490",
    "0x5106cec", "0x5107781", "0x51077da", "0x5107837",
    "0x5116812", "0x5116fc2", "0x51178c7", "0x51182ad",
    "0x5118a24", "0x5118f54", "0x51196d4", "0x511a244",
    "0x511b304", "0x511bf04", "0x511c624", "0x511cc44",
    "0x511ce34", "0x511d024", "0x511d584", "0x511d774",
    "0x511d964", "0x511df84", "0x511e174", "0x511e624",
    "0x511fca4", "0x51200e4", "0x5120594", "0x5120c54",
    "0x5120fa4", "0x5121b54", "0x51225d4", "0x5123204",
    "0x5123764", "0x5123954", "0x5125454", "0x5126714",
    "0x5126904", "0x5126db4", "0x5127794", "0x5127e54",
    "0x51281a4", "0x5128e64", "0x5129fa4", "0x512bc04",
    "0x512ce24", "0x512d014", "0x512e9f4", "0x512ef54",
    "0x5130184", "0x5130904", "0x51788c9", "0x518bf8b",
    "0x518cbdd", "0x518e2b3", "0x51957f0", "0x5196181",
    "0x519a23a", "0x519f15c", "0x519fcbc", "0x51a186b",
    "0x51a2bf9", "0x51a319a", "0x51a536c", "0x51a571b",
    "0x51aaa05", "0x51ab927", "0x51ab9d0", "0x51ac27a",
    "0x51ae603", "0x520bfe2", "0x520c7a3", "0x520cfaf",
    "0x520d0f5", "0x520d228", "0x526e546", "0x526e78f",
    "0x526eca8", "0x526ee06", "0x526f63b", "0x526f6ae",
    "0x526fe67", "0x5270222", "0x5270352", "0x527056d",
    "0x5270e49", "0x5270f84", "0x52718ba", "0x5271caf",
    "0x5272b19", "0x5273b71", "0x52740d8", "0x527466a",
    "0x5274722", "0x52751fb", "0x5275885", "0x5275dbc",
    "0x5276d0c", "0x5277650", "0x5277e2c", "0x52784b8",
    "0x527852f", "0x5278e00", "0x5279a85", "0x527a3fa",
    "0x527a98c", "0x527b19c", "0x527b541", "0x527baa7",
    "0x527bafb", "0x527caca", "0x527d135", "0x527df69",
    "0x527e955", "0x527f3a2", "0x527f41b", "0x527fb12",
    "0x527fb8b", "0x528009f", "0x5280725", "0x52813c9",
    "0x5282a75", "0x52840b0", "0x5284cf0", "0x5285385",
    "0x52859e5", "0x528652c", "0x5286fd9", "0x5287ba0",
    "0x528840c", "0x5289030", "0x5289c20", "0x528a749",
    "0x528adc2", "0x528ae35", "0x528ba2a", "0x528c5df",
    "0x528db10", "0x528e4d5", "0x528f406", "0x528fe59",
    "0x5290bce", "0x52911b0", "0x5291a35", "0x5292065",
    "0x5292caf", "0x5293535", "0x52947c1", "0x52954d5",
    "0x5295a87", "0x5295ad2", "0x5296155", "0x5296de9",
    "0x52977c2", "0x5297818", "0x5297d1b", "0x5298e25",
    "0x52996e0", "0x529a435", "0x529aa18", "0x529aa64",
    "0x529b5d5", "0x529bc35", "0x529c20a", "0x529c256",
    "0x529cca1", "0x529d90d", "0x529d982", "0x529dfa2",
    "0x529e015", "0x529e088", "0x529e5ea", "0x529e6a2",
    "0x529f075", "0x529f5dc", "0x529f652", "0x52a08d1",
    "0x52a0e77", "0x52a17ad", "0x52a1823", "0x52a224d",
    "0x52a22a1", "0x52a2ea0", "0x52a405c", "0x52a46c5",
    "0x52a4e6a", "0x52a4eb3", "0x52a59a9", "0x52a609b",
    "0x52a60f0", "0x52a69b2", "0x52a6a25", "0x52a6a98",
    "0x52a7690", "0x52a89e0", "0x52a8a2c", "0x52a8cf4",
    "0x52a9de2", "0x52aa535", "0x52ab225", "0x52ab838",
    "0x52ab8ef", "0x52ac770", "0x52ad5ee", "0x52ad639",
    "0x52add87", "0x52ade04", "0x52ae720", "0x52af0f5",
    "0x52b0220", "0x52b08fa", "0x52b11e0", "0x52b1833",
    "0x52b18f7", "0x52b208c", "0x52b2829", "0x52b348d",
    "0x52b39ee", "0x52b3a64", "0x52b5470", "0x52b6377",
    "0x52b6cb0", "0x52b75e1", "0x52b8e2e", "0x52b908e",
    "0x52b9ecb", "0x52ba68c", "0x52bb818", "0x52bbf15",
    "0x52bc554", "0x52bcf48", "0x52bd5d9", "0x52bdcec",
    "0x52bec50", "0x52bf560", "0x52c01d9", "0x52c0861",
    "0x52c19f5", "0x52c1f47", "0x52c3690", "0x52c3c12",
    "0x52c3c8b", "0x52c434a", "0x52c43c1", "0x52c4b6c",
    "0x52c589f", "0x52c6589", "0x52c6d7f", "0x52c6df2",
    "0x52c6e65", "0x52c8040", "0x52c93d0", "0x52c9446",
    "0x52c9fbe", "0x52cabd0", "0x52cb265", "0x52cbe08",
    "0x52cca20", "0x52ccdf1", "0x52cd52e", "0x52cd5a4",
    "0x52cddec", "0x52ce31c", "0x52cec00", "0x52cf5d5",
    "0x52d0ae0", "0x52d1740", "0x52d1db4", "0x52d222b",
    "0x52d2c05", "0x52d319f", "0x52d31f2", "0x52d394c",
    "0x52d41dc", "0x52d4ac0", "0x52d529c", "0x52d5f20",
    "0x52d6830", "0x52d7708", "0x52d8000", "0x52d882f",
    "0x52d938e", "0x52d9c8c", "0x52d9cff", "0x52da304",
    "0x52db020", "0x52db57c", "0x52dc830", "0x52dc8a6",
    "0x52dd01c", "0x52dd91d", "0x52dd993", "0x52df71b",
    "0x52df78e", "0x52dfcea", "0x52dfda2", "0x52e030c",
    "0x52e1ae6", "0x52e2308", "0x52e2da1", "0x52e3d20",
    "0x52e4338", "0x52e4384", "0x52e4b8c", "0x52e5535",
    "0x52e6b98", "0x52e7480", "0x52e7dfb", "0x52e7e5f",
    "0x52e8610", "0x52e8683", "0x52e910d", "0x52ea090",
    "0x52ea725", "0x52eaeaa", "0x52eaf62", "0x52eb855",
    "0x52ec0e0", "0x52ed1cc", "0x52ede00", "0x52eed0b",
    "0x52efca5", "0x52effa0", "0x52f00fa", "0x52f041c",
    "0x52f0470", "0x52f05f3", "0x52f08bd", "0x52f0b9b",
    "0x52f183b", "0x52f18ce", "0x52f1942", "0x52f2559",
    "0x52f3ac2", "0x52f3d08", "0x52f429b", "0x52f4c4b",
    "0x52f77aa", "0x52f8a8b", "0x52f8b19", "0x52faaa1",
    "0x52fab38", "0x52fc71b", "0x52fceab", "0x52fd662",
    "0x52fdd70", "0x52fe349", "0x52fe962", "0x52fea92",
    "0x52fec92", "0x52fedc2", "0x52fefd0", "0x52ff125",
    "0x52ff252", "0x52ff455", "0x52ff652", "0x52ff792",
    "0x52ff8d2", "0x52ffa65", "0x52ffb04", "0x52ffc22",
    "0x52ffdd7", "0x52ffe83", "0x52fffb2", "0x530026e",
    "0x5300442", "0x5300720", "0x5300852", "0x5300992",
    "0x5300bb2", "0x5300e52", "0x5300f82", "0x5301466",
    "0x5301652", "0x53018e2", "0x5301a22", "0x5301b85",
    "0x5301cce", "0x5301eb2", "0x5301ff2", "0x53022c4",
    "0x5302415", "0x53026a2", "0x5302805", "0x5302998",
    "0x5302ace", "0x5302cd0", "0x5302f10", "0x5302faf",
    "0x5303272", "0x53033b2", "0x53035d4", "0x5303680",
    "0x5303a02", "0x5303ca2", "0x5303ff2", "0x530413e",
    "0x5304295", "0x53043c2", "0x53047f5", "0x5304b2f",
    "0x5304bdb", "0x5304e6e", "0x5305070", "0x53051a2",
    "0x5305327", "0x53053d3", "0x5305502", "0x53057c2",
    "0x5305be2", "0x530616c", "0x53063e4", "0x53066bf",
    "0x5306c6c", "0x5306fda", "0x5309f00", "0x530a967",
    "0x530bb98", "0x530c0ab", "0x530c29d", "0x530fe44",
    "0x531c5da", "0x531c650", "0x531d1f9", "0x531d59e",
    "0x531db28", "0x531e104", "0x531ee14", "0x531f464",
    "0x5322878", "0x5323490", "0x5325054", "0x53637dc",
    "0x537c946", "0x537c9ed", "0x5382174", "0x538c500",
    "0x53a8398", "0x53a8410", "0x53a9557", "0x53a95d0",
    "0x53a9645", "0x53aabea", "0x53aac5f", "0x53aaca4",
    "0x53c57ce", "0x53c584d", "0x53c58a1", "0x53c5914",
    "0x53c79e8", "0x53c7ff6", "0x53c806c", "0x53ca4e6",
    "0x53cb838", "0x53cd8c8", "0x53ce6e4", "0x53cf218",
    "0x53d20e4", "0x53d2c8a", "0x5433478", "0x5434450",
    "0x54348f4", "0x543b967", "0x543bae5", "0x54837ca",
    "0x549fd00", "0x549fd87", "0x54a8d28", "0x55e808c",
    "0x55fdba1", "0x56137a9", "0x56466cb", "0x56735ed",
    "0x5674d6f", "0x5674dc9", "0x5674e1f", "0x5674fc9",
    "0x5675170", "0x5675711", "0x567696d", "0x56770cc",
    "0x56775a9", "0x567785d", "0x5677d4d", "0x5677da3",
    "0x56780a5", "0x567845a", "0x5678609", "0x5678746",
    "0x57cdf69", "0x57ce1e5", "0x57ce2f9", "0x57ce361",
    "0x57ce805", "0x57ce8a1", "0x57ce9d5", "0x57cea1d",
    "0x57ceac0", "0x57cec85", "0x57ced99", "0x57cee01",
    "0x57cf086", "0x57cf121", "0x57cf20d", "0x57cf270",
    "0x57cf53b", "0x57cf96b", "0x57cfa0f", "0x57cfad8",
    "0x57cfbb9", "0x57cfc47", "0x57d01eb", "0x57d02d5",
    "0x57d0352", "0x57d05a4", "0x57d064f", "0x57d07e4",
    "0x57d088a", "0x57d0976", "0x57d0a24", "0x591652b",
    "0x591815b", "0x5920e4a", "0x5927159", "0x59271e7",
    "0x592a29e", "0x593ee32", "0x5962185", "0x59621f5",
    "0x5962265", "0x59622d5", "0x5962345", "0x59623b5",
    "0x5962425", "0x5962495", "0x5962505", "0x5962575",
    "0x59625e5", "0x5962655", "0x59626c5", "0x5962735",
    "0x59627a5", "0x5962815", "0x5962885", "0x59628f5",
    "0x5962965", "0x59629d5", "0x5962a45", "0x5962ab5",
    "0x5962b25", "0x5962b95", "0x5962c05", "0x5962c75",
    "0x5962ce5", "0x5962d55", "0x5962dc5", "0x5962e35",
    "0x5962ea5", "0x5962f15", "0x5962f85", "0x5962ff5",
    "0x5963065", "0x59630d5", "0x5963145", "0x59631b5",
    "0x5963225", "0x5963295", "0x5963305", "0x5963375",
    "0x59633e5", "0x5963455", "0x59634c5", "0x5963535",
    "0x59635a5", "0x5963615", "0x59637c3", "0x5963851",
    "0x59639d9", "0x5963a6f", "0x59d8489", "0x5a0185e",
    "0x5a035cb", "0x5a038e3", "0x5a0a62e", "0x5a0e1e4",
    "0x5a0eca4", "0x5a243cd", "0x5a24acd", "0x5a28fe0",
    "0x5a72b92", "0x5aae24f", "0x5aae8d6", "0x5aaea15",
    "0x5aaede6", "0x5aaee3c", "0x5aaf5e9", "0x5ab0108",
    "0x5ab0549", "0x5ab09bc", "0x5ab0d48", "0x5ae4ecf",
    "0x5af6a66", "0x5af6b0f", "0x5b5e27d", "0x5b68764",
    "0x5b68b76", "0x5b6a9a3", "0x5b6a9ee", "0x5b6bad9",
    "0x5b6bc16", "0x5b6be6a", "0x5b6c006", "0x5b6c710",
    ],
}

EXPECTED_JUMPS = {0x5963650: []}

EXPECTED_INTERNAL_CALLS = []
EXPECTED_INTERNAL_JUMPS = []
EXPECTED_INTERNAL_INDIRECT_CALLS = ["0x59636bd", "0x59636cb",
                                    "0x59636f6", "0x5963701"]
EXPECTED_INTERNAL_INDIRECT_JUMPS = []

EXPECTED_SLOTS = {
    "64df480": "6355830",
    "64df590": "63577f0",
    "64df588": "635a7a0",
    "64df580": "635a790",
}

SPOT_BYTES = {
    0x5963650: "4157",
    0x5963664: "48f7e1",
    0x596366D: "48b90000000000000080",
    0x59636AD: "f3490fbcd7",
    0x59636BD: "ff15bdbeb700",
    0x59636CB: "ff15b7beb700",
    0x59636F6: "ff1594beb700",
    0x5963701: "ff1579bdb700",
    0x5963726: "4c893403",
}

LINE_RE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t(.*))?$")


def fail(message):
    raise AssertionError(message)


def check_digest():
    actual = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    if actual != DIGEST:
        fail("digest mismatch: %s" % actual)
    provenance = json.loads((ROOT / "provenance" / "artifacts.json").read_text())
    entries = [f for f in provenance["files"]
               if f["path"] == "artifacts/node/115/hl-node"]
    if not entries or entries[0]["sha256"] != DIGEST:
        fail("provenance entry mismatch")


def check_manifest():
    lines = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    if not lines:
        fail("empty manifest")
    seen = set()
    for line in lines:
        digest, name = line.split("  ", 1)
        seen.add(name)
        actual = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
        if actual != digest:
            fail("manifest mismatch for %s" % name)
    expected = {"README.md", "records.json", "main.txt",
                "frames.txt", "relocations.txt", "callers.tsv",
                "export_excerpts.py", "census.py", "verify.py"}
    if seen != expected:
        fail("manifest file set mismatch: %s" % sorted(seen))


def parse_excerpt(text):
    """Return [(address, bytes)] with split lines accumulated."""
    instructions = []
    for line in text.splitlines():
        match = LINE_RE.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        raw = bytes.fromhex(match.group(2).strip())
        mnemonic = (match.group(3) or "").strip()
        if not mnemonic and instructions and address == instructions[-1][0] + len(instructions[-1][1]):
            instructions[-1] = (instructions[-1][0], instructions[-1][1] + raw)
        else:
            instructions.append((address, raw))
    return instructions


def check_excerpts():
    data = BINARY.read_bytes()
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        stored = (PACKET / name).read_text()
        if text != stored:
            fail("excerpt mismatch for %s" % name)
        instructions = parse_excerpt(stored)
        if not instructions or instructions[0][0] != start:
            fail("excerpt %s does not start at %#x" % (name, start))
        for address, raw in instructions:
            if data[address - 0x1000:address - 0x1000 + len(raw)] != raw:
                fail("raw byte mismatch at %#x in %s" % (address, name))
        if instructions[-1][0] + len(instructions[-1][1]) != stop:
            fail("excerpt %s does not end at %#x" % (name, stop))


def check_spots():
    data = BINARY.read_bytes()
    for address, hex_bytes in SPOT_BYTES.items():
        raw = bytes.fromhex(hex_bytes)
        if data[address - 0x1000:address - 0x1000 + len(raw)] != raw:
            fail("spot raw byte mismatch at %#x" % address)
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % address,
             "--stop-address=%#x" % (address + 0x10),
             "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        instructions = parse_excerpt(text)
        if not instructions or instructions[0][0] != address:
            fail("spot objdump missing %#x" % address)
        if instructions[0][1] != raw:
            fail("spot objdump byte mismatch at %#x" % address)


def check_frames():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for line in (PACKET / "frames.txt").read_text().splitlines():
        match = re.search(r"pc=([0-9a-f]+\.\.[0-9a-f]+)", line)
        if not match:
            fail("frames.txt line without pc range: %s" % line)
        if ("pc=" + match.group(1)) not in text:
            fail("frame range missing: %s" % match.group(1))


def check_relocations():
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    found = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[2] == "R_X86_64_RELATIVE":
            found[fields[0].lstrip("0").lower()] = fields[-1].lower()
            if fields[-1] == "5963650":
                fail("RELATIVE addend names the routine: %s" % line)
    for slot, addend in EXPECTED_SLOTS.items():
        if found.get(slot) != addend:
            fail("slot %s addend mismatch: %s" % (slot, found.get(slot)))
    notes = (PACKET / "relocations.txt").read_text()
    for slot, addend in EXPECTED_SLOTS.items():
        if ("0x" + slot) not in notes or ("0x" + addend) not in notes:
            fail("relocations.txt missing slot %s" % slot)


def frame_ranges():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    ranges = []
    for match in re.finditer(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", text):
        ranges.append((int(match.group(1), 16), int(match.group(2), 16)))
    return ranges


def check_census():
    out = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    rows = (PACKET / "callers.tsv").read_text().splitlines()[1:]
    tsv_calls = {}
    tsv_jumps = {}
    tsv_callers = {}
    for row in rows:
        site, target, caller, kind = row.split("\t")[0:4]
        tsv_callers[site] = caller
        if kind == "call":
            tsv_calls.setdefault(target, []).append(site)
        elif kind == "tail jump":
            tsv_jumps.setdefault(target, []).append(site)
        else:
            fail("unknown callers.tsv kind: %s" % kind)
    for target, want_calls in EXPECTED_CALLS.items():
        match = re.search(
            r"routine %#x: direct calls: (\[.*\])" % target, out)
        if not match:
            fail("census output has no direct-calls list for %#x" % target)
        calls = ast.literal_eval(match.group(1))
        if sorted(calls) != sorted(want_calls):
            fail("census calls mismatch for %#x" % target)
        if sorted(calls) != sorted(tsv_calls.get("%#x" % target, [])):
            fail("callers.tsv calls do not match census for %#x" % target)
        want_jumps = EXPECTED_JUMPS[target]
        match = re.search(
            r"routine %#x: tail jumps: (\[.*\])" % target, out)
        if not match:
            fail("census jumps mismatch for %#x" % target)
        jumps = ast.literal_eval(match.group(1))
        if sorted(jumps) != sorted(want_jumps):
            fail("census jumps mismatch for %#x" % target)
        if sorted(jumps) != sorted(tsv_jumps.get("%#x" % target, [])):
            fail("callers.tsv jumps do not match census for %#x" % target)
        for label, want in (
                ("internal calls", EXPECTED_INTERNAL_CALLS),
                ("internal tail jumps", EXPECTED_INTERNAL_JUMPS),
                ("internal indirect calls", EXPECTED_INTERNAL_INDIRECT_CALLS),
                ("internal indirect tail jumps", EXPECTED_INTERNAL_INDIRECT_JUMPS)):
            match = re.search(
                r"routine %#x: %s: (\[.*\])" % (target, label), out)
            if not match or sorted(ast.literal_eval(match.group(1))) != sorted(want):
                fail("census %s mismatch" % label)
    for target in EXPECTED_CALLS:
        for want in ("routine %#x: stored qwords: []" % target,
                     "routine %#x: RELATIVE addends: 0" % target):
            if want not in out:
                fail("census mismatch, missing %r" % want)
    ranges = frame_ranges()
    for site, caller in tsv_callers.items():
        value = int(site, 16)
        cands = [(a, b) for a, b in ranges if a <= value < b]
        if not cands:
            fail("no enclosing FDE for site %s" % site)
        a, b = min(cands, key=lambda ab: ab[1] - ab[0])
        if caller != "%#x..%#x" % (a, b):
            fail("caller mismatch for %s: %s vs %#x..%#x"
                 % (site, caller, a, b))


def check_records():
    records = json.loads((PACKET / "records.json").read_text())
    if records["task"] != "RE-001":
        fail("records task mismatch")
    if records["target"]["sha256"] != DIGEST:
        fail("records digest mismatch")
    if records["target"]["upstream_main"] != "05bc2de3":
        fail("records base mismatch")
    routine = records["routines"][0]
    if routine["address"] != "0x5963650":
        fail("records routine address mismatch")
    if routine["fde"] != "0x5963650..0x5963739":
        fail("records routine FDE mismatch")
    if routine["size_bytes"] != 233:
        fail("records routine size mismatch")
    census = records["census"]["main"]
    if census["direct_calls"] != 732:
        fail("records census call count mismatch")
    if census["distinct_caller_fdes"] != 580:
        fail("records census caller FDE count mismatch")
    if census["tail_jumps"] != 0 or census["stored_qwords"] != 0 \
            or census["relative_relocations"] != 0:
        fail("records census zero counts mismatch")
    if len(records["internal_transfers"]["main"]) != 4:
        fail("records internal transfer count mismatch")
    for key in ("guard", "zero_size", "plain_dispatch",
                "aligned_dispatch", "success_publication",
                "failure_publication"):
        if key not in records["algorithm"]:
            fail("records algorithm missing %s" % key)


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_alloc_boundary_63650_115.py"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    if "checks pass" not in out:
        fail("model tests did not pass: %s" % out)


def main():
    check_digest()
    check_manifest()
    check_excerpts()
    check_spots()
    check_frames()
    check_relocations()
    check_census()
    check_records()
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
