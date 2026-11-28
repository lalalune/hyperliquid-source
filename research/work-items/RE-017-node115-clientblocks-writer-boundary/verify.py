#!/usr/bin/env python3
"""Verify the #115 ClientBlocks writer's mandatory attachment framing."""
from argparse import ArgumentParser
import hashlib
from pathlib import Path
import sys

PACKET = Path(__file__).resolve().parent
FRAMES = (
    0x5AAA810, 0x4FB65F0, 0x4E055D0, 0x5B56E10, 0x5822260,
    0x5822910, 0x5821F30, 0x4FBAD90, 0x4EFF5F0, 0x4E052F0,
)

WRITER = {
    0x5AAA829: "4883e903",       # input discriminant minus 3
    0x5AAA839: "7457",           # zero selects first tag
    0x5AAA8AE: "41837f0801",     # test error discriminant
    0x5AAA8B3: "0f85be000000",   # selected success arm
    0x5AAA997: "4d8b6720",       # number of outer entries
    0x5AAA9B8: "4d85e4",
    0x5AAA9BB: "0f84b4000000",   # zero skips Client encoding
    0x5AAA9C1: "4d8b7f18",       # first Client entry
    0x5AAA9C5: "49c1e404",       # outer count times 16
    0x5AAA9EC: "4983c710",       # next Client entry
    0x5AAA9F4: "75da",           # next iteration
    0x4FB6667: "7564",           # signature error skips rest
    0x4FB6669: "498d742410",     # header starts at first aggregate +0x10
    0x4FB6684: "755b",           # header error skips rest
    0x4FB6686: "4981c488010000", # proof starts at first aggregate +0x188
    0x4FB66A6: "7539",           # proof error skips attachments
    0x4FB66A8: "498b7708",       # load second owner from entry
    0x4FB66AC: "4883c610",       # vector starts at owner +0x10
    0x4FB66C2: "7556",           # vector error skips success
    0x4E055F5: "c6043000",       # proof absent tag
    0x4E0561E: "c6040101",       # proof present tag
    0x5B56E27: "4c8b6e10",       # mandatory attachment vector count
    0x5B56E48: "4d85ed",
    0x5B56E4B: "0f84d1000000",   # empty vector goes straight to success
    0x5B56E51: "4d8b6708",       # first row
    0x5B56E55: "4a8d04ad00000000",
    0x5B56E5D: "4c01e8",
    0x5B56E60: "498d1cc4",       # end = start + 8 * 5 * count
    0x5B56EA0: "49037618",       # destination = buffer plus cursor
    0x5B56EA4: "4889f7",
    0x5B56EA7: "4c89fe",         # source is blob data
    0x5B56EAA: "4889ea",         # amount passed to copy
    0x5B56EAD: "ff1555869800",   # copy at linked memcpy slot
    0x5B56EB7: "4801ee",         # amount added to cursor
    0x5B56EBE: "4983c428",       # physical row stride
    0x5B56EC5: "745b",
    0x5B56EE0: "4d8b7c2420",     # row's blob owner
    0x5B56EE5: "498b6f20",       # blob length
    0x5B56EF0: "4889ea",         # encode length as U64
    0x5B56F03: "4d8b7f18",       # blob data pointer
    0x5B56F22: "488b5c2408",
    0x5B56F27: "48c70308000000", # successful vector encoding
    0x5822280: "410f1001",       # first half of hash
    0x5822284: "410f104910",     # second half of hash
    0x5822292: "4883c620",       # raw hash write advances 32
    0x5821F38: "8b1e",           # compact U32 loads tag
    0x5821F3A: "81fbfb000000",
    0x5821F54: "881c31",         # compact U32 direct byte
    0x5822915: "4881fafb000000", # compact U64 direct-byte cutoff
    0x582292F: "881401",         # compact U64 direct byte
    0x5822957: "41c60400fb",     # compact U64 u16 marker
    0x5822970: "6641891400",     # compact U64 u16 body
}

READER = {
    0x4EFF622: "85c0",           # replay Block alternative tests zero
    0x4EFF624: "0f84a6000000",
    0x4E05335: "0fb602",         # replay reads an additional raw byte
    0x4E05338: "48ffc2",
    0x4E05346: "85c0",           # option zero ends without consuming a vector
    0x4E05348: "0f8491000000",
    0x4E0534E: "83f801",         # only option one admits the child
    0x4E05351: "0f859a000000",
}

CALLS = {
    0x5AAA89F: 0x5821F30,
    0x5AAA984: 0x5821F30,
    0x5AAA9A5: 0x5822910,
    0x5AAA9D9: 0x4FB65F0,
    0x4FB6659: 0x59681D0,
    0x4FB6676: 0x5967060,
    0x4FB6698: 0x4E055D0,
    0x4FB66B8: 0x5B56E10,
    0x4E05634: 0x5829210,
    0x4E05656: 0x5966A30,
    0x5B56E37: 0x5822910,
    0x5B56ED0: 0x5822260,
    0x5B56EF3: 0x5822910,
    0x4FBADAD: 0x4FB7760,
    0x4FBAED0: 0x5824840,
    0x4EFF60C: 0x5821150,
    0x4EFF6DB: 0x4FB7760,
    0x4EFF82F: 0x4E052F0,
    0x4E05366: 0x5824840,
}

LEAS = {
    0x5AAA892: ("488d35", 0x459E6C),
    0x5AAA977: ("488d35", 0x459E6C),
    0x4FBAEC1: ("488d15", 0x4E04E90),
    0x4E0535A: ("488d15", 0x4E04E90),
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def edge(raw, va, opcode, expected):
    result = va + len(raw) + int.from_bytes(raw[-4:], "little", signed=True)
    require(raw[:-4] == bytes.fromhex(opcode) and result == expected,
            f"{va:#x} expected {opcode} edge to {expected:#x}")


def verify(instructions):
    for va, encoding in (WRITER | READER).items():
        require(instructions[va] == bytes.fromhex(encoding), f"{va:#x} instruction changed")
    for va, target in CALLS.items():
        edge(instructions[va], va, "e8", target)
    for va, (opcode, target) in LEAS.items():
        edge(instructions[va], va, opcode, target)


def controls(instructions):
    for name, va, index, value in (
        ("different mandatory count slot", 0x5B56E27, 3, 0x08),
        ("different attachment row stride", 0x5B56EBE, 3, 0x30),
        ("redirect attachment encoder", 0x4FB66B8, 1, 0x00),
        ("different replay present tag", 0x4E0534E, 2, 0x02),
    ):
        changed = bytearray(instructions[va])
        changed[index] = value
        require(bytes(changed) != instructions[va], f"Control {name} has no mutation")
        try:
            verify(instructions | {va: bytes(changed)})
        except ValueError:
            print(f"PASS control: {name} rejected")
        else:
            raise ValueError(f"Control {name} escaped")


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=PACKET.parents[2])
    args = parser.parse_args()
    sys.path.insert(0, str(args.repo.resolve() / "tools"))
    from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

    data = (args.repo / TARGET).read_bytes()
    require(hashlib.sha256(data).hexdigest() == TARGET_SHA256, "Unexpected #115 image digest")
    sections = {entry["name"]: entry for entry in parse_sections(data)}

    def at(section_name, address, length):
        section = sections[section_name]
        delta = address - section["va"]
        require(0 <= delta <= delta + length <= section["size"], f"{address:#x} outside {section_name}")
        offset = section["offset"] + delta
        return data[offset:offset + length]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(at(".eh_frame", frame["va"], frame["size"]), frame["va"])
    ends = {item["entry"]: item["end"] for item in fdes}
    bounds = [(start, ends[start]) for start in FRAMES]
    print(f"target={TARGET} sha256={TARGET_SHA256} size={len(data)}")
    print(f"Python {sys.version.split()[0]}")
    for start, end in bounds:
        print(f"FDE {start:#x}..{end:#x}")
    constant = at(".rodata", 0x459E6C, 4)
    require(constant == bytes(4), "Unexpected outer tag constant")
    print(f".rodata 0x459e6c = {constant.hex(' ')}")
    checked = {}
    for va, raw in sorted((WRITER | READER | dict.fromkeys(CALLS, "e800000000") |
                           dict.fromkeys(LEAS, "488d3500000000")).items()):
        length = len(bytes.fromhex(raw))
        require(any(start <= va < va + length <= end for start, end in bounds), "Anchor outside FDEs")
        checked[va] = at(".text", va, length)
        print(f".text {va:#x}  {checked[va].hex(' ')}")
    verify(checked)
    controls(checked)
    print(f"PASS: {len(checked)} instructions across {len(bounds)} FDEs")
    print("PASS: ClientBlocks emits mandatory U64 attachment count; replay reads a separate option first")


if __name__ == "__main__":
    main()
