"""Pre-Rust decimal-string threshold oracle for the complete parser projection."""
import datetime
import gzip
import hashlib
import itertools
import json
from pathlib import Path
import random
import struct
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, __version__ as capstone_version

TARGET = ROOT / "artifacts/node/94/hl-node"
TARGET_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
START, END, MAX = 0x54307c0, 0x5430857, 2**64 - 1
SITES = [0x514b3d4, 0x514cc4e, 0x514dd13, 0x514ebcf, 0x5154289,
         0x529ec1f, 0x529ecd0, 0x529ee36, 0x529eea8, 0x529f127]
LOCK_SHA = "df51c802968a65234b5451a90abfcbf22c1df4f3df8285db2519463239706963"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def mapping(data):
    secs = sections(data)

    def offset(va, size):
        found = [s for s in secs if s["type"] != 8 and s["address"] <= va
                 and va + size <= s["address"] + s["size"]]
        require(len(found) == 1, "VA mapping is not unique")
        return found[0]["offset"] + va - found[0]["address"]

    return secs, offset


def structure(data):
    require(digest(PACKET / "static-lock.json") == LOCK_SHA, "Static lock changed")
    contract = json.loads((PACKET / "static-lock.json").read_text())
    secs, offset = mapping(data)
    read = lambda va, size: data[offset(va, size):offset(va, size) + size]
    bodies = []
    for item in contract:
        start, end = item["start"], item["end"]
        raw = read(start, end - start)
        require(hashlib.sha256(raw).hexdigest() == item["body_sha256"], "Complete body changed")
        for name, record in item["frames"].items():
            encoded = bytes.fromhex(record["hex"])
            require(read(record["va"], len(encoded)) == encoded, "FDE/CIE changed")
        fde, cie = item["frames"]["fde"], item["frames"]["cie"]
        encoded = bytes.fromhex(fde["hex"])
        pc = fde["va"] + 8 + struct.unpack_from("<i", encoded, 8)[0]
        extent = struct.unpack_from("<I", encoded, 12)[0]
        require((pc, pc + extent) == (start, end), "FDE extent changed")
        require(fde["va"] + 4 - struct.unpack_from("<I", encoded, 4)[0] == cie["va"], "CIE pointer changed")
        decoded = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(raw, start))
        require(b"".join(i.bytes for i in decoded) == raw, "Incomplete linear decode")
        rows = [{"va": hex(i.address), "hex": i.bytes.hex(), "mnemonic": i.mnemonic,
                 "operands": i.op_str} for i in decoded]
        if start == START:
            require(end == END and not any(i.mnemonic == "call" for i in decoded), "Leaf closure changed")
            for insn in decoded:
                if insn.mnemonic.startswith("j"):
                    require(START <= int(insn.op_str, 16) < END, "Branch escapes leaf")
        else:
            sites = {i.address: i for i in decoded}
            for site in item["sites"]:
                require(sites[site].mnemonic == "call" and sites[site].op_str == hex(START), "Caller edge changed")
        bodies.append({**item, "instructions": rows})
    require(read(END, 9) == b"\xcc" * 9, "Leaf padding changed")
    relocation_count = 0
    for section in secs:
        if section["name"].startswith(".rela."):
            require(section["size"] % 24 == 0, "Malformed RELA extent")
            for _, _, addend in struct.iter_unpack("<QQq", read(section["address"], section["size"])):
                require(addend != START, "Unexpected naming relocation")
                relocation_count += 1
    text = next(s for s in secs if s["name"] == ".text")
    code, direct, pos = read(text["address"], text["size"]), [], 0
    while (pos := code.find(b"\xe8", pos)) >= 0:
        if pos + 5 <= len(code) and text["address"] + pos + 5 + struct.unpack_from("<i", code, pos + 1)[0] == START:
            direct.append(text["address"] + pos)
        pos += 1
    require(direct == SITES, "Direct caller scan changed")
    return {"target_sha256": TARGET_SHA, "bodies": bodies, "direct_e8_sites": [hex(x) for x in direct],
            "relocation_records": relocation_count, "naming_relocations": 0,
            "text_scan_bytes": len(code), "capstone_version": capstone_version,
            "static_lock_sha256": LOCK_SHA,
            "prior_evidence_sha256": digest(ROOT / "research/work-items/foundation-decimal-index-replace-94/evidence.json")}


def admit():
    raw = TARGET.read_bytes()
    require(len(raw) == 91774280 and hashlib.sha256(raw).hexdigest() == TARGET_SHA, "Target identity changed")
    return structure(raw)


def expected(zeroes, tail, previous):
    """Lexical significant-digit bounds, without a multiply-add parser loop."""
    total = zeroes + len(tail)
    if total > MAX:
        return "length"
    end = next((i for i, byte in enumerate(tail) if byte not in b"0123456789"), len(tail))
    digits = tail[:end]
    significant = digits.lstrip(b"0")
    first_nonzero = len(digits) - len(significant)
    overflow = None
    if len(significant) >= 20:
        if significant[:20] > b"18446744073709551615":
            overflow = first_nonzero + 19
        elif len(significant) > 20:
            overflow = first_nonzero + 20
    if overflow is not None:
        consumed, output, wrote, rax = zeroes + overflow, previous, 0, 0
    else:
        consumed = zeroes + end
        output = int(significant) if significant else 0
        wrote = 1
        if end < len(tail):
            low_count = consumed % 2**32
            positive_signed_count = 0 < low_count < 2**31
            rax = (0xffffff00 if tail[end] >= 128 else 0) + int(positive_signed_count)
        else:
            rax = int(total != 0)
    return "ok:" + ",".join(f"{x:016x}" for x in (rax, consumed, total - consumed, output, wrote))


def fixture_bytes():
    cases = set()
    counts = (0, 1, 2, 2**31 - 2, 2**31 - 1, 2**31, 2**31 + 1,
              2**32 - 2, 2**32 - 1, 2**32, 2**32 + 1, MAX - 64, MAX)
    rng = random.Random(0x54307c0)

    def include(zeroes, tail, outputs=(0x0123456789abcdef,)):
        for previous in outputs:
            cases.add((zeroes, bytes(tail), previous))

    for first in range(256):
        for second in range(256):
            include(0, bytes((first, second)))
        for count in counts:
            include(count, bytes((first,)), (0, MAX))
    for count in counts:
        for tail in (b"", b"0", b"00", b"000A", b"000\xff", b"9\x80", b"10X"):
            include(count, tail, (0, MAX))
    for value in range(MAX - 100, MAX + 101):
        decimal = str(value).encode()
        for count in counts[:-1]:
            for suffix in (b"", b"X", b"\xff", b"0", b"9"):
                include(count, decimal + suffix, (0, MAX))
    for width in range(5):
        for symbols in itertools.product(b"019A\xff", repeat=width):
            include(0, bytes(symbols))
    for _ in range(4096):
        tail = bytes(rng.choice(b"00000123456789A\xff\x80") for _ in range(rng.randrange(81)))
        include(rng.choice(counts), tail, (rng.randrange(2**64),))
    for count in (MAX - 2, MAX - 1, MAX):
        for tail in (b"", b"0", b"00", b"000", b"X", b"\xff"):
            include(count, tail, (0, MAX))
    inputs, outputs = [], []
    coverage = {"cases": len(cases), "length_refusal": 0, "output_not_written": 0,
                "nondigit_high_rax": 0, "rax_zero": 0, "rax_one": 0,
                "compressed_zero_prefix_cases": 0, "random_seed": "0x54307c0"}
    for zeroes, tail, previous in sorted(cases):
        inputs.append(f"{zeroes:016x}\t{previous:016x}\t{tail.hex() or '-'}")
        result = expected(zeroes, tail, previous); outputs.append(result)
        coverage["compressed_zero_prefix_cases"] += int(zeroes != 0)
        if result == "length":
            coverage["length_refusal"] += 1
        else:
            rax, _, _, _, wrote = (int(x, 16) for x in result[3:].split(","))
            coverage["output_not_written"] += int(wrote == 0)
            coverage["nondigit_high_rax"] += int(rax > 1)
            coverage["rax_zero"] += int(rax == 0)
            coverage["rax_one"] += int(rax == 1)
    return (("\n".join(inputs) + "\n").encode(), ("\n".join(outputs) + "\n").encode(), coverage)


def freeze():
    require(not (ROOT / "src/node94-decimal-u64-parser").exists(), "Rust already exists")
    folder = PACKET / "frozen"
    require(not (folder / "ORACLE-FREEZE.json").exists(), "Freeze already exists")
    facts = admit(); inputs, output, coverage = fixture_bytes()
    for name, raw in (("inputs.tsv", inputs), ("expected.txt", output)):
        (folder / (name + ".gz")).write_bytes(gzip.compress(raw, mtime=0))
    record = {"frozen_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "source_base_commit": "56c0ec672bd8fdcfaa80f2db700a61e6240b3663",
              "rust_source_present": False, "oracle_source_sha256": digest(__file__),
              "inputs_sha256": hashlib.sha256(inputs).hexdigest(),
              "expected_sha256": hashlib.sha256(output).hexdigest(), "coverage": coverage,
              "static_facts": facts}
    (folder / "ORACLE-FREEZE.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"oracle_source_sha256": record["oracle_source_sha256"], "coverage": coverage}, indent=2))


if __name__ == "__main__":
    freeze()
