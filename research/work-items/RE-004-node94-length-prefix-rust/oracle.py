"""Pre-Rust arithmetic/memory-map oracle; never executes captured code."""
import datetime
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections
import foundation_length_prefix_encoder as prior
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, __version__ as capstone_version

MAX = 2**64 - 1


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
    secs, offset = mapping(data)
    read = lambda va, size: data[offset(va, size):offset(va, size) + size]
    eh = next(s for s in secs if s["name"] == ".eh_frame")
    require(read(eh["address"], len(prior.CIE)) == prior.CIE, "CIE changed")
    frames = []
    for relative, raw, start, end in (
        (0x2d14c4, prior.FDE, prior.START, prior.END),
        (0x2d1784, prior.CALLER_FDE, prior.CALLER_START, prior.CALLER_END),
    ):
        record = read(eh["address"] + relative, len(raw))
        require(record == raw, "FDE bytes changed")
        pc = eh["address"] + relative + 8 + struct.unpack_from("<i", record, 8)[0]
        extent = struct.unpack_from("<I", record, 12)[0]
        require((pc, pc + extent) == (start, end), "FDE extent changed")
        require(eh["address"] + relative + 4 - struct.unpack_from("<I", record, 4)[0]
                == eh["address"], "FDE CIE pointer changed")
        frames.append({"offset": hex(relative), "start": hex(start), "end": hex(end),
                       "record_hex": record.hex()})
    body = read(prior.START, prior.END - prior.START)
    caller = read(prior.CALLER_START, prior.CALLER_END - prior.CALLER_START)
    require(body == prior.BODY, "Complete leaf body changed")
    require(read(prior.END, 6) == b"\xcc" * 6, "Leaf padding changed")
    require(hashlib.sha256(caller).hexdigest() ==
            "45c7006af26165d8ac3e748a3ea6f52bc4865d6fe2649f9eda304dd207eb52b7",
            "Complete caller body changed")
    rows = []
    for start, raw in ((prior.START, body), (prior.CALLER_START, caller)):
        decoded = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(raw, start))
        require(b"".join(i.bytes for i in decoded) == raw, "Incomplete linear decode")
        rows.append([{"va": hex(i.address), "hex": i.bytes.hex(), "mnemonic": i.mnemonic,
                      "operands": i.op_str} for i in decoded])
    sites = {int(r["va"], 16): r for r in rows[1]}
    require(sites[prior.CALL_SITE]["mnemonic"] == "call" and
            sites[prior.CALL_SITE]["operands"] == hex(prior.START), "Caller edge changed")
    return {"target_sha256": prior.SHA256, "body_sha256": hashlib.sha256(body).hexdigest(),
            "caller_sha256": hashlib.sha256(caller).hexdigest(), "frames": frames,
            "capstone_version": capstone_version, "leaf": rows[0], "caller": rows[1],
            "prior_evidence_sha256": digest(ROOT / "research/work-items/foundation-length-prefix-encoder-94/evidence.json"),
            "prior_checker_sha256": digest(ROOT / "tools/foundation_length_prefix_encoder.py")}


def admit():
    raw = prior.TARGET.read_bytes()
    require(len(raw) == 91774280 and hashlib.sha256(raw).hexdigest() == prior.SHA256,
            "Target identity changed")
    return structure(raw)


def expected(length, initial, source):
    """Integer base-256 digits and a finite memory-map substitution.

    No register, instruction, machine-code or flag evaluation is performed.
    Unbounded integers make discarded bits irrelevant by quotient/remainder.
    """
    require(0 <= length <= MAX, "Length outside u64")
    if length < 32:
        header, width, total = 8 * length + 1, 1, 2
    elif length < 4096:
        header, width, total = 16 * length + 5, 2, 3
    else:
        header, width, total = 16 * length + 13, 4, 4
    if len(initial) < total:
        return "short:" + initial.hex()
    mode, value = source
    if mode == "o" and value >= len(initial):
        return "index:" + initial.hex()
    memory = {i: byte for i, byte in enumerate(initial)}
    header_digits = {i: (header // (256**i)) % 256 for i in range(width)}
    memory.update(header_digits)
    payload = value if mode == "e" else memory[value]
    memory[total - 1] = payload
    return f"ok:{total}:" + bytes(memory[i] for i in range(len(initial))).hex()


def fixture_bytes():
    lengths = set(range(66)) | {4094, 4095, 4096, 4097, MAX}
    for bit in range(64):
        for d in (-2, -1, 0, 1, 2):
            if 0 <= 2**bit + d <= MAX:
                lengths.add(2**bit + d)
    # Byte transitions and all bits that can affect the aliased fourth byte.
    for q in range(256):
        lengths.add(4096 + q * 2**20)
    state = 0x76D94C15A30B8E21
    for _ in range(1024):
        state = (state * 6364136223846793005 + 1442695040888963407) % 2**64
        lengths.add(state)
    rows = set()
    for length in sorted(lengths):
        # All short-buffer sizes and valid/invalid output aliases, including
        # bytes after the written prefix and the third path's fourth byte.
        for size in (0, 1, 2, 3, 4, 5, 8):
            initial = bytes((37 * i + length + size * 19) % 256 for i in range(size))
            for value in {0, 1, 2, 3, size - 1, size, size + 1}:
                if value >= 0:
                    rows.add((length, initial, "o", value))
            rows.add((length, initial, "e", 0xA6))
    for length in (0, 31, 32, 4095, 4096, 0xFFFFFF, 0x1000000, 0xFFFFFFFF,
                   0x100000000, 0x100000001, 2**63, MAX):
        for byte in range(256):
            rows.add((length, b"\xf1\xe2\xd3\xc4\xb5\xa6\x97\x88", "e", byte))
    inputs, answers, totals = [], [], {"ok:2": 0, "ok:3": 0, "ok:4": 0, "short": 0, "index": 0}
    for length, initial, mode, value in sorted(rows):
        inputs.append(f"{length:016x}\t{initial.hex() or '-'}\t{mode}:{value:x}\n")
        answer = expected(length, initial, (mode, value))
        answers.append(answer + "\n")
        key = ":".join(answer.split(":")[:2]) if answer.startswith("ok:") else answer.split(":")[0]
        totals[key] += 1
    coverage = {"cases": len(rows), "distinct_lengths": len(lengths), "results": totals,
                "boundary_lengths": "0..65;4094..4097;2^k+[-2,2] for k0..63;MAX",
                "source_classes": "external all256 at12 edges; aliases header/payload/tail/outside",
                "initial_sizes": [0, 1, 2, 3, 4, 5, 8], "seed": "0x76d94c15a30b8e21"}
    return "".join(inputs).encode(), "".join(answers).encode(), coverage


def freeze():
    require(not (ROOT / "src/node94-length-prefix/lib.rs").exists(), "Rust already exists; cannot prefreeze")
    destination = PACKET / "frozen"
    require(not (destination / "ORACLE-FREEZE.json").exists(), "Freeze already exists")
    facts = admit()
    inputs, expected_rows, coverage = fixture_bytes()
    for name, raw in (("inputs.tsv", inputs), ("expected.txt", expected_rows)):
        (destination / (name + ".gz")).write_bytes(gzip.compress(raw, mtime=0))
    record = {"created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "authorship_order": "Arithmetic/memory-map oracle and these fixtures frozen before new Rust source existed",
              "oracle_source_sha256": digest(__file__), "static_facts": facts,
              "inputs_sha256": hashlib.sha256(inputs).hexdigest(),
              "expected_sha256": hashlib.sha256(expected_rows).hexdigest(), "coverage": coverage}
    (destination / "ORACLE-FREEZE.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(coverage, indent=2))


if __name__ == "__main__":
    freeze()
