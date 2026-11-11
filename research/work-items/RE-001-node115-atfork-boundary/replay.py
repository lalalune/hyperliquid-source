#!/usr/bin/env python3
"""Static, digest-bound atfork registration evidence. Never executes the target."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BASE = "05bc2de303c05525b71e7e257426e741bc66a390"
TARGET = Path("artifacts/node/115/hl-node")
HERE = Path(__file__).resolve().parent
FDE_RANGES = [(0x634f0b0, 0x634f8d5), (0x634f910, 0x634fd81),
              (0x634fd90, 0x634ffca), (0x634ffd0, 0x635020a),
              (0x63f09f0, 0x63f0a00)]
WINDOWS = [(0x634f33c, 0x634f36b), (0x634f5c0, 0x634f5de),
           (0x63f09f0, 0x63f0a00), (0x63f1b90, 0x63f1ba0)]

def require(ok, message):
    if not ok:
        raise ValueError(message)

def decode_boundary(caller, stub, plt, failure):
    """Decode only established instruction forms, rejecting other forms."""
    require(len(caller) == 47 and len(stub) == 16 and len(plt) == 16
            and len(failure) == 30, "window sizes")
    callbacks = []
    for i, prefix in [(0, b"\x48\x8d\x15"), (7, b"\x48\x8d\x35"),
                      (14, b"\x48\x8d\x3d")]:
        require(caller[i:i+3] == prefix, "callback LEA opcode")
        callbacks.append(0x634f33c + i + 7 + struct.unpack_from("<i", caller, i+3)[0])
    require(callbacks == [0x634ffd0, 0x634fd90, 0x634f910], "callback coordinates")
    require(caller[21] == 0xe8, "registration call opcode")
    call_target = 0x634f356 + struct.unpack_from("<i", caller, 22)[0]
    require(call_target == 0x63f09f0, "registration call target")
    require(caller[26:30] == b"\x85\xc0\x0f\x85", "test eax / jne")
    nonzero = 0x634f35e + struct.unpack_from("<i", caller, 30)[0]
    require(nonzero == 0x634f5c0, "nonzero edge")
    require(caller[34] == 0xe8, "zero successor call opcode")
    zero_call = 0x634f363 + struct.unpack_from("<i", caller, 35)[0]
    require(zero_call == 0x6369dc0, "zero successor call")
    require(stub[:7] == b"\xf3\x0f\x1e\xfa\x48\x8b\x0d" and stub[11] == 0xe9,
            "stub opcodes")
    dso_slot = 0x63f09fb + struct.unpack_from("<i", stub, 7)[0]
    plt_va = 0x63f0a00 + struct.unpack_from("<i", stub, 12)[0]
    require(dso_slot == 0x64efa20 and plt_va == 0x63f1b90, "stub operands")
    require(plt[:2] == b"\xff\x25", "PLT indirect jump")
    got = 0x63f1b96 + struct.unpack_from("<i", plt, 2)[0]
    require(got == 0x64eea18, "PLT relocation slot")
    require(failure[:3] == b"\x48\x8d\x3d" and failure[7] == 0xe8,
            "nonzero successor opcodes")
    diagnostic = 0x634f5c7 + struct.unpack_from("<i", failure, 3)[0]
    helper = 0x634f5cc + struct.unpack_from("<i", failure, 8)[0]
    require(diagnostic == 0x95ac10 and helper == 0x63be670, "nonzero successor operands")
    return {"rdi": hex(callbacks[2]), "rsi": hex(callbacks[1]), "rdx": hex(callbacks[0]),
            "call_target": hex(call_target), "nonzero": hex(nonzero),
            "zero_successor": "0x634f35e", "zero_call_target": hex(zero_call),
            "dso_slot": hex(dso_slot), "plt": hex(plt_va), "got": hex(got),
            "diagnostic": hex(diagnostic), "diagnostic_helper": hex(helper)}

def collect(target=TARGET):
    data = Path(target).read_bytes()
    require(hashlib.sha256(data).hexdigest() == DIGEST, "target digest")
    require(data[:6] == b"\x7fELF\x02\x01", "ELF64 little-endian")
    require(struct.unpack_from("<H", data, 18)[0] == 62, "x86-64")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    ents, num = struct.unpack_from("<HH", data, 54)
    loads = [struct.unpack_from("<IIQQQQQQ", data, phoff + i*ents) for i in range(num)]
    loads = [x for x in loads if x[0] == 1]
    def offset(va, size):
        matches = [x[2] + va - x[3] for x in loads if x[3] <= va and va+size <= x[3]+x[5]]
        require(len(matches) == 1, "unique file-backed PT_LOAD mapping")
        return matches[0]
    def chunk(va, size):
        off = offset(va, size)
        return data[off:off+size]
    chunks = [chunk(a, z-a) for a, z in WINDOWS]
    semantics = decode_boundary(chunks[0], chunks[2], chunks[3], chunks[1])
    def run(argv):
        result = subprocess.run(argv, check=True, capture_output=True, text=True)
        return result.stdout
    frames = run(["readelf", "-wf", str(target)])
    fdes = []
    for a, z in FDE_RANGES:
        lines = [l for l in frames.splitlines() if re.search(r"pc=0*"+f"{a:x}"+r"\.\.0*"+f"{z:x}"+r"$", l)]
        require(len(lines) == 1, "exact FDE")
        fdes.append({"start": hex(a), "end_exclusive": hex(z), "raw": lines[0]})
    relocations = run(["readelf", "-Wr", str(target)])
    lines = [l for l in relocations.splitlines() if l.startswith("00000000064eea18 ")]
    require(len(lines) == 1 and "R_X86_64_JUMP_SLOT" in lines[0]
            and " __register_atfork@GLIBC_2.3.2 + 0" in lines[0], "import relocation")
    windows = []
    for (a, z), raw in zip(WINDOWS, chunks):
        dis = run(["objdump", "-d", "-M", "intel", f"--start-address={a}", f"--stop-address={z}", str(target)])
        windows.append({"start": hex(a), "end_exclusive": hex(z), "file_offset": hex(offset(a,z-a)),
                        "hex": raw.hex(), "disassembly": dis})
    off = offset(0x95ac10, 1)
    end = data.find(b"\0", off, off+256)
    require(end >= off, "bounded diagnostic terminator")
    return {"target_sha256": DIGEST, "source_revision": BASE, "target": str(target),
            "tool_versions": {t: run([t,"--version"]).splitlines()[0] for t in ["readelf","objdump"]},
            "windows": windows, "fdes": fdes, "import_relocation": lines[0],
            "diagnostic_text": data[off:end].decode("ascii"), "semantics": semantics,
            "denominator": {"selected_callers": 1, "callback_arguments": 3, "exact_fdes": 5,
                            "bounded_code_bytes": sum(z-a for a,z in WINDOWS)},
            "target_executed": False, "completion_gate_requested": False}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="regenerate reviewed packet")
    args = parser.parse_args()
    actual = collect()
    packet = HERE / "records.json"
    if args.write:
        packet.write_text(json.dumps(actual, indent=2)+"\n")
    else:
        require(actual == json.loads(packet.read_text()), "packet replay mismatch")
    print(json.dumps({"result": "static packet generated" if args.write else "static replay passed",
                      "diagnostic_text": actual["diagnostic_text"], **actual["denominator"]}))

if __name__ == "__main__":
    main()
