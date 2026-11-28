#!/usr/bin/env python3
"""Check #115 signature view construction and compile an independent layout control."""
from argparse import ArgumentParser
import hashlib
import importlib.util
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

PACKET = Path(__file__).resolve().parent
BASE = "RE-008-node115-consensus-bincode-encode-byte-matches"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BASE_SOURCE = "97ef9999c6ae6e426679746f81c2fa46088b29666a9fd936b0245517f201aca0"
BASE_VERIFIER = "1aea7a078d75df5145779e96c5624e4a0851de1788b32926376195996a35a6fa"
ENCODER = 0x59681D0
END = 0x5968332
RECOVERY = 0x59682C7
BRANCH_END = 0x59682CF
VARINT = 0x5822910
LE = "little"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(command, root):
    return subprocess.check_output(command, cwd=root, text=True)


def evidence(repo):
    binary = repo / "artifacts/node/115/hl-node"
    contents = binary.read_bytes()
    require(sha(contents) == DIGEST, "Wrong #115 artifact")
    print(f"target=artifacts/node/115/hl-node sha256={DIGEST} bytes={len(contents)}")

    baseline = repo / "research/work-items" / BASE
    source = (baseline / "consensus_encode.rs").read_bytes()
    verifier = baseline / "verify.py"
    require(sha(source) == BASE_SOURCE, "Baseline source changed")
    require(sha(verifier.read_bytes()) == BASE_VERIFIER, "Baseline ELF parser changed")
    spec = importlib.util.spec_from_file_location("consensus_baseline", verifier)
    elf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(elf)
    va, offset, size = elf.parse_elf_sections(contents)[".text"]

    def at(start, length):
        delta = start - va
        require(0 <= delta and delta + length <= size, "Outside target .text")
        return contents[offset + delta:offset + delta + length]

    def direct_call(address, target):
        instruction = at(address, 5)
        require(instruction[0] == 0xe8, f"{address:#x}: missing direct call")
        actual = address + 5 + int.from_bytes(instruction[1:], LE, signed=True)
        require(actual == target, f"{address:#x}: call target {actual:#x}")
        print(f"{address:#x} {instruction.hex(' ')}   call {actual:#x}")

    relative_binary = binary.relative_to(repo)
    print(run(["llvm-objdump", "--version"], repo).splitlines()[1].strip())
    print("llvm-dwarfdump --eh-frame artifacts/node/115/hl-node")
    frames = run(["llvm-dwarfdump", "--eh-frame", relative_binary], repo)
    fdes = ((0x4FB65F0, 0x4FB672D), (0x5829210, 0x58292B7), (ENCODER, END))
    for start, end in fdes:
        match = re.search(rf"^.* FDE .*pc=0*{start:x}\.\.\.0*{end:x}$", frames, re.M)
        require(match is not None, f"Missing FDE {start:#x}..{end:#x}")
        print(match[0])

    # Exact register and stack-lane anchors prove a pointer taken from the same
    # aggregate as the copied 64 bytes in each distinct caller.
    anchors = {
        0x4FB6607: "4c8b26",
        0x4FB660A: "498d842480010000",
        0x4FB6612: "410f10842440010000",
        0x4FB661B: "410f108c2450010000",
        0x4FB6624: "0f294c24300f29442420",
        0x4FB662E: "410f10842460010000",
        0x4FB6637: "410f108c2470010000",
        0x4FB6640: "0f294424400f294c2450",
        0x4FB664A: "4889442460",
        0x4FB6654: "488d742420",
        0x4FB6663: "4883f8087564",
        0x5829222: "488d8670010000",
        0x5829229: "0f108630010000",
        0x5829230: "0f108e40010000",
        0x5829237: "0f294c24100f290424",
        0x5829240: "0f108650010000",
        0x5829247: "0f108e60010000",
        0x582924E: "0f294424200f294c2430",
        0x5829258: "4889442440",
        0x5829262: "4889e6",
        0x582926A: "837c245008751d",
        RECOVERY: "498b4424400fb628",
        0x59682CF: "498b762049397610743b",
        0x59682D9: "498b461840882c3048ffc649897620",
    }
    for address, expected in anchors.items():
        data = bytes.fromhex(expected)
        require(at(address, len(data)) == data, f"Instruction mismatch at {address:#x}")
    for address, target in ((0x4FB6659, ENCODER), (0x5829265, ENCODER),
                            (0x4FB6676, 0x5967060), (0x582927A, 0x5967060),
                            (0x5968327, 0x5963A10)):
        direct_call(address, target)

    for start, end in ((0x4FB6607, 0x4FB667B), (0x5829222, 0x582927F), (RECOVERY, END)):
        command = ["llvm-objdump", "-d", "--x86-asm-syntax=intel", f"--start-address={start:#x}",
                   f"--stop-address={end:#x}", str(relative_binary)]
        print(" ".join(command))
        print(run(command, repo).rstrip())
    return elf, source, at(ENCODER, END - ENCODER), direct_call


def compile_controls(repo, rustc, elf, source, target, direct_call):
    sys.path.insert(0, str(repo / "tools"))
    from byte_progress import compare

    version = run([rustc, "--version"], repo).strip()
    require(version.startswith("rustc 1.95.0 "), "Use rustc 1.95.0")
    print(version)
    flags = [
        "--target=x86_64-unknown-linux-gnu", "--edition=2021", "--crate-type=rlib",
        "--crate-name", "cs_bincode_enc", "-C", "opt-level=3", "-C", "overflow-checks=yes",
        "-C", "relocation-model=pie", "-C", "lto=off", "--emit=obj",
    ]
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        (work / "candidate.rs").write_bytes(source + b"\n" + (PACKET / "signature_vec.rs").read_bytes())
        for name, cfg in (("borrowed", []), ("inline control", ["--cfg", "inline_recovery"])):
            command = [rustc, *flags, *cfg, "-o", "candidate.o", "candidate.rs"]
            print(" ".join([Path(rustc).name, *command[1:]]))
            run(command, work)
            obj = (work / "candidate.o").read_bytes()
            sections = elf.parse_elf_sections(obj)
            section, = (key for key in sections if key.startswith(".text.") and "encode_signature_view" in key)
            _, offset, size = sections[section]
            code = obj[offset:offset + size]
            relocations = elf.parse_relocations(obj, sections, ".rela" + section)
            bound = BRANCH_END - ENCODER
            prefix_relocations = [row for row in relocations if row["offset"] < bound]
            require(len(prefix_relocations) == 8, "Wrong varint relocation count")
            symtab = elf.parse_symtab(obj)
            _, reloc_off, reloc_size = sections[".rela" + section]
            for i in range(reloc_off, reloc_off + reloc_size, 24):
                operand, info, _ = struct.unpack_from("<QQq", obj, i)
                if operand >= bound:
                    continue
                require("w_u64_vec" in symtab[info >> 32] and code[operand - 1] == 0xe8,
                        "Compiled relocation does not reference the expected varint stand-in")
            call_vas = [ENCODER + row["offset"] - 1 for row in prefix_relocations]
            for address in call_vas:
                direct_call(address, VARINT)

            result = compare(code[:bound], target[:bound], prefix_relocations)
            print(f"{name}: compiled_bytes={size} target_fde_bytes={len(target)} prefix_bytes={bound} "
                  f"raw_equal={result['raw_equal_bytes']} "
                  f"equal_non_relocation={result['equal_non_relocation_bytes']}/{result['non_relocation_bytes']}")
            print(f"{name}: PLT operand offsets={[hex(row['offset']) for row in prefix_relocations]} "
                  f"non-relocation differences={[hex(off) for off in result['non_relocation_difference_offsets']]}")
            start = RECOVERY - ENCODER
            print(f"{name}: code at function +{start:#x}: {code[start:bound].hex(' ')}")
            borrowed_tail = bytes.fromhex("498b4424400fb628")
            require((code[start:bound] == borrowed_tail) == (name == "borrowed"),
                    "Borrowed/inline recovery discriminator failed")
            if name == "borrowed":
                require(len(code) != len(target), "Re-evaluate the complete FDE claim")
                require(result["non_relocation_difference_offsets"] == [0x31, 0x4f, 0x6d, 0x8b, 0xa8,
                                                                        0xc2, 0xdc, 0xf6],
                        "Unexpected mismatch outside guard branch displacements")
    print("PASS: both callers build a borrowed recovery byte view; inline control rejects that shape")


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=PACKET.parents[2])
    parser.add_argument("--rustc", default="rustc")
    args = parser.parse_args()
    root = args.repo.resolve()
    elf, source, target, direct_call = evidence(root)
    compile_controls(root, args.rustc, elf, source, target, direct_call)


if __name__ == "__main__":
    main()
