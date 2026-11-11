#!/usr/bin/env python3
"""Check pinned byte windows of node #115 against the original ELF. Nothing is executed.

Each entry below is an address range of the loaded image, the bytes (or SHA-256 for a
whole function) that were read there, and what this packet takes those bytes to mean.
The tool proves only that the bytes are still those bytes and that the constants in
the Rust crate occur as little-endian immediates in them. It does not decode
instructions, so the meaning column is a reading to be checked with `objdump -d -M intel`
(README gives the commands), not something this tool establishes.

Usage: verify_target.py [--elf PATH] --outdir NEW_DIRECTORY (writes verification.json)
"""
import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

from tool_common import CRATE, PIN, ROOT, fresh_outdir

# (label, start, length, "hex"|"sha256", value, meaning)
WINDOWS = [
    ("func 0x421dc00", 0x421DC00, 1393, "sha256", "6e6e92dc7dbca56de9498fc64913d92f88615f24528db2a251cd13df9ac6bd82", "context builder (FDE extent)"),
    ("func 0x44e6af0", 0x44E6AF0, 324, "sha256", "72e56c4c4eec3f3d7fb53ca89b0b432096e616f8e5088c9925d59a192eeb4a64", "builds three Uint tokens, calls the ABI encoder slot"),
    ("func 0x38d3100", 0x38D3100, 517, "sha256", "1658a47191d192bca98571e6f5eef1d2453aca5580de366ddbfe017da12914bc", "MessagePack bytes, then Keccak-256 of them"),
    ("func 0x41d4eb0", 0x41D4EB0, 327, "sha256", "7894d3f662f7b8cb1487795a57e260ef30091fd0bb18195cad7156c295f59b7a", "array of three"),
    ("func 0x41d2670", 0x41D2670, 316, "sha256", "473a18215664fe96d1176edc1895d1b56935476c470427ded50bdc9c6ea526cc", "one element"),
    ("func 0x41d3f60", 0x41D3F60, 489, "sha256", "bf2fe1feb1c9876774407180246837589adc7e5e7bd5eb429429aa899bb67b8f", "end of array (no buffered elements here)"),
    ("func 0x3d50270", 0x3D50270, 713, "sha256", "34e7871d6bc388afc28966de90fd524ca35cde67347519f6ecd230a4a5978ccb", "array header"),
    ("func 0x3d517e0", 0x3D517E0, 626, "sha256", "c388d76609d2e06536318df3a5a303cc618d894e4dbc18e047462a42d46dfd83", "unsigned integer, smallest form"),
    ("func 0x3d52310", 0x3D52310, 78, "sha256", "97a69885f4ce8f473e5c0139e173b3c35bbee945b4519ffa9ad5d7e5bdbe1aaa", "marker | length bits"),
    ("func 0x169dcc0", 0x169DCC0, 411, "sha256", "a12b48ccc40120cea571ae9aa678fab172542a6c263e392dac752d48c8531d45", "token class (prior packet)"),
    ("func 0x169df80", 0x169DF80, 580, "sha256", "2acb49b0d64014571ced9d3198dfba61a4acf3f965cb8c08970e4b5c4b0c313e", "token head word"),
    ("func 0x169e1d0", 0x169E1D0, 370, "sha256", "635aec4280187d5946c35732d6b09ca9cd1dfe10da55648f599cbf4025d0fb22", "head/tail pass (prior packet)"),
    ("func 0x169e350", 0x169E350, 587, "sha256", "0c19d15c4278d0951eb299052687fe0583fd8c601c1463aebff1df12d95c9a48", "ABI encode entry (prior packet)"),
    ("func 0x5cda910", 0x5CDA910, 1066, "sha256", "e24dbc47639c217bb45897e746eb069fe9e323e4098cd53fda92d4b95afb390f", "sponge absorb (prior packet)"),
    ("func 0x5cdad40", 0x5CDAD40, 765, "sha256", "94b1e9200106a1fc11ecd749e7eb693d22687fe87059406140f79c6bfdd53596", "sponge squeeze (prior packet)"),
    ("mode below 2", 0x421DC17, 15, "hex", "4080fe0248894c24280f83ac000000", "cmp sil,2; mov [rsp+0x28],rcx (b); jae"),
    ("K", 0x421DC26, 10, "hex", "48b8c5a9622eea7a35f1", "movabs rax,0xf1357aea2e62a9c5"),
    ("shared term", 0x421DC30, 14, "hex", "4889d6480faff04801ce480faff0", "rsi=(a*K+b)*K"),
    ("seed0", 0x421DC3E, 10, "hex", "48b9284e157351d7ab89", "movabs rcx,0x89abd75173154e28"),
    ("word0 tail", 0x421DC48, 21, "hex", "480fafc84c01f14801f1480fafc848c1c114480fc9", "*K, +c, +s, *K, rol 0x14, bswap"),
    ("seed1", 0x421DC5D, 10, "hex", "48bfb85beaf17f4062ea", "movabs rdi,0xea62407ff1ea5bb8"),
    ("word1 tail", 0x421DC67, 21, "hex", "480faff84c01f74801f7480faff848c1c714480fcf", "same sequence on rdi"),
    ("seed2", 0x421DC7C, 10, "hex", "49b858e33ce6505c82b1", "movabs r8,0xb1825c50e63ce358"),
    ("word2 tail", 0x421DC86, 21, "hex", "4c0fafc04d01f04901f04c0fafc049c1c014490fc8", "same sequence on r8"),
    ("seed3", 0x421DC9B, 10, "hex", "49b9982f76717a72c378", "movabs r9,0x78c3727a71762f98"),
    ("word3 tail", 0x421DCA5, 21, "hex", "4c0fafc84d01f14901f14c0fafc849c1c114490fc9", "same sequence on r9"),
    ("word stores", 0x421DCBA, 24, "hex", "48890c2448897c24084c894424104c894c2418e991010000", "four words stored at [rsp+0..0x20), jmp to overlay"),
    ("mode equals 2", 0x421DCD2, 13, "hex", "400fb6c683f8020f853c010000", "movzx eax,sil; cmp eax,2; jne (modes above 2)"),
    ("mode 2 thresholds", 0x421DCDF, 26, "hex", "4881fa347a06190f873affffff4881fac09bf50d0f833c010000", "a>0x19067a34 arithmetic; a>=0xdf59bc0 MessagePack; else ABI"),
    ("mode above 2 thresholds", 0x421DE1B, 26, "hex", "4881fae86d162a0f87fefdffff4881fae07b370d0f86c4feffff", "a>0x2a166de8 arithmetic; a<=0xd377be0 ABI; else MessagePack"),
    ("ABI path call", 0x421DCF9, 33, "hex", "4889d3488954244848894c24504c89742458488d7c2430488d742448e8d68d2c00", "[rsp+0x48..0x60)=a,b,c; call 0x44e6af0"),
    ("MessagePack path call", 0x421DE35, 43, "hex", "488994248000000048898c24880000004c89b424900000004889e7488db424800000004889d3e8a0526bff", "[rsp+0x80..0x98)=a,b,c; call 0x38d3100"),
    ("ABI sponge init", 0x421DD8F, 22, "hex", "48c78424300200008800000066c78424380200000100", "rate 0x88, delimiter byte 1"),
    ("ABI absorb and squeeze", 0x421DDBA, 55, "hex", "ff1588232c024c8dac2480000000488db42460010000bae00000004c89efff152a172c02488d742460ba200000004c89efff155f232c02", "absorb slot 0x64e0148; copy 0xe0; squeeze slot 0x64e0150 for 0x20 bytes"),
    ("overlay a", 0x421DF31, 35, "hex", "bd08000000ba080000004829da8854240a488d7c240bff15bb152c024929dc4983c409", "len at [rsp+0xa], bytes at [rsp+0xb], 8-za bytes"),
    ("overlay b", 0x421E021, 21, "hex", "4c29fd41882c24498d7c24014889eaff15d2142c02", "len at next byte, then 8-zb bytes"),
    ("fit counter", 0x421E036, 8, "hex", "4a8d043b4883c004", "rax = za + zb + 4"),
    ("c zero count", 0x421E0E6, 21, "hex", "31c94983fe014883d1074c8d2c0c4981c580000000", "zc = 8 for c = 0"),
    ("c fit test and copy", 0x421E0FB, 47, "hex", "ba090000004829ca4839d072224d29fc4983c409ba080000004829ca4188142449ffc44c89e74c89eeff15de132c02", "skip unless za+zb+4 >= 9-zc; else len byte 8-zc then bytes"),
    ("digest to out", 0x421E12A, 21, "hex", "0f2804240f284c2410488b4424200f1148100f1100", "the 32 bytes at [rsp] stored to out"),
    ("Uint tokens", 0x44E6B1A, 113, "hex", "498b070f57c00f11431048c7432000000000498b4f080f11433848c7434800000000498b57100f11436048c7437000000000c6030448894308c643280448894b30c64350044889535848c74424080300000048895c241048c744241803000000ba030000004c89f74889deff15b595ff01", "three 0x28-byte tokens, tag 4, low limb = a,b,c, other limbs 0; count 3; slot 0x64e0140"),
    ("MessagePack Vec and call", 0x38D3114, 45, "hex", "48c74424200000000048c74424280100000048c744243000000000488dbc2408010000488d742420e86f1d9000", "empty Vec; call 0x41d4eb0"),
    ("MessagePack result tag", 0x38D3141, 21, "hex", "4c8bb4240801000048b804000000000000804939c6", "Ok is 0x8000000000000004, else panic path"),
    ("MessagePack sponge", 0x38D31CD, 36, "hex", "48c78424f00000008800000066c78424f80000000100488d7c24204c89feff1557cfc002", "rate 0x88, delimiter 1, absorb (ptr,len)"),
    ("array of three", 0x41D4EC1, 51, "hex", "49bc04000000000000804889742448c744245000040001c644245400488d7c24084c8d7c24484c89feba03000000e87cb3b7ff", "array header with length 3 via 0x3d50270"),
    ("elements then end", 0x41D4F2C, 90, "hex", "498b16488d7c2408488d742420e832d7ffff4c396424087559498b5608488d7c2408488d742420e818d7ffff4c39642408753f498b5610488d7c2408488d742420e8fed6ffff4c396424087525488d7424204889dfe8daefffff", "elements [r14],[r14+8],[r14+0x10] in order via 0x41d2670, then 0x41d3f60"),
    ("array marker choice", 0x3D5027E, 28, "hex", "81fa000001000f92c034dd83fa100fb6c0bd900000000f43e84c8b36", "length < 16 -> 0x90 (fixarray), else 0xdc/0xdd"),
    ("marker combine", 0x3D52310, 78, "hex", "89f80fb6c88d9140ffffff83fa207301c381f98f0000007e1b81f990000000742281f9a000000075084080e61f4080cea089f0c385c974f94080e60f4080ce8089f0c34080e60f4080ce9089f0c3", "0x90 | (len & 0xf) for a fixarray"),
    ("uint below 0x100", 0x3D517F0, 40, "hex", "4881fa0001000073434c8b36498b76104939360f84aa000000498b06498b761084d20f8800010000", "value < 0x100; sign bit of dl splits 0x7f/0x80"),
    ("uint width thresholds", 0x3D5183C, 40, "hex", "4881fa000001007316488b3e89d6e8c10400004883f802753cc64308cdeb444889d048c1e8207516", "< 0x10000 -> u16 path; high 32 bits zero -> u32 path"),
    ("marker 0xcd", 0x3D51855, 4, "hex", "c64308cd", "u16 marker"),
    ("marker 0xce", 0x3D51874, 4, "hex", "c64308ce", "u32 marker"),
    ("marker 0xcf", 0x3D5188B, 4, "hex", "c64308cf", "u64 marker"),
    ("marker 0xcc", 0x3D51925, 4, "hex", "c60430cc", "u8 marker"),
    ("u16 big-endian", 0x3D51DC9, 17, "hex", "66c1c608488b4f08668934014883471002", "rol si,8 then 2-byte store"),
    ("u32 big-endian", 0x3D51FF9, 15, "hex", "0fce488b4708428934084883471004", "bswap esi then 4-byte store"),
    ("u64 big-endian", 0x3D5218C, 16, "hex", "480fce488b47084a8934084883471008", "bswap rsi then 8-byte store"),
    ("Uint limbs to word", 0x169DFD4, 83, "hex", "4c8b76084c8b7e104c8b66184c8b6e20490fcd490fcc490fcf490fce488b6b10483b2b75094889dfff155e41e404488b43084889e948c1e1054c892c084c896408084c897c08104c8974081848ffc548896b10", "four limbs byte-swapped; limb3 first -> big-endian 256-bit word"),
    ("class table", 0x47B72C, 40, "hex", "b72522018d26220136262201b7252201b7252201b725220136262201cd25220169262201cd252201", "tag 4 -> 0x169dce3 (one head word, no tail)"),
    ("head word table", 0x47B754, 28, "hex", "d82822012e2922015f2822018028220180282201e52922015f282201", "tag 4 -> 0x169dfd4 (limbs)"),
    ("spot-deploy call", 0x2C57499, 42, "hex", "41833e010f85d3020000498b4e08498b5628410fb6b69a0b0000488dbc24e00000004531c0e83d675c01", "[state]==1; b=[+8], a=[+0x28], mode=[+0xb9a], c=0; call 0x421dc00"),
    ("sibling body 0x55cbcc0 call", 0x55CC0B9, 42, "hex", "41833e010f85d3020000498b4e08498b5628410fb6b60a170000488dbc24e00000004531c0e81d1bc5fe", "same pattern, mode byte at [+0x170a]; call 0x421dc00"),
    ("sibling body 0x55cc610 call", 0x55CCA09, 42, "hex", "41833e010f85d3020000498b4e08498b5628410fb6b69a0b0000488dbc24e00000004531c0e8cd11c5fe", "same pattern, mode byte at [+0xb9a]; call 0x421dc00"),
    ("spot-deploy zero context", 0x2C57776, 19, "hex", "0f57c00f298424f00000000f298424e0000000", "else 32 zero bytes at [rsp+0xe0]"),
    ("spot-deploy helper call", 0x2C577C8, 53, "hex", "48b810000000000000804889442430488db424e8010000488d942460010000488d8c24e00000004c8d4424304c89f7ff15d3f28803", "buffer [rsp+0xe0] passed as 4th argument of the event helper slot"),
]

# lib.rs constant -> (window label, byte width in the immediate)
CRATE_CONSTANTS = [
    ("MULTIPLIER", "K", 8),
    ("WORD_SEEDS[0]", "seed0", 8),
    ("WORD_SEEDS[1]", "seed1", 8),
    ("WORD_SEEDS[2]", "seed2", 8),
    ("WORD_SEEDS[3]", "seed3", 8),
    ("MODE2_ARITH_ABOVE", "mode 2 thresholds", 4),
    ("MODE2_PACKED_FROM", "mode 2 thresholds", 4),
    ("LATER_ARITH_ABOVE", "mode above 2 thresholds", 4),
    ("LATER_ABI_UP_TO", "mode above 2 thresholds", 4),
]

# relocation slot -> expected RELATIVE target, or an imported symbol name
SLOTS = [
    (0x64E0140, 0x169E350, "ABI encode"),
    (0x64E0148, 0x5CDA910, "sponge absorb"),
    (0x64E0150, 0x5CDAD40, "sponge squeeze"),
    (0x64DF508, "memcpy", "memory copy"),
]


class Image:
    def __init__(self, data):
        self.data = data
        phoff, = struct.unpack_from("<Q", data, 0x20)
        entsize, count = struct.unpack_from("<HH", data, 0x36)
        self.loads = []
        for i in range(count):
            kind, _, off, va, _, filesz, _, _ = struct.unpack_from("<IIQQQQQQ", data, phoff + i * entsize)
            if kind == 1:
                self.loads.append((va, off, filesz))
        shoff, = struct.unpack_from("<Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
        headers = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
        names = headers[shstrndx][4]
        self.sections = {}
        for name_off, _, _, _, off, size, _, _, _, _ in headers:
            end = data.index(b"\0", names + name_off)
            self.sections[data[names + name_off:end].decode()] = (off, size)

    def get(self, va, length):
        for start, off, size in self.loads:
            if start <= va and va + length <= start + size:
                return self.data[off + va - start:off + va - start + length]
        raise ValueError(f"unmapped {va:#x}+{length}")

    def relocations(self):
        off, size = self.sections[".rela.dyn"]
        for at in range(off, off + size, 24):
            yield struct.unpack_from("<QQq", self.data, at)

    def symbol(self, index):
        off, _ = self.sections[".dynsym"]
        name_off, = struct.unpack_from("<I", self.data, off + 24 * index)
        base, _ = self.sections[".dynstr"]
        return self.data[base + name_off:self.data.index(b"\0", base + name_off)].decode()


def window_ok(kind, value, observed):
    return observed.hex() == value if kind == "hex" else hashlib.sha256(observed).hexdigest() == value


def flip_bit(observed, index):
    mutated = bytearray(observed)
    mutated[len(mutated) // 2] ^= 1 << (index % 8)
    return bytes(mutated)


def crate_values():
    text = (CRATE / "lib.rs").read_text()
    values = {}
    for name, literal in re.findall(r"const (\w+): u64 = (0x[0-9a-fA-F_]+);", text):
        values[name] = int(literal.replace("_", ""), 16)
    block = re.search(r"const WORD_SEEDS: \[u64; 4\] = \[(.*?)\];", text, re.S).group(1)
    for i, literal in enumerate(re.findall(r"0x[0-9a-fA-F_]+", block)):
        values[f"WORD_SEEDS[{i}]"] = int(literal.replace("_", ""), 16)
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--elf", default=str(ROOT / "artifacts" / "node" / "115" / "hl-node"))
    parser.add_argument("--outdir", required=True)
    args = parser.parse_args()
    data = Path(args.elf).read_bytes()
    if hashlib.sha256(data).hexdigest() != PIN:
        sys.exit("ELF is not node #115 (SHA-256 mismatch)")
    out = fresh_outdir(args.outdir)
    image = Image(data)
    report = {"elf_sha256": PIN, "windows": [], "relocations": [], "crate_constants": [], "controls": []}
    failures = []

    for index, (label, start, length, kind, value, meaning) in enumerate(WINDOWS):
        observed = image.get(start, length)
        ok = window_ok(kind, value, observed)
        control = not window_ok(kind, value, flip_bit(observed, index))
        report["windows"].append({"label": label, "start": hex(start), "bytes": length, "kind": kind, "ok": ok, "meaning": meaning})
        report["controls"].append({"label": label, "one_bit_flip_rejected": control})
        if not ok:
            failures.append(f"window {label}")
        if not control:
            failures.append(f"control for {label}")

    relative = {}
    for offset, info, addend in image.relocations():
        if offset in {slot for slot, _, _ in SLOTS}:
            relative[offset] = (info & 0xFFFFFFFF, info >> 32, addend)
    for slot, expected, meaning in SLOTS:
        kind, symbol, addend = relative.get(slot, (None, None, None))
        ok = kind == 8 and addend == expected if isinstance(expected, int) else kind == 6 and symbol is not None and image.symbol(symbol) == expected
        report["relocations"].append({"slot": hex(slot), "meaning": meaning, "ok": bool(ok)})
        if not ok:
            failures.append(f"slot {slot:#x}")

    windows = {w[0]: image.get(w[1], w[2]) for w in WINDOWS}
    values = crate_values()
    for name, label, width in CRATE_CONSTANTS:
        ok = name in values and values[name].to_bytes(width, "little") in windows[label]
        report["crate_constants"].append({"constant": name, "window": label, "ok": ok})
        if not ok:
            failures.append(f"crate constant {name}")

    report["failures"] = failures
    (out / "verification.json").write_text(json.dumps(report, indent=1) + "\n")
    print(f"{len(WINDOWS)} windows, {len(SLOTS)} slots, {len(CRATE_CONSTANTS)} crate constants, "
          f"{len(report['controls'])} one-bit controls, {len(failures)} failures; wrote {out}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
