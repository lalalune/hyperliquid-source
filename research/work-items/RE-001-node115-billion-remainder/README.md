# RE-001: unsigned billion remainder at node #115 `0x63bfbc0`

- Component: foundation; task RE-001 function binding. Base revision: `8fd8db68`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. No upstream source is asserted for this leaf.
- Bounded question: for a readable qword at RDI, what does the complete leaf return?
- Answer: it returns that qword interpreted as an unsigned integer modulo 1,000,000,000 in RAX. It reads no other input memory, writes no memory and makes no calls. The formula holds for every unsigned 64-bit input, assuming valid readable memory, normal execution and a valid return address. The original source name, type, ownership and units remain unknown.

## Binary observations

The half-open FDE is `0x63bfbc0..0x63bfbed`, **45 bytes**, original ELF virtual addresses; file offset `0x63bebc0`. The FDE at VA/file offset `0x1037d48` refers to CIE `0xca6ed8` (`zR`, no LSDA). Three `cc` padding bytes follow the body before the next entry. Body SHA-256 is `28a0128a34a47371283b6550713075e152b3c8f3f91cd676d12b83cabf598a85`. The complete **11 instructions** and their raw encodings are in `records.json`; its FDE/CIE bytes and instruction offsets are extracted from the authenticated target. The FDE extent, contiguous decoding, terminal return and padding support this bounded function extent; FDEs alone do not prove all functions or ownership.

The walk loads the qword into RCX, shifts a copy right by 9, performs unsigned `mul` by `0x44b82fa09b5a53`, shifts the high product limb right by 11, multiplies it by `0x3b9aca00`, and subtracts that low product from the original qword. `endbr64` and the immediate load precede the computation; `ret` terminates it. There are **0 callees**, direct or indirect, so no callee identity or extent needs binding.

Let `x` be the input and `y=floor(x/512)`. Because 1,000,000,000 = 512 * 1,953,125, `floor(x/1,000,000,000) = floor(y/1,953,125)`. The multiply and high-limb shift compute `floor(y*M/2^75)`, with `M=0x44b82fa09b5a53` and `M*1,953,125 - 2^75 = 399,807`. Since `y <= 2^55-1`, `y*399807 < 2^75`. Writing `y=1,953,125*q+r`, with `0<=r<1,953,125`, the reciprocal error is strictly too small to carry `r` into the next quotient. Thus this is the exact quotient `q`; the final subtraction returns `x - q*1,000,000,000`, the remainder. This proof covers the entire input domain; vectors are checks, not a substitute for it.

The full `.text` bytewise `e8`/`e9` rel32 scan over `[0x1419300,0x63f0a00)` yields **2 direct-reference candidates**: calls at `0x6368113` and `0x636874e`, both inside the unwind range `0x6367e60..0x6368e3f`. The call bytes are retained, and independent focused GNU objdump 2.44 inspection confirms both are instruction-aligned calls. This does not establish units, whole caller behavior or reachability. A bytewise scan is conservative: it can include embedded opcode coincidences and excludes indirect calls. Both candidates are corroborated as instructions, but no whole-program caller census beyond this explicit method is claimed.

## Reproduction and novelty

Static only. Python stdlib, Python 3.10 or newer; no disassembler is required to regenerate the packet. From the repository root:

```sh
python3 tools/node115_billion_remainder.py --out research/work-items/RE-001-node115-billion-remainder/
python3 -m unittest tests.test_node115_billion_remainder -v
python3 research/work-items/RE-001-node115-billion-remainder/verify.py
make verify
make catalogue-check
```

The generator authenticates the entire capture before output, checks ELF section geometry, FDE/CIE, body hash, strict instruction encodings, padding and every-byte direct references. It decodes operands without objdump; raw JSON uses decimal addresses, while this README uses ELF virtual addresses. No operands are masked. The checked `records.json` contains the complete semantic records. `MANIFEST.sha256` whitelists the packet files, and `verify.py` rejects additions and mismatches. The output directory's README and verifier are copied from the packet source. No target process or emulator runs.

Before choosing this address, the following searches returned no matches (exit status 1). No callees are bound:

```sh
rg -i '63bfbc0' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '104594368' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

## Controls, non-claims and next step

The focused tests verify regeneration, counts, complete decoding, arithmetic boundary vectors and the reciprocal certificate; wrong identity, a mutated instruction, a shifted FDE and a redirected direct-call operand fail closed. Invalid pointers, unwinding, indirect callers, runtime observations, original Rust/C++ source, data type identity, a reconstructed binary, build provenance, whole-ELF equivalence and any component acceptance gate remain unproved. The inferred arithmetic is grounded in the captured instruction semantics; it is not evidence of first-party ownership. No component progress gate changes. The next question is how the enclosing caller constructs the input and consumes the return value.
