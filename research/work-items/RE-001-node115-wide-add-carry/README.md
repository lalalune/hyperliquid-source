# RE-001: node #115 four-limb addition and carry

- Component: foundation arithmetic; bounded function map, not a component gate.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; independently authored MIT research. No original source is claimed.
- Question: what does the previously unbound leaf at `0x29fc880` compute and write?

Under valid, mutually disjoint readable/writable buffers, interpret the 32 bytes initially at RSI and RDX as little-endian unsigned 256-bit integers A and B. The function overwrites RSI with `(A+B) mod 2^256`, copies that result to the 32 bytes at RDI, and writes `(A+B) >> 256` as a byte at RDI+32. The carry byte is therefore zero or one. It makes no calls and returns after the stores. This is a static proof from all of its instructions, not an execution result or an assertion of an original Rust name or type.

## Geometry and instruction evidence

The original ELF VA interval is `0x29fc880..0x29fc8b1`, file offset `0x29fb880`; body SHA-256 is `9b53b28d56b050e0fb3b421ec6eadfe83deb4d37b53dad0b4c3b0328190dcce4`. The FDE at `0xd78350` names CIE `0xca6ed8` and describes that exact range with no LSDA. The body ends in RET, with INT3 fill through `0x29fc8c0`. Raw FDE/CIE bytes and every decoded instruction are in `records.json`. FDE extent alone does not prove a function boundary: the complete straight-line decoded body, return, padding, and observed direct call support this binding together.

Counts: window_bytes=49; instructions=14; padding_bytes=15; direct_callees=0; rel32_candidates=1; confirmed_direct_calls=1.

The complete instruction walk is retained as bytes, VAs and effects in `records.json`. The first load and ADD update the low 64-bit limb; the next three loads and ADC operations update successively higher limbs with carry. MOV and MOVUPS do not modify flags, so after the final ADC the two unaligned vector copies preserve the final carry until SETB stores it. No instruction reads or changes flags in between. The four limbs are ordered at offsets 0, 8, 16, 24, establishing the unsigned sum and overflow by induction on carry. No normalization masks are used.

The whole `.text` byte scan checks each possible E8/E9 rel32 start, including positions inside other instructions, so it is a candidate census rather than an instruction-boundary census. The sole candidate is a CALL at `0x2a1e7b7` within FDE `0x2a1dd50..0x2a1eb71`; decoding from that owner's entry establishes the call boundary. The retained caller context has LEAs to stack output and left operand before the call and tests the output carry byte immediately afterward. This is local caller evidence, not a full interpretation of the owner. No indirect calls, dynamically computed targets, vtables or outside-`.text` references are covered. The leaf has no direct or indirect callees; there are consequently no callee identities or extents to close.

## Reproduce and controls

Python 3.10+ standard library; Linux x86-64 static ELF data. From the repository root:

```sh
python3 tools/node115_wide_add_carry.py --out research/work-items/RE-001-node115-wide-add-carry/
python3 -m unittest tests.test_node115_wide_add_carry -v
python3 research/work-items/RE-001-node115-wide-add-carry/verify.py
make verify
make catalogue-check
```

The producer hashes the complete target before parsing or writing; it validates executable section mapping, FDE/CIE, full instruction encodings, return, padding, caller bytes and the full `.text` rel32 scan. It uses the repository's standard-library ELF/FDE readers and no disassembler. The separate static discovery used GNU objdump 2.44 to check the caller boundary with `objdump -d -Mintel --start-address=0x2a1dd50 --stop-address=0x2a1eb71 artifacts/node/115/hl-node`; no GNU output is required by regeneration. Tests include wrong digest, actual body mutation, shifted FDE, retargeted call, byte-decoder rejection, arithmetic boundary vectors, deterministic regeneration and README count consistency. Neither the node nor visor is executed.

Novelty check, run before selecting this candidate (no matches; `rg` exits 1):

```sh
rg -i '29fc880|44025984' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

## Limits and next step

The arithmetic theorem assumes valid mapped memory and mutually disjoint buffers. Aliasing, faults, concurrency, unwind behavior, and externally visible effects beyond the listed stores are not established. The numerical interpretation is an inference from the instruction sequence, not a recovered source-level type, ownership or component identity. The caller FDE and its stack argument setup do not establish first-party provenance. There is no Rust implementation, build comparison, target execution, function-coverage denominator, hosted CI result or completion gate. Imported inputs and all progress gates remain unchanged.

Next, resolve the caller's surrounding arithmetic and source provenance, including the meaning of its carry-dependent branch, before assigning this leaf a domain-specific role.
