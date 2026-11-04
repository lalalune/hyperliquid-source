# RE-001: node #115 bounded ring-style offset

- Component: RE-001 function map; original component and type are unresolved.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source/reference revision: repository base `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no original source is available.
- Question: what raw return pair does the whole function at `0x45514d0` compute from its three loaded words?

**Answer (inference from the complete decoded body):** let `C=[RDI]`, `H=[RDI+0x10]`, and `N=[RDI+0x18]` be unsigned 64-bit words, with wrapping arithmetic. If `N=0`, return `(RAX,RDX)=(1,0)`. Otherwise set `D=(C-H+(0 if H<C else C)) mod 2^64`, and return `(0,min(D,N-1))`. The last arm uses a loop to sum successive `floor(N/2)` terms until the remainder is one, which equals `N-1`. The input RSI value is overwritten before use. This is a raw register relation; ring terminology is a hypothesis, not an identified original type.

## Evidence and scope

The window is ELF VA `0x45514d0..0x4551523` (exclusive), 83 bytes, file offset `0x45504d0`; body SHA-256 `00bc78a91f54a791f2a241c7673c49ffbba6874ef36928bb474faa0f94add03b`. FDE `0xecfb5c` points to CIE `0xca6ed8`, has no LSDA and describes exactly this range. The following 13 bytes up to `0x4551530` are `cc`. The 31 individually decoded instructions and their original bytes are in `records.json`. Strict matching accepts only the recorded opcode/operand forms, validates all relative branch destinations, and covers the whole FDE. Each path returns locally; there are 0 direct or indirect callees. FDE plus reachable control flow and terminal returns support this bounded extent; unwind records alone do not establish every function.

The full `.text` byte-position `e8`/`e9` signed-rel32 scan yields 1 candidate, an `e8` at `0x3d6ecb8`. Its contiguous instruction context loads RSI with one, moves the object pointer into RDI, calls the entry, tests AL and copies RDX on the non-error path. Byte scanning can include false positives and misses indirect calls, so it is not a complete semantic caller census. The caller's surrounding function and semantic purpose remain unbound.

## Instruction rule

The first `test`/`je` handles zero length. `cmp rdi,rsi` and unsigned `cmovb` select zero when `H<C`, otherwise `C`. Subtraction and addition wrap in 64 bits. An unsigned comparison returns `D` directly when `D<N`. Otherwise `N=1` returns zero; for larger `N`, the loop adds `floor(k/2)` to RDX and replaces `k` by `ceil(k/2)` until `k=1`, so the sum telescopes to `N-1`. Every control-flow edge and `ret` is included in the recorded walk. The model takes raw words and is not captured-node execution.

## Novelty and reproduction

Before selection, both commands below returned no matches (exit status 1):

```sh
rg -i '45514d0|72684752' research/
rg -i '45514d0|72684752' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

From the repository root, Python 3.10+ stdlib only, with the materialized target:

```sh
python3 tools/node115_ring_offset.py --out research/work-items/RE-001-node115-ring-offset/
python3 -m unittest tests.test_node115_ring_offset -v
python3 research/work-items/RE-001-node115-ring-offset/verify.py
make verify
make catalogue-check
```

The generator authenticates the full input before producing output, decodes the fixed FDE/CIE and instruction forms, scans the entire `.text` for candidate rel32 calls/jumps, and reproduces the packet. No target binary is executed; no disassembler is needed by the generator, verifier or tests. Wrong digest, changed body, shifted FDE and changed caller target are rejected by focused controls. No byte comparison normalization is used.

## Limitations and next step

No original Rust signature, caller-wide behavior, source ownership, object invariants, units, implementation equivalence, data/relocation closure, full node behavior or acceptance gate is claimed. Counts are bounded to this packet and the specified raw scan. No Rust implementation or comparison build exists. Resolve the enclosing caller's object layout and establish its source association before assigning a domain meaning to these words.
