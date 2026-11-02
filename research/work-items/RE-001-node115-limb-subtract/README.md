# RE-001: four-limb unsigned subtraction with borrow

- Component: RE-001 function mapping; arithmetic context unassigned.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Reference revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no source used or recovered. Claim: static observation and value-level inference.
- Bounded question: what does the leaf at `0x564c830` compute on valid, disjoint input/output regions?

**Answer.** Treat the four little-endian qwords at RSI and RDX as unsigned 256-bit integers A and B. The leaf updates the four qwords at RSI to `(A - B) mod 2^256`, copies those 32 bytes to RDI, and stores at RDI+32 the byte 1 exactly when A < B, otherwise 0. The four subtract instructions propagate the carry flag as a borrow. The intervening moves, including the SIMD copies, do not alter flags, so SETB captures the final borrow. This describes machine behavior on normal return under the memory preconditions below; it does not establish a native type or business meaning.

## Evidence and scope

All addresses are original ELF virtual addresses; `.text` file offset is VA minus `0x1000`. The body is `0x564c830..0x564c861`, 49 bytes, file offset `0x564b830`, SHA-256 `ddc8e1d31bf3e406e23cd98cc4d8f38975b0d0d0a54b4db2dedbbe9dfa7fdb91`. FDE at `.eh_frame` VA and file offset `0xf8b80c` references CIE `0xca6ed8` (`zR`, pcrel-sdata4); it has no LSDA. The end is followed by 15 `cc` bytes until the next FDE entry `0x564c870`. The unwind extent, entry-to-return walk and post-body padding support this particular boundary; FDEs alone do not establish all functions.

Complete instruction walk, 14 instructions; bytes and operand widths are unmasked:

VA | bytes | decoded instruction
--- | --- | ---
`0x564c830` | `488b02` | `mov rax, [rdx]`
`0x564c833` | `482906` | `sub [rsi], rax`
`0x564c836` | `488b4208` | `mov rax, [rdx+8]`
`0x564c83a` | `48194608` | `sbb [rsi+8], rax`
`0x564c83e` | `488b4210` | `mov rax, [rdx+16]`
`0x564c842` | `48194610` | `sbb [rsi+16], rax`
`0x564c846` | `488b4218` | `mov rax, [rdx+24]`
`0x564c84a` | `48194618` | `sbb [rsi+24], rax`
`0x564c84e` | `0f1006` | `movups xmm0, [rsi]`
`0x564c851` | `0f1107` | `movups [rdi], xmm0`
`0x564c854` | `0f104610` | `movups xmm0, [rsi+16]`
`0x564c858` | `0f114710` | `movups [rdi+16], xmm0`
`0x564c85c` | `0f924720` | `setb byte [rdi+32]`
`0x564c860` | `c3` | `ret`

The body has 0 direct or indirect calls or tail calls, and thus no callee identity or extent to resolve. A full `.text` byte-by-byte scan for E8/E9 signed rel32 transfers to the entry found 6 candidates: `0x5600943`, `0x56009a7`, `0x56009ea`, `0x56017b3`, `0x5601817`, `0x560185a`. Each is an E8 call framed by decoded stack-address argument setup and a post-call test of byte `[rsp+0x40]`, corresponding to output+32. The containing FDE records and complete context bytes are retained in `records.json`. The scan includes overlapping byte positions; these local instruction contexts support these sites, but do not prove a global instruction-boundary census. It cannot detect indirect calls, data pointers, or branches to the interior.

The first enclosing caller FDE also contains RIP-relative LEAs at `0x56004c4`, `0x5600a84` and `0x5600aab`. Their resolved location objects, ELF `R_X86_64_RELATIVE` addends, path bytes and line/column values associate this caller with `l1/src/qtys/mod.rs:835:1` and `l1/src/qtys/impl_wei.rs:6:1`; raw records and reference bytes are in `records.json`. This is a caller-context association, not proof that the leaf itself originated in those files or that its values are a particular quantity type.

**Assumptions and limits.** The 32-byte A, 32-byte B and 33-byte result regions are valid and pairwise disjoint; other aliasing cases are not claimed. Reads and writes can fault and no execution has been performed. The result is a static theorem, not a recovered Rust implementation, source ownership, original function name, ABI beyond observed registers, or protocol meaning. Source comparison, source build, normalization, whole-ELF equivalence, caller semantics and component acceptance gates remain unmeasured. No normalizations or comparison masks are used. Next: resolve the two caller FDEs and trace the provenance and use of these values before assigning a domain meaning.

## Reproduction and controls

From the repository root, Python 3.10+ (stdlib) with the authenticated materialized target. Observed locally on Linux x86-64 with Python 3.13.5; initial focused inspection also used GNU objdump 2.44 as below. The generator and verifier do not invoke objdump:

```sh
objdump -d -Mintel --start-address=0x564c830 --stop-address=0x564c870 artifacts/node/115/hl-node
objdump -d -Mintel --start-address=0x55ffc90 --stop-address=0x5600af9 artifacts/node/115/hl-node
python3 tools/node115_limb_subtract.py --out research/work-items/RE-001-node115-limb-subtract/
python3 -m unittest tests.test_node115_limb_subtract -v
python3 research/work-items/RE-001-node115-limb-subtract/verify.py
make verify
make catalogue-check
```

The generator checks the full target digest before parsing, uses the repository's stdlib ELF/FDE parsers and strict instruction-form decoder, and scans all `.text` offsets. The focused tests exercise instruction, FDE, direct-target and digest corruption, arithmetic boundaries and packet reproducibility. No target or visor execution, network or external state is used. No independent implementation or build comparison is claimed. New code is MIT.

Novelty check before selection: the following searches returned no matches (exit status 1) in `research/` or the three local PR title lists:

```sh
rg -in '564c830' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -n '90490928' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```
