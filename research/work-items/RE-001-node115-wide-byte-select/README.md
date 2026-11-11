# RE-001: node #115 wide byte selection

- Component/task: RE-001 function map; a complete computational leaf, with original module ownership unresolved.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/reference revision: repository base `05bc2de303c05525b71e7e257426e741bc66a390`. Independently authored analysis/model under MIT; no original Rust source is available.
- Question: which byte does `0x43352f0` select from its two wide operands, what happens for a wide or out-of-range index, and which state changes occur?
- Claim status: instructions, extents, references and writes are observations; the integer rule below is a deduction from them. Source names, source types and callers' protocol meaning remain unresolved.

**Answer:** Read unsigned depth `n` from `[entry RDI+0x30]`. If `n<2`, return `AL=0x2c` with upper RAX preserved and no memory writes. Otherwise, read buffer pointer `p=[entry RDI+0x28]`, interpret its slots as little-endian 256-bit integers, let `index=slot[n-1]` and `value=slot[n-2]`, decrement depth, and replace `slot[n-2]` with `(value >> (8*(31-index))) & 255` when the full-width index is below `32`, or zero otherwise. Return `RAX=0`. Index zero selects the most significant byte. The popped index slot and all other buffer slots retain their bytes; the red-zone scratch described below is zeroed.

## Extent and evidence

| Measurement | Value |
| --- | ---: |
| Body bytes | 137 |
| Decoded instructions | 36 |
| Internal branch instructions | 3 |
| Return instructions | 2 |
| Direct or indirect callees | 0 |
| Direct rel32 caller candidates | 0 |
| Following padding bytes | 7 |
| Relocated function pointers | 2 |
| Instruction-grounded model vectors | 50 |

The full body is ELF VA `[0x43352f0,0x4335379)`, file offset `0x43342f0`, SHA-256 `91bb3b777dc0a11d83080f40def59bbec98eec1490f24f6bf92e51d88f79f45c`. FDE VA/file offset `0xe9ce8c` (section offset `0x1f5fb4`) refers to CIE VA/file offset `0xca6ed8`. Its `zR` augmentation uses `pcrel|sdata4`, no personality or LSDA, and default CFA `RSP+8` with return address at CFA-8. Raw FDE/CIE bytes and decoded fields are in `records.json`. The unwind index independently names this entry/FDE and the next entry `0x4335380`; the intervening padding is entirely `cc`. The FDE, complete reachable walk and local returns jointly support this extent. No function census denominator is inferred from unwind starts.

`records.json` retains every instruction's original bytes, VA and strict Python decoding, with no normalization. All conditional paths and the merge are covered. No body instruction transfers to a callee; therefore callee identities/extents and wrong-callee-target controls are inapplicable. An injected CALL is rejected as unsupported, and retargeted local branches are rejected.

## Instruction proof and memory contract

At `0x43352f4`, unsigned `CMP/JB` checks depth before the buffer pointer or any slot is read. The underflow arm at `0x4335376` writes AL only. On the other arm, `DEC` and the store at `0x43352fd` reduce depth before any slot read. The shift by `5` and LEA put the popped index slot address in RAX; subsequent writes to CL and SIL do not alter that retained address.

The load at `0x433530d` obtains the index's low limb. The load/OR/OR at `0x4335311..0x4335320` tests all remaining limbs for zero. `SETE CL`, unsigned `CMP RDX,32`, `SETB SIL` and `TEST CL,SIL` jointly admit exactly a full-width index below the bound. A nonzero high limb is rejected even when its low limb is small. This is not a truncating index operation.

For an admitted low limb `j`, NOT computes `-j-1` modulo the machine word. The byte load at `0x4335333` therefore reads `p+32*(n-1)-j-1`, namely byte `31-j` of the preceding little-endian slot. MOVZX zero-extends it; the alternative arm clears ECX. The common stores overwrite the result slot's low qword and zero its upper bytes. The other loaded index limbs are never written back. Both normal arms write zero to `[entry RSP-0x18,entry RSP)` and read that scratch back for the result; they leave RSP unchanged. The aligned MOVAPS scratch accesses require the usual entry alignment `RSP mod 16 = 8` and a valid red-zone. The body performs no allocation and reads no globals, import slots or constant pool.

The normal-return rule assumes valid readable header fields, a writable buffer holding the active slots, nonwrapping address arithmetic, and disjoint buffer/header/red-zone memory. It does not describe invalid pointer faults, asynchronous interference or aliasing those regions. In particular, the depth store precedes later accesses, so an access fault is not claimed to roll back state. The early underflow arm needs only the depth field and a valid return stack. ABI register preservation beyond the decoded effects and original Rust types remain unclaimed.

## References and ownership

The raw census scans the entire `.text` interval `[0x1419300,0x63f0a00)` at every possible byte position for `e8`/`e9` plus signed rel32 landing at the entry. Its empty result establishes no direct byte-pattern candidates in that interval. This scan is not a whole-program caller proof: it misses indirect calls and non-rel32 encodings, and a nonempty result would need instruction-boundary validation.

Actual `.rela.dyn` R_X86_64_RELATIVE entries at file offsets `0xb3dc0` and `0xb5bf0` have this entry as addend and write pointer slots `0x6485fc8` and `0x6486d30`. Their raw records and original zero-filled slots are retained. The pointer consumers and dispatch tables are unbound; pointer references are not counted as callers. This leaf has no panic Location or proven first-party attribution. Selection considered source-associated candidates, but this packet binds a complete byte operation rather than inheriting ownership from proximity or from a vendor name.

## Novelty, reproduction and controls

Before adding these files, both address searches produced empty stdout and exit status 1. The spelling search also produced empty stdout and exit status 1:

```sh
rg -i '43352f0|70472432' research/
rg -i '43352f0|70472432' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 'wide-byte-select|wide_byte_select' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt research/ tools/ tests/
```

From repository root, with materialized inputs and Python 3.10+ stdlib (observed locally with Python 3.13.5, Linux x86-64):

```sh
python3 tools/node115_wide_byte_select.py --out research/work-items/RE-001-node115-wide-byte-select/
python3 -m unittest tests.test_node115_wide_byte_select -v
python3 research/work-items/RE-001-node115-wide-byte-select/verify.py
make verify
make catalogue-check
```

The producer maps the binary once, authenticates its complete digest before parsing or writing output, reuses the repository's stdlib ELF/FDE parsers, decodes its complete bounded instruction vocabulary and regenerates the packet byte-identically. GNU objdump 2.44 was used for initial inspection only; no generator, verifier or test invokes it. Analysis is static and complete for this body. The Python logical-slot model and separately derived byte-address equation are independently authored; vectors cover every admitted index, boundary rejection, nonzero high limbs, byte order, unchanged storage and both underflow depths. They are instruction-grounded expectations, not runtime observations.

Controls reject wrong digest, an actual window mutation, a shifted FDE, altered CIE/index metadata, changed padding, unsupported CALL, incorrect branch target, semantic immediate changes, changed function-pointer addend and newly injected direct caller patterns. README counts are tested against the JSON. The whitelist verifier authenticates the exact packet file set, tool/test source hashes and regenerated evidence. No captured executable, emulator, network, signing or chain action is used.

## Results, non-claims and next step

Before this work no retained address match existed; after it, the bounded byte-selection rule, underflow behavior and memory writes are explained from the complete authenticated body. No Rust implementation, source-build comparison, normalization mask, instruction equivalence measurement, source identity, original ABI, dispatch closure, full-node behavior or component gate is claimed. All full-scope acceptance gates remain unchanged. Local checks validate this packet and its controls; they do not claim hosted CI or repository-wide tests.

Observed local result: regeneration, targeted unit tests, the packet verifier and `make verify` pass. `make catalogue-check` fails on the root README's pre-existing stale generated work-item inventory; this was confirmed while the tracked tree and index were still unchanged from the recorded base. Adding this packet also changes that inventory. Catalogue/progress files remain untouched under the add-only scope. Repository-wide `make test` was not run.

Next: resolve the consumers of the recorded function-pointer slots and prove their operand construction and returned-byte handling before attaching an opcode, API or protocol name.
