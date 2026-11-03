# RE-001: four-limb in-place addition with carry

- Component: unassigned arithmetic leaf; useful to the RE-001 function map.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The source/reference revision is repository base `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no upstream source mapping is asserted.
- Bounded question: what does the entire function at `0x4fb12f0` compute, and what does its output byte indicate?
- Claim status: the instructions and memory accesses are observations; the arithmetic rule below is a mathematical inference. Original type, name, ownership and business purpose remain unresolved.

For valid, mutually disjoint input/output ranges, let `A` and `B` be unsigned 256-bit integers represented by four little-endian 64-bit limbs at RSI and RDX, least significant limb first. The function writes `(A+B) mod 2^256` back to RSI and copies those 32 bytes to RDI; it writes `1` at RDI+32 exactly when the sum is at least `2^256`, and otherwise writes `0`. This rule requires the four RSI limbs to be writable, the four RDX limbs readable, and the 33-byte RDI destination writable, with ordinary nonfaulting memory and no concurrent mutation. Aliased operands, fault behavior and calling-convention types are not claimed. The function makes no calls and has no branches before its return.

## Evidence and instruction walk

All addresses are original ELF virtual addresses. `.text` maps VA `0x1419300..0x63f0a00` to file offset `0x1418300`. The full unwind-described window is `0x4fb12f0..0x4fb1321`, at file offset `0x4fb02f0`; its SHA-256 is `9b53b28d56b050e0fb3b421ec6eadfe83deb4d37b53dad0b4c3b0328190dcce4`. The FDE is at VA/file offset `0xf3b5c0`, points to the `zR` CIE at VA/file offset `0xca6ed8`, and has no LSDA. The exact FDE and CIE bytes, body SHA-256, all instruction bytes and their decoded operations are in `records.json`. The neighboring FDE begins at `0x4fb1330`; the intervening bytes are all `cc`. FDEs establish unwind ranges, not a complete global function inventory. The straight-line entry-to-return control flow corroborates this particular extent.

The instruction walk is complete and unnormalized: the first load/ADD handles limb zero, and three load/ADC pairs handle limbs one through three. MOV preserves carry between each arithmetic operation. Thus the last ADC's carry is the carry out of the highest limb. Two unaligned vector load/store pairs copy the updated four limbs; MOVUPS preserves flags. SETB writes that carry to byte offset 32, and RET terminates the body. This establishes the rule by ordinary unsigned limb arithmetic, not by executing the target. The caller setup observed immediately before each hit selects RDX and places independent stack destinations in RDI and RSI; the byte at RDI+32 is compared with zero immediately after the call. Other caller semantics and the source of RDX are unmeasured.

Machine-readable counts (derived from `records.json`; enforced by the focused tests):

- Body bytes: 49
- Instructions: 14
- Padding bytes: 15
- Callees: 0
- Direct rel32 hits: 2

The caller census scans every byte of the full `.text` for `e8` and `e9` followed by a signed rel32 resolving to the entry; it finds calls at `0x4fb85c7` and `0x4fb93f7` and no tail-jump hit. Both are instruction boundaries in disassembly begun at their containing FDE entries `0x4fb7b60` and `0x4fb8990`, respectively. The pure Python producer strictly checks the immediately surrounding instruction encodings and direct displacement; the census includes unaligned bytes as candidates and is not a complete indirect caller census. No indirect dispatch or callees occur in the selected leaf. This observation does not assign a first-party or dependency identity.

## Novelty

Before selecting this function, the following searches returned no matches (exit status 1). The leaf has no callees whose behavior is bound.

```sh
rg -i '4fb12f0|83563248' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 'four.limb.carry|4fb12f0|83563248' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

## Reproduction, controls and limits

From the repository root with the authenticated artifact materialized, Python 3.10+ and only its standard library are required. The producer authenticates the full input before writing, parses ELF section mapping and the selected FDE/CIE, strictly decodes every instruction in the leaf and its retained caller context, scans the complete text, and writes deterministic evidence. It never invokes a disassembler or executes the captured node. GNU objdump 2.44 was used only for independent static discovery and caller-boundary inspection. There is no binary normalization or comparison mask.

```sh
python3 tools/node115_four_limb_carry.py --out research/work-items/RE-001-node115-four-limb-carry/
python3 -m unittest tests.test_node115_four_limb_carry -v
python3 research/work-items/RE-001-node115-four-limb-carry/verify.py
make verify
make catalogue-check
```

The tests check arithmetic boundary vectors and reject a wrong digest, altered body instruction, shifted FDE, altered direct-call target, and changed carry instruction. The corruption checks beneath the digest gate distinguish specific checks from whole-file authentication. The verifier only reads the explicit manifest whitelist and compares regenerated semantic records. No captured executable, network, private state or chain action is used.

Before: this entry was unbound in the searched research and PR title lists. After: the target bytes and local arithmetic relation are reproducible. No independent Rust implementation, Cargo build, ABI validation, target execution, whole-function comparison, data/relocation or whole-ELF equivalence is claimed; no component gate is requested. The arithmetic identity does not establish the surrounding protocol or a first-party owner. Next, trace both callers to their inputs and source-associated locations before assigning a domain meaning to these limbs.
