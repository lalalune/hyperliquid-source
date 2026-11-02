# RE-004: gross and net gas-price beneficiary credits

Node #94 contains two separately referenced beneficiary-credit callbacks that multiply the same gas quantity by different 256-bit prices: one uses the selected price and the other subtracts the base with a floor at zero, so a reconstruction must retain both choices instead of treating every callback as the net-price variant.

- Component ID: RE-004, quantities and wei-denominated EVM gas accounting.
- Target release and full SHA-256: node #94 Linux x86-64, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; inferred can1357 reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. No reference implementation was copied.
- Claim status: observation for the selected bytes, FDE extents, immediate operands, relative control transfers and RELA records; inference for price/gas/account names, wei units and the relationship between the callbacks; unresolved for runtime selection, input validity, external helpers and native equivalence.
- Scope included and excluded: two callback adapters, two complete downstream FDE ranges, their local price/quantity/balance paths and selected descriptor relocations. Prior PR #1529 studies a separate net-credit family and account/state output; it does not select these four function bodies or establish the gross-versus-net choice. This packet does not re-own its selected functions. Historical fork naming, #115, visor and the complete EVM transition are outside scope.

## Reproduce

Run from the repository root on Python 3.12.3 with the authenticated artifact and the existing shared `tools/elf_index.py` and `tools/fde_extents.py`. The extractor checks the complete target digest before ELF parsing and calls no external programs. `README.md` and `MANIFEST.sha256` are packaging; every TSV here is generated. The named temporary directories below must be distinct, empty directories supplied by the reader.

```sh
python3 tools/evm_gas_settlement94.py --out research/work-items/RE-004-evm-gas-settlement-94
python3 -m unittest tests.test_evm_gas_settlement94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
PYTHONHASHSEED=1 TZ=UTC python3 tools/evm_gas_settlement94.py --out <tmp-dir-a>
PYTHONHASHSEED=991 TZ=Pacific/Honolulu python3 tools/evm_gas_settlement94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
```

`MANIFEST.sha256` hashes every other file in this evidence directory. The generated evidence is deterministic across the two environments above; the focused tests and both generations also ran with an empty executable search path. GNU objdump 2.42 was used only for human inspection: neither its text nor an external disassembler is used by the extractor or tests. No binary or captured target instruction is executed or emulated.

## Evidence

Coordinates are linked ELF virtual addresses before load bias; `functions.tsv` and `windows.tsv` also give file offsets. Actual `.eh_frame` records and `.eh_frame_hdr` entries agree on each selected FDE, and the extractor checks each entire unnormalized interval against its retained fingerprint. SHT_NOBITS is excluded from virtual-address-to-file mapping. Each full function, its raw FDE record and the focused windows are retained as hex; there is no objdump output, normalization or inferred function-size denominator.

| Role label | Adapter FDE | Selected callee FDE, exclusive end | Direct edge |
| --- | --- | --- | --- |
| Gross-price credit | `0x244f4b0..0x244f4c4` | `0x2468870..0x2468aae` | `0x244f4ba` to `0x2468870` |
| Net-price credit | `0x244f4f0..0x244f504` | `0x2468fa0..0x2469249` | `0x244f4fa` to `0x2468fa0` |

The adapter names are local descriptive labels. Both wrappers pass a context pointer and the same-shaped three-word input pointer to their callees. Both bodies read the 20-byte recipient identifier from context `+0xd0` and `+0xe0`; both compute from the words at input `+0`, `+8`, and `+0x10`. The source-level names beneficiary, gas limit, remaining gas, refund, effective price and base fee are inferences from this layout, operation order and the source-location suffixes; they are not recovered debug types.

The two code bodies first test the 32-bit field at environment `+0x178` against one, and read four-limb values at `+0x240`, `+0x90`, and `+0x180`. In the one arm, the latter two are added modulo `2^256` and compared unsigned, most significant limb first, with the value at `+0x240`; four conditional moves select the smaller. Otherwise the selected value is the four limbs at `+0x240`. The net callback alone subtracts the `+0x90` value from the selected price and replaces a negative result by four zero limbs. A short human-readable excerpt, whose original bytes are in `anchors.tsv` and `windows.tsv`, is:

```text
0x24690e8  subtract lower three base limbs with borrow propagation
0x24690f1  subtract the high-limb borrow
0x2469101  clear all four result limbs on the underflow path
0x24689a8  subtract input word +8 from input word +0
0x24689b2  subtract input word +0x10 from that difference
0x246899d  set bit 2 at the returned account's +0xb0
```

These lines summarize the instructions; they are not input to the extractor. The flag write precedes both checked subtractions despite being listed later above. The gross callback uses a direct account helper at `0x2460ad0`, and the net callback uses a different helper at `0x24604b0`; neither helper body is selected here.

For concise notation, let `M = 2^256 - 1`, `cap`, `base`, `priority`, and `balance` be the four little-endian-limb values, `mode` the compared word, and `g0`, `g1`, `g2` the three input words. The following expresses the observed local arithmetic, with names inferred as above:

```text
price = cap                                      if mode != 1
price = min(cap, (base + priority) & M)          if mode == 1
quantity = g0 - g1 - g2                          after two unsigned borrow checks
factor_gross = price
factor_net = max(price - base, 0)
product = (factor * quantity) & M
new_balance = min(M, balance + product)
```

Multiplication retains the low 256 bits **before** the independent saturating balance addition. No division or decimal rounding instruction is involved in these selected paths. The formula is a static interpretation of the byte windows, not a claim that every mathematically possible tuple can reach either callback.

### Branch and failure ordering

| Predicate or stage | Local observation |
| --- | --- |
| `mode != 1` | Both bodies bypass the base-plus-priority selection; the net body still applies its base subtraction. |
| Selected price below base | Net body clears all four factor limbs; gross body keeps the selected price. |
| Helper result tag is not `5` | Each body forwards the result record through its local error branch before its own flag or balance stores. Helper side effects are outside scope. |
| Helper result tag is `5` | Both set bit `0x04` at account `+0xb0`, before examining either subtraction. |
| `g0 < g1` | First borrow jumps to its source-location-bearing indirect call; the earlier flag store has already occurred. |
| `g0 >= g1` but `g0 - g1 < g2` | Second borrow reaches a distinct location-bearing indirect-call site; the flag store has already occurred. |
| Four-limb balance addition carries out | Local stores use four all-one limbs. Without that carry they use the calculated sum. |

`branches.tsv` decodes 16 selected conditional instructions from signed branch immediates, including both borrow checks, error forwarding and saturation gates. `indirect-calls.tsv` resolves the four selected failure-call slots through `R_X86_64_RELATIVE` addends; those downstream function bodies are not analyzed. `locations.tsv` follows the location-pointer relocations and records only sanitized path suffixes. The first borrow locations refer to `revm-interpreter-15.0.0/src/gas.rs:66:9`, and the second to `revm-19.2.0/src/handler/mainnet/post_execution.rs:54:57`. These are embedded source coordinates, not proof of the exact source release or of reachable error cases.

### Descriptor availability and limits

`adapter-slots.tsv` scans `.rela.dyn` for symbol-zero relative relocations whose addends are exactly either selected adapter. It finds eight slots for the gross adapter and seven for the net adapter. For each slot, `descriptors.tsv` retains the original 48 bytes from slot minus `0x28`, the file offset and the method relocation. These records each have the observed three-word `0, 0, 1` prefix and three relative method relocations; the other two method bodies are not selected. This is a census only of these two exact adapter addresses in this relocation section, not a census of all equivalent callbacks or proof that a particular running chain selects any descriptor.

### Arithmetic rationale

Write a four-limb factor as `p0 + p1 B + p2 B^2 + p3 B^3`, where `B = 2^64`, and the checked quantity as `q < B`. Each of the first three full limb products splits into a low limb and a high limb. After combining adjacent partial products and propagating carries, terms at weight `B^4` or above disappear, so the four retained limbs equal `factor * q mod B^4`. The fourth multiply's low limb is sufficient for that residue. The later four-limb addition separately tracks its carry out and replaces all limbs with `B - 1` when that carry is set. This explains the distinction between modular multiplication and saturating addition for the full unsigned input width, conditional on the instruction interpretation and ordinary preconditions; it is not a solver-generated proof of a complete machine-code CFG.

When both callbacks receive the same values and `balance + price * quantity <= M`, neither multiplication nor addition wraps or saturates, and gross credit minus net credit is `min(price, base) * quantity`. Outside that stated domain the independent modular products and saturation matter, so the identity is not asserted. The tests exhaust reduced-width limb additions, subtractions, products and a complete miniature local credit path, and use boundary and deterministic full-width vectors; these tests are model checks, not executions of node code.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Rust build, compiler/linker options, two-build comparison, target behavioral comparison and whole-ELF comparison: **not yet implemented/measured**. No normalizing masks or native target comparisons are claimed. The test model implements the four-partial-product arithmetic independently of the direct integer formulas; its synthetic vectors are not transaction captures. It does not model helper internals, dynamic dispatch, aliasing with other operations or panic unwinding.

## Results and limitations

The reproducible selected set contains four FDE intervals, 14 raw semantic windows, 26 fixed instruction anchors, 16 selected conditional branches, four direct calls, four indirect failure-call sites, 15 exact-adapter relocations and four embedded-location references. These are selected-record counts, not coverage of all code or all EVM fork variants. The focused suite includes corrupt digest, FDE start, instruction, descriptor, relocation type, address, opcode and source-suffix controls with no skips. Artifact verification and catalogue freshness are separate repository checks.

No full RE-004 or EVM milestone gate is advanced. Valid transaction-domain bounds, the complete callback installation and replacement sequence, the original source types, lookup/helper behavior, externally observable failures, account persistence and target equivalence remain unresolved. Next question: which independently established revision and hook-installation paths select each descriptor after all replacements, and which transaction bounds constrain the 256-bit inputs before crediting?
