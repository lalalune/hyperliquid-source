# RE-010: trace the node 115 govVote path

This packet identifies the node 115 `govVote` decoding and validation branches and the linked vote-state mutation, making it possible to reconstruct the ordered failure words, signature-selector handling, checked sum, cursor update, and conditional vote-weight change without treating the reference's handler file as a binary function.

- Component ID: `action-dispatch` (RE-010).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; reference tree `999556f6e0a474b8312db96ec3149e1c44e97c23`.
- Claim status: selected byte and relocation observations; semantic names and models are inferences; runtime handoff, helper closure, and implementation equivalence are unresolved.
- Scope included and excluded: the selected outer action container, one `govVote` decoder and an alternate field decoder, validation, selected typed-data and signature-input helpers, the inferred vote-state core, and selected lookup and insertion helpers. This is not a complete CFG, entire dispatcher census, signature-verification proof, node execution, or a component gate.

## Reproduce

Run from the repository root with the authenticated artifact present. The extraction uses Python's standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`; it invokes no external program and never executes the node. We used Python 3.12.3 on Linux x86-64. GNU objdump 2.42 was used only for exploratory human instruction reading, not to generate or test any evidence file. No absolute path, time, locale, or random value enters the generated output.

```sh
python3 tools/re010_gov_vote_115.py --out research/work-items/RE-010-gov-vote-path-115
python3 -m unittest tests.test_re010_gov_vote_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
PYTHONHASHSEED=1 TZ=UTC python3 tools/re010_gov_vote_115.py --out work/re010-gov-a
PYTHONHASHSEED=917 TZ=Pacific/Honolulu python3 tools/re010_gov_vote_115.py --out work/re010-gov-b
diff -r work/re010-gov-a work/re010-gov-b
```

`MANIFEST.sha256` covers this README and the 11 generator-produced files. `identity.json` identifies the input; `functions.tsv` gives file offsets, FDE/CIE coordinates, extents, and body hashes; `bodies.tsv` keeps the complete raw bytes of those selected extents. `windows.tsv` retains selected instruction bytes, and `switches.tsv`, `calls.tsv`, `branches.tsv`, `fields.tsv`, `immediates.tsv`, `literals.tsv`, and `decision-path.tsv` contain the extracted coordinates and operands. All addresses below are linked ELF virtual addresses. End addresses are exclusive. Tables and RIP-relative calls are decoded from binary bytes; relocation addends are accepted only for symbol-free x86-64 RELATIVE records. File offsets are in the TSVs. NOBITS sections are excluded from file-backed VA translation.

## Evidence

### Scope and boundary ownership

The reference file `l1/exchange/handlers/50_gov_vote.rs` is an unlicensed, agent-created split and is used as a naming lead only. The label originally describes #94, whose SHA-256 is `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`; no #94 address or implementation is transplanted into #115. Every #115 coordinate and result below is independently read from the authenticated #115 ELF. The retired RE-014 drift work at repository commit `ed15cdefc503ba2d845939fe7b65bd58b6202c59` had already related the #115 tag-50 execute arm `0x2bdbc02` to wrapper `0x2457a50`; it explicitly excluded handler semantics. The selected central dispatcher is not being claimed again here. The single wrapper call instruction below is linkage context to the newly analyzed core. Shared external helpers, including `0x4556850` from the existing link-staking work, are call boundaries rather than selected bodies.

The target has an FDE starting at `0x2b817d0`; its `govVote` branch target `0x2b81ad2` is an **interior arm**, not a separate FDE entry. Similarly, `0x36c22a0` is an interior arm of `0x36c2050`; its indirect call reaches the separately bounded function `0x44f5650`. Selected starts, exclusive ends, entry-call anchors, and FDE records are in `functions.tsv` and `calls.tsv`. An FDE is evidence for a range, not by itself proof that every neighboring byte or language-level source file has a corresponding function boundary.

### Decode and field failures

| Step | Target-grounded observation |
| --- | --- |
| Outer container | FDE `0x20f00b0..0x20f128a` calls `0x2b817d0` at `0x20f06d3` and `0x20f0a29` on selected map and sequence paths. A duplicate `action` path branches at `0x20f0688`; the diagnostic uses the `action` and `duplicate field` literals. The missing-action and decoder-error paths are retained as windows and branches. |
| Type envelope | `0x2b81827` calls `0x1fccd80`, passing the literal `type`; the selected map route calls the name adapter `0x21dfc90` at `0x1fcd14a`. The type-absent and repeated-type branches reach separate error builders. The adapter has borrowed and owned string arms. |
| Name and tag | Two overlapping four-byte comparisons at `0x2ba1507` and `0x2ba150e` recover the seven bytes `govVote`; `0x2ba151e` stores ordinal `50`. Entry `0x6070f0` leads to `0x2b81ad2`, which supplies the `GovVoteAction` literal and five-field descriptor and calls FDE `0x20aedb0..0x20aff95`. On its non-error path, `0x2b81b44` loads tag `0xb8`; selected box creation allocates and copies `0xf0` bytes. |
| Payload | The primary parser distinguishes kind `0x14` from `0x15`, and a parser error is recognized by byte value `3` at the caller. The descriptor and duplicate/missing paths identify the five names below. The separate FDE `0x20ea750..0x20ebd9c` has matching field names and diagnostics; it is comparison evidence for a different decoder instance, not an asserted direct callee of the selected outer container. |

The primary `0x20aedb0` field routes are listed below. The duplicate target and missing-guard values are directly recovered branch coordinates; a taken or fallthrough direction depends on the documented branch byte in `branches.tsv`.

| Field | Arm | Duplicate branch / target | Missing guard / name literal |
| --- | --- | --- | --- |
| `signatureChainId` | `0x20af0e3` | `0x20af0ec` / `0x20afc49` | `0x20af5df` / `0x455050` |
| `hyperliquidChain` | `0x20af3a5` | `0x20af3ad` / `0x20afb93` | `0x20af5ed` / `0x455a90` |
| `id` | `0x20af28b` | `0x20af293` / `0x20afbee` | `0x20af6e2` / `0x5e5500` |
| `choice` | `0x20af335` | `0x20af33d` / `0x20afb38` | `0x20af6f3` / `0x5e5502` |
| `nonce` | `0x20af1f2` | `0x20af1fb` / `0x20afca4` | `0x20af87c` / `0x5e5508` |

### Tag-specific validation

In the separately bounded router `0x36c2050..0x36c2f99`, subtracting `0x86` from the stored tag selects index `50`. The table entry at `0x79aab8` lands at interior arm `0x36c22a0`. Its RIP-relative call at `0x36c22b5` uses the RELATIVE relocation at slot `0x64e8d90`, whose addend is the FDE start `0x44f5650`. The selected parser output stores the nonce-like value at offset `+0x40` and the chain-like byte at `+0x48`; the validation body compares those offsets against its arguments. Names of the argument fields remain inferred.

| Ordered comparison in `0x44f5650` | Selected result word before returning |
| --- | --- |
| Argument byte differs from payload byte at `+0x48` | `0x93` |
| Otherwise, bit 0 of a control byte at `+0x18` is set | `0x15` |
| Otherwise, control value at `+0x10` differs from payload value at `+0x40` | `0x60` |
| Otherwise, the first control qword is nonzero | `0x90` |
| All four pass | Continue to helpers at `0x46e4ce0` and `0x1536a90`; their selected error path writes `0x7e`, and a selected successful path writes `0x1a2`. |

These are machine result words, not independently recovered public error names. The validation router's non-success and generic fallback paths are separately recorded. The first helper `0x46e4ce0` passes through a 32-byte result on one branch and constructs diagnostics on another. Its selected literals mention JSON serialization, hexadecimal decoding, struct hashing, conversion to a byte array, and a nested EIP-712 struct. These strings identify error context, not a complete implementation of typed-data hashing.

The second helper `0x1536a90` reads eight qwords and a following byte from one input, together with 32 bytes from a second input. Its 29-entry table and two immediate comparisons determine the following selected-byte behavior; the later arithmetic/backend calls are not fully analyzed. The signature-related interpretation is inferred from this layout and its call position.

| Selected byte | Normalized value or branch |
| --- | --- |
| `0` or `27` | `0` |
| `1` or `28` | `1` |
| `2..26` or `29..34` | Error-builder argument `6` |
| `35..255` | Bitwise complement followed by mask `1` |

The first and second backend results each have a separate branch to an error-builder call with argument `3`. The table slots, raw displacements, predicates, input windows, and RELATIVE backend targets are in the generated files. These static cases and their model are not evidence of signature verification against a live node.

### State core, early returns, and writes

The prior execute-wrapper linkage is checked at `0x2457aac`: the instruction addresses RELATIVE slot `0x64e5bc0`, whose addend is `0x3c33f10`, the selected core FDE start. The earlier #115 RE-014 name-to-execute-arm join was itself qualified as an inference; this packet retains that qualification. The parse-to-execute runtime handoff is not observed.

The following rows describe selected normal-return branches in `0x3c33f10..0x3c348ae` in execution order; the prior wrapper is outside this decision table. The descriptive column is an inference from the reference label, key widths, and data flow; the words, comparisons, and branches are byte observations in `decision-path.tsv` and `immediates.tsv`.

| Inferred decision | Observed condition / result |
| --- | --- |
| Proposal lookup | Missing lookup or an out-of-range compact index returns `0x114`. |
| Proposal cursor | Current tuple later than the stored tuple returns `0x117`; equality takes the continuation. The first 32-bit component uses signed comparison; the next two use unsigned comparisons. |
| Repeated voter key | Matching 20-byte key in either selected representation returns `0x115`. |
| Amount | The call through slot `0x64e7980` reaches `0x4221a90`; zero reaches `0x116`. That lookup calls `0x434f410`, whose selected fast and general sum paths test unsigned carry. Its failure result is mapped to zero by the caller. |
| Successful continuation | `0x4221ca0` updates selected cursor-history entries before the optional marker handling and vote insertion. Selected insertion/update paths return `0x1a2`. |

The 12-byte history comparison retains the later of its existing tuple and the supplied proposal tuple. When a 20-byte-keyed marker is present and nonzero, an earlier current tuple permits a left shift by two only if the amount has no bits above bit 61. At or above `2^62` the existing amount is retained; it is not saturated. If the tuple is equal or later, the code clears the marker's first 32-bit component. Whether the marker is a lock and whether the amount denotes voting stake are semantic inferences.

The vote collection uses a sentinel representation and a compact representation. Selected conversion tests compare the count with `32` and `64`. On the compact insertion route, the core passes a 40-byte record containing the 20-byte key, the amount at record offset `+0x18`, and the choice byte at `+0x20` to `0x454c990`; that helper has selected growth, movement, and bounds-failure branches. The tree route calls `0x370a660`, which allocates `0x198` bytes for an empty root or calls `0x3513d50` for a nonempty root; selected capacity checks compare against `11`. Conversion helpers, tree splitting, allocator behavior, and all exceptional rollback paths are not fully resolved.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo graph, build flags, source-to-binary comparison, masks, and whole-ELF equivalence: not yet implemented/measured. No unlicensed reference source is copied. The tests exercise the parser and local models of selected predicates; those models are interpretations of static instructions, not captured execution or a substitute for independent target behavior. They include altered hashes, body bytes and FDE extents, unsupported branch and call opcodes, bad relocation types, invalid or non-file-backed addresses, out-of-range switch indices, invalid names, cursor boundaries, unsigned overflow, the shift cutoff, signature-selector boundaries, and competing failure conditions.

## Results and limitations

The generator records 17 selected FDE extents, 72 selected byte windows, 123 conditional branch sites, 73 call sites, 45 selected switch entries, five field descriptors, 13 literals, and 10 decision rows. These are selected evidence counts, not total function coverage or a matched-window denominator. The focused suite passed 45 tests with zero skips; repeated extraction under different hash seeds and time zones was byte-identical. Artifact and catalogue checks passed. No target binary was executed.

The parsing, validation, and core observations are linked structurally by selected static sites and the prior RE-014 execute-arm join, not by a captured transaction or a complete proof of caller-to-callee dataflow across all surrounding layers. Shared dispatch and lookup bodies are not newly owned here. Global state layout, signer handling, allocation and conversion failure closure, unwinding, and transactional rollback remain open. No component gate or milestone is advanced. Next question: trace the decoded action object's handoff through the unowned callers to the existing execute wrapper, while preserving the boundary with prior dispatcher work.
