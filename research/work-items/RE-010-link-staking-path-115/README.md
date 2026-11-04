# RE-010: Trace the node 115 link-staking action path

Node #115's internal tag `0x91` reaches a separately callable wrapper that selects a one-write pending request or a two-write finalization path, allowing a reconstruction to preserve key order, state changes, failure precedence, and the actual call boundary.

- Component ID: `action-dispatch` (RE-010).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; investigative reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is an unlicensed lead, not implementation source.
- Claim status: selected static observations; the action name, the identities' real-world roles, and container types are inferences as distinguished below. Source-level boundaries and the full execution environment remain unresolved.
- Scope included and excluded: the parent caller's selected child, selector and gates, one dispatch arm, both wrapper branches, selected relationship lookups and writes, and normal failure returns. Other actions, complete callers and helper closure, external wire decoding, target execution, and a Rust reconstruction are excluded.

## Reproduce

From the repository root, with Python 3.10 or newer and the authenticated node artifact:

```sh
python3 tools/link_staking_path_115.py --out research/work-items/RE-010-link-staking-path-115
python3 -m unittest tests.test_link_staking_path_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

For independent deterministic outputs, set `TMPDIR` to a writable temporary directory:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/link_staking_path_115.py --out "$TMPDIR/link-staking-a"
PYTHONHASHSEED=987 TZ=Pacific/Honolulu python3 tools/link_staking_path_115.py --out "$TMPDIR/link-staking-b"
diff -r "$TMPDIR/link-staking-a" "$TMPDIR/link-staking-b"
```

The generator first checks the full input digest, then uses the repository's `elf_index.py` and `fde_extents.py` to decode file-backed sections and indexed FDEs. It checks complete, unmasked function-range hashes and decodes only the specified branch and RIP-relative forms. It reads RELA entries and the dynamic symbol table directly. It does not call binutils or execute the target. Raw range bytes, instruction bytes, offsets and records are retained in the generated TSV files; `MANIFEST.sha256` hashes this packet's files. Investigative excerpts below were checked using GNU objdump 2.42 on Linux x86-64 with Python 3.12.3; the generator and tests do not use objdump output. Output is independent of time, hash seed, time zone, and the output-directory name.

## Evidence

Addresses are linked ELF virtual addresses; `functions.tsv`, `switches.tsv`, `edges.tsv`, `indirect.tsv`, `relocations.tsv`, `constants.tsv`, `dataflow.tsv`, and `literals.tsv` also give file offsets. Ends are exclusive. FDE records are unwind ranges: direct calls to their starts, entry instructions, returns, selected control flow and table destinations corroborate these callable entries, but do not prove complete original source functions or exclude split cold code.

| Selected role | Unwind-described range | Relevant observation |
| --- | --- | --- |
| Parent caller | `0x5536770..0x5537059` | Gets the child pointer, handles preliminary rejections, calls the selector, gates, and dispatch. |
| Child selector | `0x4e10080..0x4e103e9` | The selected index writes two zero fields and the inner success word. |
| First / second gate | `0x5551140..0x555153b` / `0x5551540..0x5551914` | Both return success for this selected empty input. |
| Gate iterator | `0x51e4c80..0x51e502a` | The selected empty state returns a zero item. |
| Action dispatch | `0x55f99b0..0x55faa79` | The selected table arm calls the action wrapper. |
| Action wrapper | `0x58c07d0..0x58c08b8` | Selects the request or finalize path using one payload byte. |
| Request prerequisite | `0x5611bd0..0x5611d79` | Performs the staking-key lookup before the request core. |
| Request / finalize cores | `0x469fa60..0x469fe8d` / `0x469fe90..0x46a02ea` | Check relationship state and call the shared writer. |
| Relationship writer | `0x3ce1080..0x3ce15ad` | Replaces or inserts a key/value in compact or tree representations. |
| Compact lookup / insertion | `0x4559130..0x455936b` / `0x4546140..0x4546245` | Search 20-byte keys and insert compact records. |
| Tree insertion | `0x370caf0..0x370cc37` | Includes the empty-root allocation and node-bound checks. |
| Staking compact lookup | `0x4556850..0x4556a4d` | Its zero result is taken as a found key in the request prerequisite. |
| Independent formatter | `0x2bcbbf0..0x2bce565` | The same index selects the `linkStakingUser` literal. |

### Tag, caller and actual entries

At entry the parent saves a pointer to its 20-byte third argument and copies its contents. Before looking at the child, it computes a second 20-byte gate key using the following branches; the collection names and public identities are not established. Selected instruction-aligned raw slices for these cases are in `dataflow.tsv`.

| Condition before child selection | Observed gate-key selection |
| --- | --- |
| The first lookup in the structure at state offset `0xa18` misses | Copy the original third-argument key as the default gate key. |
| That lookup misses and the count at state offset `0x3cb0` is zero | Keep the default. |
| That lookup misses, the count is one, and the entry key matches | Replace the gate key with the 20 bytes at entry offset `0x1c`; a mismatch keeps the default. |
| That lookup misses and the count exceeds one | Opaque helpers search; a miss keeps the default, a valid match selects the entry at stride `0x30` and offset `0x1c`. An out-of-range returned index goes to the branch at `0x5537025`. |
| The first lookup succeeds | Load its candidate 20-byte value and perform a second lookup; choose either that candidate or the second result at pointer offset `0xa0`. |

The parent then reads a child pointer from its fourth argument at offset `0x18`. On the selected path it calls the selector at `0x5536d3f`, checks its result, calls the first and second gates, and calls the dispatch entry at `0x5536e14`. At that last call it passes the child pointer as the fifth argument and the original third-argument pointer as the sixth. A preliminary classifier controls whether two subsequent 20-byte lookups run; an equal comparison can instead return inner word `0x120` and outer tag `0x0f`. The classifier's implementation is outside this packet. Selector or gate failures are propagated by separate branches in the parent; those generic branches are retained even though the selected empty case below takes the success paths.

Each of three independently indexed functions subtracts `0x86` from the child discriminant and uses a signed-relative jump table. For the range represented by the target's `variant index 0 <= i < 92` literal, index 11 has these entries:

| Purpose | Table entry VA | Selected target VA | Selected evidence |
| --- | --- | --- | --- |
| Formatter | `0x609608` | `0x2bcca03` | The arm refers to the 15-byte `linkStakingUser` literal at `0x60c4eb` and `LinkStakingUser` at `0x60dced`. |
| Selector | `0x915cd0` | `0x4e100cd` | Writes zero at result offsets `0x8` and `0x18`, then word `0x1a2`. |
| Dispatch | `0x927b34` | `0x55f9efe` | Advances the child pointer by `0x8`; the direct call at `0x55f9f10` targets `0x58c07d0`. |

Thus the observed internal discriminant is `0x86 + 11 = 0x91`. The formatter and executor using the same action representation is an inference supported by these matching indices, the payload use and the action-specific error strings below; the external decoder-to-executor handoff is not proven. Values below `0x86` select index `0x14` in the pinned instructions. The 92-entry recording is a bounded window based on the literal; it does not establish the complete table length or valid discriminant domain. All 92 recorded targets of each selected table fall within that table user's FDE; this is a bounded table check, not a function census.

The parent forwards the selector's two zero fields to the first gate, whose empty branch returns `0x1a2`. The selector arm does not write the intervening word; it is copied onward, but the selected empty iterator branch does not dereference it. The second gate forms a zero-count iterator; its iterator returns a zero item and the second gate also returns `0x1a2`. For valid memory on this selected route, neither generic gate failure branch is taken. The selected dispatch arm is inside the dispatch FDE, whereas `0x58c07d0` is a distinct indexed FDE and direct-call target. A source file created for a handler is therefore not evidence for a single original function boundary.

A short human-readable excerpt, with raw bytes also retained in `windows.tsv` and destinations in `edges.tsv`, shows the handoff:

```text
55f9efe: 49 83 c4 08          add r12, 8
55f9f10: e8 bb 68 2c 00       call 58c07d0
58c07db: 80 7e 3d 00          cmp byte [rsi+0x3d], 0
58c07df: 0f 84 8c 00 00 00    je 58c0871
58c0815: ff 15 65 72 c2 00    call [rip+0xc27265]
58c089a: e8 31 13 d5 ff       call 5611bd0
```

The RIP-relative slot at `0x64e7a80` has an `R_X86_64_RELATIVE` addend of `0x469fe90`; the request prerequisite's slot `0x64e7f20` resolves similarly to `0x469fa60`. These are static relocations, not observed runtime calls. The original payload is at child offset `0x8`; the wrapper's second 20-byte input is at payload offset `0x28`, and the mode byte is at payload offset `0x3d`. Thus those are child offsets `0x30` and `0x45`. The original third-argument pointer is forwarded to the wrapper; the separately selected gate key does not replace it.

### Branch and state table

The following is a static interpretation of normal paths with valid container invariants and successful error-string allocation. Let `P` be the 20-byte payload key, `C` the 20 bytes loaded by the wrapper through the forwarded third-argument pointer, and the relationship record be a key plus a one-byte tag and 20-byte peer. These labels do not by themselves prove a public account identity. The diagnostic strings support the inferred roles `A` = staking key and `B` = trading key.

| Mode and condition in machine decision order | Inner result | Selected state effect |
| --- | --- | --- |
| Mode zero: `A=P`, `B=C`; the prerequisite lookup for `A` is absent | `0x16f`, `Staking user has no staked HYPE` | No relationship write. |
| Mode zero: `A == B` after the prerequisite | `0x16f`, `Cannot link a staking user to itself` | No relationship write. |
| Mode zero: record `B` exists and its tag is nonzero | `0x16f`, `Trading user already has a link established` | No relationship write. |
| Mode zero: record `A` exists and its tag is nonzero | `0x16f`, `Staking user already has a link established` | No relationship write. |
| Mode zero: preceding checks pass | `0x1a2` | Upsert `B -> (tag 0, A)`; an existing tag-zero `B` may be replaced. |
| Mode nonzero: `A=C`, `B=P`; record `B` is absent, has a nonzero tag, or its peer differs from `A` | `0x16f`, `Trading user must request before staking user` | No relationship write. |
| Mode nonzero: matching pending `B` exists, but `A` has a nonzero tag | `0x16f`, `Staking user already has a link established` | No relationship write. |
| Mode nonzero: preceding checks pass | `0x1a2` | Upsert `B -> (tag 1, A)`, then `A -> (tag 2, B)`, in that order. |

The nonzero wrapper path goes directly to the finalize core; it does not call the selected request prerequisite. This does not rule out other checks in its callers. A wrapper receiving inner word `0x1a2` writes outer tag `0x0e`; otherwise it copies the error result and writes `0x0f`. The dispatch tail then copies its result to the caller. These numeric words and tags are observations; interpreting them as success/error encodings follows the control flow and is not a wire-format claim.

The request core tests key equality before its two relationship lookups. Both cores treat a zero tag differently from any nonzero tag; their records use 20-byte keys and 21-byte values. On a found compact entry, `0x3ce14aa` and subsequent stores replace the 21-byte value. On an absent compact entry, `0x4546140` increments the count and copies a 41-byte key/value record. `0x3ce1080` recognizes the tree sentinel `0x8000000000000000`, checks a tree-to-compact path below 32 entries, and a compact-to-tree path for an absent key at 64 or more entries. `0x370caf0` requests `0x1d0` bytes for an empty tree node and checks a local bound of 11. These are selected instruction-level facts, not a complete container specification; tree balancing and all allocation and unwind behavior remain unproved.

### Historical lead

The retired #94 packet `research/work-items/RE-010-exchange-handlers/README.md` at repository commit `c3b77a8e84c3f2b10db7a2a69b6b66bfddea93d4` reports node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, case 11, internal tag `0x7f`, dispatcher arm `0x2759849`, and first callee `0x1e60770`. These are #94 ELF VAs, not #115 addresses. The #115 formatter, three table entries, branch bytes, FDEs, relocations, diagnostics and writes were read anew from the authenticated #115 ELF as described above. The old artifact was not independently rerun here, and no cross-release byte or semantic equivalence is claimed. The unlicensed `handlers/11_link_staking_user.rs` is a lead rather than evidence of one original #115 function.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Two-build results, compiler and linker provenance, raw/normalized source comparison, and whole-ELF comparison: **not yet measured**. All captured windows here are raw and unmasked. The selected evidence comprises 16 indexed FDEs, 107 fixed direct edges, 31 dataflow slices, 5 indirect call sites, 3 relocation records, 8 literal references, and 92 bounded entries in each of three tables. These selected counts are not a component coverage denominator. The small Python transition model in the tests is an interpretation of the recorded normal branches; its inputs are synthetic, and it does not execute, emulate, or differentially compare the node.

## Results and limitations

The focused unittest module passes 30 tests with no skips, including wrong digest, changed function bytes, changed branch opcode/displacement, out-of-range table target, duplicate/missing/corrupted relocations, and non-file-backed/ambiguous address controls. It also checks request/finalize ordering and error precedence with synthetic 20-byte keys. Separate generator runs with different hash seeds and time zones are compared byte for byte, including with a PATH lacking binutils. Artifact signature verification and catalogue consistency are separate checks. No target binary or network service is run. No progress gate is requested.

The upstream meaning of the preflight collections, the parent classifier and general gate implementations are only partially traced; the external decoding and signature/nonce handoff, caller census, helper and relocation closure, tree splitting/rebalancing, malformed in-memory objects, allocator failure and unwinding are not established. Exceptional behavior between the two normal writes in finalize remains unresolved. The observed #115 copies do not establish equivalence to the #94 lead or to any future implementation. Next, trace the selected child from its decoder and establish the remaining tree mutation and exceptional paths before writing and comparing Rust.
