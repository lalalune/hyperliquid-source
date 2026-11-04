# RE-021: node 115 BLAKE2b lookup through frame rollback

The node 115 reconstruction can now specify the mode-built direct lookup for address 09, its ordered input errors and conditional frame status, and the record-level reversal needed after an ordinary error.

- Component ID: `evm`; RE-021 is a bounded extension of RE-011, not an official TASKS row.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; historical #94 clues at `cc699eb95941cdf90933f49f4109a4aa32efe0f8` and `2fff9c5e02c5ecd6cb5062f1b23442b5ba712104`. No inferred reference source was copied.
- Claim status: observed ELF bytes, selected FDE intervals, relocations and fixed instruction shapes; inferred names, data-flow relationships, derived registry membership and result semantics; live fork selection, runtime memory, native execution and private fork completeness unresolved.
- Scope included and excluded: one selected initialization-to-frame-to-address-09-to-result path, its direct and general lookup alternatives, input/error precedence, default provider dispatch and the checkpoint journal branches. Other precompiles, hash-secret initialization, allocation/concurrency internals, host calls, exact source provenance, all exception tables and complete EVM state transitions remain outside this packet.

## Reproduce

From the repository root with Python 3.12 and the authenticated node #115 artifact present:

```sh
python3 tools/re21_blake2b_lookup115.py --out research/work-items/RE-021-blake2b-lookup-115
python3 -m unittest tests.test_re21_blake2b_lookup115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

For a separate repeatability check, replace `<tmp-dir>` with an existing writable directory:

```sh
PYTHONHASHSEED=0 TZ=UTC python3 tools/re21_blake2b_lookup115.py --out <tmp-dir>/one
PYTHONHASHSEED=937 TZ=Pacific/Honolulu python3 tools/re21_blake2b_lookup115.py --out <tmp-dir>/two
diff -r <tmp-dir>/one <tmp-dir>/two
```

The generator verifies the full input SHA-256 before reading ELF structures. It uses Python's standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py` readers; it launches no external program and does not execute the node or captured code. SHT_NOBITS is excluded from file-byte reads. Python 3.12.3 was used for this packet. GNU objdump was used only to inspect instructions manually; none of its output is an input to generated files, tables or tests. The generator writes the evidence files below, and leaves this README and MANIFEST alone. `MANIFEST.sha256` covers every other file in this work-item directory.

## Evidence

All addresses are ELF virtual addresses (VAs), not process addresses. Relocation targets are `R_X86_64_RELATIVE` addends before application of the load bias. File offsets, section names, full bytes and FDE/CIE coordinates are in the generated files; for example the record at VA `0x64c0730` is at file offset `0x64be730`. Intervals in `functions.json` come from actual FDEs, with an exclusive end. An FDE interval is not a proof that every machine-code function or semantic boundary is known.

### Selected FDE map

| Role | Start VA | End VA, exclusive |
| --- | --- | --- |
| Mode selection and context | `0x29a1290` | `0x29a5fca` |
| Default-context constructor | `0x5be7910` | `0x5be7dff` |
| Registry once adapter | `0x5bee318` | `0x5bee361` |
| Registry initializer closure | `0x5bee230` | `0x5bee2a0` |
| Mode-dependent registry builder | `0x5c18c60` | `0x5c1a09d` |
| Empty registry and direct array | `0x5c1a260` | `0x5c1a4f6` |
| Four-record extension | `0x5c184e0` | `0x5c18c52` |
| One-record extension | `0x5c17bd0` | `0x5c184dc` |
| General map insertion | `0x5c06830` | `0x5c06b1f` |
| Frame and checkpoint handoff | `0x296e2b0` | `0x297013f` |
| Lookup, callback and result handoff | `0x2a6bc40` | `0x2a6c35e` |
| Direct/general value lookup | `0x2a6c360` | `0x2a6c4bf` |
| Callback-result to frame-status converter | `0x5be6a80` | `0x5be6d5c` |
| Address-09 result adapter | `0x5c165b0` | `0x5c16642` |
| Address-09 input/gas wrapper | `0x5c16650` | `0x5c16863` |
| Provider once adapter | `0x5bee2d3` | `0x5bee318` |
| Default-provider initializer | `0x5bee2a0` | `0x5bee2d3` |
| Feature dispatch | `0x5bebac0` | `0x5bebb28` |
| Scalar compression candidate | `0x5c38870` | `0x5c38d51` |
| Vector compression candidate | `0x5c37750` | `0x5c383ea` |
| Checkpoint revert helper | `0x29710e0` | `0x29712bc` |
| Journal-entry revert dispatch | `0x5be3400` | `0x5be3b49` |

`windows.tsv`, `edges.tsv` and `rip-references.tsv` retain selected byte predicates, relative branches/calls and RIP-relative references. They are not complete x86 disassembly. `functions.json` retains the bytes of the selected FDE intervals, but does not claim every branch or callee within them is resolved.

### Registry construction and mode selection

At `0x29a16eb`, a byte indexed into the inspected table at `0x602d48` selects a 96-byte-spaced slot at `0x64fe070`; the word at slot +`0x58` controls the once adapter. The 15 inspected table bytes are recorded individually in `modes-and-cases.json`; the chosen inspection length does not establish a complete table bound or a named fork. The initialization path passes the selected byte and slot to `0x5bee318`, whose descriptor at `0x64c0020` has a +`0x20` relocation to closure `0x5bee230`. That closure passes the byte to builder `0x5c18c60` and copies its 88-byte result into the slot. Invocation by the shared once machinery is conditional; its synchronization and failure internals remain an external boundary. The context stores the slot at `0x29a1805`, and `0x29a31db` passes that context to frame `0x296e2b0`.

The caller's constructor slot at `0x29a12c6` relocates to `0x5be7910`. On its normal path, that constructor writes byte 13 at stack +`0x70`, then copies the containing 16-byte window from stack +`0x68` to output +`0x260`, placing 13 at output +`0x268`. The caller subsequently loads that field at `0x29a12e1`; inspected mapping entry 13 at `0x602d55` is 6. `default-selector.json` computes the offsets and mapping from these exact bytes. Therefore this default-construction route selects builder mode 6 if the intervening helpers return normally and do not alter the byte; this does not identify a live chain fork or cover alternate context construction. Constructor allocation and validation failure branches are in `edges.tsv`.

The empty constructor initializes 300 records of 56 bytes, totaling `0x41a0` bytes. The first word of each empty record is `0x8000000000000013`, read from the file-backed literal at `0x9428d0`; the allocated array pointer is stored at registry +`0x50`. Allocation has a separate failure target. The builder's three four-record extensions, two single-record calls and subsequent record-copy groups are linked by the selected branch and RIP-reference records. `record-copies.tsv` decodes 84 specific adjacent load/store pairs and checks the assembled destination bytes against the 21 copied source records; the other two records are passed by address. `records.json` contains all 23 source records and their callback relocations.

The following is the constructor-derived lineage, conditional on normal helper completion; it is not a dump of a live registry or proof of the selected fork. Replacements are keyed by the full 20-byte address. Mode values beyond the inspected byte range and later mutations are not validated.

| Builder mode | Changes from previous mode | Derived entries | Address 09 |
| ---: | --- | ---: | --- |
| 0 | Insert 01 through 04 | 4 | absent |
| 1 | Insert 05 through 08 | 8 | absent |
| 2 | Replace 06 through 08; insert 09 | 9 | `0x5c165b0` |
| 3 | Replace 05 | 9 | preserved |
| 4 | Insert 0a | 10 | preserved |
| 5 | Insert 0b through 11 | 17 | preserved |
| 6 | Replace 05; insert 0100 | 18 | preserved |

The 56-byte address-09 source record at `0x64c0730` has tag `0x8000000000000009`, a 20-byte key at +`0x20` ending in `09`, and a callback relocation at +`0x18` resolving to adapter `0x5c165b0`. In the mode-2 block, four actual loads assemble this record into the fourth stack slot before the call at `0x5c18fa5`. The extension checks for an all-zero first 18 bytes and a big-endian last word below 300. Its tag conversion table entry 8 reaches `0x5c18803`; the direct write at `0x5c1886e` stores the converted tag and callback at the indexed slot. The separate map insertion call remains visible at `0x5c18a91`. `conversion-table.tsv` records 19 selected entries; it is a table for value conversion, not a list of all precompile addresses.

### Runtime lookup and callback

For the frame variant selected by the branch at `0x296e394`, the depth argument is checked against 1024 before the checkpoint. After the initial state and depth handling, the path at `0x296e900` passes context +`0x3f0` to `0x2a6bc40`. That offset is the slot stored above: context starts at stack +`0xb10`, and the slot is at +`0xf00`. At `0x2a6bc5a`, the callee dereferences it and uses the 20-byte call-input field at +`0x90` as the lookup key. A lookup miss writes zero at result +`0x58` and enters the caller's non-precompile alternative; it does not invoke address 09.

`0x2a6c360` has two different lookup paths:

| Key or condition | Observed route |
| --- | --- |
| First 18 bytes zero; big-endian final 16-bit number below 300 | Read registry +`0x50`, address `56 * number`, return that direct slot if its first word differs from the sentinel; otherwise return null without consulting the map. |
| Any other 20-byte key; general element count zero | Return null. |
| Other key; general element count nonzero | Use the seed-dependent 16-control-byte grouped lookup described below. |

The constructor-derived mode-2 entry makes key 09 select direct slot 9, with its callback at slot +`0x18`; mode 0 and 1 leave that slot empty. At `0x2a6bcfd` the returned value's +`0x18` field is called. Source callbacks and runtime memory remain conditional on ordinary relocation, successful initialization and no later mutation.

For a general key define `fold(a,b) = low64(a*b) XOR high64(a*b)`, `seed = registry[+0x20]`, `secret = *(*0x64dfa78)`, `u0 = load64le(key[0:8])`, `u1 = load64le(key[8:16])`, and `u2 = load32le(key[16:20])`. The selected byte sequence yields

```text
h = fold(fold(u0 XOR seed, u1 XOR secret) XOR u2, secret)
```

The secret relocation points into NOBITS state and its runtime value is unknown. The hash's high seven bits are the control fingerprint. A 16-byte group is searched for all matching fingerprints and then all 20 key bytes are compared; matches are checked before an empty `0xff` control ends the search. Deleted controls do not terminate it. Successive masked group advances are +16, +32, +48 and so on. Buckets precede controls at 80-byte stride, with the returned value beginning 24 bytes after the key. These rules are modeled with explicitly synthetic seeds and tables; no runtime hash position is claimed.

On a hit, the caller may use the input bytes directly or take a bounded slice of a context buffer. The observed slice path increments a counter and restores it if the start/end arithmetic fails; that failure passes length zero to the callback. A saturated counter takes a separate branch. The meaning and lifetime of this counter and the saturated branch's downstream helper are unresolved.

### Input, provider and output branches

The adapter's relocation slot at `0x64eaee8` points to `0x5c16650`. The wrapper checks length first, then a four-byte big-endian rounds count against the supplied gas, then the byte at offset 212. The following statuses are inferred from the adapter, the converter at `0x5be6a80` and its caller, conditional on successful helper returns and an unmodified callback result:

| Condition, in precedence order | Inner result word | Frame status byte | Checkpoint route |
| --- | --- | --- | --- |
| Length is not 213 | `0x8000000000000002` | `0x31` | revert |
| Gas is less than rounds | `0x8000000000000001` | `0x23` | revert |
| Final flag is at least 2 | `0x8000000000000003` | `0x31` | revert |
| Valid input, provider returns, output allocation succeeds | output length 64, cost rounds | `0x02` | release depth |

Thus zero rounds with zero gas passes these input checks; an underfunded input with an invalid flag reports the gas error first. The wrapper copies 64 state bytes at input +4, 128 block bytes at +68 and 16 counter bytes at +196, then calls provider vtable +`0x58` with rounds, these buffers and the flag. It allocates a 64-byte output after the call; allocation failure reaches a separate failure helper and is not an ordinary result in the table. No compression output is asserted here.

When the frame depth is exactly one, the length and flag errors have a diagnostic branch before the result converter. The table at `0x6031b4` selects the file-backed literals `wrong input length for blake2` and `wrong final indicator flag for blake2`; `diagnostic-cases.json` records their addresses, bytes and lengths. The gas-error tag bypasses this branch. The diagnostic route also updates a context field at +`0x3a0`; behavior of its allocation, formatting and cleanup helpers is not fully established. Status conclusions assume that route reaches the ordinary converter rather than unwinding.

The initialized default provider object uses the vtable at `0x64bff60`; its +`0x58` relocation points to `0x5bebac0`. That routine consults a writable CPU feature word and jumps to scalar `0x5c38870` or vector `0x5c37750`. For the scalar candidate, `scalar-immediates.tsv` records all eight BLAKE2b IV-shaped immediates and the conditional complement of IV6; `windows.tsv` also records representative rotation instructions, zero-round branch and eight state-word writes. This independently cross-checks the compression clue on #115, but does not prove either backend's complete round equivalence, feature initialization, or a captured digest.

### State change and error rollback

For the selected frame variant, `0x296e4ed` snapshots three fields, then `0x296e539` increments context +`0x388`. Depth greater than 1024 follows the separate `0x11` status path before this checkpoint. After a normal callback conversion, frame status below 5 reaches `0x296eb4e`, which decrements that field with saturation at zero. Status at least 5 reaches `0x296f08f`, calling `0x29710e0` with the saved checkpoint. The converter's normal status values above therefore distinguish these routes; fatal/unwind paths are not assigned to them.

The revert helper decrements the depth-shaped field, truncates an 80-byte-stride collection when its saved length permits, clips another saved length, then walks 88-byte records in reverse from the current length to the saved length. A record tag of 12 stops this walk. For other selected tags it calls a handler through relocation slot `0x64e6d68` to `0x5be3400`. The 12 table entries below are decoded directly from `0x942248`; arbitrary corrupt tags are not validated and no claim is made about tags beyond this inspected range. Lookup helpers and their null/failure calls are separate boundaries. Field names below are deliberately expressed as offsets.

| Record tag | Handler VA | Selected observed write or branch |
| ---: | --- | --- |
| 0 | `0x5be3427` | Set bit `0x10` in looked-up object's byte +`0x8c`. |
| 1 | `0x5be365e` | Conditional flag mask; add four limbs at +`0x28..0x40`, and for distinct keys subtract them from a second looked-up object. |
| 2 | `0x5be358e` | Conditionally clear bit `0x04` at object +`0x8c`; one key/flag combination bypasses the clear. |
| 3 | `0x5be35dc` | Restore 32 entry bytes to object +`0x28..0x47`. |
| 4 | `0x5be34be` | Add four limbs to one looked-up object, subtract them from another. |
| 5 | `0x5be36bf` | Restore entry +`0x18` to object +`0x68`. |
| 6 | `0x5be36f1` | Decrement object +`0x68`, saturating at zero. |
| 7 | `0x5be361d` | Apply a flag-derived mask at object +`0x8c` and clear +`0x68`. |
| 8 | `0x5be3915` | After two lookups, restore 32 bytes to nested object +`0x20..0x3f`. |
| 9 | `0x5be3536` | After two lookups, set nested object byte +`0x44` to 1. |
| 10 | `0x5be372b` | Null context skips; a zero 32-byte value and nonzero value enter different helper/map paths. |
| 11 | `0x5be3458` | Restore the 32-byte literal at `0x4585a0` to object +`0x48`, release a referenced value conditionally, and clear object +`0x70`. |

`journal-cases.tsv`, the `journal_*` windows and the selected missing-lookup edges preserve the byte-level support. These operations describe individual records; no claim is made that address 09 necessarily creates every tag, that all account fields have source-level names, or that a whole transaction is rolled back correctly in all exceptional paths.

### Cross-release provenance and source clues

Historical node #94 had SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Its retained runtime packet reports a 48-byte source record at `0x574f0a8`, a callback slot at `0x574f0b0` to `0x4e9d2a0`, and a hash lookup. Its retained compression review identifies candidate `0x4e9a8a0` while explicitly leaving the captured-execution receipt pending. The #94 artifact is not available to this packet, so those are historical reports, not newly rerun #94 byte observations.

The independently read #115 56-byte record, +`0x18` callback, direct-slot lookup, input predicates, scalar immediates and explicit BLAKE2 diagnostic literals above cross-check the limited identity clues while establishing different #115 coordinates and layout. Neither release's offsets are transplanted into the other. The `z_vendor/revm-handler/src/frame.rs` and `z_forks/revm-precompile/src/lib.rs` suffixes in `modes-and-cases.json` come from two binary diagnostic descriptors. They support the presence of those source-path labels only; they do not establish a dependency version, exact source body, complete private fork boundary, or a live fork selection.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo dependency graph, compiler/linker settings, rebuilt byte comparison, normalization masks, differential execution, helper/data closure and whole-ELF equivalence: **not yet implemented or measured**.

The standard-library models cover direct vs general lookup, fixed-width hash folding, grouped probing, wrapper decisions, result-status selection and saturating decrement. Their inputs, seeds and expected decisions are synthetic, not node execution or captured fixtures. The synthetic grouped-map model requires a power-of-two capacity of at least 16; smaller tables and physical mirrored-tail layout are not modeled. The focused suite has 26 passing tests and zero skips. Negative controls include wrong target hash, NOBITS/ambiguous/out-of-range and cross-boundary reads, missing or duplicate FDEs and relocations, mutated opcode/relative target/record copy/default selector/immediate/diagnostic table, a 13th out-of-range journal table entry, every bit of a 20-byte key, group wrap and deleted controls, an independent 32-bit-limb multiplication check, malformed maps, gas boundaries and error precedence. Freshly generated files are compared byte for byte with the committed evidence.

## Results and limitations

`summary.json` records 22 selected FDE intervals containing 50,479 bytes; 100 selected byte predicates, 91 selected direct edges, 27 RIP references, nine immediate values, 14 relocations, 23 source records, 84 decoded copy pairs, 19 value-conversion entries, 12 selected journal entries, two diagnostic cases and 15 inspected mode bytes. These are explicitly selected evidence counts, not total functions, complete branch coverage, matched windows or a component completion percentage.

The EVM component remains **0/4**. In particular, the first component task asks for the full reth/revm private-fork boundaries and all state-transition inputs; these selected diagnostics and one call path do not satisfy it. No progress gate or catalogue is changed. The remaining gaps include private overrides and fork selection, arbitrary registry mutation, dynamic vtables, allocator and hash-seed behavior, exception/unwind closure, full compression rounds, externally observable semantics and any independently validated Rust implementation.

Next question: bind an actual HyperEVM fork input to the mode byte and a specific installed provider, then independently reconstruct and validate the conditional direct-slot and checkpoint behavior under a separately authorized differential protocol.
