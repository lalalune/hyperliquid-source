# RE-004: margin-tier projection, rounding and tree-layout bridge in node #94

The node #94 tier-view path converts each u64 threshold to binary64 before dividing by one million, and its 48-byte view can be inserted into a keyed tree whose layout matches a separate tier field writer; a reconstruction can preserve both rounding stages and this key/value layout.

- Component ID: RE-004, quantities and rounding, margin-tier views.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead only; no reference code is copied.
- Claim status: observation for bytes, FDE extents, selected branches, calls, field literals and layout offsets; conditional mathematical inference for the floating conversion; inference for the economic meaning and the relationship between separately observed producer and writer.
- Scope included and excluded: two projection entries, a tier iterator, the selected simple-insert tree layout, a separate tree-to-field path, selected success and error edges, and the full-u64 arithmetic argument under stated floating-point assumptions. Excluded are proof of runtime handoff between the collection and writer, complete tree split/merge semantics, full callee effects, input reachability, runtime floating-point mode, node #115 and execution of captured artifacts.

## Reproduce

Run from the repository root on Linux x86-64 using Python 3.12.3 and the standard library. The tool checks the complete target SHA-256 before parsing, imports the shared `tools/elf_index.py` and `tools/fde_extents.py`, resolves only file-backed sections, and invokes no external programs. It reads the captured binary and writes only the requested evidence directory; it does not execute the binary or use the network.

```sh
python3 tools/artifacts.py verify
python3 tools/margin_tier_scale94.py --out research/work-items/RE-004-margin-tier-scale-94
python3 -m unittest tests.test_margin_tier_scale94
python3 tools/catalogue.py --check
(cd research/work-items/RE-004-margin-tier-scale-94 && sha256sum -c MANIFEST.sha256)
PYTHONHASHSEED=1 TZ=UTC python3 tools/margin_tier_scale94.py --out <tmp-dir-a>
PYTHONHASHSEED=93 TZ=Pacific/Honolulu python3 tools/margin_tier_scale94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
```

The two placeholders denote distinct, initially empty writable directories. The generator writes the 15 evidence files in this directory; the manifest also binds this README. `evidence.json` includes full range bytes and hashes, `functions.tsv` gives each FDE and file offset, `anchors.tsv` retains selected exact byte windows, and `branches.tsv` and `calls.tsv` decode selected edges from bytes. The model tables are predictions derived from those qualified windows, not target executions. GNU objdump 2.42 was used only for human inspection of candidate ranges and was not used by the generator or tests.

## Evidence

All addresses are linked, unrebased node #94 ELF virtual addresses; `functions.tsv` gives their file offsets. FDE ranges are unwind-described extents, supported by the observed entry instructions and returns. They do not establish every entry point or a complete function census. The analysis was completed for the selected byte windows; it is not a full CFG or tree implementation analysis.

| Stage | FDE range, exclusive end | Observed role |
| --- | --- | --- |
| Request wrapper | `0x2587110..0x25872ee` | Calls the selector/lookup and carries the returned payload. |
| Selector and lookup | `0x27db850..0x27dbe50` | Applies lookup and selector gates, then calls the converter. |
| Collection builder | `0x2a0a830..0x2a0aa58` | Builds 56-byte key/view records and invokes tree construction. |
| Collection walker | `0x2a22900..0x2a22bb9` | Pairs a 32-bit key with the projected 48-byte view. |
| Tier iterator | `0x2a0a230..0x2a0a434` | Returns a source key pointer and value pointer. |
| Tier converter | `0x2a25ed0..0x2a260d6` | Emits a vector of 16-byte threshold/byte rows. |
| Tree insertion | `0x2a08270..0x2a08e05` | On the selected simple-insert edge, writes keys and 48-byte values to separate node arrays. |
| Keyed tree adapter | `0x2a02f50..0x2a03238` | Has an ordinary named-field path and a special-state field-name guard. |
| Tree pointer collector | `0x2a14370..0x2a1465e` | Extracts key and value pointers using matching node offsets. |
| Tree writer adapter | `0x2a18b90..0x2a18c53` | Calls the pointer collector and pair-list writer. |
| Pair-list writer | `0x29eedf0..0x29ef02e` | Walks 16-byte pointer pairs and handles per-pair errors. |
| Pair field writer | `0x2a30410..0x2a30584` | Reads a 32-bit key and passes its value pointer to the view field builder. |
| View and tier field builders | `0x2a31610..0x2a3166b`, `0x2a260e0..0x2a2622a`, `0x29ff1b0..0x29ff3e1`, `0x29f4270..0x29f449e`, `0x2a26230..0x2a2637a`, `0x2a02870..0x2a02a18` | Independently consume a compatible view and name its fields. |

The direct and relocation-qualified calls establish these separate paths:

```text
0x2587110 -> 0x27db850 -> external getter -> 0x2a25ed0 -> 0x2a0a230
0x2a0a830 -> 0x2a22900 -> 0x2a25ed0 -> 0x2a0a230
            -> 0x2a08270  (collection construction after the walk)
0x2a02f50 -> 0x2a18b90 -> 0x2a14370
                        -> 0x29eedf0 -> 0x2a30410 -> 0x2a260e0
                                                      -> tier field builders
```

The lines group calls, not a claim that the collection builder calls tree insertion from inside the walker. The table producer and field writer have compatible layouts; an ownership or call edge connecting those two independently observed paths has not been traced.

### Projection, branches and failure order

For the first entry, a lookup tag other than `0x186` bypasses the converter. A successful lookup with selector below 50 proceeds to the getter. At 50 or above, a custom-key search that misses takes tag `0x154`; a hit proceeds to the getter. The getter's first word selects a pointer and later cleanup. The six copy windows in `response-flow.tsv` carry the 48-byte result to the request wrapper output on the normally returning path, assuming intervening callees do not mutate the saved bytes.

The converter clones a description, treats a null tier root as an empty vector, checks the vector allocation size, then calls the iterator until exhaustion. It loads an eight-byte key and byte `+0x18` from the associated value. It writes a binary64 word followed by that byte into each 16-byte output row. A failed nonzero allocation reaches an error helper. Invalid iterator state or a required missing parent reaches an error helper followed by `ud2`; behavior on other malformed memory is not established.

The collection builder checks a 56-byte-per-entry allocation. A normal zero-element result takes the empty path, one element skips both preparation helpers, 2 through 20 elements take a direct helper, and at least 21 take an indirect helper. The largest accepted count is 164703072086692425; a larger declared count reaches the allocation-size error. The preparation, sort, allocation and tree split helpers are call edges, not reconstructed implementations. `selector-cases.tsv` and `collection-cases.tsv` are models of the qualified gates and assume normal helper returns where stated.

### Key/value layout bridge

`0x2a22900` writes each projected 48-byte view after a 32-bit key in a 56-byte intermediate row. On the simple-insert edge, `0x2a08270` admits a node count below 11 and stores the key as a 32-bit word at `node + 0x218 + 4*i`; it stores the six view words at `node + 48*i`. The node count is at `+0x246`, and the collection builder's initial node allocation is `0x248` bytes. Other node allocations and the split path are not covered by that size observation.

Independently, `0x2a14370` forms a key pointer at `node + 0x218 + 4*i` and a value pointer at `node + 48*i`, then writes a 16-byte pointer pair. `0x29eedf0` walks those pairs. `0x2a30410` dereferences the first pointer as a 32-bit key and passes the second pointer to `0x2a260e0`, whose downstream builders use the keys `description`, `marginTiers`, `lowerBound` and `maxLeverage`. This establishes compatible byte layout and a separate caller-to-field chain; it does not establish that any particular produced tree is passed to this writer.

The simple-insert guard and store/load bytes are independently checked. For all eleven slot indices, the value region ends before the key array, and the key array ends before the count field. The 44 synthetic cases cover those indices with four u32 boundary keys and arbitrary 48-byte payloads. They exercise a layout model, not the target instructions. Other insertion, duplicate-key, node split and malformed-tree branches are outside this layout proof.

The ordinary path of `0x2a02f50` clones a nonempty field name before calling the tree writer; allocation failure bypasses that call. Its special state instead requires the exact 30-byte key `$serde_json::private::RawValue`: a different length or key bytes take an error helper, while the matching key selects another external call. The separately recorded `marginTables` literal is 12 bytes and thus does not satisfy that special-state check. `keyed-cases.tsv` records the qualified branch model; it does not establish the incoming writer state.

### Numeric inference

At `0x2a26001..0x2a26028`, the integer bits are unpacked with constants at `0x203e80`, the two floating biases at `0x202ea0` are subtracted, the lanes are added, and the result is divided by the binary64 constant at `0x20ae60`. The divisor bits `0x412e848000000000` encode exactly 1,000,000. The target does not set a rounding mode in this window.

Under IEEE binary64 round-to-nearest, ties-to-even and masked exceptions, the two lane subtractions are exact and produce the low 32 bits and the high 32 bits times `2^32`. The addition rounds the full u64 once, and the division rounds again:

```text
RN64(RN64(u) / 1000000.0)
```

This argument covers every u64 input conditionally on the lifted instructions and floating-point assumptions. The exact rational `u / 1000000` has a binary64 representation exactly when `u` is divisible by 15625: after cancelling the odd factor, the remaining denominator is a power of two and the remaining numerator has at most 51 bits. This property of the exact ratio does not imply the two-step calculation preserves it.

`integer-bins.tsv` partitions the entire u64 domain by binary64 integer spacing. Below `2^53` every integer converts exactly; in each binade from `2^53` through `2^64`, the spacing doubles at the next power of two. Counting one exact integer per spacing interval gives exactly `13/4096` of all u64 inputs an exact first conversion; each of the eleven upper binades has `2^52` halfway ties. These are counts over a mathematical input space, not a frequency estimate for actual tier values, and they describe the first rounding only.

An equivalent integer lift sets `shift = max(0, bit_length(u) - 53)`, keeps the high bits and rounds them upward only when the discarded bits exceed halfway or equal halfway with an odd retained part. `rounding.tsv` records the resulting exact, down, up and ties-to-even branches for the selected inputs. For `u64::MAX`, the rounded binary64 value is the integer `2^64`: a bitwise reconstruction using an integer intermediate therefore needs a type wider than u64 for that result. This does not assert an integer cast occurs in the target; its instructions use floating-point lanes.

The first adjacent u64 values that the model maps to the same final binary64 are `8589934592000001` and `8589934592000002`, both producing bits `4200000000000001`. Their initial integer conversions are distinct and exact, so this collision occurs during division. For the proof, rounding cells centred below `2^33` are no wider than `2^-20`, less than the `10^-6` step between inputs; the asymmetric cell centred at `2^33` is checked separately, as are the first two inputs after it. `proof.json` records the exact rational spacing comparisons and boundary values. This is an all-input mathematical result under the stated mode, not evidence that either tier is valid or reaches the writer.

| Synthetic u64 | Two-step bits | Once-rounded exact ratio bits | Meaning |
| --- | --- | --- | --- |
| 9007199254740993 | `4200c6f7a0b5ed8d` | `4200c6f7a0b5ed8e` | The initial integer conversion loses one. |
| 9223372036880000000 | `42a0c6f7a0b61fff` | `42a0c6f7a0b62000` | The exact ratio is the integer 9223372036880, but the two-step result is one representable value lower. |

The 255 synthetic rounding vectors contain four two-step differences. Reachability of either witness in a valid tier is unknown.

The same assumptions give an absolute error bound for the entire u64 domain. The integer-to-binary64 conversion loses at most 1024, attained at `2^63 + 1024` by a ties-to-even conversion. Its contribution after division is at most `16/15625`. The largest possible intermediate quotient is below `2^45`, so the final binary64 division rounds by at most `1/512`. By the triangle inequality the final result differs from the exact rational by at most `23817/8000000` (0.002977125). This is a conservative bound, not a claim that the final error reaches it. `proof.json` records its exact factors and the integer-conversion witness.

The separate [RE-007 margin-path packet](../RE-007-margin-path-94/README.md) reports a first lower bound of zero and an upper limit of `10^15` on later bounds along its tier-admission path. If every key reaching this converter has passed that admission without an unchecked later change, every such key is below `2^53`, so its integer-to-binary64 conversion is exact. The final division can still round, but the absolute difference from the exact ratio is then at most `2^-24`: the quotient is at most `10^9`, below `2^30`. At that magnitude the maximum binary64 spacing is `2^-23`, smaller than the `10^-6` input step after division, so the mapping is strictly increasing throughout this restricted interval. This conditional bound makes the large collision and double-rounding witnesses above unreachable under that premise; this packet does not establish that all converter inputs satisfy it.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo lockfile, compiler and linker flags, two-build comparison, raw and normalized byte comparison, masks and complete helper/data/relocation closure are not yet measured. This packet makes no binary-equivalence claim.

The focused suite has 28 tests and no skips. Controls reject an altered input hash, FDE end, body, response-copy window, branch opcode and displacement, direct call, relocation, key name, tree key offset, payload stride, special-name bytes and invalid input ranges. Arithmetic checks include every binade boundary, the first output-collision boundary, tie-to-even cases, the separately reported admission cap and 2243 deterministic comparisons against host binary64; those host checks are not target executions. The two independent regenerations used different hash seeds and time zones with binutils absent from PATH and produced identical files.

## Results and limitations

The generated evidence records 18 selected FDEs, 34 byte windows, 67 selected conditional edges, 24 calls, six response-copy stages, four field names, 12 integer-spacing bins, 255 rounding vectors, 44 synthetic node-layout cases and seven synthetic field-gate cases. The decoded bounds and the full-u64 algebra are conditional claims over the stated scope; the vectors are controls, not exhaustive target behavior. The selector's getter and other helpers, complete tree insertion and duplicate behavior, writer-state origin, tier input constraints, floating-point control state, economic unit and runtime producer-to-writer handoff remain open. No full component gate is requested.

Next question: identify a non-overlapping ownership edge from the returned collection to the compatible named writer, then validate an independently authored Rust implementation against authorized target-grounded fixtures.
