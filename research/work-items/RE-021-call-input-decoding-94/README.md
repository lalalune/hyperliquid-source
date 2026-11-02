# RE-021: call-request byte and quantity inputs on node 94

On a selected node #94 call-request path, `input` and `data` decode into independently tracked byte buffers with a defined error order, and neighboring quantity and fee helpers expose separate 128-bit and 256-bit overflow gates needed to reconstruct request inputs before the precompile boundary.

- Component ID: `evm`, RE-021 BLAKE2b precompile connection.
- Target release and full SHA-256: `artifacts/node/94/hl-node`, node #94 Linux x86-64, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `e5c9b6436876b2a4a39daef813171f9879317699` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The latter is unlicensed inferred reference material, not implementation source; no reference code was copied.
- Claim status: static observation, bounded inference and unresolved boundaries, as separated below.
- Scope included and excluded: 18 previously unselected unwind-described ranges on two adjacent branches of the same request preparation path: field collection, byte-buffer creation, quantity parsing, and fee calculation. The earlier request visitor, environment converter, registry, precompile wrapper, payload-clone methods and digit classifier are dependencies, not newly selected function bodies. This does not establish a full node reconstruction, the full first `evm` task, node #115, visor, network behavior, captured execution or emulation.

## Reproduce

Run from the repository root with the authenticated #94 artifact and Python 3.12.3. The generator uses the standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`, checks the complete artifact digest before extraction, and never starts another program or executes target bytes. GNU objdump 2.42 was used for human inspection only; its output is not parsed or generated as evidence. The generator excludes SHT_NOBITS from file-backed address resolution. The 14 JSON and TSV evidence files are regenerated from ELF bytes; this README and its manifest are maintained separately.

```sh
python3 tools/re21_call_input94.py --out research/work-items/RE-021-call-input-decoding-94
python3 -m unittest tests.test_re21_call_input94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

To compare two clean extractions without binutils in the generator's path:

```sh
python_exe=$(command -v python3)
TZ=UTC PYTHONHASHSEED=0 PATH= "$python_exe" tools/re21_call_input94.py --out work/re21-call-input-a
TZ=Pacific/Honolulu PYTHONHASHSEED=37 PATH= "$python_exe" tools/re21_call_input94.py --out work/re21-call-input-b
diff -r work/re21-call-input-a work/re21-call-input-b
```

`MANIFEST.sha256` covers this README and every generated evidence file in this work-item directory. The two comparison directories must be empty before the commands are run.

## Evidence

All addresses are link-time ELF virtual addresses before load bias. The tables include file offsets; FDE ends are exclusive. An unwind range is not by itself a proven function boundary. `functions.tsv` and `function-bytes.json` retain 18 distinct selected ranges totaling 11,073 bytes; `unwind-records.json` retains their actual FDE and CIE records. `windows.tsv` has 100 bounded byte windows, `transfers.tsv` has 120 explicitly selected direct transfers, and `rip-references.tsv` has 21 selected RIP-relative references. These counts include the minimum boundary anchors in the earlier visitor and converter, but do not select their FDEs or claim an exhaustive instruction or control-flow census. `relocations.tsv` contains 22 selected RELA records, `numeric-operands.tsv` records 29 fixed operands, and `switch-tables.tsv` gives bounded prefixes of 15 and 22 signed-relative entries. `exception-sites.tsv` contains 74 decoded LSDA call-site intervals, 46 with nonzero landing pads, across eleven selected LSDAs; the headers and raw records are also retained. Action chains, catch types and personality behavior are not decoded.

### Field collection and bytes

The earlier request visitor reaches `0x26afab0` at `0x1bdb8b9`. At that call it also passes the `TransactionInput` label at `0x203ed0` and a two-entry name table at `0x568a828`: RELA addends resolve to `input` and `data`, with lengths 5 and 4. These data and the connecting call are retained without reselecting the earlier visitor body. The collection loop advances by 64 bytes and calls through slot `0x57746b0`, whose relocation resolves to the previously studied filter `0x4eb8d00`.

| Stage | Selected range | Observed operation or failure boundary |
|---|---|---|
| Field classification | `0x214d7c0` | The selected string branches compare `input` and `data` and produce discriminants 0 and 1; other classified names produce 2. The 15-entry table is indexed after subtracting 1 from the input representation tag. |
| Collection | `0x26afab0` | Separate stack seen flags at `+0x10` and `+0x38` guard input and data. A second occurrence of the same field goes to an error formatter; the two different fields are tracked independently. |
| Optional value | `0x209ce20` | Raw value tags `0x10` and `0x12` return a zero first value word; tag `0x11` dereferences a 32-byte value before the common adapter. A zero parser-result word and an error result follow distinct branches. |
| Value adapter | `0x219c090` | Table entries 12 and 13 reach the text converter, entries 14 and 15 have direct byte-buffer arms, and entry 20 calls the sequence converter. The retained 22 entries are a bounded table, not a proof of the complete runtime tag domain. |
| Sequence | `0x28096c0` | Advances through 32-byte elements, calls the prior-owned `0x204d6b0` for each, appends the returned byte on success, and returns an error after a failed element conversion. That helper's full input grammar is outside this packet. |
| Text buffer | `0x2809db0` | Calls the decoder through slot `0x57705c8`; RELA resolves this slot to `0x156ec60`. The negative-capacity sentinel becomes a zero-leading error object; normal results build a four-word byte buffer. |
| Decoder and helpers | `0x156ec60`, `0x156e5d0`, `0x156e890` | Check length and prefix, validate characters, identify the first invalid character, and convert selected scalar or vector chunks. Allocation failure and cleanup paths are separately represented in the retained bytes and LSDA rows. |
| Value errors | `0x2883640`, `0x2883f50` | Construct error objects using raw kinds 8 and 9 for the associated value-adapter arms. External formatting and wire text are not established. |
| Buffer release | `0x1510a30`, `0x15102c0` | The odd-pointer and shared table drop slots reach these two bodies. A shared owner is decremented atomically; a last reference reaches the data and 24-byte owner release path, with size and unwind failures retained. |

The collector's successful output stores the first byte-buffer word at result `+0x08` for `input` and `+0x28` for `data`, with the remaining three words immediately following each. The companion words are unspecified when the leading word indicates absence. The outer result word is zero on its successful path and one on its error path. A successfully parsed null still sets the relevant seen flag, so, **if the earlier parser delivers both entries to this loop**, a later occurrence of the same name takes the duplicate branch. This is a statement about the collector's input sequence, not a claim that every upstream JSON representation preserves duplicate keys. The collector does not itself compare the two different fields. Later choice, aliasing and conflict handling remain outside this packet.

The decoder makes the following checks in this order:

| Condition on the decoder's byte span | Observed branch |
|---|---|
| Odd original length | Return first word `0x8000000000000000` and error code 1, before attempting prefix removal. |
| Even length beginning with lower-case `0x` | Remove those two bytes; no prefix is also accepted by this routine. `0X` is not removed. |
| Invalid character after prefix handling | The first invalid byte is reported with raw code 0, its byte value and its zero-based index within the remaining span; the allocated buffer is released on the corresponding cleanup path. |
| Valid span | Each digit pair yields one output byte; an empty remaining span produces an empty buffer. Allocation and CPU-feature callbacks remain external. |

`nibble-map.tsv` is the entire 256-byte table at `0x251994`: exactly the 22 ASCII bytes `0`–`9`, `A`–`F`, and `a`–`f` map to nibbles; all others contain `0xff`. The five 16-byte SIMD validation constants are in `constants.json`. Applying the pinned byte-lane predicate to all 256 byte values agrees with the scalar table; the vector nibble expression also agrees on all 22 valid inputs. This is a static arithmetic comparison, not execution of the machine's SIMD path. The separate vector converter tests an output count of 32 before its large block loop and a count of 8 for its smaller tail. This does not prove every vector instruction or CPU dispatch implementation.

A 213-byte result corresponds to 426 hex digits, or 428 bytes including lower-case `0x`. The existing RE-021 compression packet establishes the address-09 wrapper's 213-byte input requirement and its additional rounds, final-flag and gas checks. The nonempty exact-capacity buffer has two pointer-bit-dependent table choices, `0x5670ae8` and `0x5670ac0`; their first RELA slots resolve to clone methods already selected in the type-2 input work. Empty and shared table entries are also retained as data. These observations are compatible with the earlier frame and registry evidence, but this packet does **not** establish the intervening consumer's field choice or prove that a particular request buffer reaches the wrapper.

On the odd-pointer table, the `+0x20` entry is relocated to the newly selected `0x1510a30`; the shared table's `+0x20` entry resolves to `0x15102c0`. In the first helper, an owner word with bit 0 clear takes a locked decrement of the word at owner `+0x10`; a nonzero result returns, while zero proceeds to free the allocation and its 24-byte owner. With bit 0 set, the helper forms `data_pointer - owner + length`, checks addition carry and the sign bit, and on the normal arm passes the owner and computed size to the free slot. The shared helper performs the same decrement-and-last-reference sequence without the pointer-bit branch. For an ordered, valid span whose owner equals its data pointer, a length of 213 therefore gives a free size of 213 on that selected odd-owner arm. This conditional arithmetic is not a claim that the real allocator returns an odd pointer, that the callback is always invoked, or that concurrent ownership is fully reconstructed. Separate failure and unwind records remain visible; external allocation and release semantics are assumptions.

### Quantity and fee branches

The earlier request visitor has four direct call sites to `0x258cbf0`; the earlier environment converter calls the relocated slot `0x5774310`, which resolves to `0x4e60140`. These are two boundary anchors in the same request preparation lineage, not a complete proof that any particular one of the four parsed fields supplies a particular fee argument.

`0x258cbf0` skips bytes selected by the mask `0x100002600` within its bounded whitespace loop, recognizes the literal `null`, and otherwise calls `0x28fc450`. For its three raw output variants, null uses tag 0, a successful quantity uses tag 1, and an error uses tag 2. The bounded mask selects byte values 9, 10, 13 and 32. The quoted-text branch in `0x28fc450` has a special comparison against the three bytes `0x0`, returning zero on equality; other selected text reaches `0x28f7ae0`. Before that point, quoted-string scanning and other JSON number arms are external or only partially selected.

For an ASCII span satisfying its caller's string invariants, `0x28f7ae0` selects radix 16 for `0x` or `0X`, radix 8 for `0o` or `0O`, radix 2 for `0b` or `0B`, and radix 10 otherwise. Unlike the byte decoder above, this numeric helper recognizes upper-case prefixes. It delegates digit classification to previously owned `0x28317c0`. For digit values supplied by that boundary, it rejects a digit greater than or equal to the selected radix with raw tag 2, updates two 64-bit limbs by multiply and add, and returns raw tag 0 on 128-bit overflow. Raw tag 5 carries the resulting pair of words on the selected success path. These are accumulator observations, not a claim about every spelling accepted by the external classifier or JSON scanner.

For `0x4e60470`, call the first canonical optional four-limb input **cap**, the second **tip**, and the four-limb third input **base**. These role names are an inference from the comparison and arithmetic, not a recovered source type or proof of the caller's original field names. Canonical options have tags 0 or 1; the observations below do not assert behavior for arbitrary tags. All comparisons and additions use the full unsigned 256-bit words.

| Guard, in execution order | Helper result |
|---|---|
| Cap present, at least one of cap or tip nonzero, and cap less than base | tag `0x0d`, code `0x0d` |
| Cap present and cap less than tip | tag `0x0d`, code `0x0a` |
| Base plus the present tip (or zero) overflows 256 bits | tag `0x0d`, code `0x0b` |
| No cap and no overflow | tag `0x21`, value `base + tip` |
| Cap present and no error | tag `0x21`, value `min(cap, base + tip)` |

The all-zero cap and tip branch skips the cap-versus-base check; it still checks the addition and then selects the minimum. Equality at either comparison is accepted. In `0x4e60140`, if the first input is present together with any of the next three flagged inputs, the selected branch returns outer tag 2 and code `0x0c`. A different selected branch returns outer tag 2, code `0x0d`, and byte `0x1c` when an auxiliary condition is missing after a successful calculation. The other dispatcher outputs, feature meanings, full caller argument provenance, and downstream state effects are not closed.

## Implementation and comparison

Independent Rust reconstruction: **not yet implemented**. No compiler, Cargo lock, native comparison, normalization mask, relocated execution, target execution or emulation is claimed. The tests use synthetic source-level projections of the pinned byte, accumulator and fee guards; they do not interpret or emulate machine instructions. In particular, arithmetic examples and malformed inputs in the tests are controls rather than captured target behavior. Full body hashes, fixed byte windows, branch displacements, RELA entries and FDE/LSDA records independently bind the projections to the selected artifact, but do not establish dynamic reachability or full semantic equivalence.

## Results and limitations

The 29 focused unittest methods pass with no skips. Controls include a corrupt full digest, wrong bytes and targets, out-of-range, ambiguous and SHT_NOBITS mappings, bad relocation type/addend and duplicates, malformed LSDA ranges and landings, changed scalar or SIMD constants, all 256 byte values, all 484 combinations of valid hex characters, first-invalid positions, duplicate/null ordering, vector-size boundaries, 212/213/214 output-byte lengths, shared-reference and odd-owner release branches, 128-bit overflow in four radices, and 256-bit fee boundary and error ordering. Regeneration is compared under two hash seeds and timezones with an empty generator `PATH`; the exact output hashes are in the manifest.

The full first `evm` task and component gate remain open; `evm` stays at 0/4. No selected start was found in repository work items or locally available prior packet records. The supplied PR inventory was inspected by title and file paths, but does not contain every PR body; a fresh public main and PR ownership check is required at submission. The calculator and byte decoder have shared external callees, possible runtime callback replacement, allocation failures, unproved dataflow through the prior-owned converter, and no runtime trace. The 18 selected FDEs and 74 LSDA entries are not a coverage denominator for the node.

Next question: using reviewed prior-owned request and frame evidence, establish which of the two collected byte buffers is forwarded to the cloned frame payload and bind the four quantity outputs to the fee helper's argument positions without selecting already owned functions again.
