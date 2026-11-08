# RE-008: node #115 signed block and timeout message admission front ends, from stake set to the move-or-error result

This packet lets an implementer write, as one flow, how node #115 decides that a signed consensus block or timeout message may speak: which certificate round selects the stake set (the `0x8000000000000001` tag word at `+0x18`), how the set is searched in its two storage forms (a B-tree of 20 byte addresses and a ring of 32 byte rows searched like `VecDeque::binary_search_by`), which digest variant is signed (0 for a block, 2 for a timeout message whose 0x38 byte box is built by the wrapper), how the recovered address is compared, and what the two wrappers return and drop on every path. All of it runs as the real bytes in a Python x86-64 interpreter against a separately written rule list: 14,400 cases, 0 mismatches, 250 negative controls all detected.

- Component ID: consensus (task RE-008)
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository base `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source was read or copied; the deleted merged #94 block admission packet (`git show 8fd8db680^:research/work-items/RE-008-block-admission-94/README.md`) was a search lead only, its addresses and layouts are not transferred
- Claim status: observation for every row run or pinned; inference where marked below; unresolved items are listed under Results and limitations
- Scope included: `0x57e8970` (block front end), `0x57e8bd0` (signer check, reached through slot `0x64e64b8`), `0x57f54e0` (ring search), `0x2786870` (signed block wrapper), `0x2786a20` (timeout message wrapper), all five from their first byte to return, with every FDE row counted
- Scope excluded: the block rules `0x59d6b80` (merged `RE-001-node115-signed-validation` maps it), the stake set provider `0x595e5c0` (named by merged `RE-008-proposer-selection-115`), the TC path `0x5960390` (merged `RE-008-tc-parallel-abort-115`), the nested certificate wrapper `0x595fd20`, the digest builder `0x57e8d40`, signature recovery, the callers of the wrappers
- Related work: open #4359 traces a consensus timer handoff and shares no function with this packet; `RE-001-*` caller lists mention some of these addresses only as inventory rows

## Reproduce

Run from the repository root. Python 3 standard library plus `tools/elf_index.py` and `tools/fde_extents.py`. No external program runs, the binary is never executed, nothing touches a network. The tool refuses any other digest. One run takes under a minute and peaks at about 440 MB resident (measured with `/usr/bin/time -v`).

```
python3 tools/consensus_signer_front_115.py --out research/work-items/RE-008-signed-message-admission-115
python3 -m unittest tests.test_consensus_signer_front_115
```

The generated files are byte-identical on two runs with different hash seeds and time zones (checked with `diff -r`).

## Evidence

Coordinates are ELF virtual addresses in `.text` and `.data.rel.ro`/`.got` slots. Function bounds are FDE bounds from the shared parser. Every table below is produced by the tool from file bytes or from a run of the real rows.

### Observations: how the five functions are reached

`slots.tsv` reads three `R_X86_64_RELATIVE` relocations: slot `0x64e64b0` names `0x595e5c0` (586 bytes), `0x64e64b8` names `0x57e8bd0` (362 bytes), `0x64e64c0` names `0x59d6b80` (1,323 bytes). `callers.tsv` is a byte scan of every `e8`/`e9` rel32 to the scope functions and of every `ff 15` call through those slots with the containing FDE. The wrappers are called from `0x2705af0` (`0x2786870` at `0x2706020`), from `0x2e098e0` (`0x2786870` at `0x2e0eee4`) and from `0x2e08b90` (`0x2786a20` at `0x2e08d5e`); `0x57e8970` has no direct caller.

### Observations: the rule list

`gates.tsv` pins 27 rows (call targets, slot calls, immediates) to the sites below; each is decoded from the bytes and checked with a wrong-site and a wrong-expectation negative.

1. Round for the stake set. If the word at block `+0x18` equals `0x8000000000000001` the certificate sits at `+0x20` and its round word is at `+0x60`. Otherwise, if `+0xa8` equals the tag the certificate is at `+0x18` (round `+0x58`), else it is at `+0xa8` (round `+0xe8`). The timeout message wrapper reads its round at `+0x40`. The stake set provider is called first, with the state and that round.
2. A provider tag other than `0x2e` is copied unchanged: all 0x48 bytes of the record into the output (front end), or into the error arm of the wrapper (below).
3. The set object has word 0 equal to `0x8000000000000000` for the tree form (root at `+8`, height at `+0x10`) and any other value for the ring form (capacity, buffer, head, length at `+0 +8 +0x10 +0x18`).
4. Tree search: a node keeps up to 11 keys of 20 bytes from `+0x60`, a `u16` count at `+0x13e` and edges from `+0x140`. Keys are compared left to right with `memcmp(address, key, 20)`: equal is found, greater moves on, smaller descends through the edge of that index. A leaf (height 0) that ends the walk is a miss; the height word is decremented per level and a root pointer of 0 is a miss. An unsorted tree is searched exactly as the walk says, not by membership (cases include swapped keys).
5. Ring search `0x57f54e0`: rows of 32 bytes, the first 20 are the key. With the back slice present, its first row decides: equal is found at the front length, smaller searches the back slice, otherwise the front slice is searched; each slice is a size-halving search that moves its base unless the row is greater. The return is `(0 found | 1 absent, index)`.
6. A miss ends the block front end with output byte 0 = 1. Otherwise the digest is built (variant 0 over the block pointer), recovery runs over the signature at `+0x130`, an error result drops its boxed error through the vtable and gives byte 1, a recovered address that differs from the 20 bytes at `+0x11c` gives byte 1, and only a match calls the block rules with the output pointer, the block and the state.
7. Signed block wrapper `0x2786870`: stake set (round from rule 1), signer check through slot `0x64e64b8` with the message `{0, block}`, block rules through slot `0x64e64c0`. Success moves 0x178 bytes of the block to the output and drops nothing. Every failure writes `0x8000000000000000` to output word 0 and the 0x48 byte result record at `+8` (a signer failure is tag 1 with the rest of the frame left as it was), frees the hash vector (`cap << 5` bytes, only if the capacity is not 0) and drops the certificates at block `+0x18`.
8. Timeout message wrapper `0x2786a20`: stake set for the round at `+0x40`; a box of 0x38 bytes is allocated (a failed allocation goes to the allocation error handler and stops) holding words `+0x68 +0x70 +0x78 +0x30`, the 20 byte address from `+0x80` and 4 bytes left as allocated; signer check with variant 2 over that box and the signature at `+0x98`; the pair at `+0x68/+0x70` must equal the state words `+0x50/+0x58` (a mismatch is tag 0 with the four words in that order); the word at `+0x30` must be below the word at `+0x78` (equal or above is tag `0x0a`); then the nested certificate wrapper runs. The box is freed (0x38 bytes) on every path after the allocation. Success moves 0xe0 bytes. Failures write `0x8000000000000001` to output word 0 and the record at `+8`, then drop the message: a vector capacity other than `0x8000000000000000` frees `cap * 96` bytes if non-zero, while the tree-held form steps its into-iterator `length + 1` times.

`layouts.tsv` lists every displacement read off a pointer register by each function, `functions.tsv` the 647 of 668 rows reached, `stubs.tsv` every contract, `outcomes.tsv` the case counts per outcome class.

### Inferences, kept apart

- Calling the set a stake set and the two certificate forms a block QC and a TC is inferred from the callers' neighbours (`RE-008-tc-parallel-abort-115`, `RE-008-proposer-selection-115`) and from the earlier #94 lead; the bytes show only tags, words and the walk.
- Calling digest variant 0 a block digest and variant 2 a timeout digest is inferred from the message each wrapper builds.
- Reading the first output word `0x8000000000000000` / `0x8000000000000001` as the error niche of a Rust `Result` is inferred from the compare and move code.
- Reading `0x57f54e0` as `VecDeque::binary_search_by` is inferred from the model matching on 14,400 cases including damaged (unsorted) rings.

## Implementation and comparison

Rust implementation: not yet implemented. `tools/consensus_signer_front_115.py` holds an x86-64 row evaluator (imported head of the earlier staking packet tools, decoder unchanged), the fixture and a rule list written from the observations above. Per case it writes tree nodes or ring rows into emulated memory, plans every contract (stake provider tag, recovery result, block rules tag, nested certificate tag, allocation failure), runs the real bytes, and compares the return value, the full 0x200 byte output region and the ordered list of stub calls with every argument.

Cases: 14,400 (front end 3,200, signer check 2,400, ring search 2,400, signed block wrapper 3,200, timeout wrapper 3,200 by default), 0 mismatches. Classes per entry: front admitted 139, other_address 102, recover_error 90, signer_not_in_set 1,242, stakes_error 1,180, verify_error 447; wrapper block admitted 109, other_address 86, recover_error 96, signer_not_in_set 1,262, stakes_error 1,224, verify_error 423; wrapper timeout admitted 41, alloc_failure 95, other_address 94, pair_mismatch 248, qc_error 88, recover_error 79, round_order 137, signer_not_in_set 1,232, stakes_error 1,186.

Negative controls (250, all detected): 15 flawed rule lists (reverse key order, first key only, wrong ring move, wrong round word, missed set miss, error box not dropped, compare skipped, tag ignored, wrong free sizes, missing drop, missing allocation stop, box without a word, pair compared by one word, strict round order), 123 one-bit edits of conditions and immediates in the real rows (each run on up to 48 cases chosen across outcome classes; 10 edits survived and are listed in `mutations.tsv`, not counted), 54 corrupted fixture bytes (address, signature, state pair, round, key) and 58 range and pin controls (wrong digest, non FDE start, outside every FDE, outside every section, each rule moved one byte and given a wrong expectation).

## Results and limitations

`measure.json` and `evidence.json` have the metrics: cases 14,400, mismatches 0, instructions reached 647 of 668. No progress gate is requested.

- The block rules `0x59d6b80`, the stake set provider `0x595e5c0`, the digest builder `0x57e8d40`, the nested certificate wrapper `0x595fd20`, signature recovery, the certificate drop `0x2780350` and the B-tree into-iter step `0x2448aa0` are contracts, not run. The digest stub is SHA-256 of the variant word and the message content, so the digest bytes themselves are not modelled.
- Tree node value slots (`+8..+0x60`) and parent links are not read by these bodies and are not checked; the tree is only searched, never rebuilt.
- 21 rows are unreached: 19 are unwind landing pads and the allocation failure `ud2` tail of the two wrappers (`0x2786a00..0x2786a13`, `0x2786d27..0x2786d51`), one is a `nop` pad at `0x57e8c77`, and one is a `jmp` at `0x57f5626` whose reach condition is not established.
- Survivors among the one-bit edits are not classified one by one; none is claimed equivalent.
- The callers `0x2705af0`, `0x2e098e0`, `0x2e08b90` and the event arms around them are not read; what a returned error does is open.
- No claim about network order, other nodes or a real chain.

Next question: what do `0x2705af0` (calls `0x2786870` at `0x2706020`) and `0x2e098e0` do with the `Result` of the signed block wrapper, and which event arm hands them the block?
