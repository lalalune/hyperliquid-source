# node-runtime: reconstruct node #115 process argv and environment snapshot collectors

- Component ID: node-runtime (Node runtime and gossip; startup process inputs)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository main at packet time; reference sources used only as hints, nothing copied
- Claim status: observation (bytes, decoded instruction forms, emulated results) plus inference (names of runtime-library call slots, Rust-level meaning)
- Scope included and excluded: functions `0x5c9a530` (argv collector, FDE end `0x5c9a709`) and `0x5c9a710` (environment snapshot collector, FDE end `0x5c9abac`). Excluded: callers, the cleanup landing pads, the library routines behind the call slots, and the function at `0x5c9abb0`.

This packet makes it possible to rebuild, as plain executable Python, what the node does with its process inputs at startup: how the saved `argc`/`argv` cells become a vector of owned byte strings, and how `environ` becomes a vector of owned key/value pairs under a read lock. The behaviour is recovered by decoding the real function bytes with a small x86-64 interpreter and checking the result against an independent specification on 10564 generated process images, with 41 of 41 negative controls detected.

## Reproduce

From the repository root with the pinned node binary materialised and Python 3.11+ (standard library only, plus `tools/elf_index.py` and `tools/fde_extents.py`):

```sh
python3 tools/node_runtime_env_collect.py --out research/work-items/node-runtime-process-env-collectors-115
python3 -m unittest tests.test_node_runtime_env_collect
```

The tool checks the binary SHA-256 first, reads function extents from the `.eh_frame` FDE records, never executes the node, calls no external program, and writes only the files listed in `MANIFEST.sha256`. Output is deterministic (no clocks, no randomness; generated cases come from a fixed linear congruential generator).

## Evidence

Coordinates are ELF virtual addresses.

- `instructions.tsv`: every instruction of both functions (address, length, decoded form, raw bytes). The decoder tiles each FDE extent exactly: 132 instructions for `0x5c9a530..0x5c9a709` and 279 for `0x5c9a710..0x5c9abac`. The instruction start addresses were also compared once with an external disassembler during development (411 of 411 starts agree); that comparison is not part of the tool or the tests.
- `call-slots.tsv`: the eleven indirect-call slots the two functions use. All are zero in the file (filled by relocation at load time), so the interpreter binds them by slot address to named models: allocate, string length, copy, allocation-error (no return), slice-index panic (no return), vector grow, read-lock contended slow path, read-unlock wake, plus three that are only reachable on unwinding or unmodelled paths and are refused if reached.
- `case-digests.tsv`: a sparse sample (every 40th environment case, every 20th argv case) with a digest of the interpreter result, so a reviewer can spot-check a regenerated run.
- `negative-controls.tsv`, `summary.json`, `measure.json`: control outcomes and counts.

Observations about `0x5c9a530` (argv collector):

- Reads the cells at `0x6500000` (argc, sign-extended by the initializer at `0x5ca55c0`) and `0x6500008` (argv). A null argv returns the empty vector `{buf=8, cur=8, cap=0, end=8}`.
- An argc above `0x555555555555555` (the largest count whose 24-byte-element product stays positive) calls the allocation-error slot with `(0, argc*24 mod 2^64)`.
- Otherwise it allocates `argc*24` bytes, then for each `argv[i]` stops at a null pointer, takes the string length, allocates exactly that many bytes (a length of zero uses the dangling pointer 1 and no allocation), copies the bytes, and stores `{cap=len, ptr, len}`. The result is `{buf, buf, cap=argc, end=buf+count*24}` in the registers `rdi+0..0x18`: capacity is `argc`, not the number of strings collected.
- Failure order: allocation 0 is the element vector (error arguments `(8, 24*argc)`), later allocations are the non-empty arguments in order (error arguments `(1, len)`).

Observations about `0x5c9a710` (environment snapshot collector):

- Takes the lock word at `0x64ffff0` as a read lock: a compare-exchange from the loaded value if it is at most `0x3ffffffd`, otherwise the contended slot. On exit it subtracts one and calls the wake slot when the result masked with `0xbfffffff` equals `0x80000000`. In the model this gives a wake only when the initial state has the writer-waiting bit and no readers.
- Walks `*environ` (the GOT slot `0x64ec7b0` holds the address of `environ`). Empty strings are skipped. The key/value split looks for the first `=` at index 1 or later, so a leading `=` belongs to the key (`=C:=\w` gives key `=C:`), and a string with no `=` after index 0 is skipped. For strings longer than 16 bytes an aligned eight-byte-word scan with the constants `0x3d3d3d3d3d3d3d3d`, `0x0101010101010100` and `0x8080808080808080` is used as a filter before the byte loop; strings of at most 16 bytes use the byte loop alone.
- Each accepted entry allocates the key (length of the prefix before `=`), then the value (no allocation when empty), copies both, and appends a 48-byte record `{kcap, kptr, klen, vcap, vptr, vlen}` to a vector that grows through a slot call. The result is `{buf, cur=buf, cap, end=buf+count*48}`.
- Failure order: key length, then value length (only if non-empty), for each accepted entry; arguments `(1, size)`.

## Implementation and comparison

`tools/node_runtime_env_collect.py` contains the decoder (about 40 opcode forms with REX, ModRM, SIB and RIP-relative operands, flags for add/sub/and/or/xor/cmp/test/neg/inc/dec/shift/compare-exchange/exchange-add), an interpreter with sparse paged memory over the ELF sections, the hook table for the call slots, process-image builders, the independent specifications `spec_env` and `spec_argv`, the case generators and the negative controls. The specification is written from the observations above, not from the interpreter output, and compared on the decoded result (records, key/value bytes, exact-capacity flags, lock word, lock events, allocation-error arguments).

Corpus (all produced by the default arguments):

- 6600 environment images: 0..25 strings of lengths around the 8/16/17/24/32/48 boundaries, `=` at any position, leading and repeated `=`, bytes `0x3c 0x3e 0xbd 0x80 0xff` that stress the word filter, eight pointer alignments, thirteen lock-word values (3068 take the contended path, 1007 of them also take the wake path).
- 2400 argv images: argc below, equal to and above the supplied pointers, null pointers in the middle, empty strings, null argv, argc above the 24-byte limit.
- 1058 environment and 332 argv runs with one injected allocation failure at a derived ordinal, checked against the specified failing size.
- 174 fixed battery cases used by the byte-level mutants.
- Total counted cases: 10564; unmatched cases against the specification: 0.

Negative controls (41, all detected = 41): 13 mutated specifications (search from index 0 or 2, keep entries without `=`, split at last `=`, value off by one, drop empty values, drop high-bit strings, lower-case keys, drop short strings, swap key and value, wrong word-path start, truncated keys), 18 single-byte patches to the real function bytes (the `=` literal in the three byte loops, the word-filter constants, the length threshold, loop and alignment branches, the lock threshold, the value start and key length displacements, the argv count limit and stride, the record stride and end-pointer scale), and 10 invalid-input controls (flipped digest, truncated binary, a start that is not an FDE start, address outside the image, unknown opcode, runaway loop, unmapped read, unknown call slot, mid-function entry, stale extent). A control counts as detected when the changed behaviour differs from the specification on the battery, or the tool refuses the input.

## Results and limitations

- 10564 cases, 0 unmatched; 41 of 41 negative controls detected; see `measure.json` and `summary.json`.
- The word-filter scan is only a filter: the result always equals "first `=` at index 1 or later", for any alignment and any byte values in the corpus.
- Vector growth is modelled as doubling from 4 elements; the packet only checks that capacity is at least the count, and does not claim the growth policy of the real library routine. The lock slow path is modelled as "increment the state"; real blocking behaviour is out of scope. The call-slot names are inferences from register arguments and return use, not recovered symbols.
- Only the modelled instruction forms are supported; any other opcode in the range makes the tool fail instead of guessing. Landing pads (unwinding cleanup) are decoded but not executed.
- No component gate is requested.

Next question: the single caller chain from `_start` that runs these collectors (who stores argc/argv for the later `0x5c9a530` call and which of the 24-byte strings feed the command-line parser), then the parsed-option consumers.
