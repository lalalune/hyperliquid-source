# RE-011: reconstruct the node #115 EVM burn/transfer log emitters and the end-of-block burn-log flush with 13,100 machine-code comparisons

This packet lets a Rust rebuild of the `evm` host reproduce, from the node #115 bytes, how the end-of-block flush turns pending account addresses into EVM log entries: which host bytes gate it (spec byte `+0x126` below `0x0e`, flag bytes `+0x124`/`+0x125`), how addresses are looked up in the account map (`+0xc8`, 0xa8-byte buckets, folded two-multiply hash with the process seed), how the nonzero records are collected into a 0x38-byte-record Vec (first allocation 0xe0 bytes, then doubling), how two to twenty records are insertion-sorted by `memcmp` over 20 address bytes, and exactly what the burn and transfer log emitters write (0x40/0x60-byte topic block, 0x20-byte big-endian data block, 0x50-byte log entry, log-vector growth, two distinct allocation-failure panics).

- Component ID: `evm` (task `RE-011`, EVM fork and RPC adapter area).
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: hyperliquid-source `0781ce04826eeefd89fe336cb8ea073be0c1de30` (repository checkout used to run the tool). The inferred reference tree was not used.
- Claim status: the code behaviour below is established by evaluating the real machine code against a pure-Python reconstruction (13,100 comparisons, 0 mismatches); role names and the EVM meaning (burn/transfer logs) are inferences from the shapes; runtime reachability is unresolved. No component gate is requested.
- Scope included and excluded: flush bodies `0x2972200` (family A) and `0x4324300` (family B); their collect bodies `0x2346480` / `0x3da9b20`, lookup closures `0x29dee60` / `0x4353ed0`, insertion sorts `0x26d4140` / `0x4376880`, record-vec grow bodies `0x231e050` / `0x43bd910`; burn emitters `0x2970eb0`, `0x4322d00`, `0x54631e0`; transfer emitters `0x29714f0`, `0x54635f0`. Excluded: the transfer emitter copy `0x4323270` and the value transfer `0x4322860` (another open pull request), the sort behind GOT slot `0x64e6d70` for lists of 21 or more records (recorded as a call, not evaluated), the vector-grow finish routines, the allocator, `free`, `memcmp` and the log-vector grow routine (stubs that record arguments), and every caller of the flush.

## Reproduce

From the repository root on Linux x86-64 with Python 3.12 (standard library only; no external program is called and the binary is never executed):

```sh
python3 tools/artifacts.py verify
python3 tools/re11_burn_log_flush115.py --out research/work-items/RE-011-burn-log-flush-115
python3 -m unittest tests.test_re11_burn_log_flush115
(cd research/work-items/RE-011-burn-log-flush-115 && sha256sum -c MANIFEST.sha256)
```

The tool checks the input SHA-256 first, then reads every FDE extent, relocation word, rodata constant and code byte from the ELF with `tools/elf_index.py` and `tools/fde_extents.py`. It reuses the concrete x86-64 evaluator of `tools/re11_transient_storage115.py` (two SSE forms, POR and MOVMSKPS, are added by an opcode-shape substitution in the decoder). Generation is deterministic (no clock, no randomness beyond a SHA-512 stream keyed by case id) and uses well under 1.5 GB.

## Evidence

All addresses are virtual addresses of the loaded image; code is read through the `.text` section mapping. Generated files:

- `functions.tsv` - FDE start/end, size and SHA-256 of the code bytes of the 15 evaluated bodies.
- `callsites.tsv` - every direct call and GOT call of those bodies in address order with the word found in the GOT slot (this is how the roles below were assigned: the n-th GOT call of an emitter is malloc, malloc, log-vector grow, alloc-error for the topic block, alloc-error for the data block, unwind).
- `constants.tsv` - the 16-byte rodata words stored into the topic block (`+0x00`, `+0x10`) and into the log entry (`+0x38`), the two data-pointer words chosen by the parity of the data block address, and the GOT words for the stubs.
- `cases.tsv` - every second comparison (case id, input summary, outcome class, digest); the remaining cases are regenerated from the same streams.
- `controls.tsv`, `summary.json`, `measure.json` - negative controls and counts.

Observations (byte-level, per body):

1. Emitters (`0x2970eb0` burn, `0x29714f0` transfer, same code in `0x4322d00`, `0x54631e0`, `0x54635f0`): `cmp byte [rdi+0x126],0xe; jb` and `cmp byte [rdi+0x124],0; jne` return before anything happens; a 32-byte value loaded with `movdqu x2`, `por`, `pcmpeqd`, `movmskps` that is all zero also returns. Otherwise the topic block is malloc(0x40) for burn or malloc(0x60) for transfer, the data block malloc(0x20) holds the four value limbs byte-swapped (the value as 32-byte big endian). Topic words are the two rodata words (burn at `0x458720`/`0x458730`, transfer at `0x4581e0`/`0x4581f0`) followed by each address left padded with 12 zero bytes; for transfer the first address argument is topic 1 and the second is topic 2. The log entry (0x50 bytes) is {topic count (2 or 3), topic pointer, count again, data-pointer word, data pointer, 0x20, tagged data pointer, 16 rodata bytes from `0x6017b0`, `0xfeffffff`, 4 stale stack bytes}. The tagged pointer is the data pointer if bit 0 is set, else the pointer or 1, and the word before it comes from GOT word `0x64df8c8` (odd pointer) or `0x64df8c0` (even pointer). When the log length equals the capacity the code calls the GOT grow slot `0x64dfa48` and reloads the pointer; the entry goes to `ptr + len*0x50` and length is incremented. The 4 stale bytes are stack garbage: the tool reruns every 40th emitter case with a different stack fill and shows that only those bytes change (130 of 212 reruns differ, never below `+0x4c`).
2. Flush: spec/flag gating as above plus `+0x125`; the pending list is `ptr = [+0x38]`, `end = ptr + [+0x40]*20`; the map at `+0xc8` is handed to the collect body through a stack iterator {cur, end, &map}. After collecting, a length of two to twenty calls the insertion sort `(ptr, len, 1)`, a longer list calls GOT slot `0x64e6d70`; every record is passed to the burn emitter as (address, value); the Vec buffer is freed with size `cap*0x38` when the capacity is nonzero.
3. Collect and closure: the closure returns nothing if the map item count (`+0xe0`) is zero; it hashes the 20-byte address (words 0 and 1 with the map secret `+0xe8` and the seed read through GOT slot `0x64dfa78`, third word, two multiplications, high bits folded), probes 16-byte control groups with the top 7 hash bits, compares 20 key bytes, and yields the record only when the 32-byte value at bucket `+0x40` is nonzero. The record is address (20 bytes), 4 pad bytes, value (32 bytes). The first record allocates 0xe0 bytes (four records); the grow body doubles the capacity (minimum four) through a finish routine.
4. Sort: comparison is `memcmp(cur, prev, 0x14)` and a non-negative result leaves the element in place, i.e. a stable insertion sort in ascending address-byte order.

## Implementation and comparison

`tools/re11_burn_log_flush115.py` contains the reconstruction (`emit_model`, `sort_records`, `flush_model`), the hashbrown fixture builder for 0xa8-byte buckets (control bytes, tombstones, h2-colliding decoys, 16/32/64 buckets), the stubbed host contract (allocator addresses, grow, free, memcmp, big sort), and the harness that runs the original code of every body and compares: return or panic (callee, `rdi`, `rsi`), the ordered stub event trace, the host bytes, every log entry, every heap block, callee-saved registers and `rsp`, and that the pending list, table and argument memory are untouched.

Cases (13,100; the five emitter bodies get 1,700 each, the two flush bodies 2,300 each, deterministic streams keyed by body and index): spec byte from 0 to 0xff (boundary 0x0d, 0x0e, 0x0f included), flag bytes zero and nonzero, zero and one-limb and full values, log vectors that are empty, partly full and full, odd and even data block addresses, malloc failure at the first or second allocation, and for flush 0 to 30 pending addresses with duplicates, missing and zero-valued map entries, items count zero with entries present, tombstones and decoys, forced collisions, and failures at the 0xe0 allocation or inside emission.

| body | cases | mismatches | logged | no-op | panic | log grows | record-vec grows | big-sort calls |
|---|---|---|---|---|---|---|---|---|
| `0x2970eb0` | 1700 | 0 | 993 | 661 | 46 | 524 | 0 | 0 |
| `0x29714f0` | 1700 | 0 | 941 | 711 | 48 | 499 | 0 | 0 |
| `0x2972200` | 2300 | 0 | 1077 | 1137 | 86 | 1752 | 931 | 33 |
| `0x4322d00` | 1700 | 0 | 967 | 685 | 48 | 504 | 0 | 0 |
| `0x4324300` | 2300 | 0 | 1084 | 1125 | 91 | 1693 | 880 | 32 |
| `0x54631e0` | 1700 | 0 | 963 | 685 | 52 | 479 | 0 | 0 |
| `0x54635f0` | 1700 | 0 | 948 | 717 | 35 | 499 | 0 | 0 |

No file in this packet is compared against a Rust build; no Rust implementation exists yet ("not yet implemented"). The Python reconstruction is the specification candidate, not an equivalence claim.

## Results and limitations

- 13,100 comparisons plus 212 stack-fill reruns: 0 mismatches.
- Negative controls: 109 counted, 109 detected. They are 17 model mutants (wrong spec threshold, ignored flag, zero value logged, no address padding, little-endian data, swapped data-pointer word, wrong sort order or sort threshold, ignored `+0x125`, ignored item count, zero-valued records kept, wrong free size, wrong topic count, wrong grow sizes, swapped topics, missing free), 86 inverted conditional branches in the code bytes (one per detectable `jcc` of every evaluated body), and 6 corrupted-input checks (a flipped binary byte, a decode window ending inside an instruction, a non-FDE address, a non-emitter body, burn arguments fed to the transfer emitter, a lowered spec byte).
- Byte mutants not counted because no sampled case distinguishes them (unreachable or equivalent): 4: `0x2972200+0x173 (family 0x2972200)`, `0x2346480+0x1f3 (family 0x2972200)`, `0x4324300+0x169 (family 0x4324300)`, `0x3da9b20+0x1f3 (family 0x4324300)`. One model mutant (non-stable insertion sort) is not listed because equal addresses always carry equal values here, so it cannot change the output.
- Limits: the sort for 21 or more records, allocator, `free`, `memcmp`, the log-vector grow routine and the vector-grow finish routines are stubs; the spec byte semantic (fork id `0x0e`), the flag bytes and the owners of the pending list and account map are unresolved; the two stack-garbage bytes per entry are masked by design; the tool says nothing about which callers reach the flush or how the log vector is consumed.
- No progress gate is requested; this is part of the `evm` component's behaviour only.

Next question: the journal revert body `0x29710e0` (476 bytes, 0x58-byte entries, applier through GOT slot `0x64e6d68`) and its two copies `0x4322f30`, `0x5463410`, which truncates the log vector to a checkpoint and replays journal entries in reverse, and the callers that fill the pending list at host `+0x38`.
