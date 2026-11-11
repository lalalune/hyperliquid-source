# RE-011: reconstruct the node #115 EVM state-map probe family (18 hashbrown entry/get/contains bodies) and the code-cache install 0x54793e0

With this packet you can rebuild, as runnable code, how the node #115 EVM state layer looks a key up in its per-block
hashbrown maps and what it does on a hit and on a miss: the foldhash of a 20-byte address or a 32-byte word (per-map seed at
map+0x20, global seed word behind GOT `0x64dfa78`), the SSE2 group walk with its triangular stride, the bucket geometry of
every instance (0xa8, 0xa0, 0x68, 0x40 and 0x28 bytes), the occupied/vacant result block, the reserve call when no growth is
left, the value pointer of the `get` form and the boolean of the `contains` form. It also rebuilds the first user of the
32-byte/0x28 instance, `0x54793e0` (install the code object of an account): the empty-code shortcut, the cache hit, the miss
path with the load callback, the exact hashbrown insertion rules, the growth and item counters, the checked Arc increments
and the replacement of the account's code pointer. The tool proves the reconstruction against the real machine code of all
19 bodies in 14,400 cases and 646 negative controls.

- Component ID: `evm` (task RE-011, EVM/forks: one bounded EVM adapter path)
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: main `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No reference source is used.
- Claim status:
  - Observation: code bytes, FDE extents, GOT slot targets, call sites, rodata constants, and the agreement of the evaluated
    machine code with the model on every case.
  - Inference: the roles named below (account map, code-hash cache, load callback); the names are labels, not recovered
    symbols.
  - Unresolved: the bodies of the callees listed under Limits, and the owners of the map types.
- Scope:
  - Included: 10 entry bodies, 7 get bodies, 1 contains body (ordinary and twin builds, extents in `functions.tsv`) and the
    code-cache install `0x54793e0` (596 bytes, 142 instructions) together with its real callee `0x4ef7e50`.
  - Excluded: the reserve/rehash callees, the code loader, the Arc slow drop, the lazy initialiser, the 603-byte and
    376-byte siblings of the same family (insert/remove forms), and the unwind landing pads.

## Reproduce

From the repository root, with Python 3 standard library only (the binary is never executed, no external program is run):

```
python3 tools/re11_state_map_ops115.py --out research/work-items/RE-011-state-map-probes-115
python3 -m unittest tests.test_re11_state_map_ops115
python3 tools/artifacts.py verify
```

The tool checks the SHA-256 of the input binary first and fails on a mismatch. The regeneration writes only into the
`--out` folder, takes about 30 seconds and stays far below 1 GB. Every output is byte-identical between runs
(`MANIFEST.sha256` lists the hashes). The evaluator is the concrete x86-64 evaluator of `tools/re11_access_list115.py`
with two additions made in this tool: the `lock` prefix and signed conditions (`jle` after `lock inc`) with a real overflow
flag for `inc`/`add`/`sub`; it also tracks which instructions were executed.

## Evidence

Coordinates are virtual addresses of the node #115 ELF; extents come from the `.eh_frame` FDE of each entry point
(`functions.tsv`, `constants.json`). All 18 map bodies are executed completely (every instruction at least once);
`0x54793e0` executes 139 of its 142 instructions (the rest are the unwind landing pad).

| group | bodies | key | bucket | role |
| --- | --- | --- | --- | --- |
| entry | `0x3ed7040` `0x4ef78b0` | 20 B | 0xa8 | account map entry, two builds |
| entry | `0x4ef7ce0` | 20 B | 0xa0 | address-keyed map entry |
| entry | `0x3ed6ee0` `0x3ed71b0` `0x4ef7b80` `0x5be1e70` | 20 B | 0x40 | address-keyed map entry, four copies |
| entry | `0x3ed6d80` | 32 B | 0x68 | 32-byte-keyed entry |
| entry | `0x4ef7a20` | 32 B | 0x40 | 32-byte-keyed entry |
| entry | `0x4ef7e50` | 32 B | 0x28 | code-hash map entry (called by `0x54793e0`) |
| get | `0x3ed7e80` `0x4ef9240` `0x5be2230` | 20 B | 0xa8 | account map get, three builds |
| get | `0x3ed7d80` `0x4ef9140` `0x5be2460` | 20 B | 0x40 | address-keyed get, three builds |
| get | `0x5be2350` | 32 B | 0x68 | 32-byte-keyed get (value at element+0x20) |
| contains | `0x5bdef30` | 20 B | 0x40 | address set membership (returns `al`) |
| install | `0x54793e0` | 32 B | 0x28 | account code object install |

Observed rules (each is exercised by named case kinds in `cases.tsv` and by negative controls):

1. Hash. With `g` the 8-byte word behind GOT `0x64dfa78` and `seed` the qword at map header +0x20, `k0..k3` the key
   qwords: 20-byte key `h = fold(fold(k1^g, k0^seed) ^ k2, g)` with `k2` the last 4 bytes zero-extended; 32-byte key
   `h = fold(fold(k1^g, k0^seed) ^ k2, g^k3)`; `fold(a,b)` = low 64 bits xor high 64 bits of `a*b`.
2. Probe. `h2 = h >> 57`; group start `pos = h & mask`; a bucket matches when its control byte equals `h2` and the key bytes
   equal (16+4 or 16+16 bytes); an `0xff` byte in the group ends the walk; otherwise the stride grows by 16 per step
   (`pos += stride`), so the group offsets are 0, 16, 48, 96, ...
3. Geometry. The map header is `ctrl` (+0), `mask` (+8), `growth_left` (+0x10), `items` (+0x18), `seed` (+0x20); bucket `i`
   ends at `ctrl - i*stride` and starts `stride` bytes lower; the key is at the start; the `get` forms return the value
   pointer `bucket_start + 0x18` (20-byte keys) or `+0x20` (32-byte keys) and null on a miss.
4. `get` and `contains` return null / false at once when `items == 0` (before hashing). `contains` returns only `al`.
5. `entry`: hit -> block `[0, bucket_end, map]`; miss -> if `growth_left == 0` call the reserve callee with
   `(map, 1, map+0x20, 1)` and re-load the registers it clobbers, then block `[map, hash, key...]` (20 or 32 key bytes).
6. `0x54793e0`: return when `account+0x70` is set. If the 32 bytes at `account+0x48` equal the empty-code constant
   (`constants.json`, halves at `0x4537f0` and `0x452020`), take the shared empty-code Arc cell behind GOT `0x64e6c78`
   (call the lazy initialiser when its state dword is non-zero) and increment its strong count with `lock inc; jle`
   (`ud2` when the old signed count is -1 or lower; `0x7fff_ffff_ffff_ffff` passes). Otherwise probe the cache at
   `ctx+0x40` with `0x4ef7e50`; on a hit increment the Arc stored at bucket+0x20; on a miss call the loader
   (GOT `0x64e6458`, argument `[ctx+0x90]` and the hash), insert the 40-byte bucket (key, Arc pointer) with the hashbrown
   insert rule (first byte of the group with the top bit set; when that byte belongs to a mirror use the first such byte of
   group 0; control byte and its mirror get `h2`; `growth_left` drops by the low bit of the old control byte; `items`
   grows by one) and increment the new Arc. Finally drop a pre-existing `account+0x70` Arc (`lock dec`; slow drop when it
   reaches zero) and store the Arc pointer there.

Files (all generated by the tool, listed in `MANIFEST.sha256`):

- `functions.tsv`: address, extent, key length, bucket stride, value offset, reserve GOT slot and target, instruction and
  executed counts, body SHA-256, role.
- `decoded-instructions.tsv`: every instruction of the 19 bodies with its bytes and an executed flag.
- `callee-sites.tsv`: every call out of a body (direct or through a GOT slot) with the contract assigned to its target.
- `cases.tsv`: one row per case (function, number, kind, buckets, items, growth, hash, outcome class, callee events, executed
  steps, match).
- `outcome-classes.tsv`, `constants.json`, `negative-controls.tsv`, `survivors.tsv`, `summary.json`, `measure.json`.

## Implementation and comparison

`tools/re11_state_map_ops115.py` evaluates the real instruction bytes of each body and compares the result with
`model_map()` (entry/get/contains, one generic function parameterised by key length, stride and value offset) or
`InstallModel` (0x54793e0). The comparison covers the return value, the map header, the output block, the full table image
(unchanged by lookups), the ordered callee event list including the reserve arguments, and the callee-saved registers and
stack pointer on return. For `0x54793e0` it compares the byte images of the account, context, table, Arc cells, the heap
of loader-created cells and the empty-code cell, plus the event list and the `ud2` outcome. Each stub clobbers every
caller-saved register with a junk value, so a body relying on a register surviving a call would fail.

Cases (`make_map_case`, `make_install_case`, deterministic from a SHA-512 stream): 700 per entry body, 600 per get and
contains body, 2,600 for the install. Map kinds cycle through hit, miss, dense tables with one empty slot, control-byte
collisions with differing keys, a differing key byte at every position, tombstones, `items == 0`, growth left zero, seed
edge values, and 64-bucket tables whose empty slot is only reachable after three groups (hits at group offsets 16 and 48).
Install kinds add early return, empty hash with lazy-cell states, one-bit changes of each half of the empty hash, Arc
count edges, growth-left zero, a loader that installs a code pointer while it runs (to reach the `lock dec` arm), dense and
tombstone tables, and long probes.

Controls (646): 121 model mutants (swapped key words, ignored seed, `h2` shift 56, comparison one byte short, probe stride
8, inverted growth test, missing items check, missing empty-code shortcut, missing mirror write, missing wrap fix,
`g ^ k3` replaced by `k3`), 520 corrupted code bytes (every executed conditional jump inverted, the lowest byte of every
executed immediate flipped, every one-byte displacement changed by 8, over the first 160 cases of each map body and 200 of
the install) and 5 input controls (a binary with one flipped byte, a code read outside `.text`, and the 20-byte model, the
0xa8 stride and the get value offset run against the wrong machine code).

## Results and limitations

`measure.json`/`summary.json`: 14,400 cases, 0 mismatches, 1,299,230 evaluated instructions, 646 of 646 negative controls
detected. Outcome classes per family are in `outcome-classes.tsv` (for example 1,441 installs with a loaded code object, 737
installs sharing a cached or empty-code Arc, 285 `ud2` outcomes, 137 early returns).

`survivors.tsv` lists the 44 corruptions that no case in the control budget detected; they are not counted as controls.
Examples: `pshufd` immediate `0x44 -> 0x45` (the broadcast lanes hold equal bytes, so the result is the same),
`add rdi,0x10 -> 0x11` after the third group of a walk, the arguments `esi`/`ecx`/displacement of the reserve call setup
in some copies, and a stack reload in `0x54793e0` that reads the same value from two slots.

Limits:

- The callees are contracts, not reconstructions: the reserve callees (GOT `0x64e7028`, `0x64e7030`, `0x64e6c88`, `0x64e6c90`,
  `0x64e6c98`, `0x64e6d48`, `0x64e6d78`), the code loader (GOT `0x64e6458`), the Arc slow drop (GOT `0x64e4fa8`) and the
  lazy initialiser `0x5b084ff`. The reserve stub only sets `growth_left` to 9; it does not rehash.
- The roles of the maps are inferred from key length and geometry; the owner types are not recovered.
- The 603-byte and 376-byte siblings in the same address ranges (`0x3ed79a0`, `0x3ed7c00`, `0x4ef8600`, `0x4ef8fc0`,
  `0x5be1fd0`, `0x3ed7620`) are not included.
- The `lock dec` arm of `0x54793e0` is reached only with a loader that installs a code pointer during the call, which is
  a synthetic exerciser of that arm; whether the real loader can do that is unresolved.
- No component gate is requested; the packet does not cover the whole `evm` component.

Rust: not yet implemented. The model is Python only; no Cargo.lock, build flags or two-build comparison apply.

Next question: reconstruct the reserve/rehash callee shared by `0x3ed7040` and `0x4ef78b0` (GOT `0x64e6d48`, target
`0x3ee52a0`), which resizes the bucket array and re-hashes with the same foldhash, then the insert/remove siblings.
