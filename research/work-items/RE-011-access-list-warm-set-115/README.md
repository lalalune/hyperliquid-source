# RE-011: EVM access-list warm-set loader 0x2668ac2 with probe, insert and foldhash (node #115)

With this packet, the node #115 EVM access-list loader can be rebuilt as code: given a transaction access list, the reconstruction yields the exact `HashMap<Address, HashSet<U256>>` that the node installs at context +`0x2e0`. "Exact" covers bucket positions, control bytes, growth counters and per-table seeds. The packet reconstructs and byte-checks this whole path:

- the loader loop and tail `0x2668ac2..0x2668e7a`;
- the address entry probe `0x2a318d0`;
- the storage-key set insert `0x2a32b00`;
- the U256 hasher `0x24b6e30` and its sponge writer `0x24b7080`;
- the foldhash byte hasher `0x1770830`, all of its length paths.

The reconstruction matches the real machine code in all 5,512 cases, and all 27/27 negative controls are detected.

- Component ID: `evm` (RE-011 "one bounded EVM adapter"; continues the RE-021 caller head packet, which stopped at `0x2668ac2`)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: `05bc2de303c05525b71e7e257426e741bc66a390` (main at the time of the run)
- Claim status: reconstructed, for the scope below. The two table-growth calls (`reserve_rehash`, GOT `0x64e7030` → `0x3eda870` for the map and GOT `0x64dfab8` → `0x143d5f0` for sets), the drop of the previous map `0x2a03a10`, and the lazy seed init `0x1770b40` are stubbed at their call boundaries. Their arguments and call order are checked.
- Scope:
  - `0x2668ac2..0x2668e7a`, the access-list branch of `0x2668a20` up to its FDE end, including the lazy-init islands;
  - the whole FDEs of `0x2a318d0`, `0x2a32b00`, `0x24b6e30`, `0x24b7080` and `0x1770830`.
  - Out of scope: the caller head before `0x2668ac2` (already reconstructed in the RE-021 selector refresh packet), the internals of `reserve_rehash`, and the seed generator `0x1770a70`/`0x1770b40`.

## Reproduce

```
python3 tools/re11_access_list115.py --out research/work-items/RE-011-access-list-warm-set-115
python3 -m unittest tests.test_re11_access_list115
python3 tools/artifacts.py verify
```

How the tool works:

- It checks the input SHA-256 first.
- It reads FDE extents with `tools/fde_extents.py` and sections with `tools/elf_index.py`. SHT_NOBITS sections are never used for byte reads; the global seed block `0x64ffe90` lies in `.bss` and gets synthetic per-case contents.
- It reads relocations from `.rela.dyn` and code bytes from `.text`.
- It runs the real code bytes with a small concrete x86-64 evaluator. The evaluator covers the SSE2 group ops (`pcmpeqb`, `pmovmskb`, `punpcklbw`, `pshuflw`, `pshufd`, `shufpd`, `psubq`), `fs:` TLS addressing and `shld`, and it raises on any instruction form it does not support. The binary is never executed and no external program is called.
- Two generations, run with different `PYTHONHASHSEED`/`TZ` and with `PATH` pointing at no binutils, are byte-identical.

Human-readable excerpt (`objdump -d --start-address=0x2668ac2 --stop-address=0x2668e52`, abridged); it is not used by the tool:

```
2668ad1: mov 0x178(%r15),%r12 ; mov 0x180(%r15),%rbx    ; list ptr / len
2668ae4: mov %fs:-0x578,%rax ; xor $0x13198a2e03707344 ; mul %rsp ; xor hi -> fs:-0x578
2668b02: movabs $0xa4093822299f31d0,%rcx ; mul ; xor     ; map seed
2668b12: mov 0x64dfa78 -> 0x64ffe90 ; cmpb $2,0x30(%rax) ; jne init
2668b7f: copy 20-byte address from item+0x18 ; call 2a318d0 (probe)
2668bec: vacant: same TLS step -> set seed ; SSE2 insert slot ; h2 = hash>>57 + mirror
2668d05: keys = item+0x8 / item+0x10 ; add = items ? (n+1)/2 : n ; if add > growth: call *0x64dfab8
2668d40: 4 x bswap ; call 2a32b00 (set insert)          ; per storage key
2668ddd: call 2a03a10(ctx+0x2e0) ; store map ; movq $0x25,(%r14)
```

## Evidence

All values below come from the generated files (`constants.json`, `decoded-instructions.tsv`).

| Item | Address | Bytes / value |
| --- | --- | --- |
| Loader (in `0x2668a20`) | `0x2668ac2..0x2668e7a` | FDE `0x2668a20`, 1114 bytes; 207 instructions in scope, 197 executed |
| Address entry probe | `0x2a318d0..0x2a31a25` | FDE `0x2a318d0`, 341 bytes; 95 instructions in scope, 95 executed |
| Set insert | `0x2a32b00..0x2a32c97` | FDE `0x2a32b00`, 407 bytes; 107 instructions in scope, 105 executed |
| U256 hash | `0x24b6e30..0x24b6e9a` | FDE `0x24b6e30`, 106 bytes; 28 instructions in scope, 24 executed |
| Sponge writer | `0x24b7080..0x24b70ff` | FDE `0x24b7080`, 127 bytes; 39 instructions in scope, 39 executed |
| Foldhash byte hasher | `0x1770830..0x1770a63` | FDE `0x1770830`, 563 bytes; 161 instructions in scope, 161 executed |
| TLS counter | `fs:-0x578` (`64 48 8b 04 25 88 fa ff ff` at `0x2668ae4`) | `t = fold((t ^ 0x13198a2e03707344) * rsp)`; seed = `fold(t * 0xa4093822299f31d0)` |
| Global seed block | GOT `0x64dfa78` → `0x64ffe90` (`.bss`, NOBITS) | 6 seed words, state byte +`0x30` (2 = ready, otherwise call GOT `0x64e22e8` → `0x1770b40`) |
| Byte hasher | GOT `0x64dfa80` | RELATIVE → `0x1770830` |
| Reserve (map / set) | GOT `0x64e7030` / `0x64dfab8` | RELATIVE → `0x3eda870` / `0x143d5f0` |
| Empty table template | `0x64371f8` (32 bytes) | control pointer → static group of 16 `0xff`, mask 0, growth 0, items 0 |
| Insert counter constant | `0x450790` (shufpd source) | high word `0xffffffffffffffff`, so `psubq` gives items + 1 and growth − (old ctrl & 1) |
| Access list | context +`0x178` / +`0x180` | items of `0x30` bytes: key Vec ptr +`0x8`, len +`0x10`, address +`0x18` (20 bytes) |
| Result | context +`0x2e0..0x308`, `*out` | new map (ctrl, mask, growth, items, seed); tag `0x25` |

## Implementation and comparison

The reconstruction is `loader_model`, `Table`, `hash_addr`, `hash_u256`, `write_model` and `bytes_hash` in `tools/re11_access_list115.py` (pure Python).

Loader (`0x2668ac2..0x2668e51`):

1. Advance the TLS counter: `t = fold((t ^ 0x13198a2e03707344) * rsp)`, where `fold(x) = lo64 ^ hi64` of the 128-bit product. The map seed is `fold(t * 0xa4093822299f31d0)`.
2. If the global seed state byte is not 2, call the lazy init once.
3. Start from an empty map (32-byte template + seed).
4. For each access-list item:
   - hash the address: `x = fold((k1 ^ g0) * (k0 ^ seed)) ^ k2`, then `h = fold(x * g0)`, where `k0`/`k1` are the first two u64 words and `k2` is the trailing u32;
   - probe: SSE2 groups with `h2 = h >> 57` and a triangular stride of 16;
   - on a miss: if the map's growth is 0, reserve 1. Advance the TLS counter again to get a fresh set seed, take the first EMPTY slot of the probe sequence (or, when the masked index lands on a full byte, the first special byte of group 0), and write `h2` plus its mirror. The 64-byte bucket is `address[20] ‖ low32(&local map) ‖ empty set (ctrl, mask, growth, items) ‖ set seed`;
   - for the item's `n` storage keys: `add = items ? (n+1)/2 : n`. If `add > growth`, reserve `add`.
   - for each key, byte-swap the 32 big-endian bytes into U256 limbs and insert it (see below).
5. Drop the previous map at +`0x2e0`, store the new map there, and write `0x25` to `*out`.

Set insert `0x2a32b00`:

1. Hash the key.
2. If growth is 0, reserve 1 (this happens even when the key is already present).
3. Run a combined find-or-insert-slot probe and write the 32-byte key.

U256 hash (`0x24b6e30` / `0x24b7080`):

1. Write the length prefix 4 into the 128-bit sponge.
2. `seed' = bytes_hash(key32, rol(seed, 32))`.
3. `h = fold((g0 ^ acc1) * (seed' ^ acc0))`.

When the sponge byte is ≥ `0x41`, the writer first flushes: `fold((g0 ^ acc1) * (seed ^ acc0))`.

`bytes_hash` `0x1770830`:

- `n < 16`: panic.
- `16..0x80`: medium path, folding head and tail words at the cuts `0x1f`, `0x40` and `0x60`.
- `0x81..0x100`: a 4-lane loop over 64-byte blocks.
- `> 0x100`: a 6-lane loop over 96-byte blocks.

Seed words `g0..g5` mix in as `g[i] + seed`.

Each loader case compares the following:

- the decoded map at +`0x2e0`, recursively: mask, growth, items, seed, every control byte including the mirror, every bucket's address, padding bytes, set header, set control bytes and keys;
- the ordered stub events (init / reserve_map / reserve_set with item count and additional / drop);
- the final TLS counter;
- the result tag;
- `rax`;
- the restored callee-saved registers and stack pointer;
- the rest of the context, which must be untouched.

Direct cases compare `rax` (byte hasher, U256 hash), or the whole sponge state and global pointer (writer).

Case sets:

- 1,700 loader cases: empty lists; growing distinct lists that grow the map 4 → 8 → … buckets; repeated addresses (occupied entries and the `(n+1)/2` heuristic); duplicate keys; one address with up to 60 keys (set growth past 16 buckets); all-zero, all-`0xff` and single-bit addresses and keys; and global-seed states 0/1/3/`0xff` (lazy init).
- 3,812 direct-entry cases: the byte hasher at every length 0..384 plus random lengths up to 4,080 (panic, medium, 4-lane and 6-lane paths); the writer at every sponge length byte 0..255, twice; and 700 U256 hashes.

## Results and limitations

- Mismatches: 0 of 5,512 cases (`summary.json`; per-case rows in `cases.tsv`).
- Coverage: 621/637 in-scope instructions executed. The 16 not executed are: two alignment nops (`0x2668b62`, `0x2668cff`); the in-loop lazy-init island `0x2668dbd..0x2668dc8`, which cannot run once the head check `0x2668b1d` has initialised the state; the unwind landing pad `0x2668e63..0x2668e7a`; the empty-sponge return `0x24b6e8d..0x24b6e9a` (the writer always leaves length `0x40`); and `0x2a32be6..0x2a32bee`, which needs a group with DELETED but no EMPTY bytes, and the loader never deletes (`decoded-instructions.tsv`).
- Outcome classes: 41; the map grows to 64 buckets and sets to 128 buckets, with and without lazy init (`outcome-classes.tsv`).
- Negative controls: 27/27 detected (`negative-controls.tsv`):
  - 12 model mutants: medium cut `≥32`, length prefix 1, no seed rotation, swapped address words, no byte swap, no full-byte fix-up, no mirror byte, raw map seed, no lazy init, zero padding, unchained set seed, full reserve instead of `(n+1)/2`;
  - 13 code-byte mutants on immediates and ModRM bytes (TLS constant, state compare, item stride, the `shr` of the heuristic, both `>>57` shifts, the key-equality mask, prefix 4, rotation 32, byte count 32, the medium and long cuts, and the `incq` base);
  - 2 input controls (flipped `.text` byte, address past `.text`).
- unittest: 8 tests OK, no skips (about 40 s).

Limits:

- `reserve_rehash` is stubbed with the hashbrown resize rule: buckets = `capacity_to_buckets(max(items + add, full_cap + 1))`, with full buckets reinserted in index order using the reconstructed hashes. The real `0x3eda870`/`0x143d5f0` bodies are not run. Duplicate addresses and keys after a growth are found again by the real probe code, which cross-checks the stubbed placement.
- The global seed words and the TLS counter are random per case. Their real values come from the seed generator `0x1770a70` (not reconstructed) and from the runtime stack address.
- The padding bytes `bucket+0x14..+0x18` hold the low 32 bits of the local map address (stack). They are reproduced, but they carry no meaning.
- Inferred, not proven: this is the EIP-2929/2930 warm set (accessed addresses → accessed storage slots) built from the transaction access list. The names `Address`, `U256` and "warm set" are not established by bytes.
