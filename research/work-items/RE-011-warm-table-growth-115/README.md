# RE-011: EVM warm-set table growth (reserve_rehash 0x3eda870 and 0x143d5f0) and teardown 0x2a03a10 (node #115)

With this packet, the storage life cycle of the node #115 EVM warm set (`HashMap<Address, HashSet<U256>>` at context +`0x2e0`) can be rebuilt as code: given a table and an `additional` count, the reconstruction yields the exact table after growth (in-place rehash or resize: control bytes with mirror, bucket positions, growth counter, allocation and free calls) or the exact error or panic, and given a map it yields the exact free sequence of its drop. The packet reconstructs and byte-checks:

- the map `reserve_rehash` body `0x3eda870` (64-byte buckets, inlined address hasher) with its allocation helper `0x3ed8040`;
- the set `reserve_rehash` body `0x143d5f0` (32-byte buckets), with its own hasher copies `0x143dd40`/`0x143dcc0` run as real code;
- the map drop `0x2a03a10` (inner set allocations, then the map allocation).

The reconstruction matches the real machine code in all 5,300 cases, and all 34/34 negative controls are detected.

- Component ID: `evm` (RE-011 "one bounded EVM adapter"; this is the growth path that the RE-011 access-list loader packet stubbed at GOT `0x64e7030` and `0x64dfab8`, and the drop it stubbed at `0x2a03a10`)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: `05bc2de303c05525b71e7e257426e741bc66a390` (main at the time of the run)
- Claim status: reconstructed, for the scope below. Allocator entry points (`malloc` `0x6355830`, `mallocx` `0x63577f0`, `sdallocx` `0x635de30`), `memset`/`memmove`, the capacity-overflow panic `0x1680e80` and `handle_alloc_error` `0x141e251` are stubbed at their call boundaries; their arguments and call order are compared.
- Scope:
  - the whole FDEs of `0x3eda870` (1,430 bytes), `0x3ed8040` (428 bytes), `0x143d5f0` (1,738 bytes) and `0x2a03a10` (255 bytes);
  - the set hasher callees `0x143dd40` and `0x143dcc0` and the foldhash byte hasher they reach are executed as real code but are not separately listed (the byte hasher is covered by the RE-011 access-list packet);
  - out of scope: the internals of the allocator and the panic/alloc-error handlers, and the consumers of the warm set.

## Reproduce

```
python3 tools/re11_warm_table115.py --out research/work-items/RE-011-warm-table-growth-115
python3 -m unittest tests.test_re11_warm_table115
python3 tools/artifacts.py verify
```

How the tool works:

- It checks the input SHA-256 first, then reads FDE extents with `tools/fde_extents.py` and sections with `tools/elf_index.py`. SHT_NOBITS sections are never used for byte reads; the global seed block `0x64ffe90` (GOT `0x64dfa78`) lies in `.bss` and gets synthetic per-case words.
- It reads `.rela.dyn` (RELATIVE addends for the GOT slots, GLOB_DAT for `memmove`/`memset`) and code bytes from `.text`.
- It runs the real code with a small concrete x86-64 evaluator. For this path the evaluator gained `pcmpgtb`, `por`, `bsr`, `cmp r8, r/m8` with a real overflow flag (the `jno` DELETED test), and `xor eax, imm32`. It raises on any form it does not support. The binary is never executed and no external program is called.
- Cases come from a SHA-512 counter stream. Every starting table is built by real insertions with the reconstructed hash and probe rule, then some entries are tombstoned, so the tables are states the node can reach.
- Two generations with different `PYTHONHASHSEED`/`TZ` and `PATH` pointing at no binutils are byte-identical.

Human-readable excerpt (`objdump -d`, abridged, not used by the tool):

```
3eda87e: mov 0x18(%rdi),%r13 ; add %r13,%rsi ; jb 3edaddb     items + additional overflow
3eda8aa: cmp $0x8,%r14 ; cmovb %r14,%rax ; shr $1,%rdi ; cmp   full_cap(mask) / 2 -> in place
3eda8d3: mov $0x40,%esi ; call 3ed8040                          new table, 64-byte buckets
3edaac4: pcmpgtb (%r15,%rcx),%xmm1 ; por 0x454f80,%xmm1         FULL->DELETED, special->EMPTY
3edace0: cmp (%r15,%rdi),%sil ; jno 3edacd7                     only DELETED slots are re-seated
3edabbe: cmp $0x10,%rbp ; jb 3edacc0                            same probe group: keep the slot
3edabf2: cmp $0xff,%bpl ; je 3edad02                            target EMPTY: move, else swap
3edadc0: cmp $0x10,%r14 ; setb %dl ; shl $0x2,%edx ; call *0x64df4a0   sdallocx flags
2a03a94: shl $0x5,%rcx ; add %rcx,%rsi ; add $0x31,%rsi         inner set size 33*mask+49
```

## Evidence

Generated files (all rebuilt byte for byte by the tool):

| File | Content |
| --- | --- |
| `constants.json` | FDE extents and code SHA-256 of the four functions, the GOT slots and their RELATIVE/GLOB_DAT targets, the `0x80` x16 constant at `0x454f80`, the static empty group `0x450150` |
| `cases.tsv` | 5,300 cases: kind, shape, table before, `additional`, fallibility, outcome, `rax`, table after, the full call sequence, a state digest, match |
| `outcome-classes.tsv` | cases per kind and outcome |
| `decoded-instructions.tsv` | every instruction of the four FDEs with its bytes and whether a case executed it |
| `negative-controls.tsv` | 34 controls: 15 model, 17 code-byte, 2 input |
| `summary.json` | totals, coverage and control counts |

Observations (from the bytes, checked by the cases):

1. Both bodies take `(table, additional, &seed, fallibility)` in `rdi, rsi, rdx, cl` and return `0x8000000000000001` for `Ok`. The table header is `[ctrl, bucket_mask, growth_left, items]`, and the per-table seed sits at +`0x20`.
2. `items + additional` carry: fallible returns `rax = 0` (CapacityOverflow); infallible calls the panic at GOT `0x64df6b8` with message length `0x39`.
3. Rehash in place when `items + additional <= full_cap(mask) / 2`, where `full_cap = mask` for `mask < 8`, else `(mask+1)/8*7`. Otherwise resize to `max(items + additional, full_cap + 1)`.
4. Capacity to buckets: `cap < 4 -> 4`, `cap < 15 -> (cap & 8) + 8`, `cap >> 61 != 0 -> overflow`, else `next_power_of_two(cap * 8 / 7)` (multiply by `0x2492492492492493`, then `bsr`). The set body also rejects `buckets - 1 > 0x7fffffffffffffe`.
5. Layout: `ctrl_offset = buckets * bucket_size` (map: `mul` with `jo`, then `> 0xfffffffffffffff0` -> overflow, rounded to 16), `total = ctrl_offset + buckets + 16`; carry or `total > 0x7ffffffffffffff0` -> overflow. Allocation is `malloc(total)` (the helper's `mallocx(total, 4)` arm for `total <= 15` cannot be reached because `total >= 20`). A null result returns `(rax, rdx) = (16, total)` when fallible, and calls `handle_alloc_error(16, total)` when infallible.
6. Resize: `memset(ctrl, 0xff, buckets + 16)`, then every full bucket in ascending group order is hashed, given the first EMPTY/DELETED slot of its probe sequence (with the small-table wrap fix that falls back to group 0), and its `h2 = hash >> 57` is written to the slot and its mirror `((i - 16) & mask) + 16`. `growth_left = full_cap(new_mask) - items`. The old allocation, if `mask != 0`, is freed with `sdallocx(ctrl - (mask+1)*size, (mask+1)*size + mask + 17, size < 16 ? 4 : 0)`.
7. In place: groups are rewritten with `pcmpgtb`/`por` (FULL -> `0x80`, EMPTY/DELETED -> `0xff`), then the first 16 bytes are mirrored (`memmove(ctrl + buckets, ctrl, 16)`, or `memmove(ctrl + 16, ctrl, buckets)` for small tables). Each `0x80` slot is re-hashed. If the new slot is in the same probe group (`((i - p) ^ (new - p)) & mask < 16`), only the control byte is written. If the target was EMPTY, the bucket is moved and the old slot becomes EMPTY. If it was DELETED, the two buckets are swapped and the same index is processed again.
8. Hashes: the map hash is inlined in both loops (`fold(k1 ^ g0, k0 ^ seed) ^ k2`, then `fold(., g0)`), the same function as the access-list probe. The set body hashes through its own copies `0x143dd40`/`0x143dcc0`, which produce the same value as the access-list set hasher `0x24b6e30`.
9. Drop: when `mask == 0` nothing is freed. Otherwise every full map bucket whose inner set has `mask != 0` frees `(inner_ctrl - 32*(mask+1), 33*mask + 49, 0)`, and then the map frees `(ctrl - 64*(mask+1), 65*mask + 81, 0)` through a tail jump.

## Implementation and comparison

`reserve_model` and `drop_model` in `tools/re11_warm_table115.py` are the pure-Python reconstruction (standard library only). For each case the tool builds the table in evaluator memory, runs the real entry point, and compares four things with the model's prediction: the returned `rax` (and `rdx` for AllocError); the boundary reached (panic or alloc error with its arguments); the ordered allocator/`memset`/`memmove`/free calls with their arguments; and the canonical table after the call. The canonical table is the header, every control byte including the mirror, and every full bucket's bytes.

Case shapes, per body: `grow` (random tables and additional), `dense` (the new table ends at exactly 7/8 load, so it has full groups and hits the small-table wrap fix), `inplace` (tombstone-heavy tables with additional inside the in-place bound), `cluster` (keys searched so their probe starts fall in one narrow window, which forces long re-seat chains with swaps), `static` (the shared empty singleton), `huge` (additional near 2^55..2^64, including wrapping sums), and `allocfail` (null allocation, both fallibilities). Drop cases use maps whose inner set headers have masks 0..4095.

## Results and limitations

- 5,300 cases (map 2,300, set 2,100, drop 900): 0 mismatches. See `outcome-classes.tsv`. Every outcome class is present for both bodies: in place, resize from the static table, resize with free, CapacityOverflow error and panic, AllocError and `handle_alloc_error`, and the three drop classes.
- Negative controls, 34/34 detected:
  - 15 wrong reconstructions: no mirror byte, no wrap fix, in-place bound `full` instead of `full/2`, move instead of swap, no same-group shortcut, growth without `- items`, wrong free flags, drop skipping inner sets, doubled bucket count, small-capacity rule, `h2 = hash >> 56`, swapped address words, length prefix 1, wrapping `items + additional`, no `cap >> 61` check;
  - 17 single code-byte changes on the immediates listed in `negative-controls.tsv`;
  - 2 input controls: wrong table seed, wrong global seed word.
- Coverage: 958/998 instructions executed (map 353/362, helper 113/121, set 408/430, drop 84/85). The unexecuted ones are:
  - padding;
  - the `buckets == 0` in-place arms (unreachable, since `mask + 1 >= 1`);
  - the helper's `total == 0` and `mallocx` arms (unreachable, since `total >= 20`);
  - the set finish arm for an empty sponge (unreachable for 32-byte keys);
  - the landing pads;
  - the in-place wrap fix of both bodies and one back-edge of the second probe continuation. The in-place wrap fix needs at least three re-seated items in an 8-bucket table, but the in-place bound allows at most `3 - additional <= 2` there. Callers only reserve with `additional > growth_left >= 0`.
- Precondition: cases use `additional > growth_left`, as the callers do. A call with `additional = 0` on the static empty table would write to read-only data.
- Limits: allocator behaviour beyond "null or a fresh 16-byte aligned block" is not modelled. The seed values are synthetic, because the seed block is `.bss`. This packet does not advance any component gate.
