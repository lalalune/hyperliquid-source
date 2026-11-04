# RE-001: the node #115 lu next-node call — thunk, table lookup, then join

Answers packet #213's next question: what the `0x63ae260` next-node call does
end to end.

## Short answer

`0x63ae260` is a 24-byte thunk, not the lookup itself. It zero-extends the
sixth argument, pushes a seventh argument `0`, tail-calls the worker
`0x63adf40`, and returns the worker's result. The worker is a hash-table
lookup in a 16-bucket table at `thread+0x1b0` with an 8-entry overflow area,
followed by a gate chain and a join call. It returns the derived entry
pointer, or NULL on any gate failure.

## The thunk (FDE `0x63ae260..0x63ae278`, 24B, single `ret`)

```
0x63ae260: endbr64; sub $0x10,%rsp; movzbl %r9b,%r9d; push $0x0;
           call 0x63adf40; add $0x18,%rsp; ret
```

Incoming args (as called by the #213 chain helper): `rdi` = thread,
`rsi` = `[ref+0xe410]`, `rdx` = node, `rcx` = 0, `r8` = kind, `r9` = 1-or-0.
The thunk passes all registers through, zero-extends `r9b`, and adds a
seventh stack argument `0`. The worker therefore sees
`(thread, [ref+0xe410], node, 0, kind, flag6, 0)`.

A sibling thunk at `0x63ae280` (FDE 26B) forces `r9 = 1` and stack `1` instead;
it has a single caller (see Census). It is cited, not claimed, here.

## The worker (FDE `0x63adf40..0x63ae252`, 786B, single `ret` at `0x63ae06a`)

Args: `rdi` = thread, `rsi` = `[ref+0xe410]`, `rdx` = node, `rcx` = arg4,
`r8` = kind, `r9` = flag6, stack7. Saves: kind → `r15d`, arg4 → `r14d`,
flag6 → `r13d`, thread → `r12`, node → `rbp`, stack7 → `r10d`.

1. **Candidate key `rbx` (flag6 selects the formula).**
   - flag6 == 0: `rbx = page([node+8]) - 0x1000`.
   - flag6 != 0: `rbx = page([node+8]) + page([node+0x10])`.
   - `rbx == 0` → NULL.
2. **Thread == 0 detour.** If thread is NULL, the worker calls `0x63d9880`
   with a stack buffer, restores `rsi`/`r10d`, and rejoins the lookup.
   The detour's internals are not decoded here.
3. **Table lookup.** Bucket = `thread+0x1b0 + ((rbx>>26) & 0xf0)` (16 buckets
   of 16B); the bucket key must equal `rbx & 0xffffffffc0000000`.
   On a bucket miss, the worker scans the 8-entry overflow at
   `thread+0x1b0+0x100 .. +0x170`: a hit at slot `i` rotates three entries
   (bucket ← overflow[i], overflow[i-1] ← bucket, overflow[i] ←
   overflow[i-1]); slot 0 is a plain swap. On a full miss it calls the
   miss handler `0x63d9700(thread, table, rbx, 0, 0)` and uses its return.
   The miss handler's internals are not decoded here.
4. **Entry validation.** `rax = value + ((rbx>>9) & 0x1ffff8)`; NULL if
   `rax == 0`. Then `rax = *rax`; NULL if `(rax & 0xffffffffff80) == 0`.
5. **Flag6-selected NULL gate.**
   - flag6 == 0: NULL if bit 44 of `[node]` is set.
   - flag6 != 0: NULL if bit 1 of the entry word is set.
6. **Arg4-selected kind check.**
   - arg4 == 0: NULL unless `kind == (entry >> 2) & 7`.
   - arg4 != 0: NULL if `(entry >> 2) == 0`.
7. **Stack7-selected gate (arg4 == 0 path only).**
   - stack7 == 0: NULL unless bit 13 of `*rax` equals bit 13 of `[node]`.
   - stack7 != 0: the bit-13 gate is skipped.
8. **Shared tail.** NULL unless bit 14 of `*rax` equals arg4. If the
   `.data` byte at `0x64ffc28` is zero, NULL unless
   `(([node] ^ *rax) & 0xfff) == 0`; a nonzero byte skips that check.
   Then the worker calls join `0x63adb50(thread, [ref+0xe410], rax, 5)`,
   discards the join's return, restores `rax`, and returns `rax`.

Notes: `[ref+0xe410]` is not read by the lookup itself — it is forwarded to
the join call (and preserved across the two detour calls). The lookup table
is `thread+0x1b0`, not `[ref+0xe410]`. The worker never frees a node and
never manufactures a NULL except through the gates above.

## What the sixth argument selects

Two things, both inside the worker: (a) the `rbx` formula (step 1), and
(b) which bit gates the NULL return (step 5: `[node]` bit 44 when 0, entry
bit 1 when nonzero). Via the chain helper, the head call passes 1 and the
retry calls pass 0. Via the sibling thunk, the sixth argument is forced to 1
and the seventh to 1 (which skips the bit-13 gate on the arg4 == 0 path).

## Census (whole-`.text` byte scan + per-site disassembly)

| target | E8 | E9 | LEA | GOT (`.rela.dyn` addends) |
|---|---|---|---|---|
| thunk `0x63ae260` | 3 (`0x63b1bad` head, `0x63b1c0a` retry, `0x63b1c75` second-next; all in chain FDE `0x63b1b60..0x63b1d5a`) | 0 | 0 | 0 of 60,723 |
| thunk-B `0x63ae280` | 1 (`0x63b479d`, FDE `0x63b46e0..0x63b4aeb`) | 0 | 0 | 0 of 60,723 |
| worker `0x63adf40` | 2 (`0x63ae26e`, `0x63ae290` — the two thunks) | 0 | 0 | 0 of 60,723 |

## Exhibits

5 excerpts, 222 bytes, 56 strict instructions (continuation lines excluded):
`thunk` 24B/7, `head` 44B/9, `valid` 39B/11, `kind` 44B/11, `tail` 71B/18.
Address-cited (key-byte checked, not excerpted): thunk-B body, worker
prologue saves, `rbx == 0` gate, bucket compare, overflow slot-0 compare,
flag6 bit test, arg4 entry check, stack7 gate, bit-13 mismatch jump,
`0x64ffc28` lea/cmpb, xor gate. Callees characterised only: `0x63d9880`
(thread == 0 detour), `0x63d9700` (miss handler), `0x63adb50` (join),
`0x63b0780` / `0x63b1810` / `0x63b0560` / `0x63c1c40` (not decoded here).

## Corrections to earlier packets

None. Confirmed, not corrected: the three chain-helper call sites match #213
exactly; the `.data` byte `0x64ffc28` first noted in #211 is read by this
worker too (as the xor-gate switch); the join call shape matches #212, with
the fourth argument a literal `5` here (callers vary it).

## Next question

Decode the `0x63d9700` miss handler end to end: what it does with
`(thread, table, rbx, 0, 0)`, what entry pointer it returns, when it returns
NULL, and how it inserts or evicts on a full miss.
