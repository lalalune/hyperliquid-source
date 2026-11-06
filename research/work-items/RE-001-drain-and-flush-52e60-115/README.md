# RE-001: drain-and-flush routine 0x5d52e60 (node #115)

## Bounded question

What does the routine at `0x5d52e60` do to the holder's two pending
lists and its hash-linked record set, in what order, and through which
single caller is it reached?

## Answer (established semantics)

The routine `0x5d52e60` is a whole 1130-byte routine (FDE
`0x5d52e60..0x5d532ca`), not a lone-window fragment: it drains two
pending lists, then repeatedly removes the head record of a hash-linked
record set and emits one callback per record until the record count
reaches zero, and finishes with a tail counter decrement, a subobject
call and a tail jump. It takes a holder pointer in `rdi`, saves
`r15`, `r14`, `r13`, `r12`, `rbp` and `rbx`, reserves `0x98` stack
bytes, keeps a stack canary at `rsp + 0x88` (checked on the tail path,
failure goes to the stack-check failure PLT), and has no plain return:
its only exit is the tail jump to `0x60d52f0`. The disassembly
excerpts in this packet are verbatim objdump output: opcodes such as
`endbr64` are genuine instructions present in the target binary, not
placeholders.

The packet was produced with:

```
objdump -d --start-address=0x5d52e60 --stop-address=0x5d532ca work/hl-node-115.bin
objdump -d --start-address=0x5dd6060 --stop-address=0x5dd6097 work/hl-node-115.bin
readelf --debug-dump=frames work/hl-node-115.bin
readelf -r work/hl-node-115.bin
```

## Holder layout (offsets pinned, kinds not pinned)

- `+0x700`: subobject `S`, passed to the guard pair below.
- `+0xa10`: object passed to `0x60d57c0` on the tail path.
- `+0x1318`: record-table base. `+0x1320`: table modulus.
  `+0x1328`: record head, re-read each loop iteration.
  `+0x1330`: record count (qword). `+0x1444`: tail counter (dword).
- List A: cursor `+0x1398`, pair `+0x13a0`, base `+0x13a8`,
  chain `+0x13b0`, end `+0x13b8`.
- List B: cursor `+0x13e8`, pair `+0x13f0`, base `+0x13f8`,
  chain `+0x1400`, end `+0x1408`.

## Guard pair (call-shape only, results ignored)

`0x606ca40(S)` is called at entry, after each list pop (so before the
next cursor read), and once after each record callback. `0x60d52f0(S)`
is called after each list pop before the element is destroyed, after
each record free before the callback, and as the routine's final tail
jump. No lock or unlock semantics is claimed for this pair; only the
observed call order is pinned.

## Phase 1: drain list A

Loop: read the cursor at `+0x1398`; when it equals the end at
`+0x13b8`, go to phase 2. Otherwise read the element at the cursor,
advance the cursor by 8, call the guard close, and destroy the element
unless it is null (null slots are skipped after the pop): call
`0x5f04800` with the element, then a sized delete of `0x58`. When the
popped slot is the last slot of a chunk (cursor equals base `+0x13a8`
minus 8 before the pop), the chunk's `0x200` buffer is freed first and
the next chunk is installed from the `+0x13b0` chain: the chain pointer
advances by 8 and the pair at `+0x13a0` becomes (next data, next data
`+ 0x200`). The chunk-chain linking invariant is an assumption, not a
pinned claim; the per-chunk free and the pop order are pinned.

## Phase 2: drain list B

Same shape as phase 1, with cursor `+0x13e8`, end `+0x1408`, base
`+0x13f8`, pair `+0x13f0`, chain `+0x1400`, element destructor
`0x5d8d820` and sized delete `0x290`. The only ordering difference:
list B's first pop has no preceding guard open of its own (it follows
list A's trailing guard open directly); every later pop follows the
same close-destroy-open pattern. When the cursor equals the end, go to
phase 3.

## Phase 3: record removal loop (while the count at +0x1330 is nonzero)

Each iteration takes the record at the head field `+0x1328`:

1. Build two stack strings with `0x5d4a6a0`, call-shape only, with
   (output, string begin, string begin + size) for the record's string
   A then string B. The outputs start in short form (their data
   pointer preset to their own base `+ 0x10`).
2. Unlink the record from its bucket chain (see below).
3. Dispose the record's string B, then string A, with the string rule:
   data pointer at string base `+ 0x00`, capacity at base `+ 0x10`;
   short form when the pointer equals the base `+ 0x10` address, else
   a sized delete of (pointer, capacity + 1).
4. Free the record with size `0x68`, decrement the count at `+0x1330`
   by 1, call the guard close.
5. Call `0x5e4b7c0` with (holder, dword at record `+ 0x60`, first
   built string, second built string, dword at record `+ 0x50`,
   qword at record `+ 0x58`), call-shape only.
6. Call the guard open, dispose built string B then built string A
   with the same string rule, and re-check the count.

Record layout: next pointer `+0x00`, bucket key `+0x08`, string A at
`+0x10` (pointer `+0x10`, size `+0x18`, capacity `+0x20`), string B at
`+0x30` (pointer `+0x30`, size `+0x38`, capacity `+0x40`), dword
`+0x50`, qword `+0x58`, dword `+0x60`; total size `0x68`.

### Unlink rule

Bucket index = record field `+0x08` modulo the modulus at holder
`+0x1320`; the table base is at holder `+0x1318`. Walk from the bucket
slot value, following next links, until a node whose next equals the
record; that node is the predecessor. A bucket slot may hold the
head-field address (`+0x1328`) itself, meaning the head record is that
bucket's first element; storing a successor into that address advances
the head. Then:

- Predecessor equals the bucket slot value, successor null: if the
  predecessor is the head-field address, store the successor into the
  head field; clear the bucket slot; store the successor into the
  predecessor link.
- Predecessor equals the bucket slot value, successor in the same
  bucket: store the successor into the predecessor link only.
- Predecessor equals the bucket slot value, successor in a different
  bucket: store the predecessor into the successor's bucket slot; if
  the bucket slot held the head-field address, store the successor
  into the head field; clear the record's bucket slot; store the
  successor into the predecessor link.
- Predecessor deeper in the chain: store the successor into the
  predecessor link, plus a predecessor store into the successor's
  bucket slot when the successor's bucket differs; no bucket clear
  and no head store.

## Tail path (when the count reaches zero)

Decrement the dword at holder `+0x1444` by 1, call `0x60d57c0` with
holder `+0xa10`, check the canary, and tail-jump to `0x60d52f0`
with the subobject. The two landing pads at `0x5d532b2` and
`0x5d532be` jump to `0x5d52e22` and `0x5d52e2c` outside this routine's
FDE; their targets are unpinned.

## Consumers

Executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's `census.py` and re-run
inside `verify.py`: exactly 0 direct calls and 1 tail jump across 1
caller FDE (see `callers.tsv`); 0 stored qwords in a full-file 8-byte
scan, 0 RELATIVE relocations for the routine itself — reached only by
code, never by data. The sole caller is the 55-byte stub at
`0x5dd6060..0x5dd6097` (excerpt in `caller.txt`): it compares the
qword at `0x64ed5d0` with zero, calls `0x606d9f0` with the same
argument when nonzero, writes 2 into the TLS slot at `fs:0 - 0x3f8`,
then tail-jumps to the routine with the argument unchanged.

## Unknowns (kept separate from findings)

- The source-level names and kinds of the holder, the subobject, the
  records, the table and the callback, and what the two lists and the
  record set mean at source level.
- What the element destructors, the range builders, the guard pair,
  the tail subobject call and the per-record callback compute; all are
  call-shape only here.
- The chunk-chain linking invariant and the table's full invariant
  (why a bucket slot sometimes holds the head-field address); the
  packet pins the observed stores, not the invariant behind them.
- Whether the record set is a cache, an index or some other table;
  the observable behaviour is the unlink rule above, and any such
  reading is an inference, not a pinned claim.
