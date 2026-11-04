# RE-015: node 115 out-buffer owner of the flag-group chain

```text
Task: RE-015
Function: 0x15a3b90 (out-slot windows), with the format consumer 0x141e3a0 and the callee 0x15ae430 as cited boundaries
Topic: who allocates the 24-byte out header the chain's descriptors carry, and where the accumulated output is consumed
Input binary SHA-256: a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
Status: static evidence derived from authenticated native bytes
Executed: false
```

Why this item: the RE-015 descriptor-table-method packet
(#2463) traced the chain's final write — the table method
`0x141e8f0` appends the selected level name into a 24-byte out
header (capacity at `+0x0`, buffer pointer at `+0x8`, length at
`+0x10`) — and left the header itself open: which function
allocates that header, and where the accumulated output goes
after the format walk. This packet answers both ends. The
header the write target formats into is constructed by the
format consumer `0x141e3a0` itself, on its own stack; the
terminal owner of the delivered header is a stack slot of the
large consumer `0x15a3b90`, which moves it into a sorted-node
map after the calls.

The answer, in three stages:

1. **Construction (format consumer `0x141e3a0`).** For each
   format, the consumer sizes a capacity from its template
   scan (the total doubled, or 0 when the total is under
   `0x10` and a placeholder came first), allocates that many
   bytes through the `.got` alloc slot (`0x64df480` →
   `0x6355830`), stores the triple `{capacity, pointer, 0}`
   into a header on its own stack, calls the write target
   with the header's address, and on success copies the whole
   triple — advanced length included — into its caller's out
   slot. The consumer never reads the caller slot's previous
   words. (Construction sites re-pinned here; the full trace
   of this body is the flag-group-format packet, #2408.)
2. **Delivery (callee `0x15ae430`).** The callee receives the
   two formats' headers in its own scratch out slots
   (`[rsp+0x28]`, then `[rsp+0x10]`), and stores the second
   format's triple into its caller's out slot; on its zero
   path it copies its aux argument's triple there instead.
   (Delivery sites re-pinned here; the full trace of this
   body is the derived-byte-callee packet, #2396.)
3. **Terminal ownership (large consumer `0x15a3b90`, traced
   here).** All four of the large consumer's callee calls —
   two per flag segment — pass the same stack slot
   `[rsp+0x158]` as the out argument. On the segments'
   non-format paths the large consumer prefills that slot
   itself: it allocates a fresh buffer of a recorded size,
   copies the recorded bytes in through the `memcpy` slot,
   and stores `{size, pointer, size}`. After the calls, the
   slot is read only by the consumption windows: the consumer
   walks its sorted-node map (root handle at `[rsp+0x178]`)
   and, on a hit, stores the triple into the found entry —
   freeing the replaced entry's buffer through the dealloc
   slot (`0x64df4a0` → `0x635de30`) unless its capacity is 0
   or a sentinel — and, on a miss, copies the triple verbatim
   into the value record of a call to the map insert function
   `0x156d840`. The chain never frees the delivered buffer:
   ownership passes to the map entry.

## Exact scope

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| large_consumer (owner) | `0x15a3b90..0x15a6509` | 10617 | `7995f7af57e2be27ca6ed1e307d9bcce9d6140f72b0ff0cf0804d7f09e5505fb` |

Measured denominator: one complete FDE, **10617 bytes**,
hash-pinned with two retained window disassembly exports
(segment A `0x15a3ee2..0x15a420c`, segment B
`0x15a420c..0x15a44e0`) covering every traced site. Cited but
not counted: three boundary FDEs — the format consumer
`0x141e3a0..0x141e538` (408 bytes), the callee
`0x15ae430..0x15ae5ae` (382 bytes) and the map insert
`0x156d840..0x156d9ac` (364 bytes) — each hash-pinned in
`records.json` with its frame records; the construction and
delivery sites inside the first two are re-pinned byte for
byte, and the five `.got` slot bindings (consumer, alloc,
dealloc, write target, memcpy) are re-derived from
`.rela.dyn`.

The out slot's access census is complete over the owner body:
exactly 18 rsp-relative accesses to the slot's three words
exist — 4 `lea` sites (the callee call setups), 6 stores (the
two inline prefill triples), and 8 loads (the two consumption
windows per segment: a length load and a head load at the map
hit, and the same pair at the map miss). No other instruction
in the body touches the slot, so the slot is written only by
the callee (format paths) or by the prefill (non-format
paths), and read only after the calls.

## Trace stages

1. **Call setups.** At `0x15a3f3a`/`0x15a3f5f` and
   `0x15a3ff2`/`0x15a401e` (segment A, flag byte 1 stored at
   `0x15a3f10`) and at `0x15a423e`/`0x15a4263` and
   `0x15a42f0`/`0x15a431c` (segment B, flag byte 0 stored at
   `0x15a420c`), the consumer loads `rdi = &[rsp+0x158]`,
   `rdx = &[rsp+0xc0]` (arguments block) and calls the callee
   `0x15ae430` directly (`E8`). The out slot address is the
   callee's first argument at all four sites.
2. **Inline prefill.** On each segment's materialised-value
   path (segment A at `0x15a3f8b`, segment B at `0x15a4281`)
   the consumer loads a recorded size, calls the alloc slot
   (`0x15a3f9f` / `0x15a4295`), copies the recorded source
   bytes into the fresh buffer through the `memcpy` slot
   (`0x15a3fbf` / `0x15a42b5`), and stores
   `{size, pointer, size}` into the slot (`0x15a402a` /
   `0x15a4328` and the two following stores). No format call
   is made on this path.
3. **Map walk.** Both segments then load the map root from
   `[rsp+0x178]` (`0x15a4055` / `0x15a4353`, companion word at
   `[rsp+0x180]`). A node carries a u16 count at `+0x112`
   (loaded at `0x15a4081`), key bytes at `+0x115` (loaded at
   `0x15a40aa`), child pointers at `+0x120` (loaded at
   `0x15a40fd`), and 24-byte value entries from `node-0x10`
   in steps of `0x18` (step at `0x15a40c7`) — each entry one
   `{capacity, pointer, length}` triple.
4. **Map hit.** At the found entry the consumer first loads
   the replaced triple's capacity and pointer (`0x15a4110` /
   `0x15a4406` and the following load), then stores the out
   triple over it — length word at `0x15a411f` / `0x15a4415`,
   capacity+pointer by `movups` at `0x15a412b` / `0x15a4421`.
   The replaced buffer is freed through the dealloc slot
   with `(pointer, capacity, 0)` exactly when its capacity
   is neither 0 nor one of the sentinel values bracketed by
   the `movabs 0x8000000000000002` / `cmp` pair (`0x15a412f` /
   `0x15a4425`): in segment A by `call r14` at `0x15a4145`
   (`r14` loaded from the dealloc slot at `0x15a406e`), in
   segment B by the branch at `0x15a443b` into the shared
   free block at `0x15a3f03` (call at `0x15a3f05`).
5. **Map miss.** When the walk finds no entry, the consumer
   builds a stack record around the root slot's address
   (`0x15a417c` / `0x15a4456`), copies the out triple
   verbatim into a value record at `[rsp+0x1d0]`/`[rsp+0x1e0]`
   (`movaps` at `0x15a41c8` / `0x15a44a2`, length store at
   `0x15a41b8` / `0x15a4492`), and calls the insert boundary
   `0x156d840` (`0x15a41eb` / `0x15a44c8`) with
   `(map handle, record, value record)`. The insert's body
   is a boundary: its FDE and body hash are pinned, its
   internals are not traced.
6. **Cited construction and delivery.** Inside the format
   consumer, the alloc call (`0x141e47c`, through slot
   `0x64df480`), the triple stores (`0x141e49d`,
   `0x141e4a1`, `0x141e4a5`), the write-target call with the
   stack header's address (`0x141e4b4`, `0x141e4be`) and the
   success copy into the caller's slot (`0x141e4c8`–
   `0x141e4d4`) are re-pinned; inside the callee, the two
   consumer calls with their scratch out slots (`0x15ae46c`,
   `0x15ae476`, `0x15ae4eb`, `0x15ae4f5`) and the delivery
   stores into the caller's slot (`0x15ae4fb`–`0x15ae509`,
   copy path `0x15ae53f`–`0x15ae54a`) are re-pinned. Their
   full traces belong to packets #2408 and #2396.

## Traced result

Composing the chain end to end: the level name the pointer
formatter selects is appended by the table method into a
buffer the format consumer allocated for that format; the
resulting owned byte string travels up two out slots — the
callee's scratch slot, then the large consumer's
`[rsp+0x158]` — and comes to rest as a value of the large
consumer's sorted-node map, either moved into an existing
entry (whose previous buffer is freed under the sentinel
guard) or handed to the map insert call inside a stack
record. Nothing in the chain reads the accumulated bytes
back, and nothing in the chain frees the delivered buffer;
its next free happens only when a later store replaces that
map entry, under the same guard. Who owns the map itself —
the root handle's provenance and the map's lifetime beyond
the large consumer — is outside this packet.

Reproduce from the repository root:

```bash
python3 -B tools/out_buffer_owner_static.py
python3 -m unittest tests.test_out_buffer_owner_static -v
```

Out-buffer ownership for the RE-015 flag-group chain only:
the large consumer 0x15a3b90 stack out slot at [rsp+0x158]
(its complete 18-access census, the four callee call setups
that pass its address, the two inline prefill windows, and
the two post-call consumption windows per segment — the
sorted-node map hit store with the replaced buffer's guarded
free and the miss path's insert-record build), plus
hash-pinned boundary FDEs whose construction and delivery
sites are re-pinned but whose full traces are owned by the
sibling packets (the format consumer 0x141e3a0's buffer
construction by the flag-group-format packet, the callee
0x15ae430's scratch delivery by the derived-byte-callee
packet). The map insert function 0x156d840, the
allocator/deallocator targets behind slots 0x64df480/0x64df4a0,
the map root's own provenance and lifetime beyond the large
consumer, the value the map handle register holds on the
format paths, and every other caller of the format consumer
are NOT traced. No captured code executed, no runtime value,
indirect-call recovery beyond the pinned slot bindings, #94
correspondence, or reconstruction gate is claimed.
