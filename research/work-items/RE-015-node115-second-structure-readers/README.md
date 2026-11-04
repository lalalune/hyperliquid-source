# RE-015 — node 115 second-structure readers and the [rsp+0x90] vector

Questions (the recorded next questions of the phase-2 descriptor
packet, #2490): (1) What do the second structure's readers do with
the two payload kinds — the 0x30-byte record stored under tag
`0x63ffbf8` versus the 0x70-byte record stored under tag
`0x63ffc70`? Identify the structure, enumerate its readers, and pin
how each reader dispatches and which payload fields it consumes.
(2) Who consumes the vector the collect call leaves at `[rsp+0x90]`
after phase 2 — the uses of the `{capacity, buffer, count}` header
and the element records after the phase-2 region of the large
consumer, and any forwarding of the vector out of the consumer?

Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Static trace only; no captured code executed.

## Owners

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| large consumer | `0x15a3b90..0x15a6509` | 10617 | `7995f7af57e2be27ca6ed1e307d9bcce9d6140f72b0ff0cf0804d7f09e5505fb` |
| entry take | `0x156edc0..0x156eea9` | 233 | `b17233bfd018fa2c5f0243a29cc392b995b77617e7ad2f0da834a5615f7142c7` |
| second-tree drop | `0x1542870..0x15429b2` | 322 | `1112794f86fd4eb9eb110927bb2f59d6da9dd87d7aa4ffa966cc725791abb218` |
| second-tree iterator | `0x153c5b0..0x153c96e` | 958 | `c4ae9a2d1e327692d764f385adac7980a4d47fbf4b16294a38b794db798ece22` |
| payload drop (0x30 record) | `0x15ac880..0x15ac904` | 132 | `fe9e166c34d907122fd4f6d01a465639b7c3e4eda4be064eb18aa638c358dc7d` |
| payload drop (0x70 record) | `0x15acde0..0x15acfa5` | 453 | `855c12f2077cd2b57f498096d0649d36b5328d45e23dcdeeba962e99065040ee` |
| second-record drop | `0x15ac780..0x15ac872` | 242 | `3ed26c922f030453313ed5dbbda85051eccdcf5482d448c34d7a67892af2dd7c` |

The consumer is retained as seven windows (init, branch A, replace,
branch B, insert, post-loop, tail); the six callees are retained in
full. The remove extract `0x149ca30` is a boundary; its head window
(extraction of the key byte and the value pair, node count
decrement) is exported.

## Trace

### Stage 1 — the structure

The second structure is a byte-keyed B-tree owned by the large
consumer, born empty once per field-loop iteration in the phase-2
init (`0x15a44e0`): handle at `[rsp+0x1b8]` = {root +0x0, height
+0x8 (stack `[rsp+0x1c0]`), size +0x10 (stack `[rsp+0x1c8]`)}. The
init stores root = 0 and size = 0 (the height word is first stored
by the first-node creation path, `0x15a4bf4`), plus the word 2 at
`[rsp+0x1d8]` and the key-byte word 1 at `[rsp+0x1e0]`. Node layout
(from the creation path, the walks and the take chain): count word
at node +0xba, single-byte keys at node +0xbc, value pairs
{payload pointer, tag pointer} at node + index*0x10, children at
node + index*8 + 0xc8, first node allocated inline at 0xc8 bytes.
Keys are the probe's current field byte, staged at `[rsp+0x150]`
from the key-byte buffer at `[rsp+0x1e0]`; the init word 1 makes
the buffer's bytes {0x01, 0x00}. Writers (per #2490 plus the shared
tail pinned here): insert-or-replace — a search hit replaces the
pair in place and destroys the old value through its descriptor;
a non-empty miss calls the tree insert `0x1497040` (its only call
site in the consumer, `0x15a4c88`); an empty tree creates the first
node inline. The tag descriptors are `.data.rel.ro` records
{drop (RELATIVE addend), size, align}: `0x63ffbf8` = {drop
`0x15ac880`, size 0x30, align 8}, `0x63ffc70` = {drop `0x15acde0`,
size 0x70, align 8}, and the companion `0x63ffbd0` for the boxed
second record = {drop `0x15ac780`, size 0x30, align 8}.

### Stage 2 — reader 1: the two post-loop lookups (take semantics)

After the field loop, the consumer walks the tree twice — for byte
key 0 (the `neg`-compare walk at `0x15a4cfa..0x15a4d03`) and byte
key 1 (`ebx` = 1 set at `0x15a4cbb`, walk at `0x15a4dea`). Each hit
builds a cursor {node, height, index, handle} at `[rsp+0x20]` and
calls the take helper `0x156edc0` with out = `[rsp+0xc0]`. The take
decrements the handle size word (`dec [rax+0x10]` at `0x156edf1`,
rax = cursor +0x18 = handle), runs the remove core `0x149e250`,
replaces a single-child root when the core's flag byte is 1
(height decremented, old node freed with size 0x128), and returns
the removed entry's 24-byte record verbatim. The consumer tests
the record's first byte against 4 (`0x15a4d74` / `0x15a4e64`) and
its +0x8 word against zero (`0x15a4d92`); both failures — like an
empty tree and a descent underflow — branch to panic arms that
call the panic entry through slot `0x64df830` with location
statics `0x63ffb48` / `0x63ffb60` (`base/src/log/handle.rs`, lines
144 / 145). Otherwise the record's +0x8 word is stored to
`[rsp+0x210]` / `[rsp+0x220]` and its +0x10 word to `[rsp+0x208]` /
`[rsp+0x218]`, and both are later copied opaquely into the
assembled 0x40-byte records (`0x15a5129` / `0x15a5136`,
`0x15a5269` / `0x15a5276`). Neither word is dereferenced anywhere
in the consumer, and no instruction compares a stored tag against
either descriptor address: dispatch is by byte key and through
descriptor words, never by tag identity.

### Stage 3 — reader 2: the replace arm (old-value destroy)

On a search hit in the shared phase-2 tail (`0x15a47e0..`), the old
pair is loaded, the new pair stored over it, and the old value is
destroyed through its own tag descriptor: descriptor word 0 (drop)
is called on the old payload when non-null (`0x15a47ee`,
`0x15a47fa`), then the old payload is freed through the dealloc
slot `0x64df4a0` with the size class computed from descriptor
words +0x8 (size) and +0x10 (align) (tzcnt/cmov sequence,
dealloc call at `0x15a4830`).

### Stage 4 — reader 3: the tree drop (full drain)

The drop helper `0x1542870` is called exactly twice — at the end of
post-loop processing (`0x15a54fc`) and on the unwind tail
(`0x15a63cc`) — with rdi = &handle only. It builds two iterator
cursors from the handle triple and drives the consuming iterator
`0x153c5b0`, which yields (node, index) pairs and frees exhausted
nodes through the dealloc slot (call sites at `0x153c91a`,
`0x153c94a`, plus register-indirect calls). For every yielded
entry the helper loads the value pair and destroys it exactly like
the replace arm: descriptor word 0 on the payload when non-null
(`0x1542927..0x1542933`), then the dealloc slot with the
descriptor's size/align class. Both payload kinds are treated
uniformly — the descriptor words decide everything.

### Stage 5 — the payload drops (first field use)

Drop `0x15ac880` (tag `0x63ffbf8`, the 0x30-byte transformed
descriptor record) reads only payload +0x18 (boxed second-record
pointer, `0x15ac885`) and +0x20 (its tag descriptor, `0x15ac889`):
it calls that descriptor's drop (`0x15ac780` for the consumer's
records) on the boxed record and frees the box with the
descriptor's size word. The record's configuration words
+0x0/+0x8/+0x10 and flag byte +0x28 are never read.

The second record's drop `0x15ac780` consumes it as {capacity
+0x0, buffer +0x8, count +0x10} — a vector of 0x58-byte elements
(the collect vector's own header, copied in): it drops the
elements one at a time stepping 0x58 from the buffer through
`0x1538bf0`, frees the buffer with size capacity × 0x58, then
frees the boxed string {length +0x18, pointer +0x20}.

Drop `0x15acde0` (tag `0x63ffc70`, the 0x70-byte snapshot) reads,
in order: the word at +0x40, sentinel-tested by negation/overflow
(`0x15acdeb`, `0x15acdf2`) — the `0x8000000000000000` arm skips
the vector drain, the buffer free and the close call; the byte at
+0x58, which gates the element drain of the vector at +0x40
through `0x1533e80` / `0x1538380` (`0x15acdf7`, `0x15ace04`,
`0x15ace15`); the dealloc pair (pointer +0x48, size word +0x40)
at `0x15ace22..0x15ace28`; the dword at +0x5c, passed to `close`
(GLOB_DAT slot `0x64dfe78`) at `0x15ace2e..0x15ace31`; the dealloc
pair (pointer +0x8, size word +0x0); and the two tagged pairs
{data +0x18, tag +0x20} and {data +0x28, tag +0x30}, each
destroyed through its descriptor's drop word and size class.
Snapshot fields the drop never loads (+0x10, +0x38, the vector
count word at +0x50 beyond the drain helpers, +0x60..+0x70) are
not claimed.

The consumer's unwind tail also calls the drops directly:
`0x15acde0` once on the stack snapshot record at `[rsp+0xc0]`
(`0x15a6234`), and `0x15ac780` three times — on a heap second
record in r15 (`0x15a62ce`) and on the stack second record at
`[rsp+0xc0]` (`0x15a63a4`, `0x15a63bc`).

### Stage 6 — censuses closing the reader set

Binary-wide, instruction-validated: RIP-relative references to
the three descriptors exist only at the four store-side lea sites
in the consumer (`0x15a4730`, `0x15a4b8f`, `0x15a46d8`,
`0x15a4932`); there are no imm64 occurrences. Direct-call census:
the take helper's only call sites are the two lookups; the tree
drop's only call sites are the two consumer calls; the remove
core's only call site is inside the take; the tree insert's only
call site is the consumer miss path; drop `0x15ac880` has zero
direct call sites (reached only through its descriptor); drop
`0x15acde0` and `0x15ac780` have only the tail sites above. The
helper `0x149e5b0` (single call site `0x15a569e`) was examined and
excluded: it walks map-#1 node offsets (+0x112/+0x120) in the
map-#1 drain, after the second structure was already dropped.

### Stage 7 — question 2: the [rsp+0x90] vector after phase 2

A stack census over the whole consumer body (every literal
`[rsp+0x90]` / `[rsp+0x98]` / `[rsp+0xa0]` access, classified by
region) pins the answer. Within phase 2 the branches read the
header only to copy it into the second record (branch A:
`0x15a465c..0x15a4674`; branch B: `0x15a48b3..0x15a48cb`); branch B
then overwrites the slot itself with the tagged second-record
value {boxed pointer (`0x15a492a`), tag `0x63ffbd0` (`0x15a4932`,
`0x15a4939`), flag byte 1 at +0x10 (`0x15a4941`)} and forwards the
slot by pointer as the value argument (rsi = &[rsp+0x90],
`0x15a4a92` / `0x15a4a9a`) of the descriptor map insert
`0x156f680`. The buffer freed in branch B at `0x15a49f5` is read
from the format consumer's record at `[rsp+0xc0]`, not from the
slot. In the post-loop region the census is empty for all three
slots until `0x15a4f79`/`0x15a4f81`, where a table pair selected by
the byte at `[rsp+0x17]` (tables `0x6400220` / `0x468e60`,
`0x15a4f5b`) overwrites +0x0/+0x8 — the capacity and buffer words
are destroyed without ever being loaded after phase 2, and the
count word at +0x10 is not touched at all in between. The slot's
address is forwarded once more as word 0 of the format-argument
record (`0x15a4f89`) for the write call through slot `0x64df6f0`
(target `0x1680500`, the #2424 owner) at `0x15a4fb4`. At
`0x15a5019..0x15a503d` the slot is reset to {0, 8, 0} and reused
as a fresh vector (first loads at `0x15a505b`+ belong to it); the
drain region later reuses the slot a third time (#2479). So no
reader consumes the collect vector through its `[rsp+0x90]`
header after phase 2, and its elements are consumed only through
the boxed second record — including on the destroy path, by the
second record's drop (stage 5).

## Boundaries

Hash-pinned, not traced: the remove core `0x149e250` and remove
extract `0x149ca30` beyond its head window (promotion/rebalance
internals; the take record's first byte is claimed only at the
consumer's compare pins), the tree insert `0x1497040`, the
snapshot drain helpers `0x1533e80` / `0x1538380`, the element drop
`0x1538bf0` (a shared helper — four of its six direct call sites
belong to other owners and are recorded as census), the iterator
drop `0x1537f70`, the descriptor map insert `0x156f680`, the emit
function `0x473c130`, the tagged destroy `0x15a8dc0`, and the
panic entry `0x1680c10`. The iterator's traversal state machine
beyond yielding (node, index) and freeing exhausted nodes is not
traced. The handle word at `[rsp+0x1d8]` (stored 2 at init) is
never read anywhere in the consumer body (stack census); its role
is outside the traced regions. The collect function and the bind
function are #2490 owners, the format consumer is the #2408
owner, the write target is the #2424 owner, and the sentinel
branch's in-phase-2 header copies are #2490's trace. No captured
code executed, no runtime value or reconstruction gate is claimed.

## Next question

Who reads the two assembled 0x40-byte records the post-loop region
appends (carrying the taken entries' +0x8/+0x10 words at their
+0x8/+0x10 slots) once the drain region (`0x15a5501..0x15a5861`)
and the consumer tail take over — in particular the role of the
map-#1 drain helper `0x149e5b0` (excluded here on its node layout)
and the final disposition of the extracted words?

## Reproduce

```sh
python3 tools/second_structure_readers_static.py \
  --binary artifacts/node/115/hl-node \
  --output research/work-items/RE-015-node115-second-structure-readers
python3 -m unittest tests.test_second_structure_readers_static
```
