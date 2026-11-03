# RE-015 — node 115 assembled-record readers: the drain, the exit reader, and the destroy paths

Question (the recorded next question of the second-structure
readers packet, #2506): who reads the two assembled 0x40-byte
records the post-loop region appends (carrying the taken entries'
+0x8/+0x10 words at their +0x30/+0x38 slots) once the drain region
(`0x15a5501..0x15a5861`) and the consumer tail take over — in
particular the role of the map-#1 drain helper `0x149e5b0` and the
final disposition of the extracted words?

Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Static trace only; no captured code executed.

## Owners

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| large consumer | `0x15a3b90..0x15a6509` | 10617 | `7995f7af57e2be27ca6ed1e307d9bcce9d6140f72b0ff0cf0804d7f09e5505fb` |
| exit reader | `0x4749ab0..0x4749d71` | 705 | `6f4caa139b97d81e99776e8cf0f570c906c02c5133d755baec41104d77e9b0bb` |
| pair drop | `0x15ac5f0..0x15ac779` | 393 | `e2953a3c6bd271b64b76fcef0d618208195a928d6a9b24ffb2da1b9734079995` |
| tagged destroy A | `0x158bee0..0x158bf62` | 130 | `843692aaa8b2a5d2e2bd2ce150f1211842a558804f66db3e53d3a1586c959862` |
| tagged destroy B | `0x15ad360..0x15ad3e2` | 130 | `bcb8ecc826669ce312d41cea207fe154dc20649bb7c3adba25550e12acf82303` |
| map-#1 drain helper | `0x149e5b0..0x149e70e` | 350 | `341f372e53bbbca10894eb94e045628d3fb576e6e97824e4ce9cd28a4ce49e0c` |

The consumer is retained as three windows (post-loop, drain,
tail); the five callees are retained in full; the merge delegate
is retained as two entry windows (its two element loops).

## Trace

### Stage 1 — where the records live

Restating #2506's pins for context: the taken words are staged at
`[rsp+0x208]`/`[rsp+0x210]` (key 0) and `[rsp+0x218]`/`[rsp+0x220]`
(key 1); each assembled record is built at `[rsp+0x20]` with the
taken words at its +0x30/+0x38 slots and appended to a vector
(grow `0x474e420` via slots `0x64e1470`/`0x64e1478`); a third
record is appended to the second vector of the working pair at
`[rsp+0x1d0]`. At `0x15a54c4..0x15a54ec` the updated pair (0x30
bytes: two vector headers) is stored back to its home at
`[rsp+0x240]`, before the tree drop at `0x15a54fc` and the drain.

### Stage 2 — the drain does not read them

A stack census over the whole consumer body (every literal
`[rsp+…]` access to the pair home `0x240..0x268`, the working pair
`0x1d0..0x1f8`, and the taken-word slots `0x208..0x220`, classified
by region) shows **zero drain-region accesses** to any of them.
The drain works on a different map (handle words at
`[rsp+0x178..0x188]`, cursors at `[rsp+0x28]`/`[rsp+0x48]`) through
the iterator `0x153ba90` (call at `0x15a5580`) and on the
0x18-byte-element vector at `[rsp+0x90]`.

The helper `0x149e5b0` — its only consumer call site is
`0x15a569e`, with rdi = `&[rsp+0xc0]`, rsi = `&[rsp+0x28]` — is a
map-#1 cursor function, not a record reader: it loads only its
cursor argument's three words (`0x149e5be`/`0x149e5c1`/`0x149e5c5`),
walks nodes by the count words at node +0x110/+0x112 and the child
link at node +0x120 (`0x149e643`, `0x149e6a3`), frees nodes through
the dealloc slot with size class 0x120 (first node) or 0x180
(deeper nodes), and writes a fresh 0x30-byte cursor {next node, 0,
remainder, node, index, count} to its out argument. The consumer
stores that cursor over its cursor-1 slot (`0x15a56ea`,
`0x15a56ee`) and loops. No 0x40-byte record field is loaded
anywhere in the helper.

### Stage 3 — the normal-path reader: the consumer exit

At the exit block (`0x15a58f2`, reached from the pre-phase-2
dispatch) the consumer builds an empty vector {0, 8, 0} at
`[rsp+0xc0]` and calls the exit reader `0x4749ab0` through slot
`0x64e1480` (RELATIVE addend `0x4749ab0`) with rdi = `&[rsp+0x20]`
(out), rsi = `&[rsp+0x240]` (the saved pair), rdx = `&[rsp+0xc0]`.
This is the pair home's only load in the tail besides the final
cleanup (stage 5).

The reader first calls its delegate `0x4748500` through slot
`0x64eafd8` to fill a 0x68-byte temp from the pair, then:

- **Discriminant arm** (temp word +0x60 non-zero): it writes
  out = {6, temp+0x50, temp+0x58, temp+0x60} (`0x4749b2e`..
  `0x4749b3a`) and destroys the temp's pair copy inline —
  first-vector elements through the element drop `0x474dcd0`
  (`0x4749b6d`), its buffer freed at capacity × 0x40, second-vector
  elements freed inline (the +0x8/+0x10 allocation and the +0x28
  0x18-byte sub-vector of each; element pointer load at
  `0x4749c54`).
- **Move-out arm** (temp word +0x60 zero): it copies the temp's
  first 0x50 bytes verbatim to out (`0x4749cc4`..`0x4749ced`) —
  the pair copy moves out with it — and frees only the delegate's
  0x20-byte entry-vector buffer (count << 5, `0x4749cf5`).

Back in the consumer, an out word of 6 (`cmp DWORD PTR
[rsp+0x20],0x6` at `0x15a5930`) branches to the assertion arm at
`0x15a5b8c` (slot `0x64df6a0` → `0x1680c30`); otherwise the
consumer copies the 0x50-byte out struct to the destination
pointer loaded from `[rsp+0x278]` (`0x15a5940`, copies at
`0x15a5948`/`0x15a596c`) and returns.

### Stage 4 — the delegate's entry loops

The delegate `0x4748500` (5,545 bytes; hash-pinned boundary, entry
loops pinned here) consumes both vectors of the pair. It copies
the second vector's header in at the entry (words from pair
+0x18/+0x28 to its local at `[rsp+0x240]`, `0x474854b`/`0x474853f`)
and runs the same transform loop over each vector in turn
(first-vector loop head at `0x47485d4`, second-vector loop head at
`0x4748c47`): for every 0x40-byte element whose first word is not
the sentinel `0x8000000000000000` (movabs at `0x474868f`), it
stages the element at `[rsp+0x170]` (word 0 verbatim at
`0x47486a6`, the word at +0x38 re-staged), copies the element's
string through alloc + `memcpy` (slots `0x64df480`/`0x64df508`),
gates the element through the transform gate `0x474ba60` (calls at
`0x4748742` and `0x4748dae` — its only direct call sites), and on
a true result appends a 0x20-byte entry {0, element word 0,
length, pointer} (`0x4748772`/`0x474877a`) to a fresh local vector
(grow `0x474e490` via slot `0x64eafe0`); the element's tagged pair
(staged at `[rsp+0x1a0]`/`[rsp+0x1a8]`) is then destroyed through
its descriptor. At the end it writes the entry vector's header to
the temp at +0x50/+0x60 (count store at `0x47494d6`, header store
at `0x47494df`) — exactly the words the exit reader's
discriminant arm extracts. The delegate's later merge phases are
not traced.

### Stage 5 — final disposition on the destroy paths

On unwind paths the taken words never reach the records: the
consumer's landing pads destroy each taken pair directly through
a tagged destroy — `0x158bee0` at `0x15a5dfa` (key-1 words) and
`0x15a5e4c` (key-0 words), and its byte-twin `0x15ad360` at
`0x15a6186`/`0x15a61a3`. A tagged destroy (130 bytes, both
instances pinned at the same instruction shape) calls descriptor
word 0 (drop) on the +0x8 word when non-null (`0x158beeb`,
`0x158bef6`) and frees it through the dealloc slot with the class
from descriptor words +0x8 (size) and +0x10 (align, tzcnt)
(`0x158bef8`, `0x158bf01`).

The assembled records themselves are destroyed by the pair drop
`0x15ac5f0`, called on the working pair at `[rsp+0x1d0]`
(`0x15a5eb2`), on the pair at `[rsp+0x90]` (`0x15a5e14`), on the
pair in the `[rsp+0xc0]` scratch (`0x15a60d9`), and on the saved
pair at `[rsp+0x240]` (`0x15a64d4`, the final cleanup before
`_Unwind_Resume`). The drop reads the first vector's buffer/count
at pair +0x8/+0x10 (`0x15ac601`/`0x15ac605`), drops every element
through the element drop `0x1538ec0` stepping 0x40
(`0x15ac616`/`0x15ac61d`), frees that buffer at capacity × 0x40
(`0x15ac62f`), then destroys every second-vector element inline:
the allocation at element +0x10 freed with size element +0x8
(`0x15ac689`/`0x15ac693`), the 0x18-byte sub-vector at element
+0x28 (buffer at `0x15ac69b`, count at `0x15ac69f`) drained with
each sub-element's allocation freed and the sub-buffer freed at
count × 0x18 (`0x15ac6d9` + `lea rsi,[rax+rax*2]`), and finally
the second buffer freed at capacity × 0x40 (`0x15ac6f8`) through
the pair tail helper `0x15ad260` (`0x15ac766`).

On the normal path the words' ownership passes out of the
consumer inside the records (stage 3); no other consumer of the
+0x30/+0x38 slots exists in the consumer body (stack census) or
among the pinned helpers' direct callers (call census).

## Boundaries

Hash-pinned, not traced: the merge delegate `0x4748500` beyond
its two entry loops and its temp writes, the transform gate
`0x474ba60` (627 B), the element drops `0x1538ec0` / `0x474dcd0`
(258 B each), the pair tail helper `0x15ad260` (244 B), the drain
iterator `0x153ba90` (938 B; also called from the final cleanup
at `0x15a6459`/`0x15a64b5` over the cursor pair saved at
`[rsp+0x2d0]`), the grow functions `0x474e420` / `0x474e490`
(100 B each) and the assertion entry `0x1680c30` (82 B). What the
delegate's entry vector means semantically, why the
discriminant-6 arm is an assertion in the consumer, and what the
destination object at `[rsp+0x278]` does with the 0x50-byte
result are not claimed. The two tagged-destroy instances are
claimed identical only at their pinned instruction shape. The
collect function and descriptor emission are #2490 owners, the
second structure and its readers are #2506 owners, the map owner
is #2479's. No captured code executed, no runtime value or
reconstruction gate is claimed.

## Next question

What does the merge delegate `0x4748500` do in its later phases —
in particular how the 0x20-byte entry vector built from both
record vectors is merged with the third argument's vector (the
consumer passes an empty {0, 8, 0} vector) and what the transform
gate `0x474ba60` decides per element?

## Reproduce

```sh
python3 tools/assembled_record_readers_static.py \
  --binary artifacts/node/115/hl-node \
  --output research/work-items/RE-015-node115-assembled-record-readers
python3 -m unittest tests.test_assembled_record_readers_static
```
