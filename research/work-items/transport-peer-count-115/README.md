# transport: reconstruct node #115 rate limiter peer counter 0x4fabf60 and btree step 0x5135900

This packet lets you reimplement, as a plain function, the node #115 routine at 0x4fabf60: under a shared lock on a rate
limiter record it counts the recorded 24 byte entries (kept either in a ring buffer or in a B-tree map keyed by a 4 byte
address) whose leading address is not a member of a B-tree set of 4 byte addresses, and it releases the lock with a
single-waiter wake rule. The routine, the ordered B-tree iterator it calls (0x5135900) and the exact lock-word arithmetic
are reproduced from the ELF bytes and checked on 10,500 generated inputs, with 68 deliberately wrong controls all detected.

- Component ID: transport (Network transport; the rate-limit part of "TCP framing, LZ4, channels, rate limits and reconnects")
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`, a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: repository main at time of writing; no reference source was used or copied
- Claim status: observation (instruction semantics, executed from bytes) with inference (the names of the roles) kept separate below
- Scope included and excluded: the two bodies 0x4fabf60..0x4fac30f and 0x5135900..0x5135b24 and the lock protocol they run.
  Excluded: the lock slow path and the waiter wake (recorded, not run), the panic routines, the writer side that fills the
  record, the callers, the sibling bodies at 0x4fac310 (copy of the entries) and 0x4fac470, the larger limiter check at
  0x5a628d0, and any network behaviour. No gate is requested.

## Reproduce

```sh
python3 tools/artifacts.py verify
python3 tools/transport_peer_count_115.py --out research/work-items/transport-peer-count-115
python3 -m unittest tests.test_transport_peer_count_115
sha256sum -c research/work-items/transport-peer-count-115/MANIFEST.sha256
```

The tool checks the input SHA-256 first, reads only the ELF section table (through `tools/elf_index.py`) and the code
bytes of the two bodies, never runs the binary and never calls objdump or readelf. It needs the Python 3 standard library
and takes about one minute with a peak of about 233 MB. Output is byte-identical between runs.
Human-readable disassembly, used only while reading, is not part of the evidence.

## Evidence

Coordinates are virtual addresses of the file-backed sections; the code segment maps file offset to VA with a constant
shift, which `Image.offset` computes from the section table.

- `instructions.tsv`: all 252 decoded instructions of 0x4fabf60 (FDE 0x4fabf60..0x4fac30f) and all 126 of 0x5135900
  (FDE 0x5135900..0x5135b24) with their raw bytes. The decoder covers exactly the subset these bodies use and refuses
  anything else, so a byte that decodes differently cannot pass silently.
- `summary.json`: SHA-256 of each body's code bytes, the four out-of-line import slots (GOT slots for the lock slow path
  0x64e0fd8, the wake 0x64e0fe8 and the two panics 0x64df4c0 / 0x64df830), case and control counts, step counts.
- `cases.tsv`: every 50th of the 10,500 cases with the lock word, collection size, member count, outcome, count, events.
- `controls.tsv`: every negative control and whether it was detected, with the first case that exposed it.

Observed behaviour of 0x4fabf60 (arguments rdi = pointer to the record handle, rsi = pointer to {set root, set height}):

1. Lock word at record+0x10. A reader enters with `lock cmpxchg` adding 0x10 when the word is below 0xfffffffffffffff0
   and bit 3 (0x8) is clear; otherwise it calls the slow path with (word address, 0, 1,000,000,000) and the routine is
   stopped there by this packet. After the walk it subtracts 0x10 with `lock xadd`; if the old value masked with
   0xfffffffffffffff2 equals 0x12 it calls the wake import with the word address.
2. The collection is an enum selected by the word at record+0x18. The value 0x8000000000000000 (detected by `neg` setting
   overflow) selects the map: root at +0x20, height at +0x28, length at +0x30. Any other value is the ring capacity:
   buffer at +0x20, head at +0x28, length at +0x30, 24 byte entries. A head at or past the capacity is reduced by the
   capacity before use; the entries run from the head and wrap, as two slices.
3. Every entry's first four bytes are the key. For the ring the keys come from the two slices in order; for the map the
   in-order iterator 0x5135900 supplies them (its node layout is below).
4. With an empty set (root 0) every entry is counted. Otherwise the key is searched in the set tree: each node's keys
   (4 bytes each, at node+8, count as u16 at +0x36) are compared as byte-swapped 32 bit words, i.e. in the order of the
   big endian bytes; a hit stops the descent without counting, falling off a leaf counts the entry.
5. Set node layout: parent at +0, keys at +8 (11 slots), parent index u16 at +0x34, length u16 at +0x36, 12 edges from
   +0x38. Map node layout read from 0x5135900: values 16 bytes from +0, parent at +0xb0, keys 4 bytes from +0xb8, parent
   index u16 at +0xe4, length u16 at +0xe6, edges from +0xe8. The iterator keeps its remaining length at +0x40, and the
   descent to the first leaf and the ascent over exhausted nodes both use 8-way unrolled loops, so a map of height 8 or
   more exercises the unrolled and the remainder paths.

## Implementation and comparison

`tools/transport_peer_count_115.py` contains: an x86-64 subset decoder (about 45 opcode forms), a small evaluator with
flags, locked compare-exchange and exchange-add, sparse memory and recorded imports; builders that lay out valid ring
buffers and B-trees (sets and maps up to height 8) in memory; a written rule list `spec`; the deterministic case
generator; the control runners; and the evidence writer. The rule list is written separately from the bytes: it counts
keys absent from the set, applies the lock-word predicates, and predicts the wake and the slow-path arguments.

- Cases: 10,500 (4 fixed boundary shapes, 4 tall maps of height 3, 7, 8, 8, then LCG draws). Outcomes: 7,858 returns
  (including 520 wake requests) and 2,642 slow-path stops; shapes: 1,578 unwrapped rings, 3,661 wrapped rings, 5,261 maps.
  Every case matches the rule list (return value, event list and stop kind). Executed steps: 11,292,529.
- Negative controls: 68, all detected: 14 wrong rule lists (counting members, ignoring the set, first entry only,
  little-endian member order, three-byte prefix match, off by one, stopping at the first member, skipping the last
  entry, distinct keys only, wrong wake mask, always wake, never wake, ignoring the slow path, skipping the first ring
  entry); 45 inverted conditional jumps of the two bodies; 2 erased byte swaps; 7 boundary refusals (wrong SHA-256,
  address outside the file-backed sections, a range ending inside an instruction, an opcode outside the subset, a legacy
  high byte register, an entry inside an instruction, and an unknown import slot).
- Not claimed as decided: the four conditions at 0x4fac24d, 0x4fac26e, 0x4fac27c and 0x4fac2a6 sit in the empty-set map
  loop after the iterator tag would become two, which only the ring path can produce, so no input decides them. The unwind
  landing pad from 0x4fac2db is also not executed. Both are excluded from the controls and listed in `summary.json`.
- Rust is not yet implemented; this packet is a Python rule list proven against the bytes.

## Results and limitations

- Machine readable counts are in `measure.json`: cases 10,500, negative controls 68, detected 68.
- Inference, not observation: the roles (a rate limiter, the entries being recent connections and the set being an allow
  list) come from the surrounding strings near `net_utils/src/rate_limiter.rs` and a call site at 0x5a62bce; the packet
  proves only the arithmetic above.
- The slow path of the lock and the wake are recorded at their import slot; their behaviour is unknown here. Concurrency
  (two threads interleaving at the compare-exchange) is not modelled; the evaluator is single threaded.
- Entries of fewer than four bytes, malformed trees (unsorted keys, wrong lengths) and rings longer than their capacity
  are outside the generated inputs; the routine's behaviour on them is not claimed.
- No gate is requested for the `transport` component: this is one function family of its rate limiting.

Next question: the sibling 0x4fac310 copies the same collection into a vector under the same lock (calling 0x5213860 and
0x58571d0), and 0x4fac470 takes the write side; reconstruct them and then the check at 0x5a628d0 that compares this count
with a clamped limit between 8 and 100.
