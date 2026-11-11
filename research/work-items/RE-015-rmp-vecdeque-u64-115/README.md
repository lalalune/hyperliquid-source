# RE-015: rmp-serde newtype(VecDeque<u64>) serializers and their chain writers (node #115)

This packet makes it possible to rebuild, as one executable Python model, the MessagePack writer of every
`newtype(VecDeque<u64>)` field in the 0x226/0x419/0x52f serializer copy families: the exact
`VecDeque::as_slices` split (head wrap, front/back slice, inconsistent-state behaviour), the u32 test that picks
"array header first" or "0x80-byte counted compound", the chain writer that streams both slices through
`write_uint` (cursor advanced before the write, u32 counter that panics at 0xffffffff, error hand-back) and the
buffer release. The model was checked against the real bytes of 6 bodies, 6 chain writers, 6 header writers,
4 distinct `write_uint` copies and 6 `Compound::end` copies on 13,125 cases with 0 mismatches, and 87 of 87
negative controls were detected.

- Component ID: `constants` (RE-015 serializer/string-reference work)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: lalalune/hyperliquid-source main `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`; no reference source
  used (references/can1357-hl was not consulted for these bodies)
- Claim status: observation (bytes, call pattern, executed behaviour of the original instructions) + inference
  (the rmp-serde / `std::collections::VecDeque` names)
- Scope included: the six 556-byte bodies and six 597/619-byte chain writers in `bodies.tsv` / `chains.tsv`; the
  header writer, `write_uint` copies and `Compound::end` they call run for real. Excluded: the sibling
  `newtype(Vec<T>)` bodies (other RE-015 packets), the
  `Compound::end` bodies as a claim (they run only as dependencies), the output Vec growth path
  `finish_grow` (see Limits). No progress gate is requested.

## Reproduce

From the repository root (Python 3 standard library only; binutils not needed; the binary is never executed):

```
python3 tools/re015_rmp_vecdeque_u64_115.py --out research/work-items/RE-015-rmp-vecdeque-u64-115
python3 -m unittest tests.test_re015_rmp_vecdeque_u64_115
```

- The tool checks the input SHA-256 first and stops on any other binary.
- It writes `bodies.tsv`, `chains.tsv`, `cases-sample.tsv`, `chain-cases-sample.tsv`, `controls.tsv`,
  `coverage.tsv`, `summary.json` and `measure.json`.
- Two runs with different `PYTHONHASHSEED` and `TZ` give byte-identical files (checked: all 8 files).
- A full run takes about 172 s and peaks at about 560 MB resident. Cases are generated and evaluated one at a
  time; only the comparison result and the written bytes are kept.
- Case generation is a SHA-512 counter stream keyed by body address. `--per-body N` (default 1400) and
  `--per-chain N` (default 450) change the case counts.

## Evidence

Coordinates are virtual addresses in node #115; sections are mapped through `tools/elf_index.py`, FDE extents come
from `tools/fde_extents.py`. Every number in the tables is read from ELF bytes by the tool.

### Body shape

Human-readable excerpt (`objdump -d -M intel`, not used by the tool) of `0x226c0f0` (family 0x226, layout a):

```
226c10e: cmp    rcx,0xa                     ; name length; "_ExtStruct" movabs/xor test follows
226c12f: je     226c2bf                     ; -> {0x8000000000000002, 0x5e90a1 "expected tuple", 14}
226c141: mov    rax,[r8+0x10]               ; head
226c14a: cmovae rcx,rdx                     ; rcx = cap if head >= cap
226c157: mov    rcx,rsi ; sub rcx,rdi       ; len - (cap - phys)
226c15d: ja     226c16f                     ; wrapped: front = phys..cap, back = 0..len-room
226c17f: sub    rdx,rax ; add rdx,rcx       ; total = (end - phys) + back
226c188: shr    rax,0x20 ; jne 226c1ce      ; total >= 2^32 -> buffered compound
226c1b3: call   25e7c10                     ; array header (low 32 bits of total)
226c1d4: mov    edi,0x80 ; call [malloc]    ; buffered: 0x80-byte Vec<u8>
226c243: call   2518da0                     ; chain writer(out, &slices, &compound)
226c278: call   227e1b0                     ; Compound::end (word0 0x8000000000000000 -> Ok at once)
```

The four slice words go to the stack record `[front_start, front_end, back_start(=base), back_end]`
(`226c18c..226c1a1`), which is what the chain writer reads as `[r14], [r14+8], [r14+0x10], [r14+0x18]`.

### Chain writer shape (`0x2518da0`)

```
2518dc0: cmp    r13,rbx ; je 2518e1c        ; each slice is a do-while guarded by start != end
2518dc5: mov    rax,[r15] ; cmp rax,0x8000.. ; jne 2518e9c   ; direct (mark) or buffered compound
2518df3: add    r13,8 ; mov [r14],r13       ; cursor advanced BEFORE the write
2518dfa: mov    rdx,[rax] ; call 25e9f10    ; write_uint(&mut res, ser_or_compound, value)
2518e0d: cmp    rdx,2 ; jne 2518fba         ; error: out = {0x8000.., word, word}
2518f12: cmp    eax,0xffffffff ; je 2518fe8 ; buffered only: counter overflow -> panic(Location 0x642c1e0)
2518f1b: inc    eax ; mov [r15+0x20],eax    ; counter after the write
2518fd6: mov    [rax],rsi                   ; rsi = 0x8000000000000004 = Ok
```

### Tables

- `bodies.tsv`: the 6 bodies (family, layout, header writer, chain writer, `Compound::end`, "expected tuple"
  message). Each body has exactly 3 direct calls besides `_Unwind_Resume`, exactly one `ja` and one `cmovae`.
- `chains.tsv`: the 6 chain writers with their direct-mode and buffered-mode `write_uint` copy and the panic
  Location. Layout a uses one copy for both modes; layout b uses a different, longer direct-mode writer
  (`0x25e9c70`, `0x3d517e0`, `0x57d00b0`) that calls the u16/u32/u64 helpers `0x25ea4b0/0x25ea780/0x25ea910`.
  Call patterns are checked by `chain_facts` (all six calls same target for a; `d d d b d b` for b).
- `cases-sample.tsv`, `chain-cases-sample.tsv`: every third (bodies, k mod 12 in 0,3,5,8; only k mod 12 == 8 of the exhaustive group) / sixth (chains) case with its inputs, written
  bytes (hash), result record and an event summary. The full 13,125 case set is regenerated by the tool.
- `controls.tsv`: the 87 negative controls and the index of the first case that detects each.
- `coverage.tsv`: instructions reached per function on every 7th case (the real `write_uint` copy 0x25e9f10 is
  reached 240/240).
- `summary.json`, `measure.json`: totals and a digest over all case outputs.

### Ownership and overlap check

- A text scan of `research/` finds the six bodies only as address mentions in RE-001 packets (`RE-001-owner-tail-phases-115`, `RE-001-skiplist-holder-115`, `RE-001-skiplist-rep-factory-115`),
  the six chain writers in no file, and none of the 15 addresses in an open or merged PR title or file list
  (`open.json`, checked in the run that produced this packet).
- The shared `write_uint` copies (`0x25e9c70`, `0x3d517e0`, `0x57d00b0`) and `Compound::end` copies appear in other
  packets as listings or dependencies; this packet only runs them and claims their behaviour for the VecDeque path.
- The earlier `newtype(Vec<T>)` packet fixed the mechanics of the header writers and `Compound::end`; this packet
  reuses that evaluator design but none of its case data.

## Implementation and comparison

`tools/re015_rmp_vecdeque_u64_115.py` holds (1) a pure-Python x86-64 subset evaluator that runs the original bytes
(the evaluator of the earlier RE-015 rmp packets, copied to keep the packet standalone), and
(2) the reconstruction:

- `deque_slices(cap, head, len)`: `VecDeque::as_slices` exactly as the bytes do it. `phys = head - (cap if head >=
  cap)`, `room = cap - phys` (wrapping), wrapped iff `len > room` (unsigned), else one slice `phys..len+phys`.
  Empty deques ignore `cap` and `head`. The element count is `(end - phys) + back` (mod 2^64).
- `model(case)`: reserved-name reject; `total >> 32 == 0` selects the direct path (array header of `total as u32`,
  then the chain writer with the outer serializer) otherwise malloc(0x80), buffered chain writer with a u32
  counter, then `Compound::end` writes the counted header, copies the buffer and releases it.
- `walk_model`: both slices front to back, cursor advanced before the write, the write error handed back as
  `{0x8000..0, word, word}`, counter incremented after the write, panic at 0xffffffff.
- `write_uint`: smallest MessagePack unsigned form with the exact reserve calls (`reserve(len, 1)` when full
  before the tag byte, `reserve(len, 2/4/8)` when the payload does not fit).
- `chain_model`: the chain writer on its own, with arbitrary cursor ranges and counter states (including
  0xfffffffd..0xffffffff), so the panic and error arms are reached.

Comparison: for every case the evaluator checks written bytes, the 24-byte result record, the ordered event list
(header writes with their u32, every `write_uint` call with value, serializer kind, both cursors, counter and
compound config word, reserve calls, malloc/free with sizes), and for chain cases also the final cursors, the
compound capacity/length/counter and its buffer bytes. Fault injection fails the k-th header or `write_uint` call
with a distinguishable result so every error arm is exercised. Allocation failure ends in the
`handle_alloc_error(1, 0x80)` Boundary.

- Case set: per body, ordinary deques, `head >= cap`, wrapped deques, empty deques with garbage cap/head,
  inconsistent states (`head >= 2*cap`, `len > cap`), and lengths `j*2^61 + m` that the u32 test sees as
  >= 2^32 while the pointer walk (modulo 2^64) is only m elements; plus an exhaustive group (every state with cap 1..7, head 0..2*cap-1, len 0..cap for every body: 2,016 cases) and two 64 Ki-element walks (0xffff and
  0x10000 elements) per body so the `0xdc`/`0xdd` header form boundary is reached by the real header writers.
- Negative controls (87): 22 model mutants (header forms, name test, config mask, split, `head` fold, back slice
  length, slice order, cursor timing, counter limit, error tags, release, copy, four `write_uint` bounds),
  60 one-bit byte flips of the immediates and branches the model depends on (name length, config mask, buffer
  size, message length, `ja`, `cmovae`, counter compare, counter increment, result compare), and range controls
  (5: address that is not an FDE start, chain writer not at an FDE start, declared family wrong, declared layout
  wrong, flipped binary digest).

## Results and limitations

- 13,125 cases (8,400 body + 2,700 chain + 9 large walks + 2,016 exhaustive ring states), 0 mismatches; case kinds are in `summary.json`:
  ext error 1,050, alloc error 420, direct ok 6,410, direct fault 1,789, buffered ok 621, buffered fault 135,
  chain ok direct 912, chain ok buffered 594, chain fault 877, chain panic 317.
- 87 / 87 negative controls detected.
- Findings (observation):
  - `head >= cap` folds by exactly one `cap` (`cmovae`), not a modulo: `head` in `[2cap, ...)` is read as
    `phys = head - cap >= cap`, takes the non-wrapping branch and reads from `ring + phys*8`.
  - An empty deque (`len == 0`) never reads `cap` or `head` for the slice split and writes an array header of 0.
  - The u32 test is on the element count `(end - phys) + back`, taken modulo 2^64; lengths that are multiples of
    2^61 plus m make the pointer walk finite while the count is huge.
  - The cursor is stored before `write_uint` runs, so on an error the stored cursor already points past the
    failed element.
  - The u32 counter is tested after the element is written: with the counter at 0xffffffff the write has already
    happened and the writer panics instead of incrementing (the 4,294,967,296th element is written, then the
    panic).
  - Layout b uses a different direct-mode `write_uint` than its buffered compound.
- Limits:
  - Layout b direct-mode `write_uint` copies grow the output Vec through an inlined `finish_grow`; this packet
    gives those cases enough room, so that growth arm (and the layout-b header writer growth arm) is not modelled
    and the layout-b direct writers are only partly reached (80/165, 63/179, 68/103 instructions).
  - The u32 threshold bit (`shr 0x20`) is constrained from above only: counts in `[2^31, 2^32)` would need a
    walk of billions of elements, so `shr 0x1f`/`0x21` mutants cannot be told apart and are not claimed.
    `len >= room` vs `len > room` is an equivalent pair (identical slices) and is not claimed either.
  - The output Vec reserve is a contract stub (capacity becomes `len + additional`); real amortised growth is not
    modelled. `memcpy`, `malloc` and `sdallocx` are contract stubs; the binary is never executed.
  - The element values come from a fixed pool; only the MessagePack forms (7-bit, u8, u16, u32, u64) are covered.
- Next question: the 658/727/850-byte "other-shape" `_ExtStruct` bodies of the earlier family scan, and the
  `newtype(Vec<(A, B)>)` bodies whose element serializers take two fields.
