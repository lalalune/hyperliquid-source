# RE-004: reconstruct the node #115 order value gate (minimum 1e10, maximum 5e14, product cap) from its three byte-identical copies

This packet rebuilds, as an executable pure-Python rule, the function that decides whether an order's
value is accepted: it multiplies a host-supplied price by the order size, rejects products above
`0x1999999999999999` (tag 0x6d), then applies the open-total check (tag 0xd2), and finally refuses a value
below 10^10 (tag 0xd7, payload 100.0) or above 5 * 10^14 (tag 0xd8, payload 5000000.0). The rule, and the
exact sequence of host calls it makes, are proved against the real instruction bytes of all three copies
(0x22e5c90, 0x57ca550, 0x57caa40) on 14100 generated cases with 0 mismatches, every instruction and every
branch direction of each copy executed, no write into the state, order or key blocks, and 180 negative
controls (175 byte mutants and wrong rules plus 5 damaged inputs) all detected. A Rust port can now take
this function's order of checks, error tags, payload constants, saturating arithmetic and read-only field
set from `tools/order_value_gate_115.py` instead of re-reading 0x4ea bytes three times.

- Component ID: RE-004 (quantities and rounding); no other component
- Target release and full SHA-256: node #115,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: 7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6 / references/can1357-hl (labels were not used)
- Claim status: observation for the check order, constants, tags, state offsets, call sites and call
  order under the stated host model; inference for every role name and for the unit reading of 10^10 and
  5 * 10^14; the host callees are unresolved (stubbed)
- Scope included: the three gate copies, their 17 call sites each, the three direct callers, and the
  layout difference of the third copy. Scope excluded: the bodies of the 11 callees (they are stubs that
  check what they receive), the callers' use of the result, the meaning of the tags, and every progress gate.

## Reproduce

Platform: Linux x86-64, Python 3.12. Run from the repository root. The binary is read as bytes and never
executed, no external program is called, and the output does not depend on a binutils version.

```
python3 tools/artifacts.py verify
python3 tools/order_value_gate_115.py --out research/work-items/RE-004-order-value-gate-115
python3 -m unittest tests.test_order_value_gate_115
(cd research/work-items/RE-004-order-value-gate-115 && sha256sum -c MANIFEST.sha256)
```

The tool checks the input SHA-256 first and stops on a mismatch. It takes about 75 seconds and 446 MB of
resident memory; it streams every case and keeps counters only. Two runs into different folders with
different hash seeds and time zones were byte-identical. Outputs: `evidence.json`, `measure.json`,
`calls.tsv`, `layouts.tsv`, `copy-diff.tsv`, `outcomes.tsv`, `call-sequences.tsv`, `cases-sample.tsv`,
`copy-agreement.tsv`, `reach.tsv`, `branch-edges.tsv`, `fields-read.tsv`, `mutations.tsv`, `survivors.tsv`,
`damaged-inputs.tsv` and `callers.tsv`. The analysis completed and was not limited by a timeout.

## Evidence

Coordinates are ELF virtual addresses. Boundaries come from `.eh_frame_hdr` and the FDEs.

**Copies.** [0x22e5c90, 0x22e617a), [0x57ca550, 0x57caa3a) and [0x57caa40, 0x57caf2a): 0x4ea bytes and 287
instructions each. `copy-diff.tsv` lists the 40 instructions where copies 2 and 3 differ from copy 1: all
call displacements (17 per copy) and, in copy 3 only, the six state offsets below, each moved by 0xb70.
Every other byte is identical, so one rule describes all three.

**State layout** (`layouts.tsv`): copies 1 and 2 read the enable byte at +0x39fd, the market byte at +0x39fc,
an address argument at +0x3ad8, a set object at +0x3ce8, an element count at +0x3ad0 and an element base at
+0x3ac8. Copy 3 reads the same fields 0xb70 higher. Offsets +0x780, +0x7b8, +0x7b9, +0x80 and +0x90 are the
same in all three. Order fields: +0x38, +0x40, +0x48 (asset word), +0x50, +0x51 and the head word at +0.

**Fields actually read** (`fields-read.tsv`, counted over the 12600 gate cases): the state is read at
+0x780 (8 bytes, the limit), +0x7b8 and +0x7b9 (1 byte each, the two skip flags), the market and enable
bytes, the element count and the element base; the order is read at +0x0, +0x38, +0x40, +0x48, +0x50 and
+0x51 only. The address-argument and set-object offsets are passed to callees as pointers and never
dereferenced by the gate. Across all cases no copy wrote into the state block, the order block or the
key block.

**Rule** (the order is the order of the bytes; `spec` in the tool is the same rule):

| Step | Condition | Result |
|---|---|---|
| 1 | enable byte is 0 | tag 0xdd |
| 2 | asset word not in 5..=10080 | tag 0xd1, payload = the word |
| 3 | first host call (resolve) returns a tag other than 0x1a2 | that tag; its +8 word is the size |
| 4 | second host call (market check) returns a tag other than 0x1a2 | that tag |
| 5 | product = price * size overflows u64 or exceeds 0x1999999999999999 | tag 0x6d |
| 6 | head word is not 0x8000000000000001 and the market byte is 0 | tag 0xdc |
| 7 | head word is not 0x8000000000000001 and the margin call returns another tag | that tag |
| 8 | record kind 4: total check runs only if +0x7b8 is 0; other kinds: only if kind >= 3 and +0x7b9 is 0 | continue |
| 9 | total check: saturating sum of a set total and `count` element totals >= the limit at +0x780 | tag 0xd2 |
| 10 | product >> 10 < 0x9502f9 (that is product < 10^10) | tag 0xd7, payload 0x4059000000000000 (100.0) |
| 11 | product > 0x1c6bf52634000 (5 * 10^14) | tag 0xd8, payload 0x415312d000000000 (5000000.0) |
| 12 | classifier byte is 2 | tag 0x1a2 |
| 13 | any other classifier byte b | tag 0x78, payload byte b |

Steps 10 and 11 call a text-formatting host function first: a negative length ends in the panic helper and a
positive length whose allocation returns 0 ends in the panic helper too. Both tags then carry the f64
payload at +8. The two f64 payloads equal the two thresholds divided by 10^8, which is why the thresholds
read as 100 and 5,000,000 in units of 10^-8 (inference). Kinds 0..=2 skip the total check, kind 3 runs it
unless +0x7b9 is nonzero (`test_open_total_check`). A temporary tag 0x6d is written at 0x22e5fa3 and dropped
at once through the drop call; it is never returned.

**Host call order.** `call-sequences.tsv` lists every (outcome, stub-call sequence) pair seen: 104 pairs over
the 12600 cases. `predict_calls` in the tool states the order from the rule alone (resolve, market check,
price, optional margin check, kind lookup, optional set total and `count` element totals, drop, then one
text/allocation/copy chain or the classifier) and every case must match it exactly. The drop call happens
for every case that reaches step 10, including the ones that then return 0xd7 or 0xd8.

**Call sites** (`calls.tsv`). 17 per copy, in address order: resolve, market check, price lookup (slot call),
record kind lookup, margin check, set total, element total, drop of a temporary tag, two text-of-value slot
calls, two allocations, two copies, two panic-helper slot calls and the classifier call. The role names are
mine. In copy 1 the targets are 0x29aea00, 0x22e7f80, slot 0x64e4e90, 0x2a8a770, 0x292a0c0, 0x2d35520,
0x2d357d0, 0x2308120, slot 0x64e4e98, slots 0x64df480/0x64df508/0x64df498 and 0x2c6f290. The two text calls
share one slot, as do the two allocations, the two copies and the two panic helpers, so stubs are bound by
slot and told apart by return address.

**Stub arguments checked.** resolve: the second order word, the first order word as size, the address of
state+0x90; market check: state+0x80, the key block, the size, the order flag byte, and the state pointer
on the stack; price: state+0x80, the first order word and state+lea offset; kind lookup: the state and a
key copy equal to the caller's 20 bytes; margin check: the order, the first order word, the flag byte xor 1,
the price and state+0x90; set total: the set object and the key copy; element total i: base+0x188+0x200*i
and the key copy; text calls: state+0x90 and the first order word; allocation: the length; copy: the buffer
and the length; classifier: the state pointer.

**Callers** (`callers.tsv`): one direct call per copy, from 0x2c2e230 (call at 0x2c2e5b6), 0x556caa0 (0x556ce26)
and 0x556d0b0 (0x556d436), each checked to start on a decoded instruction.

**Method.** An x86-64 evaluator inside the tool runs the real instruction bytes. Each call site is bound to
a recording stub; a stub checks every register and memory argument it receives and fails otherwise, so a
changed argument is a refusal and not a silent pass. Cases come from a fixed LCG per copy: asset words at and
around the window edges, size/price pairs that land on each threshold and on overflow, tag choices for the
three host calls, record kinds 0..=255 classes, element counts 0..=5 with totals at limit-1, limit and
limit+1, text lengths and allocation failures. A separate stream of 1500 cases is run through all three
copies and must give identical outcomes and identical stub-call sequences (`copy-agreement.tsv` keeps every
fifth).

**Where each rule step sits in copy 1** (copies 2 and 3 have the same relative offsets, see `copy-diff.tsv`
for the only differing bytes; addresses below are VAs in copy 1):

| Step | Address range | What the bytes do |
|---|---|---|
| 1 | 0x22e5ca1, 0x22e5ccc | `cmp byte [rcx+0x39fd],0` then store tag 0xdd |
| 2 | 0x22e5cad..0x22e5cca | `lea rcx,[rax-0x2761]`, `cmp rcx,0xffffffffffffd8a4`, store 0xd1 and the word |
| 3 | 0x22e5d14, 0x22e5d1e | resolve call, `cmp eax,0x1a2`; error path copies the result at 0x22e5dab |
| 4 | 0x22e5d56, 0x22e5d5b | market check call, `cmp word [rsp+0x20],0x1a2`; error path copies at 0x22e5e0a |
| 5 | 0x22e5d75..0x22e5da1 | price slot call, `mul r13`, `seto`, `cmp rax,0x1999999999999999`, store 0x6d |
| 6 | 0x22e5e5f, 0x22e5ea9, 0x22e6012 | head word compare with 0x8000000000000001, market byte test, store 0xdc |
| 7 | 0x22e5ed4..0x22e5ee3 | margin call with the flag byte xor 1, error path copies at 0x22e6066 |
| 8 | 0x22e5e8e..0x22e5f05 | kind call, `cmp al,4`, `cmp al,3`, the two flag bytes +0x7b8 and +0x7b9 |
| 9 | 0x22e5f05..0x22e5f9d, 0x22e6057 | set total call, element loop (stride 0x200 from +0x188), saturating add, limit compare, store 0xd2 |
| 10 | 0x22e5fa3..0x22e5fcc, 0x22e6127..0x22e613b | drop call, `shr rcx,0xa`, `cmp rcx,0x9502f9`, text call, store 0xd7 and 100.0 |
| 11 | 0x22e6021..0x22e603a, 0x22e6143..0x22e614d | `movabs rcx,0x1c6bf52634000`, `cmp rax,rcx`, text call, store 0xd8 and 5000000.0 |
| 12 | 0x22e60cd..0x22e60e3 | classifier call, `cmp al,2`, store 0x1a2 |
| 13 | 0x22e60e8..0x22e60f2 | store 0x78 and the classifier byte at +2 |

**Outcome classes and their usual call chains** (from `call-sequences.tsv`; the file holds every pair):

| Outcome | Calls before the result |
|---|---|
| tag 0xdd, tag 0xd1 | none |
| host tag from resolve | resolve |
| host tag from market check | resolve, market check |
| tag 0x6d | resolve, market check, price |
| tag 0xdc, margin tag | resolve, market check, price, (margin check) |
| tag 0xd2 | ... kind lookup, set total, count element totals |
| tag 0xd7 / 0xd8 | ... kind lookup, (totals), drop, text call, (allocation, copy) |
| tag 0x1a2 / 0x78 | ... kind lookup, (totals), drop, classifier |
| panic | the chain up to and including the text call, and the allocation when its result is 0 |

**Host model used for each role** (what a stub returns, so a port knows what it must be given):

| Role | Receives | Returns |
|---|---|---|
| resolve | second order word, first order word, state+0x90, a stack buffer | tag word at buffer+0 and the size at buffer+8 |
| market check | state+0x80, key block, first order word, size, flag byte, state on the stack | tag word at its buffer |
| price | state+0x80, first order word, state+lea offset | one word (the price) |
| kind lookup | state, a 20-byte key copy | pointer to a record whose byte +0x3c is the kind |
| margin check | order, first order word, flag xor 1, price, state+0x90 | tag word at its buffer |
| set total | state+set offset, key copy | one word |
| element total i | element base+0x188+0x200*i, key copy | one word |
| drop | a temporary tag | nothing |
| text of value | state+0x90, first order word | pointer and signed length |
| allocation | the length | pointer or 0 |
| copy | buffer, source, length | nothing |
| panic helper | 0 (negative length) or 1 (allocation failed) | does not return |
| classifier | state | one byte |

**Notes for a port.** The gate reads the order and state and writes only its result; the result block is
0x70 bytes with the tag in the first word and the payloads at +8, +0x10, +0x18 and +0x20 for tags 0xd7 and
0xd8 (payload, then the three words of a text string written as length, pointer, length; the pointer is 1 when the text is empty). Error results from the
callees are moved into the result block whole, so a port should forward them unchanged. The product is
computed once and reused by the three later checks; the value thresholds compare the product, not the
price. The sum in step 9 saturates at u64::MAX and is compared with `>=`, so a limit of 0 always rejects
once the check runs. The minimum test is written as a shift by 10 and a compare with 0x9502f9, which equals
`product < 10^10` exactly because 10^10 is a multiple of 1024.

**Review checklist** (each item is a command or a file, so a reviewer can redo it without trusting this text):

1. `sha256sum artifacts/node/115/hl-node` equals the digest at the top.
2. `copy-diff.tsv` has 40 rows and every row is a call target, a call slot or a layout offset.
3. `layouts.tsv` shows the 0xb70 shift for copy 3 and no other difference.
4. `reach.tsv` shows 287 of 287 instructions executed in each copy and `branch-edges.tsv` has no zero in
   its last two columns.
5. `fields-read.tsv` lists no offset outside the sets named above and `evidence.json` records no write.
6. `mutations.tsv` has `yes` in every detected column; `survivors.tsv` lists only the edits explained above.
7. `python3 -m unittest tests.test_order_value_gate_115` passes without skips on a PATH with no binutils.

## Implementation and comparison

The implementation is the pure-Python `spec` and `predict_calls` in `tools/order_value_gate_115.py`; they are
compared with the bytes, not with a Rust build (no Rust path yet, not yet measured). Results are in
`evidence.json`:

- 12600 gate cases (4200 per copy) plus 1500 agreement cases: 14100 cases, 0 mismatches, digest
  recorded in evidence.json over the outcome and the stub-call sequence of every gate case.
- `reach.tsv`: 287 of 287 instructions executed in each copy. `branch-edges.tsv`: all 23 conditional
  branches of each copy were seen both taken and not taken (138 of 138 directions over the three copies).
- `outcomes.tsv`: every tag of the table above, both panics, and the accepted tag 0x1a2 occur in each copy.
- 180 negative controls, all detected (`measure.json`): per copy 23 inverted branches, 9 compare constants,
  9 tag constants, 4 or 5 64-bit constants (both f64 payloads, the product cap, the 5 * 10^14 limit, the
  head mark) and 10 field offsets; for copy 1 also 9 wrong rules (wrapped product, kind 3 skips, no skip,
  strict and wrapped sum, inclusive minimum and maximum, swapped payloads, any classifier byte accepted);
  and 5 damaged inputs (a flipped byte, a truncated file, an empty file and two addresses outside .text).
- `survivors.tsv`: 32 more single-byte edits that change nothing the cases can see; they are not counted as
  controls. Per copy 9 are displacement edits in the error-copy blocks and in the +0x10..+0x20 words of the
  0xd7/0xd8 results (bytes beyond the tag word and the f64 payload are not compared), 1 is the dropped 0x6d
  temporary, and in copies 2 and 3 one 64-bit constant edit each hits a byte the compared fields never see.
- 43 unit tests, all passing, including two tables of hand-written edge rows (67 + 51 rows; expected
  outcomes written from the byte reading, not computed by the tool) run in all three copies, the kind/flag
  matrix of the total check (32 pairs), 14 saturating-sum rows, the ordering tests (product before market
  checks, total check before value check), the predicted call sequences, the read-only property, the
  field-read sets and mutants in copies 2 and 3.

## Results and limitations

`measure.json`: cases 14100, negative_controls 180, negative_detected 180. No progress gate is requested.

Limits:

- The 11 callees are stubs. The tool proves the gate under that host model: the resolve call writes a tag
  and a size, the market and margin checks write a tag, the price call returns a word, the kind call
  returns a record whose byte +0x3c is the kind, the totals return words, the text call returns a
  (pointer, signed length) pair, and the classifier returns a byte. What those functions compute is not
  shown here. The classifier 0x2c6f290 and its two copies are already covered by the merged
  mixed-tuple-threshold packet and are used only as a stub.
- Cases are pseudo-random with fixed edges, not an interval proof; the arithmetic has no loop but the total
  check, which is run with counts 0..=5 only.
- The error-copy blocks (tags returned from the host calls) are compared on the tag word only.
- The role names and the unit reading (10^-8) are inference. Which order types reach the gate, and how the
  three callers use the result, are not traced.
- Hand-read machine text was taken with GNU objdump 2.42 for review only; it is not in the generated files.

Next question: the record-kind lookup (0x2a8a770 and its shorter copies 0x55e8c30, 0x55e8cb0) decides which
orders run the total check; what keys it and what does the byte at +0x3c mean?
