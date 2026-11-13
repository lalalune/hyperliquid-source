# Equal keys: which row survives, at every input length

Target: node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
ELF virtual addresses. Fact ids (`W01`, `D04`, ...) are rows of `spec/facts.tsv`; each is
re-checked against the binary by `verify_target.py`. Everything below is a reading of
those instructions, written before the oracle was generated (`ORACLE_FROZEN.txt`).
Nothing was executed or emulated.

## Observation 1: the wrapper `0x2dd2980..0x2dd2bd7`

It calls the vector helper `0x232cd90` with the NodeIp element decoder `0x26e5710` (W01, W02).
On helper failure (result byte != 0x12) it copies the error out and sorts nothing (W03, W04).
On success the vector is (capacity r12, pointer r14, length r15) and:

| length | action | facts |
| --- | --- | --- |
| 0 or 1 | no sort, no replacement | W05, W06 |
| 2..20 | insertion sort `0x26ca410` | W07, W08, W09 |
| 21 or more | slot `0x64e8678` (a RELATIVE relocation to `0x4f3a610`) | W07, W08, W31 |

After sorting, one in-place pass looks for equal neighbouring key dwords:

- It scans pairs (j-1, j) for `cmp esi,[rax-0x30]` equality (W10, W11). With no equal pair the kept
  count is the length.
- At the first equal pair it swaps the two 24-byte rows (W12-W15) and sets the kept count to j (W16),
  so the **later** row of the pair now sits at j-1 and the earlier one at j, outside the kept prefix.
- Every later row is compared for equality with the last kept row (W17, W18). Different key: the row is
  copied down to the kept prefix and the count grows (W19-W22). Equal key: the row is swapped with the
  last kept row (W23-W26), again putting the **later** row in the kept slot.

So within a run of equal keys in the sorted order, the last row of the run is kept. The comparison is a
dword equality of the first four bytes of the 24-byte row. The element decoder stores the wire dword
(zero-extended) at row +0, the scalar at +8 and the boolean at +0x10 (E01-E05), so the dword is the four
wire bytes and the comparison is on the key alone.

Kept count against `0x40` decides the container: `<= 64` calls `0x24d6e80` with minimum capacity 0 (W27-W29),
`> 64` calls the tree builder `0x23a3800` (W27, W28, W30). Only the choice is modelled. `0x24d6e80` was read
as a capacity shrink of a ring-shaped record (capacity, pointer, head 0, length); `0x23a3800` re-sorts the
already ascending, already unique rows with the same key order (T01-T12, see below) and calls `0x1d0e4d0`,
which was **not** read.

## Observation 2: key order is byte order, and every sort compares strictly

Each comparison loads the key dword, byte-swaps it and compares unsigned: the first four wire bytes are
compared as a big-endian number, i.e. as bytes (I03-I05, D01, M01-M05, Q07, Q09, T07-T09). A numeric comparison
of the little-endian dword would put `01 00 00 00` (value 1) before `00 00 00 01` (value 0x01000000); the
byte-swapped compare puts `00 00 00 01` first. The corpus keeps cases where the two orders differ.

## Observation 3: stability of each sort used

The sort an input reaches depends only on its length (W07-W09, W31, S01-S03, Q01-Q06). Each tie decision
was read where it is made.

**2..20 rows, `0x26ca410`.** A row is skipped when `cur >= left` (I05, I06) and moves left only while
strictly smaller than the next left row (I07, I08). Equal keys never pass each other.

**21 or more rows, `0x4f3a610 -> 0x4f99e70` (run detection, merging), `0x4e880e0` (quicksort),
`0x5403600` (small sort), `0x4e62c00` (pivot).** The structure matches the standard library's stable
`driftsort`: run detection, powersort-style merge stack, stable quicksort with an equal-key partition, a small
sort of sort4 plus insertion plus bidirectional merge, and median-of-3 pivots. The structure was recognised
from the code, not derived from a library version number; what follows is each tie site.

- Run detection: `v[1] < v[0]` strictly starts a descending run (D01, D02). The descending run continues
  only while the next row is strictly smaller and ends on not-less (D05, D06). An ascending run continues
  on equal and ends on strictly smaller (D03, D04). Only a strictly descending run is reversed (D07, D08).
  Reversing a strictly descending run cannot reorder equal keys.
- Merge, shorter run copied to scratch (D09). Forward merge (left run in scratch): the left row is taken
  whenever `right >= left` (D14-D17), so on equal keys the left (earlier) row goes first. Backward merge
  (right run in scratch): the scratch (right) row is taken whenever `right >= left` (D10-D13) and the output
  fills from the end, so on equal keys the right (later) row lands later. Both keep input order.
- Unsorted runs are sorted with the quicksort slot `0x64eb548` (RELATIVE to `0x4e880e0`) (D18-D20).
- Quicksort `0x4e880e0`: 32 rows or fewer go to the small sort (Q01-Q03). When the limit counter is exhausted
  it hands over to the merge sort with the eager flag (Q04-Q06). The partition moves a row to the front of the
  scratch only when strictly less than the pivot (Q09-Q12); rows equal to the pivot go to the back part with
  the other non-smaller rows, each side written in input order and the back part copied back reversed, so the
  partition is stable. Equal-key partition: chosen when the pivot is not greater than the ancestor pivot, or
  when nothing was below the pivot (Q07, Q08, Q13, Q14); it moves rows with `pivot >= row` to the front
  (Q16-Q18) and continues after them (Q19), again in input order.
- Small sort `0x5403600`: the 4-row network picks `a, b, c, d` from two pair comparisons and orders the middle two
  with a last comparison, every comparison strict `less` (M01-M11); the tail insertion moves while strictly less
  (M12-M15); the bidirectional merge takes the left row on `right >= left` going up and the right row on
  `right >= left` going down (M16-M20), like the merge above.
- Pivot choice `0x4e62c00` only affects performance, not the order of equal keys (V01-V03).

No tie site takes the later row first or reorders equal keys. Therefore, for any input length, equal-key rows
leave the sort in input order, the in-place pass above keeps the last of them, and **the input-order-last row
wins**.

## Observation 4: the tree builder sorts again

`0x23a3800` runs an insertion sort (`0x26ca410`, T03) for 2..20 rows or the sort at `0x64e52d8` (RELATIVE to
`0x4f3ac90`, T01, T02, T04) for more, on rows that are already strictly ascending, one per key. `0x4f3ac90`
calls `0x4fa4110` (T06), whose run-detection comparisons are the same byte-swapped strict compares (T07-T12).
With unique keys any correct sort returns the same order, so the second sort does not change the set. `0x4fa4110`
was read only at the run-detection compares, not as a whole.

## What this reading does not establish

- It is a human reading of compare and select sites against the shape of a known algorithm, not a machine
  proof. A stable result for every length rests on that recognition plus the sites listed.
- The Rust crate uses the standard library's stable sort for 21 or more rows. It does not port `0x4f99e70`,
  `0x4e880e0` or `0x5403600`; it relies on a stable sort of a total key order being unique.
- Scratch sizing, allocation failure, panics, `0x24d6e80`'s reallocation and `0x1d0e4d0` were not read.
- The twin wrapper `0x4de6210` has the same 155 instructions (checked offline: mnemonics, operands and internal
  branch offsets equal; external call targets and rip displacements masked). It reaches the same sort slot
  `0x64e8678` but different insertion-sort, small-set and tree-builder copies, which were not read.
