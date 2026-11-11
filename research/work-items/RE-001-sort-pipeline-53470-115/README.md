# RE-001: sort pipeline 0x5d53470 (node #115)

Task ID: RE-001 (node #115 function map). Bounded question: what does
routine 0x5d53470 do end to end — how does it sort the indexed
container it is handed, which helpers do the quicksort, heap and
insertion phases, what order do the comparisons define, and who
calls it?

## Bound to

- Target: node #115, `work/hl-node-115.bin`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (from `provenance/artifacts.json`)
- Sort entry FDE: 0x5d53470..0x5d53577 (263 bytes)
- Introsort loop FDE: 0x5d4c1c0..0x5d4c8cf (1807 bytes)
- Heap sift-down FDE: 0x5d4bce0..0x5d4c15a (634 bytes)
- Less-than predicate FDE: 0x5d4a830..0x5d4a90f (223 bytes)
- Element swap FDE: 0x5d496d0..0x5d49739 (105 bytes)
- Insertion-sort pass FDE: 0x5d4ba10..0x5d4bcd7 (711 bytes)
- Single-element insertion step FDE: 0x5d4b3f0..0x5d4b5c0 (464 bytes)
- Caller FDEs: 0x5d6da20..0x5d6ee3c (site 0x5d6e48e) and
  0x5d6ef60..0x5d6faa0 (site 0x5d6f51c); only the call-site windows
  are pinned, not the whole caller functions

## How to reproduce the excerpts

From the repository root:

```
objdump -d --start-address=0x5d53470 --stop-address=0x5d53577 work/hl-node-115.bin
objdump -d --start-address=0x5d4c1c0 --stop-address=0x5d4c8cf work/hl-node-115.bin
objdump -d --start-address=0x5d4bce0 --stop-address=0x5d4c15a work/hl-node-115.bin
objdump -d --start-address=0x5d4a830 --stop-address=0x5d4a90f work/hl-node-115.bin
objdump -d --start-address=0x5d496d0 --stop-address=0x5d49739 work/hl-node-115.bin
objdump -d --start-address=0x5d4ba10 --stop-address=0x5d4bcd7 work/hl-node-115.bin
objdump -d --start-address=0x5d4b3f0 --stop-address=0x5d4b5c0 work/hl-node-115.bin
objdump -d --start-address=0x5d6e460 --stop-address=0x5d6e4a0 work/hl-node-115.bin
objdump -d --start-address=0x5d6f4f2 --stop-address=0x5d6f530 work/hl-node-115.bin
readelf --debug-dump=frames work/hl-node-115.bin
python3 research/work-items/RE-001-sort-pipeline-53470-115/census.py
python3 research/work-items/RE-001-sort-pipeline-53470-115/verify.py
```

Or regenerate every excerpt at once with the packet's
`export_excerpts.py` (same commands, same windows). `verify.py`
re-runs the regeneration and checks every excerpt line byte-for-byte
against the raw binary, plus the census, the relocation record and
the model. Note: mnemonics such as `endbr64` in the excerpts are
genuine instructions present in the target binary, not placeholders;
the excerpts are verbatim objdump output.

## Observations

### The container

Every pinned routine addresses elements the same way, through a
base pointer with two tables:

- slots 0..31 live inline at base + 0x108, one 8-byte handle each;
- slots 32 and up live in a heap table whose pointer is stored at
  base + 0x110 and aims at the slot for element 32, so slot `i > 31`
  sits at `heap - 0x100 + i * 8`.

The split constant is 0x1f everywhere it appears, and the heap
form always subtracts 0x100. No allocation happens inside the
pinned code: the heap table is already in place when the sort runs.

### The comparator

All ordering goes through one less-than predicate, 0x5d4a830. It
loads two element handles through the slot split, reads an int32
key from each element's +0x40 object through virtual slot +0x30,
and returns 1 when the first key is less, 0 when it is greater.
On equal keys it checks the second element's vtable slot +0xd0
against the qword at 0x64ecfb0. That qword's file bytes are zero;
a single RELATIVE relocation installs 0x5d48410 there at load time
(see `relocations.txt`). On a match the predicate calls virtual
slot +0x10 on (object + 0x20) and returns the sign bit; on a
mismatch it calls the +0xd0 slot itself with (object, first element
pointer, second element pointer, 0, 0) and returns the sign bit of
that result. The same compare-and-tie-break idiom is inlined in the
insertion pass, the insertion step, the partition loop and the heap
sift-down, always against the same global.

### The sort entry (0x5d53470)

- Returns at once when the flag byte in `dl` is nonzero, and when
  the count in `rsi` is zero. `rdi` is never read by the pinned code.
- Builds two range structs on the stack (container at +0x00, range
  start 0 at +0x08; container at +0x10, count at +0x18) and calls
  the introsort loop with depth `2 * bsr(count)`.
- When count is 16 or fewer it calls the insertion-sort pass once
  over the whole range. Otherwise it calls the pass over the first
  16 elements and then calls the single-element step once per index
  from 16 to count - 1.
- Returns void. Canary at rsp+0x28, checked on the normal path.

### The introsort loop (0x5d4c1c0)

- The range `[begin, end)` comes from the two structs (+0x08
  each). A range of 16 or fewer returns at once, leaving it for the
  insertion-sort tail.
- A zero depth jumps to the heapsort fallback at 0x5d4c6c4;
  otherwise the depth is decremented once per level.
- Pivot selection moves the median of (first + 1, mid, last - 1)
  into first. The predicate calls and the swap arms match
  libstdc++ `__move_median_to_first` exactly, in this order:
  `comp(first+1, mid)`; on the false arm `comp(first+1, last-1)`
  then `comp(mid, last-1)`; on the true arm `comp(mid, last-1)`
  then `comp(first+1, last-1)`; the swap target in each arm is
  recorded in `callers.tsv`.
- The Hoare partition runs around the pivot now at first: the low
  cursor advances from first + 1 while its element is less than
  the pivot, the high cursor retreats from last - 1 while the
  pivot is less than its element, and the cursors' elements are
  swapped inline until they cross. After the partition the left
  half recurses through the self-call at 0x5d4c682 and the right
  half is processed by the tail loop back to 0x5d4c239.
- Heapsort fallback: make_heap by sifting down from `(n - 2) / 2`
  to 0 through 0x5d4bce0, then sort_heap by swapping the root with
  the last element and sifting the new root down, until one element
  is left. Canary at rsp+0x98, checked on the small-range and
  heapsort returns.

### The heap sift-down (0x5d4bce0)

- Hole index in `rsi`, range length in `rdx`, value in `rcx`.
- Sift-down: the larger child (right child `2 * hole + 2` when it
  exists and is not less than the left) is moved up until the hole
  reaches a leaf; a lone left child is moved up when the length is
  even.
- Push-up: the value is walked back up toward the hole it started
  in, moving each smaller parent down, and is stored where the walk
  stops. No canary.

### The element swap (0x5d496d0)

Exchanges the handles at (container `rdx`, index `rcx`) and
(container `rdi`, index `rsi`), each through the inline/heap slot
split. Pure swap: no calls, no stack frame, no canary.

### The insertion-sort pass (0x5d4ba10)

- Range `[start, end)` from the two structs (+0x08 each); returns
  at once when start equals end.
- For each index `i` from start + 1 to end - 1 it compares
  element `i` with element `start`. When element `i` is less, the
  whole prefix `[start, i)` is shifted right by one slot and
  element `i` is stored at start. Otherwise it calls the
  single-element step for `i`. Canary at rsp+0x38.

### The single-element insertion step (0x5d4b3f0)

Takes the element at the index in `*(rdi + 0x08)` and walks it
down: while it is less than the element one slot below, that
element is shifted up one slot and the hole moves down; the value
is stored in the hole once it is no longer less than the element
below it. The step has no lower-bound check: its callers only
reach it when the element at the range start is not greater than
the value, so the walk stops at the start at the latest. No canary.

### The callers

Exactly two direct calls reach the sort entry, both from large
owner functions whose full bodies are not pinned:

- 0x5d6e48e in FDE 0x5d6da20..0x5d6ee3c: flag byte from
  `-0x1bb0(%rbp)`, count from `-0x1bb8(%rbp)`, container built by
  `lea -0x1ac0(%rbp)`, `rdi` from `-0x1b60(%rbp)`.
- 0x5d6f51c in FDE 0x5d6ef60..0x5d6faa0: flag byte from
  `-0x1634(%rbp)`, count from `-0x1608(%rbp)`, container built by
  `lea -0x1590(%rbp)`, `rdi` from `-0x1628(%rbp)`.

No tail jump and no stored qword reaches any pinned routine; the
full census is in `census.py` and `callers.tsv`.

## Inferences (kept separate from observations)

- The entry plus the introsort loop plus the insertion-sort tail is
  the libstdc++ `std::sort` shape for this container:
  `__introsort_loop` with depth `2 * log2(n)`, threshold 16,
  median-of-three pivot, Hoare partition, make_heap/sort_heap
  fallback, then `__final_insertion_sort`.
- The container reads as a small-buffer-optimized vector of 8-byte
  element handles with 32 inline slots; the element type and the
  key's meaning are not in the binary.
- The `rdi` object the callers pass and the sort entry never reads
  is plausibly the comparator object, since every comparison goes
  through the elements' own virtual slots instead.

## Assumptions (explicit)

- The flag byte's nonzero meaning and the `rdi` object's role are
  not interpreted.
- The sorted order is the order the virtual key comparison plus
  the tie-break define.
- The heap sift-down picks the right child over the left child
  when the two children compare equal; the choice between equal
  children does not affect the sorted result.
- The container's heap table is already allocated with room for
  every element before the sort runs.

## Unknowns

- The meaning of the flag byte in `dl` and the role of the `rdi`
  object.
- The element type, the key's meaning, and the identities of the
  virtual slot +0x30 / +0x10 / +0xd0 targets.
- The function at 0x5d48410 behind the comparator-identity global.
- The owning functions behind the two caller FDEs beyond their
  call-site windows.

## Environment honesty

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so
`make doctor` exits non-zero on the pre-existing missing Rust and
Ghidra toolchains and `make verify` / `make test` /
`make catalogue-check` were not run in a tooled environment; no
hosted CI result is claimed. The packet checker
(`verify.py`) and the model tests run in plain Python against the
materialized node #115 binary and all pass; the model tests are
invoked directly because pytest is not installed on this VM.
