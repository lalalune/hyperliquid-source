# RE-001: map node #115 pair introsort loop 0x5d4a3f0 with its adjust-heap helper 0x5d49530

- Component ID: RE-001 (node #115 function map)
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json, `artifacts/node/115/hl-node`; local copy
  `work/hl-node-115.bin` hashes exactly)
- Source commit / reference commit: upstream main `8fd8db68`
- Claim status: observation for everything below except the items listed
  under Unknowns, which are inference boundaries, not claims.

## Bounded question

What does the routine at 0x5d4a3f0 do to a range of 16-byte pairs, how
does its adjust-heap helper at 0x5d49530 work, and where are the two
routines used? This closes the sort-phase gap that PR #2600 (the
sorted-unique clear) and PR #2602 (the insertion-sort helper) left
open: both pinned the call sites of 0x5d4a3f0 but not its body.

## Reproduce

```
python3 research/work-items/RE-001-introsort-loop-4a3f0-115/export_excerpts.py
# (equivalent: objdump -d --start-address=0x5d4a3f0 --stop-address=0x5d4a698
#  work/hl-node-115.bin; objdump -d --start-address=0x5d49530
#  --stop-address=0x5d496cd work/hl-node-115.bin)
readelf --debug-dump=frames-interp work/hl-node-115.bin
python3 research/work-items/RE-001-introsort-loop-4a3f0-115/census.py
python3 research/work-items/RE-001-introsort-loop-4a3f0-115/verify.py
python3 -m unittest tests.test_introsort_loop_4a3f0_115
```

Tool versions: system objdump/readelf (GNU binutils 2.42), python3 3.12.
No execution of the binary, no synthetic packets: every byte below was
read from the digest-verified binary. The mnemonics in main.txt and
helper.txt, such as `endbr64`, are genuine instructions present in
the target binary, not placeholders; verify.py checks every excerpt
instruction byte-for-byte against the raw binary.

## Evidence

- FDEs: main `pc=0x5d4a3f0..0x5d4a698` (680 bytes); helper
  `pc=0x5d49530..0x5d496cd` (413 bytes).
- Whole-function verbatim excerpts: main.txt, helper.txt, regenerated
  byte-for-byte by export_excerpts.py (the objdump header is
  normalized to the bare binary name so the files carry no
  machine-specific path).
- Caller census: main exactly 4 direct calls + 0 tail jumps, 4
  distinct caller FDEs; helper exactly 2 direct calls + 0 tail jumps,
  1 distinct caller FDE; 0 stored qwords and 0 RELATIVE relocations
  for either address (callers.tsv, helper_callers.tsv,
  relocations.txt; reproduced by census.py). Both routines are
  reached only by code, never by data.
- Caller FDE ranges: frames.txt (both routine FDEs plus every
  distinct caller range).
- Semantic records only: records.json. Instruction-level detail lives
  only in the raw disassembly excerpt text files.

## Semantics

Element layout: each element is 16 bytes, a pair of qwords ordered
ascending by unsigned lexicographic order on (first, second). The
main routine takes rdi = begin, rsi = end (exclusive), rdx = depth
budget (signed). The helper takes rdi = first, rsi = hole index,
rdx = length in elements, rcx = value first qword, r8 = value second
qword.

### Main routine, in order

1. Small range. Byte count (end - begin) at most 0x100 (16 elements)
   returns immediately at 0x5d4a697, sorting nothing. The caller runs
   the final insertion sort over such ranges (see Consumers).
2. Depth gate. Depth exactly zero at entry jumps to the heapsort
   path at 0x5d4a5fd (whole range); the depth is decremented once
   per partition level at 0x5d4a429.
3. Median step. The middle element is begin + (byte count >> 5 << 4),
   i.e. element index count // 2. The compare/swap network over the
   second element (begin + 0x10), the middle element and the last
   element (end - 0x10) moves the median of the three to begin:
   second below middle takes the 0x5d4a458 arm, second at or above
   middle takes the 0x5d4a520 arm; each arm compares against last
   and swaps begin with middle (0x5d4a478), begin with last
   (0x5d4a54d) or begin with second (0x5d4a590). Equal first qwords
   fall through to a second-qword comparison, and exact equality
   follows the greater-or-equal arm. The 0x5d4a53f seconds block is
   shared by the 0x5d4a683 equal-first arm and the 0x5d4a520
   fallthrough; a middle first qword above last's is unreachable
   in the fallthrough, because it would contradict the second
   element being at or above middle while sharing last's first
   qword.
4. Partition. The pivot is the element at begin after the median
   step and stays there. The left cursor starts at begin + 0x10 and
   advances while its element is strictly below the pivot; the
   right cursor starts at end and retreats (reading end - 0x10
   downward) while its element is strictly above the pivot; when
   the cursors have not crossed, the stopped pair is swapped and
   the left cursor advances. When the left cursor reaches or
   passes the right cursor element, the cut is the left cursor: on
   return, every element in [begin, cut) is at most the pivot and
   every element in [cut, end) is at least it. The scans are
   unguarded; they cannot run out of range after the median step,
   because at least one candidate at or above the pivot and at
   least one at or below it remain inside the range.
5. Recursion and tail loop. The routine calls itself at 0x5d4a5d9
   with (cut, end, depth - 1). Then a left byte count at most
   0x100 returns, a decremented depth of zero heapsorts the left
   part, otherwise the tail iteration reuses the same depth on
   [begin, cut).
6. Heapsort fallback. Heapify calls the helper at 0x5d4a62d for
   hole indices (count - 2) // 2 down to 0, each with the element
   at that hole as the value. The pop loop swaps the first element
   with the last, calls the helper at 0x5d4a66f with hole 0, the
   remaining count and the old last element as the value, and
   repeats while the pre-swap last offset exceeds 0x10 bytes — so
   the body also runs once with the last element at begin + 1,
   which swaps the final two elements into ascending order. The
   routine then returns; it never recurses after a heapsort.

### Helper routine, in order

1. Sift-down. Let limit = (length - 1) // 2. While the hole is below
   limit, the larger of the two children (indices 2 * hole + 1 and
   2 * hole + 2) moves up into the hole and the hole becomes that
   child; the right child wins exact ties, because the second
   child's comparison falls through to it on equality.
2. Even-length tail. When the length is even and the hole equals
   (length - 2) // 2, the lone left child at 2 * hole + 1 moves up
   into the hole and the hole becomes that child.
3. Push-up. While the hole is below its start index and its parent
   (index (hole - 1) // 2) is strictly below the value, the parent
   moves down and the hole becomes the parent. Then the value is
   stored in the hole. The old hole slot's value is never read,
   only overwritten. Caller precondition, as in both binary uses:
   the value is at most every ancestor above the original hole
   (heapify passes the hole's own element; the pop loop passes a
   leaf element with the hole at the root), so the push-up never
   needs to rise above the original hole.
4. The helper is a leaf: no calls, no allocation, no landing-pad
   region inside its FDE. The main routine likewise makes no PLT
   or indirect calls and has no landing-pad region; its only
   transfers are the recursive call and the two helper calls.

## Consumers: the shared pair-sort driver

Census (executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by census.py and re-run inside verify.py):

- Main routine, 4 direct calls: the recursive call at 0x5d4a5d9,
  and one call from each of the three sort drivers — 0x5d50470
  (sorted-unique clear, PR #2600) at 0x5d504ef, 0x5d60090..0x5d60388
  at 0x5d601cf, and 0x5d78b40..0x5d7a806 at 0x5d7a128. The three
  drivers are exactly the three callers of the insertion-sort
  helper mapped in PR #2602, in the same two-site shape: a byte
  count above 0x100 calls this loop with (begin, end, depth) and
  then the insertion-sort helper with (begin, begin + 0x100) plus
  an inlined insertion-sort tail; a byte count at most 0x100 calls
  the insertion-sort helper with the whole range and this loop
  returns immediately.
- Helper routine, 2 direct calls, both inside the main routine
  (heapify at 0x5d4a62d, pop at 0x5d4a66f); no other routine in the
  binary calls it.
- Depth convention, observed at the 0x5d50470 call site only:
  2 * floor(log2(element count)) by bsr at 0x5d504df plus doubling
  at 0x5d504e5, or the literal -2 left in the register when the
  byte count is below 16. The -2 case coincides with an empty range
  for that caller, which this routine's small-range check returns
  on first.

## Model and tests

`tools/introsort_loop_4a3f0_115.py` transcribes the pinned
algorithm: median network, Hoare partition, recursion with tail
iteration, heapsort fallback and adjust-heap helper. Its tests
(`tests/test_introsort_loop_4a3f0_115.py`, 17 tests) cover: small
ranges returned unchanged; depth zero sorting large ranges fully;
the loop's output completed to sorted order by a final insertion
sort, at several depths and sizes; permutation preservation;
unsigned order across the 2**63 boundary; the median landing on
begin with the multiset preserved; the partition cut property;
adjust-heap restoring a max-heap with the expected multiset,
including the even-length lone-child case and the right-child tie
rule; and heapsort on whole ranges and subranges.

## Evidence notes

- main.txt and helper.txt are the raw objdump outputs for the
  whole functions, verbatim: the instruction mnemonics in them
  (such as `endbr64`) are genuine instructions present in the
  target binary, not placeholders. The headers are normalized to
  the bare binary name so the files carry no machine-specific
  home-directory path.
- records.json holds semantic records only, not a per-instruction
  list. Instruction-level detail lives only in main.txt and
  helper.txt.
- verify.py in this directory re-checks the digest, the manifest,
  both excerpts' regeneration byte-for-byte from fresh objdump
  runs, every excerpt instruction byte-for-byte against the raw
  binary, both FDE ranges, both censuses including the exact site
  lists, the empty relocation record, and model spot checks.
- Reproduce the excerpts with:
  objdump -d --start-address=0x5d4a3f0 --stop-address=0x5d4a698 \
      work/hl-node-115.bin
  objdump -d --start-address=0x5d49530 --stop-address=0x5d496cd \
      work/hl-node-115.bin

## Unknowns

- The libstdc++ names (introsort loop, adjust heap, median to
  first, unguarded partition) are inference from the structure;
  the pinned facts are the disassembly behavior, the call sites
  and the census.
- Behavior on ranges whose byte length is not a multiple of 16,
  and on inverted ranges (begin above end); all four call sites
  pass element-aligned ranges with begin at most end, so nothing
  further is claimed.
- A negative entry depth: the routine tests depth for exact zero
  only, so a negative depth would partition rather than heapsort;
  no observed caller passes one for a non-empty range (the -2 left
  by PR #2600's driver coincides with an empty range, which the
  small-range check returns on first).
- The depth computations of the 0x5d60090 and 0x5d78b40 drivers;
  only PR #2600's driver computation is pinned here.
- The element type name and the purpose of the sorted order; only
  the sort protocol is pinned.

## Environment limits

This work was done with static disassembly only (objdump/readelf
on the digest-verified local binary). No cargo/rustc, Ghidra or
git-lfs is available on this machine, and no live node was run;
the model in tools/ is a Python transcription of the pinned
algorithm, not a build of node code.
