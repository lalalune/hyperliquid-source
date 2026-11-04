# RE-001: pair insertion sort 0x5d497e0 (node #115)

Task: RE-001. Bounded question: what does the 213-byte leaf routine
at 0x5d497e0 do to a range of 16-byte pairs, and where is it used?

Target: node #115, work/hl-node-115.bin, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(provenance/artifacts.json, path artifacts/node/115/hl-node).
Reference commit: upstream main 8fd8db68.

## Answer

The routine is an in-place insertion sort over 16-byte elements
(rdi = begin, rsi = end, exclusive). Each element is a pair of
qwords, sorted ascending by unsigned lexicographic order on
(first, second): the first qwords are compared unsigned, and only
when they are equal are the second qwords compared unsigned.

Behavior, pinned from the disassembly in main.txt:

1. Empty range (begin == end): immediate return, nothing read or
   written. Single-element range (end == begin + 0x10): return
   with nothing moved.
2. Otherwise, for each element from the second to the last: hold
   the current pair, scan backward over the already-sorted prefix,
   shift right each predecessor strictly greater than the current
   pair, stop at the first predecessor less than or equal to it,
   and store the current pair in the freed slot. The prefix is
   sorted after every outer iteration.
3. Begin-insert fast path: when the current pair is strictly less
   than the begin element, the block at 0x5d49852 shifts the whole
   prefix [begin, current) right by one slot and stores the current
   pair at begin.
4. The backward walk has no lower-bound check. It terminates
   because it is entered only when the current pair is greater
   than or equal to the begin element, and the prefix is sorted, so
   the walk stops at or before begin and never reads before it.
   (The same unguarded-walk shape appears in the sorted-unique
   clear's inlined insertion-sort tail; see PR #2600.)
5. The routine is a leaf: it calls nothing, allocates nothing,
   and never reads or writes outside [begin, end) on aligned
   ranges. It returns void.

The walk stops at predecessors equal to the current pair instead
of shifting them, so equal pairs are never reordered by the walk.
Because an element carries no identity beyond its two compared
qwords, that has no observable effect on the output; no stability
claim is made beyond the pinned walk behavior.

## Consumers: the shared introsort final-insertion-sort helper

Census (executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by census.py and re-run inside verify.py):
exactly 6 direct calls, 0 tail jumps, 3 distinct caller FDEs,
0 stored qwords, 0 RELATIVE relocations — reached only by code,
never by data. All three callers use the same two-site shape with
the introsort-loop callee 0x5d4a3f0:

- 0x5d50470 (sorted-unique clear, PR #2600): 0x5d5050f passes
  (begin, begin + 0x100) after the byte count exceeds 0x100;
  0x5d50606 passes the whole (begin, end) range on the small-range
  path (jle at 0x5d504fb).
- 0x5d60090..0x5d60388: 0x5d601ee passes (begin, begin + 0x100)
  after cmp $0x100 and lea 0x100(%rbp); 0x5d602e6 passes
  (begin, end) on the small-range path (jle at 0x5d601db to
  0x5d602e0).
- 0x5d78b40..0x5d7a806: 0x5d7a14b passes (begin, begin + 0x100)
  after cmp $0x100 and lea 0x100(%rdi); 0x5d7a310 passes
  (begin, end) on the small-range path (jle at 0x5d7a13b to
  0x5d7a30d).

So this routine is the shared helper that sorts the first 16
elements after the introsort loop, or the whole range when the
range is at most 16 elements; the large-range callers then run an
inlined insertion-sort tail over [begin + 0x100, end). The
introsort-loop identification and the inlined tails are inference
from the call pattern; the pinned facts are this routine's own
algorithm and the six call sites with their argument setup.

## Evidence notes

- main.txt is the raw objdump output for the whole function,
  verbatim: the instruction mnemonics in it (such as `endbr64`)
  are genuine instructions present in the target binary, not
  placeholders. The header is normalized to the bare binary name
  so the file carries no machine-specific home-directory path.
- records.json holds semantic records only, not a per-instruction
  list. Instruction-level detail lives only in main.txt.
- verify.py in this directory re-checks the digest, the manifest,
  excerpt regeneration byte-for-byte from a fresh objdump run,
  every excerpt instruction byte-for-byte against the raw binary,
  the FDE range, the census including the exact site list, the
  empty relocation record, and model spot checks.
- Reproduce the excerpt with:
  objdump -d --start-address=0x5d497e0 --stop-address=0x5d498b5 \
      work/hl-node-115.bin

## Unknowns

- Bodies of the introsort-loop callee 0x5d4a3f0 and of the inlined
  insertion-sort tails in the three callers; only their call
  sites, arguments and the shared two-site shape are pinned.
- Behavior on ranges whose byte length is not a multiple of 16,
  and on inverted ranges (begin above end); all six call sites
  pass element-aligned ranges with begin at most end, so nothing
  further is claimed.
- The element type name and the purpose of the sorted order; only
  the sort protocol is pinned.

## Environment limits

This work was done with static disassembly only (objdump/readelf
on the digest-verified local binary). No cargo/rustc, Ghidra or
git-lfs is available on this machine, and no live node was run;
the model in tools/ is a Python transcription of the pinned
algorithm, not a build of node code.
