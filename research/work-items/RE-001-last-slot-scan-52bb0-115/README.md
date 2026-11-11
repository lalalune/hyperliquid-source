# RE-001: last-slot scan routine 0x5d52bb0 (node #115)

## Bounded question

What does the routine at `0x5d52bb0` return for a holder, a container
and a count, and where is that routine used?

## Answer (established semantics)

The routine `0x5d52bb0` takes a holder pointer in `rdi`, a container
pointer in `rsi` and a 32-bit count in `ecx`, and returns a 32-bit
result. It is a complete behaviour end to end, not a lone-window
fragment: the whole 191-byte routine is pinned (FDE
`0x5d52bb0..0x5d52c6f`), its entry call, its table scan, its two
fallback calls and its single direct caller are all pinned.

### Entry call

The routine first calls `0x60d5390` with `H+0x700` (the holder plus
`0x700`) and ignores the result. That call is recorded as call-shape
only: what `0x60d5390` does to `H+0x700` is not pinned here, and no
matching release call appears in this routine.

### Object layout

Let `O = [C+0x30]` be the qword at container offset `0x30`. The
routine reads two things from `O` and nothing else:

- the element pointer `E = O+0x40`, passed unchanged to both fallback
  calls;
- the table pointer `T = [O+0xad8]`, the base of an array of `0x18`-byte
  entries. Entry `i` holds a low qword at `T + i*0x18 + 0x00` and a
  high qword at `T + i*0x18 + 0x08`.

### Scan

If `count <= 1` (signed 32-bit comparison), the routine returns
`count` at once, without reading the table.

Otherwise it scans indices from `count-1` down to `1`, in that order.
For index `i` it computes `span = (high - low) >> 3`, where the
subtraction wraps modulo 2^64 and the shift is arithmetic (sign
extending), and:

1. if `span > 0`, it returns `i + 1`;
2. otherwise it calls `0x5f6c740(E, i)` and `0x5f6c300(E, count)`,
   and if the first result is unsigned-less than the second result,
   it returns `i + 1`;
3. otherwise it moves to `i - 1`.

If no index returns, the routine returns `1`. Index `0` is never
read: when the scan reaches `i = 1` without returning, the routine
returns `1` directly, which equals `0 + 1` anyway. The routine writes
nothing except its own stack slots; it returns an `int`.

So in words: the routine returns one past the highest index whose
table entry is non-empty (positive span) or whose fallback pair
orders the first result below the second; it returns `1` when no
index qualifies, and it returns the count itself when the count is
at most 1.

### Fallback calls (call-shape only)

The two fallback calls are pinned by address and argument order
only; what they compute is not pinned here:

- `0x5f6c740(E, i)` — element pointer, current index;
- `0x5f6c300(E, count)` — element pointer, original count.

Their results are compared unsigned (`first < second`). The model
takes them as injected callables, so the scan rule is testable
without claiming their internals.

### Consumers

Exactly one direct call, no tail jumps, no stored qwords, no
RELATIVE relocations — reached only by code, never by data:

- `0x5ded3c7` (call) in FDE `0x5decc70..0x5dedffa`.

See `callers.tsv`, reproduced by `census.py` and re-run inside
`verify.py`.

## Unknowns (explicitly not pinned)

- What `0x60d5390`, `0x5f6c740` and `0x5f6c300` compute, and what
  the holder, container, element and table entries represent in the
  source. The names above (holder, container, element, table) are
  positional descriptions, not recovered source names.
- Whether the table holds at least `count` entries: the routine
  reads entries up to index `count-1` without a bounds check, so
  callers must guarantee that. The model requires the entries list
  to cover indices `1..count-1`.
- The routine has no stack canary and no landing pads in its FDE.

## Evidence notes

- The excerpt file `main.txt` is the verbatim output of
  `objdump -d --start-address=0x5d52bb0 --stop-address=0x5d52c6f work/hl-node-115.bin`,
  with only the header normalized to the bare binary name. The
  first line's `endbr64` is a genuine instruction present in the
  target binary, not a placeholder.
- `records.json` holds semantic records only. Instruction-level
  detail lives only in the verbatim excerpt text files.
- `verify.py` re-checks the artifact digest, the manifest, excerpt
  regeneration byte-for-byte, every excerpt line against the raw
  binary, the FDE lines, the census, the empty relocation census,
  the records and the model tests.
