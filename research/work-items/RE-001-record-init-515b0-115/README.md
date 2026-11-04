# RE-001: record initializer 0x5d515b0 (node #115)

## Bounded question

What initial state does the routine at `0x5d515b0` establish for the
record it takes in `rdi`, and where is that routine used?

## Answer (established semantics)

The routine `0x5d515b0` takes one argument, a record pointer in
`rdi`, and returns nothing. It is straight-line code: no branches,
no calls, no stack canary, a single return at `0x5d516e5`. Its only
observable outcome is the record's initial field values, listed
below exactly as written. It is a complete behaviour end to end, not
a lone-window fragment: the whole 342-byte routine is pinned, its
17 direct callers across 12 caller functions are censused, and the
bytes it does *not* write are recorded as unestablished rather than
assumed zero.

### What it writes

Self-referential pointer fields (the field holds the record's own
address plus the stated offset):

- `+0x08` = record + `0x18`
- `+0x28` = record + `0x38`
- `+0xb0` = record + `0xa0`
- `+0xb8` = record + `0xa0`
- `+0x138` = record + `0x148`
- `+0x160` = record + `0x170`

Zero fields:

- dword zero: `+0x00`, `+0x60`, `+0xa0`, `+0x130`, `+0x15c`
- word zero: `+0x134`
- qword zero: `+0x10`, `+0x30`, `+0x58`, `+0x78`, `+0x90`, `+0xa8`,
  `+0xc0`, `+0x128`, `+0x140`, `+0x168`
- byte zero: `+0x18`, `+0x38`, `+0x148`, `+0x158`, `+0x170`
- 16-byte zero blocks: `+0x48`, `+0x68`, `+0x80`, `+0xc8`, `+0xd8`,
  `+0xe8`, `+0xf8`, `+0x108`, `+0x118`

### What it does not write (unknowns, not zeros)

Byte ranges `+0x04..+0x07`, `+0x19..+0x27`, `+0x39..+0x47`,
`+0x64..+0x67`, `+0x98..+0x9f`, `+0xa4..+0xa7`, `+0x136..+0x137`,
`+0x149..+0x157`, `+0x159..+0x15b`, and everything beyond `+0x170`
are never written by this routine, so their values after the call
are whatever the caller left there. The record is at least `0x171`
bytes long (the highest write reaches `+0x170`); its total size is
not pinned. The `+0x19..+0x27` and `+0x39..+0x47` gaps are the tails
of the inline buffers at `+0x18` and `+0x38` past their NUL byte.

### Inferred readings (separate from the observations above)

- The triples (`+0x08` -> own `+0x18`, `+0x10` = 0, byte `+0x18`
  = 0), (`+0x28` -> own `+0x38`, `+0x30` = 0, byte `+0x38` = 0)
  and (`+0x138` -> own `+0x148`, `+0x140` = 0, byte `+0x148` = 0)
  read as three empty short-form strings (pointer to the record's
  own buffer, size zero, NUL first byte).
- The pairs (`+0xb0`, `+0xb8`) both holding own `+0xa0`, and
  (`+0x160` holding own `+0x170`, `+0x168` = 0), read as two empty
  ranges. The element types of those ranges are not pinned.
- The record's source-level name and owning class are not pinned,
  and what any caller does with the record after initialization is
  not claimed here.

### Consumers

Census (executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's census.py and re-run inside
verify.py): exactly 17 direct calls + 0 tail jumps across 12 caller
functions (see callers.tsv for the site list and caller FDEs); 0
stored qwords, 0 RELATIVE relocations — reached only by code, never
by data. Note the mnemonic tokens that appear in the verbatim
disassembly excerpts (for example `endbr64` at the routine entry)
are genuine instructions present in the target binary, not
placeholders: the excerpts are unmodified objdump output and
verify.py checks every excerpt line byte-for-byte against the raw
binary.

## Packet contents

- `main.txt`: whole-function verbatim objdump excerpt
  (`0x5d515b0..0x5d516e6`), header normalized to the bare binary
  name only.
- `frames.txt`: the routine's FDE line plus the 12 caller FDEs.
- `callers.tsv`: the 17 confirmed call sites with caller FDEs.
- `relocations.txt`: header only — no stored references found.
- `records.json`: semantic records only (field map, gaps,
  inferences kept separate from observations).
- `verify.py`, `export_excerpts.py`, `census.py`: the packet's own
  runnable checker, excerpt generator, and census.
- `MANIFEST.sha256`: hashes of every other packet file.

## Model and tests

`tools/record_init_515b0_115.py` models the initializer: it applies
exactly the established writes and nothing else, so gap bytes keep
whatever value they had. `tests/test_record_init_515b0_115.py`
checks the self-pointers, the zero fields, the empty-string
triples, the empty-range pairs, that gap bytes are never claimed,
that re-initialization restores dirtied established fields while
leaving gap bytes untouched, and that the modeled write set equals
the established set exactly.

## Verification

- Binary SHA-256 matches `provenance/artifacts.json`
  (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  for node #115).
- `verify.py` prints ALL CHECKS PASSED (digest, provenance,
  manifest, excerpt regeneration byte-for-byte from fresh objdump
  runs, all excerpt lines byte-for-byte vs the raw binary, all FDE
  lines, census including the exact site list, empty relocation
  census, records, model spot checks, and the model tests).
- Three extra spot checks byte-for-byte vs fresh objdump and the
  raw binary, beyond verify.py's own checks: the self-pointer store
  at `0x5d515c0`, the zero block at `0x5d51689`, and the
  `+0x160` self-pointer store at `0x5d516cc`.
- Environment limits, stated honestly: this VM has no cargo/rustc,
  no git-lfs, no Ghidra/Java, and pytest is not installed, so the
  test functions are invoked directly by verify.py. The repository
  gates `make verify` / `make test` / `make catalogue-check` were
  not run here and are left for a tooled environment.
