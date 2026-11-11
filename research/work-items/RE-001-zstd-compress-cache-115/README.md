# RE-001: node #115's cached ZSTD compress context

## Bounded question

How does node #115 hand a calling thread its cached ZSTD *compress*
context, and what owns the context's lifetime? The answer is one
complete behaviour: a kind-7 holder factory that builds a fresh CCtx
and pins one parameter on it, the CCtx create/reset/free chain, and
the log-writer refresh routine that installs the holder.

This is the compress-side twin of open PR #3635, which pins the
decompress side (`StreamingUncompress::Create`, a fresh DCtx, no
parameter set). The two factories sit side by side in the binary
(`0x61c1c10` / `0x61c1ce0`) with different holders (0x70 vs 0x38
bytes), different tables and different callees.

## Answer (pinned)

- **Factory** (`0x61c1c10`, catalogue:
  `rocksdb::StreamingCompress::Create(CompressionType, const
  CompressionOptions&, uint64_t, uint64_t)`, 167/184): kind `7`
  (ZSTD) builds the `0x70`-byte holder with table `0x64d7408+0x10`
  at `+0x0` and kind byte `7` at `+0x8`; any other kind returns
  null. It copies the 0x30-byte template to `+0x10..+0x40`, writes
  arg3 to `+0x40` and arg4 to `+0x48`, creates a fresh CCtx at
  `+0x50`, sets parameter 201 to 1 on it, and zeroes `+0x58` and
  `+0x60..+0x70`. On unwind the landing pad (`0x61c1bee`, its own
  FDE) deletes the 0x70-byte holder and resumes.
- **Create** (`0x6218920`, zstd `ZSTD_createCCtx` by shape — no
  catalogue row pins this address): `calloc(1, 0x1480)` plus the
  pinned field init: `+0x08` is the CPUID leaf-7 BMI1+BMI2 flag (0
  when max leaf <= 6), `+0x10..+0xe8` zeroed, `+0x30 = 1`,
  `+0x3c = 3`. The reset runs on the fresh context first; its
  pointers are all null, so it frees nothing. Six direct call sites:
  the factory plus five other CCtx consumers.
- **Reset** (`0x62188a0`): frees the `+0xe48` workspace pointer
  through the custom free at `+0x370` (opaque `+0x378`), or plain
  `free` when that is null; frees the `+0xe68` CDict via
  `ZSTD_freeCDict`; zeroes `+0xe48..+0xe90`. Only the create calls
  it — no separate freeCCtx was found.
- **FreeCDict** (`0x62187a0`, catalogue `ZSTD_freeCDict`, 242/251):
  null returns 0 at once; otherwise zeroes `+0x20..+0x60` and
  `+0x60` and releases the backing allocation and the CDict itself
  through the `+0x17a0` custom free (opaque `+0x17a8`) when set,
  else plain `free`; returns 0. Thirteen direct call sites.
- **Setter** (`0x6212010`, zstd `ZSTD_CCtx_setParameter` by shape):
  two gates on the flag at CCtx+0xe18 (0 on a fresh context). When
  set, only params 100 and 102..107 are accepted (else -60) and the
  dirty flag at CCtx+0x4 is set. When clear, the accepted params are
  10, 100..107, 130, 160..164, 200..202, 400 (value 0, or value != 0
  only when CCtx+0x388 == 0), 401, 402, 500, 999..1002, 1004..1016
  (else -40), with no dirty write. Accepted params tail-jump into
  the apply worker with the params struct at CCtx+0x10.
- **Apply** (`0x6211a10`): two jump tables (`0x980e20` for params
  100..202, `0x980fbc` for params 1000..1016) plus special arms.
  Every arm is decoded in `records.json`: the cParams block
  (+0x04..+0x1c, windowLog/chainLog/hashLog/searchLog/minMatch/
  targetLength/strategy), the level at +0x2c (clamped to
  (-131072, 22); 0 means the default level 3), the boolean arms
  (200/201 store `(value != 0)`, 202 stores `(value == 0)`), the
  64-bit size arms (130, 1015), and the 1000..1016 block. Unlisted
  params return -40; a failed range check returns -42.
- **Bounds** (`0x62117e0`) and **range check** (`0x62119e0`): the
  lookup returns `(status, lo, hi)` per parameter (full table in
  `records.json`); the check returns 1 iff `lo <= value <= hi`.
  The factory's parameter 201 has bounds (0, 1) and its arm stores
  `(value != 0)` at params+0x24.
- **Refresh caller** (`0x5f041d0`, catalogue:
  `rocksdb::log::Writer::AddCompressionTypeRecord`, 547/588): when
  the owner's kind byte (+0x45) is set, it appends the kind dword
  to a stack string and emits it as a type-9 physical record via
  `0x5f03b80` (catalogue `EmitPhysicalRecord`); an emit failure
  clears the kind byte and returns the status. Otherwise it builds
  the 0x30-byte template — first qword from the global at
  `0x459aa0` (`0x7ffffffffff2`; as int32s (-14, INT_MAX), where -14
  matches RocksDB's documented default window_bits), `0x100000000`
  at +0x10, flag byte 1 at +0x28 — and calls the factory with
  (kind, template, 2, 0x7ff5 or 0x7ff9 by owner+0x18), installing
  the holder at owner+0x48 and a fresh array of the same size at
  owner+0x50 (delete[]ing the old array). When the kind byte is
  clear it zeroes the 16-byte out instead.

## Evidence

- `records.json`: semantic records only (no per-instruction mnemonic
  list). Instruction-level detail lives in the raw disassembly
  excerpts below, kept verbatim and whole-function. Mnemonics such
  as `endbr64` are genuine instructions present in the target binary,
  not placeholders.
- Whole-function verbatim excerpts (`*.objdump.txt`, regenerated by
  `export_excerpts.py`): factory, factory landing pad, create, reset,
  freeCDict, setter, apply, range check, bounds, refresh caller.
- `frames.txt`: the 10 FDE blocks from `objdump --dwarf=frames`.
- `callers.tsv`: every census site with its containing FDE and role
  (69 sites, each confirmed as a real call/jump in its FDE).
- `relocations.txt`: no `R_X86_64_RELATIVE` entry points at a packet
  window; the factory table and the template global are RIP-relative.
- `verify.py`: the packet checker — run it from the repo root. It
  re-derives the excerpts, byte-checks fixed samples plus 3 seeded
  random gate spots against a fresh objdump run and the raw binary,
  re-runs the census, verifies every census site in its FDE,
  re-decodes the jump tables, and runs the model tests.
- `census.py` / `gen_records.py`: regenerate the census and
  `records.json` from the binary.

## Model and tests

- `tools/zstd_compress_cache_115.py`: the Python model (factory,
  create, reset, freeCDict, setter gates, apply with the full arm
  map and bounds table, range check, refresh caller).
- `tests/test_zstd_compress_cache_115.py`: 182 checks, all passing.

## Bound to

- Artifact `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (`provenance/artifacts.json`).
- Binary `work/hl-node-115.bin` (same digest, verified by `verify.py`).

## Environment limits (honest)

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java, so `make
verify` / `make test` / `make catalogue-check` could not be run here;
the packet's own `verify.py` and the model tests are the checks that
were run. The vendor attributions are the catalogue's
relocation-qualified matches (167/184, 547/588, 242/251, 394/422),
not this packet's own rebuilds. The create and setter are identified
by shape (calloc size, CPUID probe, parameter-number ranges, the
level 0 → 3 rule), not by a catalogue row.

## Open unknowns

See `records.json` `unknowns`: the +0xe18 setter flag; the
+0x30/+0x3c create fields; the freeCDict embedded-region rule; no
freeCCtx analogue found; the five other create consumers and the
refresh caller's caller are FDE-only; the 0x6051a20 helper contract;
LSDA call-site tables.
