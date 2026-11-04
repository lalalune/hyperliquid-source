# RE-001: lazy-cache adapter routine 0x5d548a0 (node #115)

## Bounded question

What does the routine at `0x5d548a0` do with its holder, and what does
its callee at `0x61bcde0` do with the holder's cache slot? In
particular: how are the holder's two fields routed, what happens on the
cached path versus the fresh path, what record is built and installed on
the fresh path, and how is the routine reached?

## Answer (established semantics)

The adapter `0x5d548a0` is a thin forwarder. It takes four arguments
— `A` in `rdi`, a holder `H` in `rsi`, `X` in `rdx`, `Y` in `rcx` — and
returns `A` unchanged. Between entry and return it does exactly this:

1. Read `S = [H+0x320]` (the cache slot object).
2. Call the getter `0x5d54890(H)`, which returns `G = [H+0x540]`.
3. Call the cache routine `0x61bcde0(A, S, G, X, Y)`.
4. Return `A` (the cache routine also returns `A`, but the adapter
   returns its own saved copy regardless).

The getter is twelve bytes: `endbr64`, `rax = [rdi+0x540]`, `ret`.

### The cache routine 0x61bcde0

Arguments: `out = A` in `rdi`, `S` in `rsi`, `G` in `rdx`, `X` in `rcx`,
`Y` in `r8`. It first calls `0x606ca40(S+0x20)` — the lock-acquire
shaped call also seen on the flag path of the node-link routine
(#2661); only its argument and its pairing with the release below are
pinned here, not what it computes. It then branches on the cache slot:

**Cached path** (`[S+0x60]` non-null): write into `out` exactly three
values — a dword `11` at `out+0x00`, a word `0` at `out+0x04`, a qword
`0` at `out+0x08` (bytes `out+0x06..0x07` are not written) — then call
`0x60d52f0(S+0x20)` (the release paired with the acquire) and return
`out`. No allocation, no key copy, no record build, no notifier call.

**Fresh path** (`[S+0x60]` null): copy a 25-byte key from `X` into
`S+0x00..0x18` — 16 bytes from `X+0x00` to `S+0x00`, then 16 bytes from
`X+0x09` to `S+0x09`, so bytes `S+0x09..0x0f` are written twice with
the same source bytes and the covered range is exactly 25 bytes.
Allocate a 0x30-byte record with operator new, build it with
`0x61bc290`, install it, mark the slot present, notify, release, return:

1. `new = operator new(0x30)`.
2. `0x61bc290(new, G, X, Y)` builds the record (below).
3. `[S+0x60] = new` via `xchg` (the old value is null on this path, so
   nothing is discarded); `[S+0x68] = 1` (present byte).
4. Call `0x61bca30(out, [S+0x60])` — the notifier. Only its argument
   list and position are pinned here; what it writes into `out` is
   NOT claimed (it is a separate, larger routine, FDE
   `0x61bca30..0x61bcd5a`, and is left as a future work item).
5. Call `0x60d52f0(S+0x20)` (release) and return `out`.

The routine has a stack canary and two landing-pad fragments at the
end of its FDE range (`0x61bcec c` and `0x61bced8`, each moving the
exception object into `rbx` and jumping into the cleanup routine
below). The first jumps to `0x61bcdb5` (unlock, then resume: the
exception happened before any record was allocated); the second jumps
to `0x61bcda6` (free the record, then unlock, then resume: the
exception happened after allocation).

### The record builder 0x61bc290

Arguments: `new` in `rdi`, `G` in `rsi`, `X` in `rdx`, `Y` in `rcx`.
It writes a 0x30-byte record and consumes one qword:

- `new+0x00 = G`
- `new+0x08..0x27 = X[0x00..0x1f]` (32 bytes, two 16-byte copies)
- `new+0x28 = [Y]` (the first qword of `Y`)
- `[Y] = 0` (the qword is moved, not copied)

It returns nothing. Note the overlap the model preserves: the fresh
path copies `X[0..24]` into the slot key and the builder copies
`X[0..31]` into the record, so the first 25 bytes of the record blob
equal the slot key.

### The cleanup routine 0x61bcda6

Its own FDE (`0x61bcda6..0x61bcdda`) covers the fragment the cache
routine's landing pads jump into. Entry at `0x61bcda6` (after
allocation): sized-delete the record at the cache frame's stack slot
`+0x08` with size `0x30`, then fall into `0x61bcdb5`. Entry at
`0x61bcdb5` (before allocation, or after the free): call
`0x60d52f0` on the lock slot, check the canary, and resume unwinding
with the exception object in `rbx`. The cleanup reads the same stack
slots the cache routine used (record pointer at `+0x08`, canary at
`+0x18`); that frame sharing is the recorded reading of the fragment.

## Consumers

The adapter has 0 direct calls and 0 tail jumps in the executable
LOAD segment, and exactly 4 stored references (see `relocations.txt`
and `census.py`): `R_X86_64_RELATIVE` slots at `0x64c9790`,
`0x64cb508`, `0x64cb9e8`, `0x64cbfe8`. All four sit at the same
position in four parallel pointer tables with identical neighbours
(`0x5e46100`, `0x5d4a770`, `0x5d4e420`, then this routine, then
`0x5d48da0`, `0x5d49140`, `0x5d490c0`). The adapter is reached only
through pointers, never by a direct call. The neighbouring
`0x5d4e420` routine is the subject of the merged take-record packet
(`RE-001-take-record-4e420-115`), which lists `0x5d548a0` only as a
table neighbour; this packet is the first to pin the adapter itself.

The cache routine has exactly 1 direct call (the adapter's call at
`0x5d548e5`) and 0 tail jumps; the builder has exactly 1 direct call
(the cache routine's call at `0x61bcea3`); the getter has exactly 1
direct call (the adapter's call at `0x5d548d1`). All censuses are
reproduced by `census.py` and re-run inside `verify.py`.

## Unknowns (recorded, not filled in)

- What the holder, the cache slot, the key, the record, or `out`
  denote beyond the field offsets above; no class or source names are
  claimed.
- What the lock pair `0x606ca40` / `0x60d52f0` computes beyond the
  acquire/release pairing (both are call-shape only here).
- What the notifier `0x61bca30` writes into `out` on the fresh path;
  the cached path's `out` writes are pinned, the fresh path's final
  `out` contents are whatever the notifier writes.
- Why the cached path writes the value 11, and what bytes
  `out+0x06..0x07` hold on that path (they are never written).
- Behaviour on null or dangling pointers other than the pinned
  `[S+0x60]` null branch (the model raises on null inputs, stated
  openly).

## Relation to neighbouring packets

- #2661 (node-link `0x5d54630`) pins the same lock pair
  `0x606ca40` / `0x60d52f0` in call-shape only, and its flag-set
  wrapper `0x5d54880` sits immediately before the getter pinned here.
- The take-record packet (`RE-001-take-record-4e420-115`) lists
  `0x5d548a0` as a pointer-table neighbour of its own subject; it
  does not pin the adapter's behaviour.

## Evidence

- `adapter.txt`, `getter.txt`, `cache.txt`, `builder.txt`,
  `cleanup.txt`: whole-function verbatim objdump excerpts (header
  normalized to the bare binary name; the only modification).
  `endbr64` and the other short tokens in these excerpts are genuine
  target-binary text, not placeholders.
- `frames.txt`: the five FDE lines for the routines above.
- `records.json`: semantic records only — field layouts, branch
  outcomes, call sites, and the consumer census. No per-step list.
- `callers.tsv`, `relocations.txt`: the census in tabular form.
- `verify.py`, `export_excerpts.py`, `census.py`: the checker and
  the generators, committed in the packet.
- Model: `tools/lazy_cache_adapter_548a0_115.py`; tests:
  `tests/test_lazy_cache_adapter_548a0_115.py`.
- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  per `provenance/artifacts.json`; the local copy is
  `work/hl-node-115.bin`.
- Environment limits: no cargo/rustc, no git-lfs, no Ghidra/Java on
  this VM; the packet was verified against the materialized node
  #115 binary only, by static inspection plus the Python model.
