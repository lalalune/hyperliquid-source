# RE-001: node #115 drain-until-quiet 0x5d51d10

## Bounded question

What does routine `0x5d51d10` (FDE `0x5d51d10..0x5d51d53`, 67 bytes)
do to an object before it returns, and when exactly does it stop
calling the worker at `0x606ccb0`?

## Answer, pinned to the target

The routine takes one argument -- an object pointer in `rdi` --
writes nothing itself, and returns the original object pointer.
Between entry and return it runs one loop, end to end: it keeps
calling the worker at `0x606ccb0` with the object's field at
`+0xa10` (the field's address, taken with `lea`) until the
object is quiet, where quiet means BOTH pending indicators are
zero:

- the qword at object `+0x1430`, and
- the dword at object `+0x143c`.

The check order, per iteration, is what makes the behaviour
observable:

1. Read the `+0x1430` qword first. If it is non-zero, call the
   worker immediately and start a new iteration -- the dword at
   `+0x143c` is NOT read on this iteration.
2. Only when the qword reads zero, read the `+0x143c` dword. If
   it is non-zero, call the worker and start a new iteration.
3. Only when one iteration reads a zero qword and then a zero
   dword does the routine return, with no further call.

The loop has no iteration bound in the binary: a worker that
never clears both fields never returns. That unboundedness is
stated openly, not smoothed over -- the model takes the worker
as a caller-supplied callable and pins only the loop contract.

Fields read, and nothing else:

| offset | width | role |
| ------ | ----- | ---- |
| `+0xa10` | address only | worker argument; the field's contents are not read by this routine |
| `+0x1430` | 8 bytes | pending qword; read first on every iteration |
| `+0x143c` | 4 bytes | pending dword; read only when the qword is zero |

The routine's own control transfers are exactly one direct call
(to the worker), three direct jumps that all land inside itself
(the entry jump to the loop head and the two jumps back to the
worker-call block), and no tail jump out. It has no landing-pad
block inside its FDE range; the bytes after the range
(`0x5d51d53..0x5d51d80`) are int3 padding followed by a separate
routine's landing-pad block, not part of this routine.

## Consumers (site-only)

The census finds exactly two direct call sites, no tail jumps:

- `0x5d5b8d5`, inside caller `0x5d5b7f0..0x5d5bbe1`. Only the
  site and FDE range are claimed.
- `0x5d68e05`, inside caller `0x5d68dc0..0x5d6980a`. Same: only
  the site and FDE range are claimed.

## NOT claimed

What the worker at `0x606ccb0` does, what the two pending fields
denote, what the `+0xa10` field denotes, what the callers do
before or after calling this routine, or behaviour on dangling
pointers or a null object pointer (the routine reads `+0x1430`
through the pointer unconditionally, so the model raises on a
null object, stated openly). The neighbouring routines, including
the `0x5d51d80` routine that starts after the padding, are not
part of this claim.

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole routine, verbatim, produced by
  `objdump -d --start-address=0x5d51d10 --stop-address=0x5d51d53 work/hl-node-115.bin`.
  Instruction-level detail lives only in that excerpt text, never as
  a per-instruction list in records.json. The opening `endbr64`
  (bytes `f3 0f 1e fa`) is a genuine instruction present in the
  target binary, not a placeholder.
- `records.json`: semantic records only (loop contract, branches,
  reads, census).
- `frames.txt`: FDE lines for the routine and its two caller
  functions. `callers.tsv`: the two direct call sites with their
  smallest enclosing caller FDE ranges. `relocations.txt` is empty:
  no relocation record mentions this routine.
- Census method: the external call census uses the exhaustive
  executable-segment E8/E9 scan with objdump confirmation per
  candidate; both sites were confirmed as real calls to
  `0x5d51d10` by direct dumps. The routine's own control
  transfers are classified from one linear disassembly of the
  whole routine range (true instruction starts only).
- `verify.py` re-checks the digest, the manifest, excerpt
  regeneration byte-for-byte against a fresh objdump run, every
  excerpt instruction byte-for-byte against the raw binary, the FDE
  ranges, the empty relocation set, the census, the records, and
  the model tests. `census.py` reproduces the census;
  `export_excerpts.py` regenerates `main.txt`.
- Model: `tools/drain_until_quiet_51d10_115.py`, tested by
  `tests/test_drain_until_quiet_51d10_115.py`.

## Reproduce

Working directory: the repository root. Tools, all from this run:

- GNU objdump (GNU Binutils for Ubuntu) 2.42, invoked as
  `objdump -d --start-address=0x5d51d10 --stop-address=0x5d51d53 work/hl-node-115.bin`
- GNU readelf (GNU Binutils for Ubuntu) 2.42, invoked as
  `readelf --debug-dump=frames work/hl-node-115.bin` and
  `readelf -r work/hl-node-115.bin`
- Python 3.12.3 for `census.py`, `verify.py`,
  `export_excerpts.py`, and the model tests
- Input: `work/hl-node-115.bin`, SHA-256 as above; no execution of
  the target binary, no network, no side effects beyond writing
  the packet files listed in MANIFEST.sha256.

## Verification scope and next step

This packet's own checker (`verify.py`) and the model tests are
run before submission and must print ALL CHECKS PASSED and the
model check count. Repository-wide gates (`make verify`,
`make test`, `make catalogue-check`) are not claimed here: they
cover the whole tree, and their baseline on this VM is affected
by missing LFS material and the absence of cargo/rustc, which
are pre-existing environment limits, not results of this change.
The next question is: what does the worker at `0x606ccb0` do to
the object on each call -- which of the two pending fields it
clears, and in what order -- and what do the two caller
functions do around this drain?
