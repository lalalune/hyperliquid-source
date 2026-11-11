# RE-001: node #115 refcount increment 0x5f12a00

## Bounded question

The merged drain-driver packet (RE-001-drain-driver-115) mapped
the copy-on-write prepare at 0x5f13f90 end to end, but left two
of its helpers by contract only: "The field-by-field contents
moved by 0x5f12840 and established by 0x5f12a00 are unknown; both
are by contract only." What does the callee at 0x5f12a00 --
called by the prepare on the fresh object immediately before the
tail jump into the release -- actually do to that object, and
who else calls it?

## Answer, pinned to the target

The routine (FDE `0x5f12a00..0x5f12a09`, 9 bytes, CIE 0, no
LSDA) is three instructions:

```
endbr64
addl $0x1, 0x40(%rdi)
ret
```

It takes one argument, an object pointer in `rdi`, and its
entire observable effect is a single read-modify-write: the
unsigned 32-bit dword at object `+0x40` is incremented by one,
wrapping modulo 2^32. In particular:

- It establishes no field contents. In the prepare sequence the
  only state change this call makes to the fresh object is the
  `+0x40` increment; whatever the move helper 0x5f12840 copied
  into the other fields is neither read nor modified here.
- The increment is a plain `addl` with no `lock` prefix, so the
  read-modify-write is not atomic, and it neither saturates nor
  traps: a count of 0xffffffff wraps to 0.
- It reads and writes exactly one field, and nothing else:

| offset | width | role |
| ------ | ----- | ---- |
| `+0x40` | 4 bytes | unsigned reference count; read and stored back incremented by one |

- It makes no calls, takes no branch, has no tail jump and no
  landing pad, pushes nothing on the stack, has no stack
  canary and no rip-relative reference. It writes no register:
  only the flags are set, by the `addl`, per its result; `rax`
  and every other register are preserved, and all three census
  callers treat the routine as returning void.

The `+0x40` dword is the shared reference count of the inner
object: the merged drain-driver packet pinned the matching
release at 0x5f13ea0, whose first step decrements the same dword
and runs its destroy path only when the result reaches zero,
and the prepare's sole-owner fast path returns exactly when the
old object's count is 1. So 0x5f12a00 is the retain primitive of
that pair -- the increment half, shared by every caller that
takes a new reference -- and this packet closes the drain-driver
packet's by-contract use of it. The move helper 0x5f12840
remains by contract only; it is a separate, larger item and is
not claimed here.

## Consumers (site-only)

The census finds exactly three direct call sites, no tail
jumps, no stored qwords and no RELATIVE addends:

- `0x5f13fd6`, inside the copy-on-write prepare
  `0x5f13f90..0x5f13ff5` (mapped by RE-001-drain-driver-115).
  `rdi` is the fresh 0x50-byte object; the call runs after
  `[outer + 0x08]` has been stored with the new pointer and
  immediately before the tail jump into the release 0x5f13ea0
  on the old object.
- `0x5d8bcb8`, inside caller `0x5d8bc90..0x5d8bcd2`. The
  argument setup is visible immediately before the call: `rdi`
  is reloaded from the caller object's `+0x10` field
  (`mov 0x10(%rdi), %rdi` at 0x5d8bcb0). Caller semantics
  beyond the site, the FDE range and that load are not
  claimed.
- `0x5d95ad5`, inside caller `0x5d954b0..0x5d96890`. Only the
  site and FDE range are claimed; the argument setup is
  earlier in this large caller and was not read.

## NOT claimed

What the reference count counts (what ownership means to the
callers); what the move helper 0x5f12840 copies into the fresh
object before this call runs in the prepare; what any caller
does after the increment; behaviour on a null object pointer
(the `addl` dereferences `rdi + 0x40` unconditionally, so a null
pointer faults at address 0x40 -- stated openly, and the model
does not accept a count read from a null object); behaviour
under concurrent access (the increment is not atomic, and
whether callers serialise it is a caller question); the meaning
of the neighbouring routines at 0x5f12a10 and 0x5f12a20 (two
small getters) or of the larger window at 0x5f12a30.

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole routine, verbatim, produced by
  `objdump -d --start-address=0x5f12a00 --stop-address=0x5f12a09 work/hl-node-115.bin`.
  Instruction-level detail lives only in that excerpt text,
  never as a per-instruction list in records.json. The opening
  `endbr64` (bytes `f3 0f 1e fa`) is a genuine instruction
  present in the target binary, not a placeholder. The bytes
  after the FDE range (0x5f12a09..0x5f12a10) are int3 padding,
  not a landing-pad block.
- `records.json`: semantic records only (the single
  unconditional effect, the read/write field, the census, the
  consumers, the closed unknown).
- `frames.txt`: FDE lines for the routine and its three caller
  functions. `callers.tsv`: the three direct call sites with
  their smallest enclosing caller FDE ranges.
  `relocations.txt` is empty: no relocation record mentions
  this routine.
- Census method: the external call census uses the exhaustive
  executable-segment E8/E9 scan with objdump confirmation per
  candidate; all three sites were confirmed as real
  `call 0x5f12a00` instructions by direct dumps. The routine's
  own control transfers are classified from one linear
  disassembly of the whole routine range (true instruction
  starts only): there are none.
- `verify.py` re-checks the digest, the manifest, excerpt
  regeneration byte-for-byte against a fresh objdump run, every
  excerpt instruction byte-for-byte against the raw binary, the
  FDE ranges, the empty relocation set, the census, the
  records, and the model tests. `census.py` reproduces the
  census; `export_excerpts.py` regenerates `main.txt`.
- Model: `tools/refcount_increment_12a00_115.py`, tested by
  `tests/test_refcount_increment_12a00_115.py` (19 checks,
  including both wrap boundaries).
- Differential: `differential.py` runs the real 9 bytes under
  Unicorn against the model on 704 cases (structured boundary
  counts plus randomised object images and register fills),
  comparing the whole 4 KiB object page byte for byte and every
  general-purpose register the routine must preserve: 0
  mismatches.

## Reproduce

Working directory: the repository root. Tools, all from this
run:

- GNU objdump (GNU Binutils for Ubuntu) 2.42, invoked as
  `objdump -d --start-address=0x5f12a00 --stop-address=0x5f12a09 work/hl-node-115.bin`
- GNU readelf (GNU Binutils for Ubuntu) 2.42, invoked as
  `readelf --debug-dump=frames work/hl-node-115.bin` and
  `readelf -r work/hl-node-115.bin`
- Python 3.12.3 for `census.py`, `verify.py`,
  `export_excerpts.py`, and the model tests; the Unicorn
  differential additionally needs the `unicorn` package
  (2.1.4 used here).
- Input: `work/hl-node-115.bin`, SHA-256 as above; no
  execution of the target binary (the differential emulates
  the 9 routine bytes only), no network, no side effects
  beyond writing the packet files listed in MANIFEST.sha256.

## Verification scope and next step

This packet's own checker (`verify.py`), the model tests and
the Unicorn differential are run before submission and must
print ALL CHECKS PASSED, the model check count and
DIFFERENTIAL PASSED. Repository-wide gates (`make verify`,
`make test`, `make catalogue-check`) are run and reported
separately with the change; their full-tree baseline on this
VM is affected by submodule state and the absence of
cargo/rustc, which are pre-existing environment limits, not
results of this change. The next question is the remaining
by-contract helper of the same prepare: what the move helper
0x5f12840 copies, field by field, from the old inner object
(and its `outer + 0x18` argument) into the fresh one.
