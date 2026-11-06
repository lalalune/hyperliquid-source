# RE-001-node115-lu-reregister: the node #115 lu re-register

- Component ID: RE-001-node115-lu-reregister
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  105,896,032 bytes,
  SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `05bc2de30`
  (confirmed by fetch before analysis)
- Claim status: observation for all exhibited bytes and stated stores;
  inference for the count/byte-total/remainder names of the slot and
  global triples; unresolved for the `0x63d88d0` callee's body and for
  the full caller-side establishment of `+0x11`/`+0x14`
- Scope included and excluded: included — the single FDE
  `0x63d9070..0x63d9337` end to end (entry, three arms, tail
  gates, list reconcile) and its 9 call sites by address.
  Excluded — the bodies of the size mapper (`0x63e8bf0`), the
  handoff (`0x63d8790`), the `0x63d88d0` callee, the class
  search (`0x63d9340`), the register (`0x63d94b0`), and the
  give-back drivers (all cited only, never re-claimed)

## Reproduce

Working directory: a worktree of upstream main `05bc2de30`.
Static analysis only; the binary was never executed.

- `python3 tools/node115_lu_reregister.py` — exit 0
- `python3 -m unittest tests.test_node115_lu_reregister` — 10/10
- `make verify` — exit 0 (see README for the tally)
- `make catalogue-check` — exit 2, `Stale catalogue: README.md`
  (pre-existing on a pristine `05bc2de30` checkout, verified
  for #242; base unchanged since)
- Full `make test` — not attempted (584 files on the new base;
  hours-long and VM-restart liable, per #234); the parent
  task's explicit rule outranks the worktree `AGENTS.md`
  full-suite line, as disclosed in #245 and here

Tool versions: GNU objdump 2.42, readelf 2.42, Python 3.12.3,
git-lfs 3.4.1 (restored from the workspace tarball extract
before worktree creation, as the VM image had dropped it).

## Evidence

Coordinate system: `.text` file offset = VA − 0x1000 (from the
program headers: PT_LOAD off `0x1418300` ↔ vaddr `0x1419300`);
`.data.rel.ro`/`.got` = VA − 0x2000; `.rodata` = VA as-is.
RELATIVE `.got` slots are zero-filled in the file, so the GOT
census uses `.rela.dyn` addends (60,723 entries, 0 equal to
`0x63d9070`).

Validated boundaries: FDE bounds from `.eh_frame`
(`pc=0x63d9070..0x63d9337`, 711 bytes; the section uses
PC-relative sdata4 FDE encoding, decoded directly rather than
assumed). `endbr64` entry; `int3` padding 5 bytes before
(`0x63d906b..0x63d9070`) and 9 bytes after
(`0x63d9337..0x63d9340`).

Raw disassembly: 6 exhibits beside this record (433 bytes,
102 strict instructions), plus key-byte checks for the zero
arm, the overflow stub, and the anchor block. Internal calls
(rel32-verified): size mapper `0x63e8bf0` (site `0x63d90a5`),
handoff `0x63d8790` (site `0x63d9232`), `0x63d88d0` (site
`0x63d9247`). Two `ret` sites (`0x63d91c1`, `0x63d92b6`).
All direct jump targets lie inside the FDE.

Callers: 9 direct `E8` sites, each objdump- and
rel32-confirmed (A `0x63b7b0e`, `0x63b7cb7`, `0x63b7da9`,
`0x63b7e6c`; B `0x63b8014`, a loop-head site; D `0x63b83ac`,
`0x63b8455`; C `0x63b8a43`, `0x63b8c95`, #232's, cited
only). No `E9` jump, no rip-relative `LEA` targets this FDE.

Key constants, byte-verified: the `0x200` arm's `.rodata`
vector at VA `0x450b10` is `(1, 512)` — the exact inverse of
give-back's `(-1, -512)` at `0x451800`. The overflow stub
uses `r11d = 0x2970 = 48*199 + 0x420`, index 199.

Analysis was complete over this FDE (all paths traced); the
callee bodies and the caller-side flag establishment beyond
the cited sites were not decoded here.

## Implementation and comparison

Not yet implemented/measured. No Rust reconstruction is
claimed from this packet; no build, comparison, or equivalence
result is implied by the passing self-derived checks.

## Results and limitations

Passing: static verifier exit 0, own unit tests 10/10,
`make verify` exit 0, MANIFEST 17 entries all matching.
Failing (pre-existing, not a packet regression):
`make catalogue-check` exit 2, `Stale catalogue: README.md`.

What remains unknown: the `0x63d88d0` callee's body; the
full establishment of `+0x11`/`+0x14` across all 9 caller
sites; the domain names of the slot/global triples; the
reader of `[block+0x23]` beyond this function's clear;
whether the `+0x14` desired-membership reading holds on
non-driver caller paths; `.bss` contents (runtime-filled,
not in the file; nothing here depends on them).

Next question (#247): decode the `+0x13`-gated callee FDE
`0x63d88d0..0x63d8a00` end to end — what it does with the
(first-arg, block) pair when `+0x13` is set, whether it
reads `+0x13` itself, and how it relates to the handoff and
the register.
