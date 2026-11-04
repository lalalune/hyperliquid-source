# RE-001-node115-lu-record-reset: bounded question

- Component ID: RE-001-node115-lu-record-reset
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `05bc2de30` (confirmed
  before analysis via fetch; worktree HEAD `05bc2de30`)
- Claim status: observation (bytes, rel32s, census); inference (the
  "reset sweep" reading of the caller pattern, flagged as such in the
  README); unresolved (redundancy reason, sweep trigger, other reset
  paths)
- Scope included and excluded: included — the whole work-function FDE
  `0x63bf7f0..0x63bf83d`, its census, the cited copy helper's
  semantics, the cited `.rodata` zero constant. Excluded — the
  caller FDE's internals (#253's exhibits), the wait helper's
  internals (#251), the sweep's own callers (next question #255).

## Reproduce

Working directory: the worktree at upstream main `05bc2de30`.
Binary path: `artifacts/node/115/hl-node`. Tools: system `objdump`
(x86-64), `readelf`, `python3`. No execution of the binary, no
network beyond the initial fetch, no side effects.

- FDE bounds: `.eh_frame` parse (CIE augmentation `zR`, FDE
  encoding `0x1b` = PC-relative sdata4; initial location = field
  address + signed 32-bit value). Cross-checked against the known
  FDEs `0x63bf680..0x63bf7ee` (#251), `0x63a5bf0..0x63a6470` (#253),
  `0x63b9180..0x63b91d2` and `0x63b91e0..0x63b930c` (#250).
- Disassembly: `objdump -d --start-address=0x63bf7f0
  --stop-address=0x63bf83d artifacts/node/115/hl-node`, with the
  function-header line dropped and leading spaces stripped (the
  stored `.objdump.txt` format).
- Coordinate system: `.text` file offset = VA − 0x1000 (verified
  against program headers: PT_LOAD off `0x1418300` ↔ vaddr
  `0x1419300`); `.rodata` = VA as-is (section VA `0x430400`,
  size `0x76e640`, so `0xb9e830` lies inside it).
- Census: raw `E8`/`E9` scan over `.text` file offsets
  `0x1418300..0x63f0ba0`, rel32-verified per site; rip-relative
  `LEA` scan (`48 8d`/`4c 8d` with modrm mod=00 r/m=101);
  `.rela.dyn` scan (file offset `0x6be8`, 24-byte entries,
  60,723 total).
- The static verifier (`tools/node115_lu_record_reset.py`) repeats
  every check above from the packet files alone and exits 0.

## Evidence

- FDE `0x63bf7f0..0x63bf83d`, 77 bytes. Entry bytes `f3 0f 1e fa`
  (`endbr64`). Single `ret` at `0x63bf83c` (`c3`). No jump
  instructions in the body (no `jmp`/`je`/`jne` mnemonics), so
  there are no internal jump targets to check.
- Padding: `cc cc` at `0x63bf7ee..0x63bf7f0` (2 bytes, `int3`)
  after the wait helper FDE; `cc cc cc` at
  `0x63bf83d..0x63bf840` (3 bytes, `int3`) before the next FDE
  at `0x63bf840` (cited only).
- Zero constant: `.rodata` qword at file offset `0xb9e830` reads
  `00 00 00 00 00 00 00 00`. The `lea` at `0x63bf7f9` computes
  `0x63bf800 + (-0x5820fd0) = 0xb9e830` (objdump confirms the
  target comment).
- Copy calls: site `0x63bf81e`, rel32 `0x3cd` → `0x63bfbf0`;
  site `0x63bf829`, rel32 `0x3c2` → `0x63bfbf0`. Copy helper FDE
  `0x63bfbf0..0x63bfbfb` (11 bytes): `mov (%rsi),%rax;
  mov %rax,(%rdi); ret` — a plain qword copy, cited only.
- Tag ignored: the only instructions before `lea 0x8(%rsi),%rdi`
  at `0x63bf800` are `endbr64`, `push %rbp`, `pxor %xmm0,%xmm0`,
  `lea 0xb9e830,%rbp` — none reads `%rdi`. The entry tag is
  therefore dead on arrival.
- Zeroed span: `movups` stores at `record+0x00`, `+0x10`, `+0x20`,
  `+0x30` cover bytes `+0x00..+0x40` exactly. The mutex at `+0x40`
  and the flag at `+0x68` are outside the span and never written
  by any instruction in the FDE.
- Census: 18 direct `E8` sites, all in FDE
  `0x63a5bf0..0x63a6470`; `E9` 0; rip-`LEA` 0; `.rela.dyn`
  addends 0 of 60,723.
- Exhibits: 4, 77 bytes total, 22 strict instructions; pairwise
  disjoint and jointly equal to the whole FDE (no gaps, no
  overlaps — verified by the verifier's range-union check).
- Disjointness inputs: merged-tree records plus all prior
  worktree records, deduplicated by real path, ranges
  deduplicated as a set, own slug excluded, census/cited-only
  metadata subtrees excluded (per #253's documented exclusion);
  0 overlaps.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is included in
this packet (evidence only, per the light style). No Cargo graph,
no build comparison, no execution.

## Results and limitations

- Passed: verifier exit 0, own unit tests 10/10, `make verify`
  exit 0 (559 manifests, 7167 entries), MANIFEST `sha256sum -c`
  all OK.
- Failed (pre-existing, not a packet regression):
  `make catalogue-check` exit 2, `Stale catalogue: README.md`,
  identical on a pristine `05bc2de30` checkout (finding from #242,
  base unchanged since).
- Not attempted: full `make test` (584 files on the new base;
  hours-long, VM-restart risk; parent rule outranks the worktree
  `AGENTS.md` gate, disclosed in README/body).
- Unknown: redundancy reason for the zero copies and last-tag
  store; sweep trigger; other reset paths. Next question (#255):
  who calls the sweep FDE `0x63a5bf0..0x63a6470`, and what
  triggers it?
