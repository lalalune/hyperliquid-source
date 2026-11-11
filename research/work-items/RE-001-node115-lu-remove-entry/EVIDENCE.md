# RE-001-node115-lu-remove-entry: <bounded question>

- Component ID: RE-001-node115-lu-remove-entry
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes, `artifacts/node/115/hl-node`)
- Source commit / reference commit: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390` (confirmed
  before analysis)
- Claim status: observation for all byte claims; inference
  for the queue net effect (under the neighbour invariant),
  the bitmap nonemptiness reading, and the caller role;
  unresolved for the caller FDE's own logic, the `0x200`
  writers, and the `+0x1080` anchor identity
- Scope included and excluded: included — the single FDE
  `0x63d8630..0x63d8790` end to end (entry, queue unlink,
  size dispatch, probe tail), its census, and its caller
  site (cited only). Excluded — the caller FDE's own logic,
  the size mapper, the class remove, the entry probe, and
  the tail-jump target `0x63d84e0` (all cited only)

## Reproduce

Worktree `~/workspace/hl-wt-calls242-115`, branch
`codex/re-004-calls242-115`, from upstream main `05bc2de30`.
Static analysis only; the binary was never executed.

- `sha256sum artifacts/node/115/hl-node` →
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- `readelf --debug-dump=frames-interp
  artifacts/node/115/hl-node` → FDE
  `pc=0x63d8630..0x63d8790` (352 bytes)
- `objdump -d --start-address=0x63d8630
  --stop-address=0x63d8790 artifacts/node/115/hl-node` →
  full FDE disassembly (see exhibits; `re_entry`,
  `re_queue`, `re_anchor`, `re_200`, `re_size`, `re_tail`)
- Coordinate system: `.text` file offset = VA − 0x1000
  (verified against program headers: PT_LOAD
  off=0x1418300 ↔ vaddr=0x1419300); `.rodata` = VA as-is;
  `.rela.dyn` addends used for the GOT census (60,723
  entries)
- Tool versions: `objdump`/`readelf` from system binutils,
  `python3` stdlib only for the verifier and census scans

## Evidence

- FDE bounds confirmed by `.eh_frame`, not by scanning for
  `endbr64`: the entry is `push %r14` (no `endbr64`), the
  previous FDE ends at `0x63d8622` (14 bytes of `int3`
  padding before this FDE), the next FDE (#238's handoff)
  starts at `0x63d8790` with no gap.
- Entry bytes `41 56 41 55 41 54 55 48 89 fd 53 48 8b 46 68
  48 89 f3 c6 46 12 00` (pushes, arg saves, `[block+0x68]`
  load, `[block+0x12] := 0`).
- Queue splice bytes (exhibit `re_queue`) and anchor block
  bytes (exhibit `re_anchor` plus key-byte-checked
  `0x63d8784..0x63d8790`: `4c 89 9f 80 10 00 00 e9 c8 fe
  ff ff`, anchor `:= [block+0x28]`, jump back to splice).
- Size computation bytes (exhibit `re_size`) match #238's
  scheme instruction for instruction, including the
  `0x7000000000000000` overflow threshold and the
  `0xc70`/`0xc7`/`0xc7` overflow stub (key-byte-checked at
  `0x63d8770..0x63d8784`).
- Tail bytes (exhibit `re_tail`): remove call rel32 at
  `0x63d870f` → `0x63b9d10`, probe call rel32 at
  `0x63d8717` → `0x63b9680`, `test %al,%al` at `0x63d871c`,
  bitmap clear (`rol` of `~1`, `and` at `0x63d8735`) at
  `first-arg+0x400`.
- Census: raw `.text` scans for `E8`/`E9` rel32 and
  rip-relative `LEA` to `0x63d8630`, each candidate
  confirmed by per-site objdump; `.rela.dyn` addend scan
  (60,723 entries). Result: 1 E8 (`0x63d9000`), 0 E9,
  0 LEA, 0 GOT.
- Caller site context (cited only): FDE
  `0x63d8e70..0x63d906b`, `mov %rbx,%rsi; mov %rbp,%rdi;
  call 0x63d8630; cmpb $0x0,0x13(%rbx); je ...; jmp
  0x63d84e0` on nonzero.
- Disjointness: 912 exhibit ranges from the merged tree's
  `records.json` files plus the #235–#241 worktree records
  (both dict- and list-shaped records handled) checked
  against `0x63d8630..0x63d8790`; 0 overlaps.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is
claimed here; this packet is evidence only (disassembly,
exhibits, verifier, unit tests). No independent
implementation path, Cargo graph, or build comparison is
asserted.

## Results and limitations

- `tools/node115_lu_remove_entry.py`: exit 0 (SHA/size,
  exhibit bytes, strict counts, FDE bounds, three `ret`
  sites, three call rel32s, key bytes, jump targets
  internal, full census, neighbour disjointness, MANIFEST
  coverage 17 entries).
- `tests/test_node115_lu_remove_entry.py`: 10/10 pass
  (standalone).
- `make verify`: exit 0 (559 manifests; entry tally
  reported in the PR body).
- `make catalogue-check`: fails on the new base with
  `Stale catalogue: README.md` — identically on a pristine
  `05bc2de30` checkout, so this is pre-existing upstream
  staleness from the merge wave, not a packet regression.
- Full `make test`: not attempted on the new base (584
  files; a full run takes hours and was already shown in
  #234 to be liable to VM-restart termination). This
  packet's own file passes 10/10 standalone.
- Limitations: the queue net effect (unlink + self-link)
  is stated under the neighbour invariant from #238's
  insert; no membership test exists in this FDE, so a
  non-queued block with `[block+0x68] == 0` would be
  unlinked unconditionally. The bitmap nonemptiness
  reading, the caller FDE's role, the `0x200` writers,
  and the `+0x1080` anchor identity are unresolved.
- Next question (#243): decode the caller FDE
  `0x63d8e70..0x63d906b` end to end — what it does with
  the (first-arg, block) pair before and after calling
  this removal entry, and what the `[block+0x13]`-gated
  tail jump to `0x63d84e0` does.
