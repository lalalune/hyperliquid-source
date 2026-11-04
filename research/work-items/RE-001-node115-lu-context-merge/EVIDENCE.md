# RE-001-node115-lu-context-merge: lu context merge

- Component ID: RE-001-node115-lu-context-merge
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  105,896,032 bytes,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `05bc2de30` (confirmed
  by fetch before analysis)
- Claim status: observation (bytes, counts, census) / inference (the
  "merge" reading of the add, the caller-tail pattern) / unresolved (see
  README)
- Scope included and excluded: included — FDE `0x63d8b20..0x63d8e67`
  end to end, its census, and the two caller FDEs' call sites and tail
  patterns (cited only, no caller bytes claimed). Excluded — the caller
  FDEs' remaining bookkeeping, the next FDE `0x63d8e70..0x63d906b`,
  and any runtime behaviour (static analysis only).

## Reproduce

Worktree `~/workspace/hl-wt-calls249-115`, branch
`codex/re-004-calls249-115`, base `05bc2de30`. Static disassembly with
system objdump on the target ELF; no execution, no side effects.

- `objdump -d --start-address=0x63d8b20 --stop-address=0x63d8e67
  artifacts/node/115/hl-node` reproduces the FDE disassembly.
- `objdump --dwarf=frames artifacts/node/115/hl-node` confirms
  `pc=0x63d8b20..0x63d8e67`.
- `python3 tools/node115_lu_context_merge.py` — static verifier, exit 0.
- `python3 -m unittest tests.test_node115_lu_context_merge` — 10/10.

## Evidence

Coordinate system: `.text` file offset = VA − 0x1000 (verified against
program headers: PT_LOAD off `0x1418300` ↔ vaddr `0x1419300`).
`.rodata` = VA as-is; not used here. `.rela.dyn` addends used for the
GOT census (RELATIVE slots are zero-filled in the file).

Raw disassembly: the FDE is 839 bytes, `endbr64` entry, one `ret`
(`0x63d8e66`), no internal calls, one internal jump (loop-back `jne
0x63d8be0`). Scalar sequence: 12 qword loads from `src + 0xc00..0xc58`
added into `dst + 0xc00..0xc58`. Loop: 8 iterations × 384 bytes
(`0x180` stride, exit at `src + 0xc00`), 24 16-byte pairs per chunk,
each stored exactly once, each with matching src/dst loads and one
`paddq`. Exhibits (`mg_entry`, `mg_scalar`, `mg_loop`, `mg_exit`)
total 333 bytes / 51 strict instructions; the remaining loop body is
covered by the verifier's whole-loop checks, not exhibited.

Callers/callees: census to `0x63d8b20` is E8 = 2 (`0x63b9190` in FDE
`0x63b9180..0x63b91d2`, `0x63b9272` in FDE `0x63b91e0..0x63b930c`,
both rel32-confirmed), E9 = 0, rip-relative LEA = 0, `.rela.dyn`
addends = 0 of 60,723. Caller A passes its own `(dst, src)` through
and adds `src + 0xc60`/`+0xc70` into `dst + 0xc60`/`+0xc70` after the
call. Caller B passes `(dst = third arg, src = object + 0x560)` and
adds `object + 0x1628`/`+0x1638` into `dst + 0xc60`/`+0xc70` after
the call. Caller bytes are cited only, never claimed.

Source mapping evidence: none — this packet is pure binary evidence;
no source file is claimed to implement this function.

ABI/layout observations: `rdi` = dst, `rsi` = src (SysV, first two
args). No stack use. The merged span `+0x0..+0xc60` covers the
reset's helper region, the global triple, and the `+0x420`-based
counter region through `+0xc60`, but not the slot-pointer table
(`+0x1088`), bitmap (`+0x1488`), or anchor (`+0x1498`).

## Implementation and comparison

Not yet implemented/measured — this packet is evidence only; no Rust
reconstruction is claimed here.

## Results and limitations

- Verifier: exit 0, all checks passed (4 excerpts, 333 bytes,
  51 strict, census 2 E8 sites, MANIFEST 13 entries).
- Unit tests: 10/10 pass, including a tamper control that flips
  `mg_entry.hex` and fails verification.
- `make verify`: exit 0 (559 manifests, 7167 entries).
- `make catalogue-check`: exit 2, `Stale catalogue: README.md` —
  pre-existing on a pristine `05bc2de30` checkout (verified for #242;
  base unchanged since), not a packet regression.
- Full `make test`: not attempted (584 files on the new base;
  hours-long, VM-restart liable per #234). The parent task's
  no-full-`make test` rule outranks the worktree `AGENTS.md` line;
  the deviation is disclosed in the README, as in #245–#248.
- Limitations: caller FDEs not decoded end to end; the domain roles
  of the merged objects and the reason for the caller-side 32-byte
  tail are unresolved; `.bss` contents are runtime-filled and not
  readable from the file — nothing here depends on them.
