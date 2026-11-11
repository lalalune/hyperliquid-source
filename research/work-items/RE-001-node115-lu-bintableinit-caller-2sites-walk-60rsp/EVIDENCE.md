# RE-001-node115-lu-bintableinit-caller-2sites-walk-60rsp: bin_table_init caller FDE 0x6361320..0x63620da

- Component ID: RE-001 (node-115 lookup, bin_table_init caller family)
- Target release and full SHA-256: node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes, `artifacts/node/115/hl-node`
- Source commit / reference commit: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation (disassembly + byte census; static analysis only, binary never executed)
- Scope included and excluded: included — the full FDE 0x6361320..0x63620da, its two bin_table_init sites, four lu-miss fallbacks, phase-1 context walk, drain sweep, stack-temp walk scans, single tail-jump exit. Excluded — bin_table_init body (#262), lu-miss handler body (#215), tail-jump target body, drain callback bodies, runtime values of any .bss byte.

## Reproduce

Worktree `~/workspace/hl-wt-calls289-115` (branch `codex/re-004-calls289-115`, HEAD `05bc2de30`). Static reads only:

- `objdump -d --start-address=0x6361320 --stop-address=0x63620da artifacts/node/115/hl-node` (targeted window only; no full-.text dump)
- `python3 tools/node115_lu_bintableinit_caller_walk_60rsp_2sites.py` — static verifier, exit 0, 63 checks
- `python3 tests/test_node115_lu_bintableinit_caller_walk_60rsp_2sites.py` — unit tests, exit 0, 17 checks (tamper controls first)
- `make verify` — exit 0 (559 evidence-packet manifests, 7159 entries = base 7154 + this packet's 5 MANIFEST entries)
- `make catalogue-check` — exit 2, pre-existing `Stale catalogue: README.md` on the new base (also on a pristine checkout; not a packet regression)
- Full `make test` is NOT run: 584 test files on the new base take hours and risk a VM-restart kill mid-run; no full-suite tally is claimed. This deviation from the repository's stated gate is declared here rather than hidden.

## Evidence

Coordinates are virtual addresses (VA); .text file offset = VA − 0x1000. FDE bounds from `.eh_frame` (PC-relative sdata4, fixed 4-byte range fields, not ULEB; CIE pointer relative to the CIE_id field, rec+4, not rec), not from endbr64 scanning. Previous FDE `0x63612b0..0x636131a` (gap 6 bytes, all `0xcc`); next FDE `0x63620e0..0x6362130` (padding 6 bytes, all `0xcc`).

Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0x1f8,%rsp`, canary at `0x1e8(%rsp)`, one canary check at `0x6361750..0x6361761` (`sub %fs:0x28,%rax`, `jne` to the `__stack_chk_fail` call at `0x6361c74`).

Entry: rsi = owner struct (kept in r15), rdi = context (kept in rbx, saved at `0x38(%rsp)`), key = `0x8(%rbp)` where rbp = `0x2920(%r15)` — the +0x8 field of the struct at entry-rsi's +0x2920 field. Mutexes: rsi+0x2968 (kept in r13) and rsi+0x2928 (saved at `0x8(%rsp)`). Every trylock failure goes through the lock-wait helper `0x63bf680` and retries (7 trylock / 7 unlock / 7 wait-helper calls).

The FDE has three parts. (1) A phase-1 walk on the context+0x1b0 table (no bin_table_init call): top index `(key >> 0x1a) & 0xf0`, high bits `key & 0xffffffffc0000000`, second level `(key >> 0x9) & 0x1ffff8 + table + 0x8`, node resolution through the `0x6727a00` table indexed by `(value >> 0x30)`, an ordinary (returning) call to `0x63bd6c0` at `0x636143f`, and two scan chains over context fields `0x2b0` (insert) then `0x2c0..0x320` (7 scan slots) with move-to-front at `0x63619a3` / `0x6361c91` and lu-miss fallbacks at `0x6361de8` (rejoin `0x6361422`) and `0x6361edc` (rejoin `0x6361947`). (2) A drain sweep over a 360-entry table at `0x6711b40` (entries at +0x14 step 0x28 to +0x5b4, parallel u32 array at `0x6511780` step 4): each entry's count drives an inner loop over 0xe0-stride records from base r15 + [u32], with per-record trylock/wait-retry, counter updates, callback `0x63c0340` on 0xc0 chain heads and 0xd8 list nodes, `0x63ac480` on the 0xc8 chain, a doubly-linked-list splice at `0x6361789`, and fields 0xc0/0xd8/0x88/0xb0 cleared. (3) A stack-temp walk on a table at `lea 0x60(%rsp)` with the packet's two bin_table_init sites (both rdi = the stack temp), top index `(key >> 0x1e) & 0xf` with slot stride 16, second level `(key >> 0x9) & 0x1ffff8 + slot + 0x8`, node resolution through `0x6727a00`, 8-slot scans at table+0x100 (stack `0x160..0x1d0` step 0x10) with move-to-front, and lu-miss fallbacks at `0x636201d` (rejoin `0x6361a53`) and `0x63620d0` (rejoin `0x6361c31`).

Census from the objdump exhibit (strict mnemonic lines: address + bytes field + tab + lowercase-start mnemonic; byte-continuation lines excluded): 737 strict lines, 42 calls (2 bin_table_init + 4 lu-miss + 7 trylock + 7 unlock + 7 wait-helper + 2 `0x63bd6c0` + 3 `0x63c0340` + 2 `0x63ac480` + 3 `0x6360610` + 2 `0x63be4d0` + 2 `0x63c3330` + 1 `__stack_chk_fail`), 0 ret, 0 bsr, 0 lock sub. Raw 0xe8 census: total 108, tiers 10x1, 8x1, 6x2, 5x1, 4x8, 2x12, 1x17; this FDE holds 2 raw sites (raw is an upper bound; site counts come from objdump mnemonics). `.rela.dyn`: 60,723 total, 59,534 RELATIVE; `.rela.plt`: 278 entries, counted separately.

Exits: no ret. One tail-jump exit at `0x6361784` to `0x63bffe0`, after a full epilogue (`add $0x1f8,%rsp` + pops) and the canary check. No other jump leaves the window (verified by program). Exit-ness is per-FDE: `0x63bd6c0` is an ordinary returning call here, although it was a tail-jump exit in packet #288's FDE.

## Implementation and comparison

Not yet implemented/measured. This packet is evidence only: a static verifier (`tools/node115_lu_bintableinit_caller_walk_60rsp_2sites.py`, byte reads only, never executes the binary) and unit tests with tamper controls (hex flip, strict-count change, call-site change, injected overlap — each confirmed to fail the temp-copy verifier; clean temp copy confirmed to pass).

## Results and limitations

- Verifier: exit 0, 63 checks pass (binary size + SHA-256, `.eh_frame` bounds, gap/padding int3 bytes, exhibit bytes, strict recount 737, call census 42 total / 2 bin_table_init / 4 lu-miss / 0 ret, bsr 0, lock-sub 0, branch shapes at both sites, canary checks, records consistency, `.rela.dyn` census, disjointness, slug check, raw-e8 census and ranking, MANIFEST digests).
- Unit tests: exit 0, 17 checks pass.
- `make verify`: exit 0 (559 manifests, 7159 entries). `make catalogue-check`: exit 2, pre-existing failure, not a packet regression.
- Disjointness: NONE over prior ranges (range-only collector over the merged tree plus all prior `hl-wt-calls*` worktree records; cited-only subtrees, enclosing-fde annotations, next-caller pointers, scan descriptors, and cfg edges never collected; decimal-integer start/end forms accepted, 0 records skipped).
- Limitations: drain callback bodies, tail-jump target body, and bin_table_init / lu-miss handler bodies are not decoded here; .bss values are never claimed (mechanism only); the drain sweep's purpose is described from its field-clearing + callback pattern, not from runtime observation.
