# RE-001-node115-lu-wait-callers: survey of the lu wait helper's other direct callers

- Component ID: RE-001-node115-lu-wait-callers
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`, confirmed by fetch before analysis
- Claim status: observation for the census, the 6 exhibits, and the 4 decoded caller patterns; inference for the "one layout" reading (4 cross-checked families, not all 474 sites); unresolved for the items listed in README.md
- Scope included and excluded: included — all 474 direct E8 sites grouped by FDE and classified by argument shape; 4 caller FDEs decoded in depth. Excluded — internals of the other 381 caller FDEs; provenance of mov-shape pointers; post-wait statistic reads; domain identity of any lock; runtime .bss values

## Reproduce

Working directory: the packet worktree (upstream main `05bc2de30`, local branch `codex/re-004-calls252-115`). Static analysis only; the node binary was never executed. Tools: system `objdump`, `readelf`, Python 3 (standard library plus the repo's own `tools/fde_extents.py` / `tools/elf_index.py` for `.eh_frame` parsing).

1. Confirm the binary: `sha256sum artifacts/node/115/hl-node` = the SHA-256 above; size 105,896,032.
2. Confirm FDE bounds: parse `.eh_frame` (PC-relative sdata4, CIE augmentation `zR`, encoding byte `0x1b`) — the four cited FDEs are `0x63cf9d0..0x63cff1b`, `0x6364280..0x6364342`, `0x63b5a40..0x63b5b3d`, `0x63ec7a0..0x63ec900`.
3. Reproduce the census: scan `.text` file offsets `0x1418300..0x63f0ba0` for `0xE8` bytes whose rel32 lands on `0x63bf680` (474 sites); repeat for `0xE9` (0 sites) and for REX+`8d` rip-relative LEA resolving to `0x63bf680` (0 sites). Coordinate conversion: `.text` file offset = VA - `0x1000` (re-derived from program headers: PT_LOAD file offset `0x1418300` ↔ vaddr `0x1419300`).
4. Reproduce the grouping: map each site to its enclosing FDE from step 2 (385 FDEs; distribution 1:348, 2:19, 3:9, 4:4, 5:1, 7:2, 8:1, 18:1).
5. Reproduce the shapes: disassemble each caller FDE with `objdump -d --start-address --stop-address`, strip objdump `#` comment suffixes, and walk back at most 40 instructions from each helper call to the nearest instruction writing `rdi`.
6. Run the packet verifier: `python3 tools/node115_lu_wait_callers.py` (exit 0) and the unit file `python3 -m unittest tests.test_node115_lu_wait_callers -v` (10/10).

## Evidence

Original addresses and coordinate system (VA/file offset): VAs as shown by objdump; `.text` file offset = VA - `0x1000`; `.data.rel.ro`/`.got` = VA - `0x2000`; `.rodata` = VA as-is. RELATIVE `.got` slots are zero-filled in the file; GOT census uses `.rela.dyn` addends (60,723 entries; 0 equal to `0x63bf680`).

Raw disassembly of the exhibits is preserved beside this record as `.hex` + `.objdump.txt` pairs; the verifier regenerates the objdump lines and compares them exactly (header line stripped, as it embeds the invoked path).

Callers/callees: the helper `0x63bf680` (cited only, decoded by packet #251) is the callee; `pthread_mutex_trylock@plt` (`0x63f17b0`) and `pthread_mutex_unlock@plt` (`0x63f0b70`) are the PLT callees in the decoded callers. Indirect calls: none in the exhibits.

ABI/layout observations: the wait helper's argument is a pointer in `rdi`; the decoded callers pass records embedded at `+0x18`, `+0x38`, `+0x40` (common case), `+0x28a8`, or as globals. In every decoded case the mutex is at record `+0x40` and the flag byte at record `+0x68`, verified by trylock/unlock target addresses and flag store addresses, not by assumption.

Analysis completeness: complete for the census (all 474 sites) and the argument-shape classification; limited to 4 FDEs for deep decoding, as stated. No execution, no timing, no runtime values are claimed.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is proposed by this packet; it is evidence only, for a future packet to use. No Cargo graph, no build comparison, no fixture identities are claimed.

## Results and limitations

Machine-readable metrics with explicit denominators: 474/474 direct E8 sites surveyed and grouped; 474/474 classified by argument shape; 4/385 caller FDEs decoded in depth; 6 exhibits, 122 bytes, 23 strict instructions; disjointness 0 overlaps over 962 unique prior claimed ranges.

What passed/failed: verifier exit 0; unit tests 10/10; `make verify` exit 0; `make catalogue-check` fails with pre-existing `Stale catalogue: README.md` on the new base (also on a pristine checkout), not a packet regression; full `make test` not attempted (584 files, hours-long, VM-restart risk — parent task rule).

What remains unknown: see README.md "Unresolved". No gate is requested beyond the packet's own checks; this packet does not claim full-scope completion of the wait-helper survey.

Next question (#253): trace the provenance of the register-passed and memory-loaded arguments, starting with the largest caller FDE (`0x63a5bf0..0x63a6470`, 18 helper sites) — deciding whether the `mov`-shape callers pass the same record type through, or a different one.
