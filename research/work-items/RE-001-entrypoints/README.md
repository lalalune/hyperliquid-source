# RE-001 follow-up: entrypoint membership and direct-call reach over the decoded FDE extents

- Component ID: foundation (cross-component function map)
- Target release and full SHA-256: node #94 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
  node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (separate target, reported apart)
- Base commit / reference commit: repository `1f8c67c` (after #2), can1357 submodule `999556f6e0a474b8312db96ec3149e1c44e97c23`
- Claim status: observation for every number; membership and reach are signals, not a call graph
- Scope included: `e_entry`, `DT_INIT`, `DT_INIT_ARRAY`/`DT_FINI_ARRAY` slot resolution through `R_X86_64_RELATIVE`, and byte-level
  rel32 `E8` target classification against the decoded extents and gaps. Excluded: CFG recovery, disassembly, symbol
  identity, component ownership, any equivalence claim.

Follow-up to #2 as requested in [the closing note on #5](https://github.com/lalalune/hyperliquid-source/pull/5#issuecomment-6521373038).
It keeps #2's decoder untouched and adds the two measurements that were unique to #5.

## Reproduce

```sh
./scripts/setup.sh
make verify test catalogue-check
make fde-index          # both nodes; summary carries entrypoints and E8 buckets
```

Host for this run: macOS 15 arm64, Python 3.9.6. `make` is not installed here, so each recipe command was run directly
(`python3 tools/fde_extents.py --release 94|115`). Static only: nothing is executed. The 6.3 MB extent TSVs stay in
`work/index/`; the non-padding gap TSVs and the summaries are kept here. Both summaries are byte-identical on a second
run. `readelf` and `llvm-objdump` are also absent on this host, so the binutils cross-checks other packets carry were not
run here; the `objdump` that is present was used once, by hand, to name the CRT stubs in the `_start` cluster.

The analysis is byte-based: every byte of every executable section is scanned for `0xe8`, the rel32 operand is added, and
the target is bucketed by the section that holds it. An `0xe8` inside an immediate is therefore also a candidate, and no
CFG is built. Sections without FDEs (`.plt`, `.init`, `.fini`) are a separate bucket so stub callers do not inflate the
gap reach.

## Evidence

Coordinates are linked VAs; the ELF is a PIE and no loader rebase is applied.

| | #94 | #115 |
| --- | ---: | ---: |
| `e_entry`, in `.text`, on an FDE start | `0x1343c80`, yes, yes | `0x1419300`, yes, yes |
| `DT_INIT` (`0x56600b0` / `0x63f0a00`), section, FDE start | `.init`, no | `.init`, no |
| `DT_INIT_ARRAY` slots / relative-relocated / on an FDE start | 168 / 168 / 167 | 168 / 168 / 167 |
| `DT_INIT_ARRAY` exception | `0x1343d60` | `0x14193e0` |
| `DT_FINI_ARRAY[0]` | `0x1343d20`, not a start | `0x14193a0`, not a start |
| E8 targets on an FDE start | 483,120 | 545,621 |
| E8 targets inside an FDE | 7,671 | 11,460 |
| E8 targets on a gap start / in a gap interior | 8 / 108 | 26 / 157 |
| E8 targets in a section without FDEs (`.plt`) | 106,111 | 112,107 |
| E8 targets outside any executable section | 102,044 | 131,078 |
| Distinct gaps reached | 82 (61,876 B) | 151 (62,868 B) |
| of those, non-padding | 3 (60,994 B) | 3 (61,393 B) |

The `_start` cluster resolves. `e_entry` is the first byte of `.text`; the 195 B (#94) / 202 B (#115) gap at `0x1343ca6` /
`0x1419326` begins 38 B after `_start` and holds, after 10 B of `cc`, the compiler-generated CRT stubs:
`deregister_tm_clones` (`0x1343cb0`), `register_tm_clones` (`0x1343ce0`), `__do_global_dtors_aux` (`0x1343d20`) and
`frame_dummy` (`0x1343d60`). #115 is the same layout at `0x1419330`, `0x1419360`, `0x14193a0`, `0x14193e0`.
`DT_FINI_ARRAY[0]` is `__do_global_dtors_aux`, the `DT_INIT_ARRAY` exception is
`frame_dummy`, and `0x1343cb0` is also the first E8 target in the gap. Neither of the first two stubs carries `endbr64`;
the last two do. The rest of `_start`'s body, the `__libc_start_main` argument setup, also has no FDE.

Gap taxonomy for the 134 (#94) / 133 (#115) non-padding gaps, 65,584 / 65,949 B:

- 3 gaps contain `endbr64` at all: the `_start` cluster above (its only `endbr64` at `frame_dummy`), `0x54a54dd`
  (60,675 B, first `endbr64` after 35 B of `cc`) and `0x5631543` (2,493 B, after 61 B); #115: `0x1419326`,
  `0x633a4d2` (61,070 B, after a multi-byte NOP and 430 B), `0x62e46c3` (2,493 B, after 61 B).
- 73 (#94) / 74 (#115) gaps are 16 B or shorter and hold no `endbr64`: alignment filler between neighbours.
- Only 4 gaps per node exceed 64 B. The reach concentrates: 116 (#94) / 183 (#115) targets touch 82 / 151 gaps, but only 3
  per node are non-padding, and 2 of those are the large assembly regions.

## Validation

| Check | Result |
| --- | --- |
| `make verify` (both commands run directly) | 8 SHA-256 OK, 3 signatures valid, 37 imports + pins verified |
| `tests/test_fde_extents.py` | 20 tests OK, including 3 new ones |
| `make catalogue-check` | OK |
| `make fde-index` twice | byte-identical summaries for both nodes |

New controls: a relocated `init_array` slot resolves through its addend; the same slot without the relocation reads the
zero in place and reports no FDE start; call targets are bucketed by the section that holds them, so a stub caller does
not inflate the gap reach. Full `make test` also runs 360 tests here; 16 of them fail on this host for a pre-existing
reason (no `readelf`/`llvm-objdump`), none of them in `test_fde_extents`.

## Limitations

An FDE extent is still not a validated boundary, and none of this is a function census. Reach proves a `call`-shaped byte
sequence points into a gap, not that the byte is a call or that the target is a function entry. The two 60 KB regions and
`0x5631543`/`0x62e46c3` are assembly without CFI; a validated entry set there needs disassembly and xref review, not this
scan. `DT_INIT` in `.init` and the `.plt` stubs carry no FDEs at all, so their counts are lower bounds. No gate changes:
RE-001 stays open and every component stays 0/4.

Next question: do `0x54a54dd` and `0x5631543` (#94) decode into self-contained routines whose entry is the `endbr64`, and
which of the 7,671 interior call targets are tail calls into the next FDE rather than mid-body?

All new code and docs are MIT and independently written.
