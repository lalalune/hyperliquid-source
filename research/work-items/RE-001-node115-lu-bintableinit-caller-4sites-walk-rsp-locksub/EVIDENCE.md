# RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp-locksub: bin_table_init caller FDE 0x63d3080..0x63d379c

- Component ID: lu bin_table_init caller chain (node-115 lookup)
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390 (fetch-confirmed at build time)
- Claim status: observation (disassembly + byte census); walk-variant attribution for individual lu-miss sites is partial (arguments and rejoins listed; full variant mapping unresolved)
- Scope included and excluded: included = the single FDE window 0x63d3080..0x63d379c and its call sites. Excluded = callee internals, runtime values, remaining 4-raw FDEs, static leaves.

## Reproduce

Working directory: worktree at upstream main 05bc2de30. Binary never executed.

- `objdump -d --start-address=0x63d3080 --stop-address=0x63d379c artifacts/node/115/hl-node` (targeted dump only; no full-.text dump)
- `python3 tools/node115_lu_bintableinit_caller_walk_rsp_locksub_4sites.py` (static verifier, byte reads only)
- `python3 tests/test_node115_lu_bintableinit_caller_walk_rsp_locksub_4sites.py` (tamper controls first, then clean temp copy + regeneration)
- `make verify`, `make catalogue-check` (see Results)
- Strict-line pattern: `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]` (lowercase-start mnemonic; byte-continuation lines excluded)

## Evidence

- Window from `.eh_frame` (PC-relative sdata4, fixed 4-byte range fields, CIE pointer rec+4), confirmed by readelf: FDE 0x63d3080..0x63d379c, 1820 bytes. Previous FDE 0x63d2a80..0x63d3071 (gap 15 bytes 0xcc); next FDE 0x63d37a0..0x63d37a9 (padding 4 bytes 0xcc).
- Coordinates: .text VA - 0x1000 = file offset. .bss tables referenced by address only (0x6727a00, 0x65096c0, 0x6511a00); no values claimed.
- Census: 379 strict lines, 9 calls (4 bin_table_init at 0x63d31d6, 0x63d3236, 0x63d329e, 0x63d3526; 4 lu-miss at 0x63d35c1, 0x63d3659, 0x63d36e9, 0x63d3792; 1 __stack_chk_fail at 0x63d376a), 0 ret, 0 bsr, 1 lock sub (0x63d315c).
- Frame: sub $0x198,%rsp, canary 0x188(%rsp), fs:0x28, three canary checks (0x63d31ad, 0x63d334f, 0x63d3391) to __stack_chk_fail.
- Exits: three canary-checked tail-jumps (0x63d31ca -> 0x63637f0, 0x63d3375 -> 0x63bd6c0, 0x63d33b5 -> 0x6363260); no ret.
- Raw files beside this record: bintableinit_caller_walk_rsp_locksub_4sites.hex (raw binary bytes, 1820) and .objdump.txt (379 strict lines).
- Analysis complete for the window; no timeout, no range limit.

## Implementation and comparison

Not yet implemented/measured. No Rust reconstruction is claimed from this packet; the packet is evidence only.

## Results and limitations

- Static verifier: exit 0. Unit tests: exit 0 (tamper controls first, all fail as required).
- `make verify`: exit 0. `make catalogue-check`: exit 2, pre-existing "Stale catalogue: README.md" on this base (also on a pristine checkout); not a packet regression.
- Full `make test` (584 files) not run by design (hours + VM-restart risk); no full-suite tally claimed.
- Disjointness: NONE over prior records (range-only collector; census/cited-only subtrees excluded; self excluded by exact window equality).
- Remaining unknown: per-scan mapping of all four lu-miss sites to distinct walk variants; callee internals; runtime values.
- Next question: packet #286 decodes 0x63d5940..0x63d605c (1820 bytes, 4 raw candidates).
