# RE-001-node115-lu-grant-callers: the grant-wake callers — no explicit grantor

- Component ID: RE-001-node115-lu-grant-callers (lu = base/src/lu.rs
  conversion family; the worked-example FDE's panic provenance names
  base/src/l1_map/entry.rs)
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  105,896,032 bytes,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main
  `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (node-115-only migration)
- Claim status: observation
- Scope included and excluded: see README.md (worked-example FDE
  `0x4fb52e0..0x4fb5435` end to end; the complete 66-site `esi` census;
  the complete 58-site `mov esi,0x1` census; panic provenance).
  Excluded: the flag helper `0x4dccf20` and completion helper
  `0x4da86a0` internals; the `esi = 1` callee internals; any runtime
  behavior.

## Reproduce

Exact commands, tool versions, options, input and output hashes, working
directory, platform, environment requirements, and any declared
execution/side effects.

Worktree base: upstream main `8fd8db6` (no move past it at scout time;
verified by `git fetch origin` + `git rev-parse origin/main` before
worktree creation). Binary: `artifacts/node/115/hl-node` (digest and
size above). `.text` file offset = VA − 0x1000; `.data.rel.ro`/`.got`
file offset = VA − 0x2000; `.rodata` file offset = VA. Tools: system
`objdump` (GNU, Intel syntax), `readelf`, Python 3 (stdlib only).
Working directory: the worktree root. No execution of the node binary
at any point; no side effects beyond the packet files, the verifier,
and the unit test.

```sh
objdump -d -M intel --start-address=0x4fb52e0 --stop-address=0x4fb5435 \
  artifacts/node/115/hl-node > research/work-items/RE-001-node115-lu-grant-callers/fde52e0.objdump.txt
readelf -r artifacts/node/115/hl-node
python3 tools/node115_lu_grant_callers.py
python3 -m unittest tests.test_node115_lu_grant_callers -v
make doctor && make verify && make catalogue-check && make test
```

FDE body bytes: 341, SHA-256
`11531754ab1dd77cf9c351f947de43c62bf03221a5a328cb5ab8b23349e96705`.
Body proper to `ret` at `0x4fb53ba`: 219 bytes, 59 instructions.
Tail: 122 bytes, 32 instructions. Total: 91 instructions, 0 `nop`.

## Evidence

Original addresses and coordinate system (VA/file offset), validated
boundaries, raw disassembly/data, callers/callees/indirect calls, source
mapping evidence, ABI/layout/rounding/overflow observations. Keep raw
files beside this record. State whether analysis was complete, timed
out or limited to a range.

- Boundaries: FDE `0x4fb52e0..0x4fb5435` from `.eh_frame` (CIE
  `0039672c`, `zPLR`); single `ret` opcode `c3` at `0x4fb53ba`;
  body/tail split at `ret + 1`. Raw disassembly:
  `fde52e0.objdump.txt`; raw bytes: `fde52e0.hex`.
- Gate: acquire `lock cmpxchg [rsi+0x10],rcx` (`f0480fb14e10`) at
  `0x4fb52f7` (`rcx = 8`, `rax = 0`); timed-wait GOT call `ff15` at
  `0x4fb53c9` via `0x64e0ff0` -> `0x5bb2440` with `edx = 0x3b9aca00`;
  release `lock cmpxchg [rbx],rcx` (`f0480fb10b`) at `0x4fb53aa`
  (normal) and `0x4fb5413` (unwind), both `rcx = 0`, `rax = 8`.
- Grant sites in the FDE: `jmp` (`ff25`) at `0x4fb53e8` via
  `0x64e1000`, `xor esi,esi` (`31f6`) at `0x4fb53dd`; `call` (`ff15`)
  at `0x4fb5427` via `0x64e1000`, `xor` at `0x4fb5425`.
- Census: 0 direct `E8` callers of `0x5bb35f0`; 66 GOT-indirect sites
  (65 `ff15` call, 1 `ff25` jmp) via slot `0x64e1000` across 26 FDEs
  (identical sets from an every-position byte scan over `.text` and
  the objdump-boundary census; the 26 FDEs match #193's census
  exactly). Per-site kind, FDE, `xor` address, `rdi` writer address,
  writer bytes, and writer class are pinned in `records.json`
  (`sites`, 66 entries).
- `esi` result: 65 call sites with `31f6` at `site - 2`; 1 jmp site
  with `31f6` at `0x4fb53dd`; 0 sites with `esi = 1`. Dominance: a
  full-`.text` objdump direct-jump-target scan contains no grant site.
- `mov esi,0x1` result: 58 sites inside the 26 FDE ranges (identical
  sets from an every-position byte scan for `be 01 00 00 00` and
  objdump-boundary next-call resolution); next-call GOT targets 55x
  `0x64df9f0` -> `0x5c87d50`, 1x `0x64e0ff8` -> `0x1557260`, 1x
  `0x64e1070` -> `0x155a430`, 1x `0x64e1080` -> `0x1559e80`, 0x
  `0x64e1000`. Per-site records pinned in `records.json`
  (`mov_esi_1_census.sites`, 58 entries).
- Panic: wrapper `0x64df770` at `0x4fb53ee`; message `Out of bounds
  access` (20 bytes) at `0x9171a2`; Location struct at `0x649cc08`
  with `len = 24`, `line = 64`, `col = 17` inline and the file string
  `base/src/l1_map/entry.rs` at `0x4402cd` (relocation addend; the
  file's pointer field reads 0, the addend names the string).
- Payload mechanics: flag helper `0x4dccf20` (direct `E8` at
  `0x4fb530f`, out-flag `[rsp+0x8]`, `jne 0x4fb53a3` on flag != 1);
  24-byte-stride entry access with capacity from `[rcx+0x18]`;
  saturating decrement via `cmp`/`adc` (`[entry] = count - 1` for
  `count >= 1`, else 0); completion helper `0x4da86a0` (direct `E8`
  at `0x4fb539e`) when the original count is `<= 1`.
- Analysis was complete for the claimed FDE and both censuses. The
  flag/completion helper internals and the `esi = 1` callee internals
  were not decoded (out of scope, stated in README.md).

## Implementation and comparison

Independent Rust path, Cargo.lock, compiler/linker/build flags,
two-build result, raw and normalized comparisons and masks,
helper/data/relocation closure, fixture identities, boundary/error
cases and corruption controls. Use "not yet implemented/measured"
where applicable, rather than implied success.

Not yet implemented/measured: no Rust reconstruction is included in
this packet. The deliverable is the static evidence (FDE decode +
censuses) with a byte-level verifier and corruption controls
(verifier opcode spot checks; unit tests flip a grant-site `xor`,
a release `cmpxchg`, the `ret`, the FDE bytes, and the packet files,
and each flip is rejected with the expected message).

## Results and limitations

Machine-readable metrics with explicit denominators, what passed/failed,
what remains unknown, and why any requested progress gate covers its
entire scope. If requesting no gate, say so. Finish with a concrete
next question.

- FDE: 341/341 bytes pinned (SHA-256 above); 91/91 instructions
  counted (59 body + 32 tail); 1/1 `ret`; 0 `nop`.
- Census denominators: 66/66 GOT sites resolved (65 call + 1 jmp);
  66/66 sites with `esi = 0` proven (65 adjacent `xor` + 1 block
  `xor`); 0/66 with `esi = 1`; 58/58 `mov esi,0x1` sites resolved to
  a next call; 0/58 feeding the grant slot; 26/26 caller FDEs matching
  #193's census.
- Gates run: verifier exit 0; unit tests pass (own file); `make
  doctor` analysis_ready true; `make verify` exit 0; `make
  catalogue-check` exit 0; `make test` with the single pre-existing
  `test_node115_catalogue` Errno 18 failure only (see below). No gate
  is requested by this packet; the packet is an observation, not a
  component completion.
- Pre-existing failure (not a packet regression): the full `make test`
  suite has one known failure in `test_node115_catalogue.py`
  (`test_wrong_owner_target_and_changed_evidence_rejected`, OSError
  Errno 18 cross-device link because `/tmp` is tmpfs while the
  worktree is on another disk); it fails identically on a pristine
  checkout.
- Remaining unknowns: what the flag helper selects; what the
  completion helper does at zero count; the internals of the
  `esi = 1` callees. See README.md limitations.
- Next question: what does the flag helper `0x4dccf20` select (what
  makes its out-flag 1), and what does the completion helper
  `0x4da86a0` do when an l1_map entry's count hits zero — removal,
  notification, or recycle?
