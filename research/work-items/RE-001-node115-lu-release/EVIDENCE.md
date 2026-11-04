# RE-001-node115-lu-release: the node #115 release function

- Component ID: RE-001-node115-lu-release
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes, `artifacts/node/115/hl-node`)
- Source commit / reference commit: upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis)
- Claim status: observation for all decoded control flow, argument
  shapes, census, and FDE bounds below; inference only where marked
  (role labels such as "release" / "pool object" / "hand-on"
  describe observed argument and accounting shapes, not proven
  upstream semantics); unresolved items are listed, not filled in.
- Scope included and excluded: included — release FDE
  `0x63b3080..0x63b38c2` in full (all paths traced), the flag
  normalization, the three pool-method slots and their
  sentinel direct-call variants, the retry path and global
  accounting, the two tail destinations characterised by head
  inspection, and the census of release. Excluded — internals
  of `0x63b2e60`, `0x63ae980`, `0x63ae2b0`, `0x63ef5e0`,
  `0x63ef8e0`, `0x63c3730`, `0x63ad9a0`, `0x63ada60`,
  `0x63ada80`, `0x63b42e0`, `0x63c1c40`, `0x63b38d0`,
  `0x63b5760`, `0x63aa7d0`, and every item in the README's
  unresolved list.

## Reproduce

Worktree `~/workspace/hl-wt-calls211-115`, branch
`codex/re-004-calls211-115`, from `origin/main` of the main
clone (HEAD untouched). Static only: `objdump -d
--start-address=… --stop-address=… artifacts/node/115/hl-node`
for the FDE ranges, `objdump --dwarf=frames` for FDE bounds,
`readelf -SW` for section coordinates (`.text` VA
`0x1419300`, file offset `0x1418300`, so `.text` file offset
= VA − 0x1000; `.data.rel.ro` `0x63f3c20..0x64e2248`;
`.got` `0x64df458..0x64ee158`; `.data`
`0x64efa20..0x64ffe08`; `.bss` `0x64ffe40..0x6728924`),
and a byte scan of `.text` plus a `.rela.dyn` addend scan
for the census. No node execution, no network, no writes
outside the worktree packet dir, `tools/`, `tests/`, and
scratch `~/workspace/scratch-hl211/`. Tool versions: system
`objdump`/`readelf`, python3.

## Evidence

Coordinate system: virtual addresses (VA) as shown by
objdump; `.text` file offset = VA − 0x1000.

- Release FDE (`.eh_frame`): `0x63b3080..0x63b38c2`
  (2114B). Prologue (`rel_head.hex`, 50B/16 strict):
  endbr64, six pushes, (rdi, rsi, rdx, rcx) saved to
  (r12, r13, rbp, rbx), `sub $0x38,%rsp`, rax =
  [pool+8], r14 = lea `0x64df1a0` (`.data.rel.ro`
  default object), compare, je `0x63b3200`.
- No-`ret` fact: objdump of the full FDE range returns
  zero lines matching a `ret` mnemonic; the only
  out-of-FDE jumps are `e9 ba 07 00 00` at `0x63b3111`
  → `0x63b38d0` and `e9 67 25 00 00` at `0x63b31f4` →
  `0x63b5760` (both recomputed by the verifier).
- Dead size argument: every path overwrites r8 before
  any read — tail path r8 = node (`0x63b30f4`), main
  path r8 = [node] (`0x63b3148`), bit-13 path r8 =
  [node+0x10] & ~0xfff (`0x63b32e0`/`0x63b32f4`),
  retry path r8 = 0 (`0x63b3257`), probe-fallback
  r8 = [node] (`0x63b3490`). Sizes used downstream
  are [node+8] & ~0xfff and [node+0x10] & ~0xfff,
  computed at `0x63b3166`/`0x63b316d` and equivalents.
- Flag normalize (`rel_flag.hex`, 28B/7 strict):
  `0x63b30c7` r9d = `0x8000`; test bit 13 (`0x2000`)
  of node[0]; jne `0x63b32e0` (predicate path);
  clear bit 15 (`and $0x7f,%ah`); set bit 15 iff r9
  (`or %r9,%rax`); store node[0] (`0x63b30e0`); then
  `.bss` byte `0x6713606` (lea at `0x63b30c0`,
  `4c 8d 3d 3f 05 36 00`) clear → tail; else
  `0xe0000` field zero → `lock sub` pages from
  `.bss` `0x67121d8` (`0x63b3468`, `f0 48 29 3d`
  + rip → `0x67121d8`) then tail.
- Slot-+8 call (`rel_vcall.hex`, 31B/7 strict):
  thread+`0x330` gate, r8d = [pool], rsi = aligned
  [node+8], rdi = pool-obj, `41 ff 52 08` at
  `0x63b31c2`, result to ecx. Result 0 → tail
  `0x63b5760`; nonzero → retry path.
- Slot-+0x30 call: `41 ff 52 30` at `0x63b338b`
  (pool-obj, aligned8, aligned10, 0, [pool]); result
  in dl selects the r9 = 0 flag path (nonzero) or the
  r9 = `0x8000` flag path (zero) at `0x63b339e`.
- Slot-+0x28 call: `41 ff 52 28` at `0x63b350a`
  (same shape); both outcomes rejoin the r9 = 0 flag
  path at `0x63b351b` (via `0x63b30d6`).
- Predicate call: `e8 60 fb ff ff` at `0x63b32fb` →
  `0x63b2e60` (thread, pool, node, 0, aligned size);
  nonzero → slot-+0x30 path (`0x63b3330`); zero →
  flag path (`0x63b3304` → `0x63b30d6`, r9 restored).
  Head of `0x63b2e60` (FDE `0x63b2e60..0x63b307e`,
  574B): compares [pool+8] against a `.got`-resident
  pointer (slot `0x64ee140`) and checks
  [pool-obj+`0x20`]; internals not decoded.
- Setup call: `e8 3f b8 ff ff` at `0x63b313c` →
  `0x63ae980` (thread, [ref+`0xe410`], node).
- Retry call (`rel_retry.hex`, 26B/6 strict):
  `e8 46 b0 ff ff` at `0x63b3265` → `0x63ae2b0`
  (thread, [ref+`0xe410`], node, `0xe8`, 0). Zero
  result → accounting: pages = [node+0x10] >> 12,
  `lock xadd` to `.bss` `0x67121d8` (`0x63b3295`,
  `f0 4c 0f c1 15` + rip → `0x67121d8`), `lock
  cmpxchg` high-water on `.bss` `0x67121d0`
  (`0x63b32ad`, `f0 4c 0f b1 15` + rip →
  `0x67121d0`), `.bss` byte `0x67124d0` set →
  `0x63c3730(thread)` (`0x63b36ce`), then flag path.
- Tail call (`rel_tail.hex`, 38B/13 strict):
  `e9 ba 07 00 00` at `0x63b3111` → `0x63b38d0`
  (thread, ref, pool, ref+`0x9818`, node).
- Tail destination heads (characterised only):
  `0x63b38d0` (FDE `0x63b38d0..0x63b3af1`, 545B)
  trylocks (ref+`0x9818`)+`0x40`, bumps +`0x38`/
  +`0x28` with owner tracking, tests node[0] bit 16,
  and at `0x63b3a92` unlocks and re-enters release
  with the same (thread, ref, pool, node).
  `0x63b5760` (FDE `0x63b5760..0x63b57e1`, 129B)
  trylocks [ref+`0xe418`]+`0x58`, bumps counters,
  calls `0x63aa7d0` (obj, node); `0x63aa7d0` head
  (FDE `0x63aa7d0..0x63aab78`, 936B) zeroes
  node+`0x28` and node+`0x38` and begins a sorted
  list walk on [obj] by [node+0x10] & 0xfff and
  address.
- Census: byte scan of all of `.text` for E8 rel32 →
  `0x63b3080` gives `0x63b3a92`, `0x63c0e84`,
  `0x63c1194`; E9 rel32 gives `0x63b3b80`; LEA
  rip-relative gives none; `.rela.dyn` addend scan
  (60,723 entries) gives none. Per-site disassembly:
  `0x63b3a92` inside `0x63b38d0` (re-entry);
  `0x63c0e84` inside wrapper `0x63c0dd0..0x63c0f4d`
  (pool via `0x636b340([ref+0xe408])`, `0x63b42e0`
  tried first); `0x63c1194` inside #210's walk
  `0x63c1030..0x63c1360`; `0x63b3b80` inside
  wrapper `0x63b3b20..0x63b3bf4` (`0x63ae2b0`
  `0xe8` retry first, then tail to release).
- #210's walk probe `0x63b3c00` (called from the
  walk at `0x63c11ef`) is a different function from
  release-internal `0x63b2e60` (called from release
  at `0x63b32fb`); the two are not conflated.

## Implementation and comparison

Not yet implemented/measured: no independent Rust
reconstruction is claimed in this packet. The static
verifier `tools/node115_lu_release.py` re-extracts
every exhibit from the binary, recomputes every
key-byte target and census site, scans `.rela.dyn`,
and checks MANIFEST; the unit tests additionally
cover a tamper control (one flipped byte must fail).

## Results and limitations

- Verifier exit 0; unit tests 8/8; MANIFEST 15/15.
- Denominators: 5 excerpts, 173 bytes, 49 strict
  mnemonics; census 3 E8 + 1 E9, 0 LEA, 0 GOT over
  all of `.text` and 60,723 `.rela.dyn` entries.
- What remains unknown is listed in the README, not
  filled in. No gate is claimed beyond the packet's
  own verifier, unit tests, MANIFEST, `make verify`,
  `make catalogue-check`, and `make test` results.
- Next question: decode the hand-on destination
  `0x63b38d0` end to end — what does it do with
  (thread, ref, pool, ref+`0x9818`, node), and on
  which path does it re-enter release?
