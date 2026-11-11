# RE-001-node115-lu-opt-leaves-bin-cleanup

Node-115-only light packet. Five more control-tree leaves classified
(opt/abort_conf, opt/cache_oblivious, opt/trust_madvise, opt/confirm_conf,
opt/hpa), the bin-removal cleanup callee 0x63ec690 decoded in full, the
small enable-slow-path bin-setup callee 0x6352f60 decoded in full, and
entry windows for the three remaining enable-slow-path bin-setup callees
(0x6352fc0, 0x63e91c0, 0x6365150) decoded, with whole-FDE call/jump
censuses characterizing the unexhibited tails. The 108 bin_table_init
callers are surveyed by enclosing caller FDE (census only, no new claims).

## Target

- Binary: `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`.
- Coordinate system: `.text` file offset = VA − 0x1000 (program-header
  PT_LOAD off=0x1418300 ↔ vaddr=0x1419300, re-derived for this packet);
  `.data.rel.ro`/`.got` = VA − 0x2000; `.rodata` = VA as-is; `.data` =
  VA − 0x3000 (section headers: `.data` VA 0x64efa20 ↔ file offset
  0x64eca20). `.bss` contents are runtime-filled and not in the file.
- `.hex` exhibits contain RAW BINARY bytes, not hex text (format since
  packet #255). The verifier, tests, and MANIFEST all treat them as raw.

## Classified leaves (5 of the 166 remaining at packet start)

All five handlers are consecutive 134-byte FDEs with the identical
read-only byte contract (the same shape as packet #260's opt/abort and
packet #261's opt/prof): a write attempt (newp|newlen != 0) returns 1
without touching memory; a read with oldp==0 or oldlenp==0 returns 0;
a read with *oldlenp==1 stores the byte and returns 0; any other
*oldlenp returns 0x16 after storing the required size 1 into *oldlenp
and copying one byte only when *oldlenp != 0. The five differ only in
the global byte they read:

| leaf | node | handler FDE | global byte | file value |
| ---- | ---- | ----------- | ----------- | ---------- |
| opt/abort_conf | 0x64de308 | 0x636ecd0..0x636ed56 | .bss 0x651174c | runtime (not in file) |
| opt/cache_oblivious | 0x64de330 | 0x636ed60..0x636ede6 | .data 0x64ffb5c | 1 |
| opt/trust_madvise | 0x64de358 | 0x636edf0..0x636ee76 | .bss 0x6511748 | runtime (not in file) |
| opt/confirm_conf | 0x64de380 | 0x636ee80..0x636ef06 | .bss 0x651174b | runtime (not in file) |
| opt/hpa | 0x64de3a8 | 0x636ef10..0x636ef96 | .bss 0x65116b8 | runtime (not in file) |

Each handler's node+0x20 slot was confirmed via `.rela.dyn` addends
(60,723 RELATIVE entries; file slots are zero-filled, so the addend is
the authority). Note: opt/confirm_conf reads byte 0x651174b, the same
byte packet #259 identified as the init-done flag; this packet claims
only that the leaf reads that byte, not what sets it. The .bss bytes
0x651174c/0x6511748/0x651174b/0x65116b8 are adjacent to packet #260's
opt/abort flag 0x651174d, consistent with a byte array of option flags;
the runtime values are unknown from the file and are not claimed.

After this packet, 161 of the 204 static leaves remain unclassified
(204 − 43 classified through #263; the 43 = 38 through #262 + these 5).

## Bin-removal cleanup callee 0x63ec690 (full FDE, 263B)

Called from 3 sites: bin_remove's FDE 0x63ec7a0 (site 0x63ec86a,
confirming packet #262's framing), 0x635e1a0 (site 0x635e262), and
0x63edf10 (site 0x63edff6). Contract, from the full disassembly:

- Guard: if the global count at 0x6728850 is 0, return immediately.
- Loop index ebp runs while ebp < [0x6728850] (unsigned).
- Indices 0..35: resolve a record via 0x6362130(ctx, 0, index), take
  its mutex at +0x40 with pthread_mutex_trylock (contention path calls
  the wait helper 0x63bf680 and sets the contended byte at +0x68 to 1,
  then proceeds as if locked); always increment the counter at +0x38;
  if the last-ctx field at +0x30 differs from ctx, increment the
  counter at +0x28 and store ctx; add the 24-stride array slot value
  [rsi + index*24 + 0x10] into the record field at +0x80; clear the
  contended byte and unlock.
- Indices 36+: instead of the mutex path, atomically add the same slot
  value into a 0x30-stride array entry (base rdx−0x2e0, advancing 0x30
  per iteration) and atomically increment that entry's +0x10 field.
- Every iteration ends by clearing the 24-stride slot to 0.
- Single ret at 0x63ec796; 9 bytes of padding to the next FDE 0x63ec7a0.

The exact identity of the two arrays (and whether the 0x30-stride
array is the same structure 0x63e91c0 initializes) is NOT proven by
this packet and is left open; the shared count global 0x6728850 and
the shared 36 split are the observed link.

## Enable-slow-path bin-setup callee 0x6352f60 (full FDE, 86B)

Called from 10 sites in 7 FDEs, including enable-slow 0x63ed090 (site
0x63ed58c) and the allocator 0x6365150 (site 0x636549f). Contract:
call the getter family 0x6364420(rsi, 0), then 0x6364410(rdx, 0),
store rdx into rdi+0x90, call 0x6364400(rsi, 0); if that last call
returns nonzero, return; otherwise tail-call 0x6360ed0(rdi, rsi, 0, 1).
The three getters' own semantics are named only, not decoded.

## Entry windows for the three larger enable-slow-path callees

- 0x6352fc0 head (0x6352fc0..0x63530d5, 277B of the 1608B FDE):
  entry guards on the global at 0x64ffb80 (>2 diverts to 0x63533c0)
  and on 0x65096a0 (<=1 diverts to 0x63532d0); then the record
  whose mutex is 0x6511700 (the same record packet #261's
  bin_getcreate uses, base 0x65116c0) is locked with
  pthread_mutex_trylock, its base+0x38 counter (0x65116f8)
  incremented, and on ctx change its base+0x28 counter (0x65116e8)
  incremented and its base+0x30 last-ctx field (0x65116f0) updated
  — the same three offsets bin_cleanup uses; then a table walk over
  0x65096c8 entries (r13 advancing 8 per entry, r15 counting from 1)
  in which getter 0x6364400 is called per entry and the winning entry
  index is recorded in a stack array. Whole FDE: 379 strict instructions, NO jumps
  outside the FDE, single ret at 0x635319c; calls include 0x634ebb0
  (x1, cited only — packet #261's substitute topic, not re-claimed),
  0x6364400 (x3), 0x6364410 (x4), 0x6364430 (x1), 0x6367450 (x2),
  0x6368e40 (x2), 0x63bf5b6 (x1), 0x63bf680 (x1, wait helper).
  The unexhibited tail (0x63530d5..0x6353608) is characterized only by
  this census, not decoded.
- 0x63e91c0 head (0x63e91c0..0x63e92cd, 269B of the 721B FDE; entry has
  NO endbr64, starting with pushes like packet #238's case):
  initializes an output struct: [rsi] = rdi, [rdi+0xa8] = rsi,
  [rdi+0xa0] = rdx, [rdi+0x30] = 0, [rdi+0x28] = 0, zeroes a
  count*24-byte array at rsi+8 where count = max([0x6728850], 36),
  calls 0x63eeb90([0x6728868], [0x6728850], rdx, &stack), then loops
  index ebx while ebx < [0x6728850]: indices <=35 additionally set
  per-index bytes at out+0x34 (:=1), out+0x58 (:=0), and out+0x7c
  (:= min(0xff, [0x6728870] / table[ebx]) with table 0x6727a00);
  every index calls 0x63eebd0. Whole FDE: 173 strict instructions, NO
  jumps outside, single ret at 0x63e948b; calls 0x63eeb90 (x1),
  0x63eebb0 (x1), 0x63eebd0 (x8), memset (x1).
  The unexhibited tail (0x63e92cd..0x63e9491) is census-only.
- 0x6365150 fast path (0x6365150..0x6365212, 194B of the 1296B FDE,
  ending at the small-size ret): size thresholds 0x3800 and 0x1000
  (same thresholds as packet #260's enable-slow head); for size
  <=0x1000, class = byte-class table 0x67277c0[(size+7)/8], entry =
  table(r9) + class*24; the entry cursor at +0x8 advances by 8 past
  the entry's +0x18 limit check, the count at +0x10 increments when
  the r8b flag is 0, and the previous cursor contents are returned
  (mov %r9,%rax) after a stack-canary check. Whole FDE: 305 strict
  instructions, single ret at 0x6365211, THREE tail-jumps outside the
  FDE (to 0x63bd2c0, 0x63bcd20, 0x6364880 — tail-call exits, not
  escapes); calls include 0x6352f60 (x1) and 0x6352fc0 (x1), so
  0x6365150 is the parent that invokes both other setup callees, and
  enable-slow 0x63ed090 calls all three directly as well (sites
  0x63ed18d, 0x63ed58c, 0x63ed605). The unexhibited remainder
  (0x6365212..0x6365660) is census-only.

## bin_table_init caller survey (census only, no new claims)

bin_table_init is 0x63d9880..0x63d9a64 (484B, next FDE 0x63d9a70),
immediately after packet #215's lu-miss handler FDE. Raw E8 scan of
`.text` (VA 0x1419300, file offset 0x1418300, size 0x4fd7700) finds
exactly 108 E8 sites, 0 E9, all 108 verified by objdump as `call`
instructions — matching packet #262's census. They fall in 42 caller
FDEs: 5 FDEs hold >=5 sites (0x63cba10: 10, 0x63c9c80: 8, 0x63ce8c0: 6,
0x63d4bbe: 6, 0x63bd8c0: 5), 8 FDEs hold 4 sites (32 sites), 12 FDEs
hold 2 sites (24 sites), 17 FDEs hold 1 site (17 sites); 35+32+24+17 =
108. The enable-slow FDE 0x63ed090 holds exactly the 2 sites packet
#260 named (0x63ed478, 0x63ed4e7). A second FDE cluster 0x63ed8b0
holds 2 sites and also calls 0x63e91c0, 0x6352fc0, and 0x6365150.
Sampled 6 sites across 6 FDEs (0x63ed478, 0x63cbf88, 0x63ca4e1,
0x63661c0, 0x63ecb28, 0x63d4eed): every sampled site sets rdi to a
stack-slot lea (0x20/0x60/0x10(%rsp) etc.) immediately before the
call, consistent with an initializer taking an output-struct pointer.
The 108 sites' full argument patterns and subsystem identities are NOT
determined; the per-site list is in records.json under `survey`
(census only, excluded from the claimed set).

## Claimed bytes (10 windows, 1759 bytes total)

| window | range | bytes | strict ins |
| ------ | ----- | ----- | ---------- |
| opt_abort_conf | 0x636ecd0..0x636ed56 | 134 | 36 |
| opt_cache_oblivious | 0x636ed60..0x636ede6 | 134 | 36 |
| opt_trust_madvise | 0x636edf0..0x636ee76 | 134 | 36 |
| opt_confirm_conf | 0x636ee80..0x636ef06 | 134 | 36 |
| opt_hpa | 0x636ef10..0x636ef96 | 134 | 36 |
| bin_cleanup | 0x63ec690..0x63ec797 | 263 | 71 |
| bin_setup_52f60 | 0x6352f60..0x6352fb6 | 86 | 31 |
| bin_setup_52fc0_head | 0x6352fc0..0x63530d5 | 277 | 61 |
| bin_setup_e91c0_head | 0x63e91c0..0x63e92cd | 269 | 66 |
| bin_alloc_65150_fastpath | 0x6365150..0x6365212 | 194 | 50 |

Strict counts are mnemonic-line counts (address + bytes field + tab +
mnemonic starting with a lowercase letter; objdump byte-continuation
lines excluded) and match across README, records.json, and the PR body.
Total: 1759 bytes, 459 strict instructions.

## Disjointness

The verifier's collector scans the merged tree plus prior worktree
records (#183–#262), deduplicated by real packet slug, and gathers
ONLY exhibited windows: string `range` fields, `[start, end]` lists,
and `start`/`end` pairs inside `exhibits` lists or dicts, and
`windows` lists or dicts. It never collects enclosing-`fde`
annotation fields (packet #259 lesson) and never collects
census/cited-only metadata subtrees (packet #253 lesson: keys named
census, cited, survey, largest_caller_fde, callers, or fde are
skipped). All 10 windows above are disjoint from every prior claimed
range, from packet #232's merged FDE 0x63b8820..0x63b8d85 (checked
explicitly), from packet #252's r28_wait window 0x63ec890..0x63ec8a3
(the bin_cleanup window ends at 0x63ec797, before bin_remove's FDE
starts at 0x63ec7a0), and from each other. The survey's 108 call sites
are census only and are not claims.

## Verification

- `tools/node115_lu_opt_leaves_bin_cleanup.py` (static byte reads
  only; never executes the binary) exit 0.
- `tests/test_node115_lu_opt_leaves_bin_cleanup.py` 10/10 standalone.
- `make verify` exit 0 (see the run's actual tally; never a copied one).
- `make catalogue-check` result reported honestly (expected exit 2,
  pre-existing `Stale catalogue: README.md` on the new base, not a
  packet regression).
- Full `make test` is NOT attempted (584 test files on the new base;
  hours-long, VM-restart risk) and no full-suite tally is claimed.
- MANIFEST.sha256 verified with `sha256sum -c` (all OK).

## Not covered (explicit)

- The remaining 161 static leaves (list in the scout record; the next
  batch is packet #264's question).
- The tails of 0x6352fc0 (0x63530d5..0x6353608), 0x63e91c0
  (0x63e92cd..0x63e9491), and 0x6365150 (0x6365212..0x6365660):
  whole-FDE call/jump censuses only, not decoded.
- The getter family 0x6364400/0x6364410/0x6364420/0x6364430, the
  resolver 0x6362130, the wait helper 0x63bf680, and the 0x63eebd0
  family: named only.
- bin_table_init's own 484-byte FDE and the 108 callers' full argument
  patterns and subsystem identities: survey only.
- The identity link between 0x63e91c0's initialized structure and
  0x63ec690's drained arrays: observed shared count global and 36
  split only, not proven.
- Packet #262's 0x63bf840 framing is NOT corrected or re-claimed
  here; nothing in this packet's disassembly contradicts it.

## Files

26 files: README.md, EVIDENCE.md, records.json, MANIFEST.sha256, 10
`.hex` + 10 `.objdump.txt` exhibits (packet dir), plus
`tools/node115_lu_opt_leaves_bin_cleanup.py` and
`tests/test_node115_lu_opt_leaves_bin_cleanup.py`. The count exceeds
the 8–16 light target with reason: 5 leaves + 2 full callees + 3
partial-callee windows (10 exhibits), following packets #256–#262.
