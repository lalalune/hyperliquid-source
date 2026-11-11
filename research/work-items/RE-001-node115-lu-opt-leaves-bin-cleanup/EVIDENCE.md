# RE-001-node115-lu-opt-leaves-bin-cleanup: five opt leaves, bin-removal cleanup, enable-slow-path bin-setup callees, bin_table_init caller survey

- Component ID: node-115 control-tree leaves (opt/*) and bin machinery
  (cleanup callee, setup callees, bin_table_init callers).
- Target release and full SHA-256: node 115 binary
  `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390` (verified by fetch before
  analysis; base not moved).
- Claim status: observation for all decoded bytes and censuses;
  inference for the "initializer taking an output-struct pointer"
  reading of bin_table_init call sites (6 sampled sites) and for the
  init/drain counterpart suggestion between 0x63e91c0 and 0x63ec690
  (shared count global and 36 split only); unresolved for the tails of
  the three large callees, the getter/resolver/wait-helper semantics,
  and the 108 callers' subsystem identities.
- Scope included and excluded: included — 5 leaf FDEs in full,
  0x63ec690 in full, 0x6352f60 in full, entry windows of 0x6352fc0 /
  0x63e91c0 / 0x6365150 plus whole-FDE call/jump censuses, and the 108
  bin_table_init call-site census by caller FDE. Excluded — the 161
  remaining static leaves, the three large callees' tails, all callee
  internals named only, bin_table_init's own FDE, and any full-suite
  test run (see Results and limitations).

## Reproduce

Working directory: the packet's worktree at upstream main 05bc2de30.
Static analysis only; the node binary was never executed. Commands:

- `sha256sum artifacts/node/115/hl-node` (must equal the digest above).
- `objdump -d --start-address=<s> --stop-address=<e>
  artifacts/node/115/hl-node` per exhibit window (see records.json);
  strict instruction counts use the pattern address + bytes field +
  tab + mnemonic starting with a lowercase letter (byte-continuation
  lines excluded).
- `.eh_frame` FDE bounds: PC-relative sdata4 decoding (CIE zR,
  encoding byte 0x1b), `.eh_frame` VA = file offset 0xca6ed8, size
  0x77137c; bounds cross-checked against the next FDE start and the
  padding length.
- `.rela.dyn` leaf-slot check: file offset 0x6be8, size 0x163cc8,
  24-byte entries, R_X86_64_RELATIVE (type 8); node+0x20 slot addend
  must equal the handler address (file slots are zero-filled).
- Raw E8 census: scan `.text` (VA 0x1419300, file offset 0x1418300,
  size 0x4fd7700) for E8 + rel32 targeting each callee; every raw hit
  re-verified by disassembling the 5-byte site with objdump.
- Verifier: `python3 tools/node115_lu_opt_leaves_bin_cleanup.py`
  (byte reads only). Tests:
  `python3 tests/test_node115_lu_opt_leaves_bin_cleanup.py`.
- No execution, no network, no side effects; objdump/binutils version
  as installed in the VM (readelf/objdump present; xxd and pyelftools
  absent, not needed).

## Evidence

Coordinate system: `.text` file offset = VA − 0x1000, re-derived from
program headers (PT_LOAD off=0x1418300 ↔ vaddr=0x1419300) for this
packet; `.data.rel.ro`/`.got` = VA − 0x2000; `.rodata` = VA as-is;
`.data` = VA − 0x3000 (section headers: `.data` VA 0x64efa20 ↔ file
offset 0x64eca20; `.bss` VA 0x64ffe40 NOBITS). `.bss` values are
runtime-filled and are reported as unknown, never invented.

Leaf handlers (all endbr64 + sub $0x18,%rsp + stack canary; full text
in the `.objdump.txt` exhibits): write attempt (newp|newlen != 0,
computed by `or 0x20(%rsp),%r9`) returns eax=1; read with oldp==0 or
oldlenp==0 returns eax=0; read with *oldlenp==1 stores the global byte
at (%rcx) and returns 0; other *oldlenp returns 0x16 after storing 1
into *oldlenp and copying one byte only when *oldlenp != 0. The lea
targets differ per leaf: abort_conf 0x651174c (.bss), cache_oblivious
0x64ffb5c (.data, file byte 1), trust_madvise 0x6511748 (.bss),
confirm_conf 0x651174b (.bss; the same byte packet #259 identified as
the init-done flag), hpa 0x65116b8 (.bss). Node+0x20 slots confirmed
via `.rela.dyn`: 0x64de328→0x636ecd0, 0x64de350→0x636ed60,
0x64de378→0x636edf0, 0x64de3a0→0x636ee80, 0x64de3c8→0x636ef10.

bin_cleanup 0x63ec690..0x63ec797 (263B, endbr64 + 6 pushes; single ret
at 0x63ec796; 9B padding to next FDE 0x63ec7a0): entry loads
[0x6728850], returns if 0; loop ebp < [0x6728850] unsigned; indices
0..35 take the 0x6362130 resolver + mutex path (trylock on record+0x40,
wait helper 0x63bf680, contended byte +0x68, counters +0x38 always and
+0x28/+0x30 on ctx change, accumulate [rsi+index*24+0x10] into
record+0x80); indices 36+ take the lock-add path into the 0x30-stride
array (base rdx−0x2e0); every iteration clears its 24-stride slot.
Callers: 0x63ec7a0 (site 0x63ec86a, bin_remove per packet #262),
0x635e1a0 (site 0x635e262), 0x63edf10 (site 0x63edff6).

bin_setup 0x6352f60..0x6352fb6 (86B, endbr64 + 3 pushes; tail-jump to
0x6360ed0 with (rdi, rsi, 0, 1) on the zero path, plain ret on the
nonzero path): calls 0x6364420(rsi,0), 0x6364410(rdx,0), stores rdx to
rdi+0x90, calls 0x6364400(rsi,0). Callers: 10 sites in 7 FDEs,
including enable-slow 0x63ed090 (0x63ed58c), allocator 0x6365150
(0x636549f), thread/arena handler FDE 0x6379310 (2 sites), and
thread/idle handler FDE 0x6378120 (0x6378225).

0x6352fc0 head 0x6352fc0..0x63530d5 (277B of 1608B; entry endbr64 +
6 pushes + sub $0x48): guards [0x64ffb80] > 2 → 0x63533c0 and
[0x65096a0] <= 1 → 0x63532d0; record (mutex 0x6511700, base 0x65116c0)
trylock, base+0x38 += 1, base+0x28 += 1 and base+0x30 := ctx on change;
second [0x65096a0] <= 1 check → 0x63535c8; table walk from 0x65096c8
(r13 += 8, r15 from 1) with getter 0x6364400 calls and a stack-array
best-index record; head ends at the loop-back jmp 0x63530d3.
Whole FDE 379 strict instructions, no jumps outside, single ret
0x635319c; call census: 0x634ebb0 x1, 0x6364400 x3, 0x6364410 x4,
0x6364430 x1, 0x6367450 x2, 0x6368e40 x2, 0x63bf5b6 x1, 0x63bf680 x1,
pthread_mutex_unlock x2, pthread_mutex_trylock x1, 0x63f0bf0 x1,
0x63f1ad0 x1, __stack_chk_fail x1. Callers: 23 sites in 18 FDEs,
including enable-slow 0x63ed090 (0x63ed605) and allocator 0x6365150
(0x636555c).

0x63e91c0 head 0x63e91c0..0x63e92cd (269B of 721B; entry has NO
endbr64 — push r15 + pxor xmm0, as in packet #238's case): struct
init ([rsi] = rdi, [rdi+0xa8] = rsi, [rdi+0xa0] = rdx, [rdi+0x30] = 0,
[rdi+0x28] = 0), memset of count*24 bytes at rsi+8 with count =
max([0x6728850], 36), call 0x63eeb90([0x6728868], [0x6728850], rdx,
&stack), loop ebx < [0x6728850] with the <=35 arm setting out+0x34
:= 1, out+0x58 := 0, out+0x7c := min(0xff, [0x6728870] / table[ebx])
(table 0x6727a00) and every index calling 0x63eebd0; head ends at the
loop-back jb 0x63e92cb. Whole FDE 173 strict instructions, no jumps
outside, single ret 0x63e948b; call census: 0x63eeb90 x1, 0x63eebb0 x1,
0x63eebd0 x8, memset x1, __stack_chk_fail x1. Callers: 2 sites —
enable-slow 0x63ed090 (0x63ed254) and 0x63ed8b0 (0x63eda85).

0x6365150 fast path 0x6365150..0x6365212 (194B of 1296B; entry
endbr64 + pushes; ends at the small-size ret 0x6365211): size > 0x3800
→ 0x6365218, size > 0x1000 → 0x6365250; class =
0x67277c0[(size+7)/8]; entry = table(r9) + class*24; cursor [entry+8]
advances 8 past the [entry+0x18] limit check; count [entry+0x10] += 1
when the r8b flag is 0; returns the previous cursor contents after a
stack-canary check. Whole FDE 305 strict instructions, single ret
0x6365211, three tail-jumps outside (0x63bd2c0, 0x63bcd20, 0x6364880);
call census includes 0x6352f60 x1 and 0x6352fc0 x1. Callers: 29 sites
in 10 FDEs, including enable-slow 0x63ed090 (0x63ed18d) and the
0x63577f0 FDE (8 sites).

bin_table_init 0x63d9880..0x63d9a64 (484B, next FDE 0x63d9a70): 108 E8
sites, 0 E9, all objdump-verified, in 42 caller FDEs (distribution in
README and records.json `survey`). Sampled 6 sites across 6 FDEs all
set rdi to a stack-slot lea before the call. The enable-slow pair
(0x63ed478, 0x63ed4e7) matches packet #260's census exactly.

Disjointness: the verifier's range-only collector (merged tree plus
prior worktree records #183–#262, deduplicated by real packet slug)
collects only exhibited windows — string `range` fields, `[start,
end]` lists, `start`/`end` pairs inside `exhibits` lists or dicts, and
`windows` lists or dicts — and skips census/cited-only metadata
subtrees (keys census, cited, survey, largest_caller_fde, callers,
fde) and enclosing-`fde` annotation fields. All 10 windows are
disjoint from every prior claimed range, from packet #232's merged FDE
0x63b8820..0x63b8d85 (explicit check), from packet #252's r28_wait
window 0x63ec890..0x63ec8a3, and from each other. The survey's 108
sites are census only and are excluded from the claimed set.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction, no Cargo graph,
no build or equivalence comparison is claimed by this packet. The
verifier is a static byte checker, not an implementation.

## Results and limitations

- Verifier exit 0; own unit tests 10/10 standalone (see the run
  output; tallies are reported from the actual run, never copied).
- `make verify` exit 0 with the run's actual tally.
- `make catalogue-check` run and reported honestly: expected exit 2
  with pre-existing `Stale catalogue: README.md` on the new base, not
  a packet regression; not claimed as passing.
- Full `make test` NOT attempted: 584 test files on the new base take
  hours and risk a VM-restart kill mid-run; no full-suite tally is
  claimed anywhere in this packet.
- MANIFEST.sha256 verified with `sha256sum -c` (all OK).
- Remaining unknowns: the 161 unclassified leaves; the three large
  callees' tails; getter/resolver/wait-helper semantics; the 108
  callers' subsystem identities and full argument patterns; the
  init/drain structure identity between 0x63e91c0 and 0x63ec690.
- No gate is requested beyond the packet's own verifier, tests,
  `make verify`, and MANIFEST check.
- Next question: decode the tails of 0x6352fc0 and 0x63e91c0 and the
  remainder of 0x6365150, and classify the next five leaves in tree
  order (the opt/* value leaves adjacent to this packet's batch), or
  decode the largest bin_table_init caller FDE 0x63cba10 (10 sites) —
  packet #264 should pick one of these, not both, to stay light.
