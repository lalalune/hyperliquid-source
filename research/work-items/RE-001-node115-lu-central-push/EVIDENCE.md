# RE-001-node115-lu-central-push: evidence

- Component ID: RE-001-node115-lu-central-push
- Target release and full SHA-256:
  node #115 hl-node,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `8fd8db6`
  (unmoved by fetch before analysis)
- Claim status: observation for all byte-level claims; inference flagged
  where a mechanism is named (e.g. "page counter", "fallback"); unresolved
  where the file cannot decide (method pointee identities, header-bit
  semantic labels, all `.bss` contents).
- Scope included and excluded: see README.md. Analysis is static only
  (byte reads, objdump, readelf); the node binary was never executed.

## Reproduce

Worktree `~/workspace/hl-wt-calls205-115` at upstream main `8fd8db6`.
Binary `artifacts/node/115/hl-node`. Coordinate system: `.text` file offset
= VA − 0x1000 (`.text` VMA `0x1419300`, file offset `0x1418300`, size
`0x4fd7700`); `.data.rel.ro` / `.got` = VA − 0x2000; `.rodata` = VA as-is.
Tools: `objdump`, `readelf`, `od`, `python3` (byte scans, census).
No execution, no side effects.

Exhibit regeneration (from the worktree root):

```
od -An -tx1 -j $((0x63c0340 - 0x1000)) -N 168 artifacts/node/115/hl-node
objdump -d --start-address=0x63c0340 --stop-address=0x63c03e8 artifacts/node/115/hl-node
```

## Evidence

### The push FDE (push.hex / push.objdump.txt, 168B, 45 strict)

FDE from `.eh_frame`: `0x63c0340..0x63c03e8`. Disassembly, in order:

- `0x63c0340` endbr64; prologue pushes r13/r12/rbp/rbx; `r8d = 0`;
  `r13 = rdi` (thread), `r12 = rcx` (&flag), `rbp = rdx` (block),
  `rbx = rsi` (seg+0x2998 object); `ecx = 0xe8`.
- `0x63c0362` `mov 0x10aa8(%rsi),%rsi` — loads [seg+0x13340].
- `0x63c0369` `call 0x63aefe0` — always-run helper
  (thread, [seg+0x13340], block, 0xe8, 0).
- `0x63c036e` reload block header; `0x63c0372` `test $0x10,%ah`
  (header bit 0x1000); if set, `0x63c03d0` cold path: reload
  [seg+0x13340], `call 0x63aed40` (thread, [seg+0x13340], block),
  reload header, jump back to `0x63c0377`.
- `0x63c0377` `andq $~0xfff, 0x8(%rbp)` — page-mask block+0x8.
- `0x63c037f` `mov 0x10(%rbp),%rdx; shr $0xc,%rdx` — page count.
- `0x63c0383` header `&= 0xfffffffff00fffff` (clear bits 20–27);
  `0x63c0389` header `|= 0xe800000` (set bits 20–27 to 0xe8);
  `0x63c0393` store header back.
- `0x63c0397` `lock sub %rdx, 0x8(%rbx)` — obj+0x8 -= page count.
- `0x63c039c` `testq $0x4000, 0x0(%rbp)` (header bit 0x4000);
  `0x63c03a4` `lea 0x18(%rbx),%rcx`; `0x63c03a8`
  `lea 0xf338(%rbx),%rsi`; `0x63c03b5` `cmove %rcx,%rsi`
  (bit clear → +0x18, bit set → +0xf338); `0x63c03af` `rdx = block`;
  `0x63c03b2` `rdi = thread`; `0x63c03b9` `rcx = &flag`;
  `0x63c03bc` `mov 0x20(%rsi),%r8` — method pointer load;
  `0x63c03ca` `jmp *%r8` — tail jump to method
  (thread, subobject, block, &flag). No `ret` in this FDE.

The method pointees live at [obj+0x38] (bit clear) and [obj+0xf358]
(bit set), i.e. [seg+0x29d0] and [seg+0x11cf0]. A full-`.text` grep for
stores to displacements `0x29d0` / `0x11cf0` finds no static writer
(the hits are stack-relative or negative displacements, unrelated),
and no `.rela.dyn` RELATIVE addend covers these slots (they are
per-segment memory, not file-backed). Their identities are therefore
unresolved from the file alone — stated, not worked around.

### The flag tails (flag_large / flag_small)

- push-large wrapper `0x63bd640..0x63bd6ba`: resolves
  `seg = seg_table[(*arg2) & 0xfff]` via `.bss` table `0x65096c0`,
  calls `0x63c0340` at `0x63bd682` with (thread, seg+0x2998, block,
  &stack-flag). `flag_large.hex` (`0x63bd687..0x63bd6b3`, 44B, 13
  strict) shows the check: `cmpb $0x0, flag; jne fallback`; on
  nonzero, `call 0x6360610` at `0x63bd6ae` with (thread, seg).
  This range starts exactly where #204's push_large.hex ends
  (`0x63bd687`); no bytes overlap.
- push-small wrapper `0x63612b0..0x636131a`: `rsi += 0x2998`, calls
  `0x63c0340` at `0x63612e1`. `flag_small.hex`
  (`0x63612e6..0x6361313`, 45B, 13 strict) shows the same check and
  the fallback call at `0x636130e` with (thread, seg).
- `0x63c0340` itself never writes *flag: r12 (&flag) is only moved
  to rcx for the tail call. The method owns the flag value.

### The fallback gate (fallback_gate.hex, 42B, 13 strict)

Fallback FDE `0x6360610..0x63606ca` (186B), args (thread, seg).
`fallback_gate.hex` (`0x6360610..0x636063a`) shows: load
[seg+0x10f40] (`0x6360620`); if zero → cold path `0x63606a0` which
calls `0x635fb50` (thread, seg, seg+0x10ec8, [seg+0x11cc0],
seg+0x29e8, 1) and loops back; else load `.bss` byte `0x6711ab8`
(`0x636062c`); if zero → return doing nothing; else the
seg+0x13450 counter path (divide by [.bss `0x6711aa8`], index a
table at [.bss `0x6711aa0`], test byte [entry+0xac]) gates a tail
jump to `0x635f4b0` (thread, seg, seg+0x10ec8, 0) at `0x6360695`.
`0x635fb50` itself (FDE `0x635fb50..0x635fcf2`) uses the record-C
pattern (mutex at arg3+0x40, +0x28/+0x30/+0x38 counts) and
references seg+0x29b0 (= obj+0x18) at `0x635fbc5` — corroborating
that obj+0x18 is a real subobject, not an arithmetic artifact.

### Pre-push helpers (characterised, not fully decoded)

- `0x63aed40..0x63aefdb` (443B): cold path only. Walks the block's
  4KB pages (block+0x10 masked, block+0x8 masked), stamps each
  8-byte page-table entry at `(page >> 9) & 0x1ffff8` with
  `0xe8000000000000` (top byte 0xe8 = huge class), then resolves
  the segment slot `((ptr >> 0x1a) & 0xf0) + thread+0x1b0` with the
  1-entry cache (thread+0x2b0 key / +0x2b8 page base) and 8-slot
  scan, calling `0x63d9700` (segment registration) on a full miss.
- `0x63aefe0..0x63af45f` (1119B): always run, args (thread,
  [seg+0x13340], block, 0xe8, 0). Compares the class arg against
  0xe8 (`0x63af027`, special path at `0x63af0c1` when equal);
  otherwise performs segment-slot lookup
  `((ptr >> 0x1a) & 0xf0) + thread+0x1b0` and page-entry work at
  `(ptr >> 9) & 0x1ffff8`, calling `0x63d9700` on miss. Full
  semantics out of scope for this packet.

### Census (whole `.text`, byte scan + per-site disassembly check)

Target `0x63c0340`. Direct E8 callers (9), all with the
(thread, seg+0x2998, block, &flag) setup and a flag check after
return:

- `0x63612e1` push-small `0x63612b0..0x636131a`
- `0x63bd682` push-large `0x63bd640..0x63bd6ba`
- `0x636156e`, `0x63615e2`, `0x63616a1` in FDE `0x6361320..0x63620da`
- `0x63627a9` in FDE `0x6362190..0x6362901`
- `0x6363ab6` in page-owning free `0x63637f0..0x6363d50`
- `0x6364e28` in FDE `0x6364880..0x6365142`
- `0x63bd730` in page sink `0x63bd6c0..0x63bd8b5`

E9 tail jumps: 0. Rip-relative LEA sites: 0. GOT slots (`.rela.dyn`
RELATIVE addend == `0x63c0340`): 0. The push is reached only by
direct calls.

### Disjointness

Claimed exhibit ranges in this packet — `0x63c0340..0x63c03e8`,
`0x63bd687..0x63bd6b3`, `0x63612e6..0x6361313`,
`0x6360610..0x636063a` — are disjoint from all prior packets'
exhibit ranges, including #203 (`0x635c6d0..0x635c886`,
`0x635cdf8..0x635ce47`, `0x635cce8..0x635cd7f`), #204
(`0x63eaef0..0x63eaf7e`, `0x63eb9d0..0x63eba48`,
`0x63bd640..0x63bd687`, `0x63ec019..0x63ec068`), and #202's
fast-path exhibit (`0x635de30..0x635dec6`) and 0x5a8xxxxx
free/drop exhibits. Prior FDE citations (e.g. push-small /
push-large bounds) are not exhibit claims and do not conflict.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed for
this packet. The verifier and tests below check byte-level facts
only (regeneration, strict counts, key bytes, census, MANIFEST).

## Results and limitations

- Proven: dispatch mechanism, header stamp, page-counter update,
  flag protocol, fallback gating routes, 9-site census.
- Unresolved: method pointee identities; header-bit 0x4000 / 0x1000
  semantic labels; `.bss` contents (segment table, class tables,
  threshold, per-class array); full decodes of `0x63aed40`,
  `0x63aefe0`, `0x635fb50`, `0x635f4b0`.
- Next question: decode the fallback's inner route `0x635fb50` (record
  C at seg+0x10ec8, obj+0x18 reference) and when its gating fires.
