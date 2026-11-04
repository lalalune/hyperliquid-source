# RE-001-node115-lu-handon: the node #115 hand-on destination

- Component ID: RE-001-node115-lu-handon
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes, `artifacts/node/115/hl-node`)
- Source commit / reference commit: upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis)
- Claim status: observation for all decoded control flow, argument
  shapes, census, and FDE bounds below; inference only where marked
  (role labels such as "hand-on" / "dest" / "chain" / "join"
  describe observed argument and accounting shapes, not proven
  upstream semantics); unresolved items are listed, not filled in.
- Scope included and excluded: included — hand-on FDE
  `0x63b38d0..0x63b3af1` in full (all paths traced), the
  lock protocol, the three pre-chain gates, the `0x63b1b60`
  chain shape, the threshold and `0x63c1c40` probes, the
  join path, the re-entry path with its accounting, and
  the census of hand-on. Excluded — internals of
  `0x63b1b60`, `0x63adb50`, `0x63b0560`, `0x63c1c40`,
  `0x63bf680`, the three E8 caller FDEs (`0x63b46e0`,
  `0x63b4b50`, `0x63c1cd0`), and every item in the
  README's unresolved list.

## Reproduce

Worktree `~/workspace/hl-wt-calls212-115`, branch
`codex/re-004-calls212-115`, from `origin/main` of the main
clone (HEAD untouched). Static only: `objdump -d
--start-address <VA> --stop-address <VA>` for disassembly
(VA used directly; file bytes read at VA − `0x1000` for
`.text`), byte scans in Python over `.text`
(VA `0x1419300`, file offset `0x1418300`), `.rela.dyn`
(file offset `0x6be8`, 60,723 entries of 24 bytes), and
`.eh_frame` parsing for FDE bounds (PC-relative sdata4
encoding). No execution of the node binary at any point.

## Evidence

Coordinate system: virtual addresses as printed by objdump;
`.text` file offset = VA − `0x1000`; `.data.rel.ro` /
`.got` file offset = VA − `0x2000`; `.rodata` VA as-is.

FDE bounds (`.eh_frame`, PC-relative sdata4 parse,
135,313 FDEs): hand-on `0x63b38d0..0x63b3af1` (545B),
matching #211's stated bounds. Release FDE
`0x63b3080..0x63b38c2` (2114B) confirmed the same way.

Entry register provenance (release tail jump,
#211's rel_tail excerpt at `0x63b30f0..0x63b3116`):
`mov %rbx,%r8; mov %rbp,%rdx; mov %r13,%rsi;
lea 0x9818(%r13),%rcx; mov %r12,%rdi;
jmp 0x63b38d0`. Cross-checked against hand-on's own
uses: rbp is compared against dest+`0x30` (owner)
and passed as the first argument everywhere (thread);
r12 supplies [ref+`0xe410`], [ref+`0xe510`],
[ref+`0xf310`] (ref); r13 is passed as the third
argument everywhere (pool); rbx is dereferenced as
node[0] and node+`0x10` (node); rcx is the dest
object (dest+`0x40` is the trylock argument).

Exhibits (5, 266B, 65 strict mnemonics; strict =
address + byte field + tab + mnemonic lines, objdump
byte-continuation lines excluded):
- ho_lock `0x63b38d0..0x63b3929` (89B/26): prologue,
  stack canary, trylock, counter/owner block.
- ho_loop `0x63b3960..0x63b3983` (35B/10): chain
  loop body, flag test, loop-back.
- ho_join `0x63b39a0..0x63b39d7` (55B/11): kind load,
  `0x63adb50` call, dest+`0x70`/`0x2628` select,
  `0x63b0560` call.
- ho_reenter `0x63b3a76..0x63b3a97` (33B/9): flag
  clear, unlock call, release re-entry call.
- ho_acct `0x63b3a97..0x63b3acd` (54B/9): three
  atomic updates on [ref+`0xf310`].

Address-cited (key-byte checked in the verifier,
not exhibited): trylock-or-wait at `0x63b3908`
(trylock PLT) / `0x63b3a33` (wait helper
`0x63bf680`) / `0x63b3a38` (flag set); bit-16 test
`0x63b3929` + `jne 0x63b39a0`; dest+`0x4be8`
compare `0x63b3932` + `je 0x63b3a08`; size gate
`0x63b393f`–`0x63b394f` (mask, `cmp $0x3fff`,
`jbe 0x63b39a0`); single-call path `0x63b3a08`
(r9 = 0) + `jmp 0x63b39a0`; post-loop threshold
`0x63b3983`–`0x63b3999` (mask, [ref+`0xe510`]
compare, `jae 0x63b3a48`); probes `0x63b3a48`
(`0x63c1c40(ref, 1)`, -1 → join) and `0x63b3a5f`
(`0x63c1c40(ref, 2)`, -1 → join); join-path flag
clear `0x63b39d7` and tail-jump unlock
`0x63b3a00`; shim FDE `0x63b3b00..0x63b3b18`
(two `andq` normalizations + `jmp 0x63b38d0`).

Census method: whole-`.text` byte scan for E8/E9
rel32 and for REX + `8d` modrm-`05` LEA forms,
each hit re-checked by disassembling the site
(real instruction, correct target); `.rela.dyn`
addends scanned for the target. Results: E8
`0x63b4aa1` (FDE `0x63b46e0`), `0x63b5186`,
`0x63b51a5`, `0x63b545d`, `0x63b54d8` (FDE
`0x63b4b50`), `0x63c1f15` (FDE `0x63c1cd0`); E9
`0x63b3111` (release FDE `0x63b3080`),
`0x63b3b13` (shim FDE `0x63b3b00`); LEA none;
GOT none (60,723 `.rela.dyn` entries scanned).
Note: the byte scan alone also matches immediates
that merely resemble rel32 encodings; every site
above was confirmed as a genuine call/jump by
objdump, which is why the census lists exactly
these 8 sites.

## Implementation and comparison

Not yet implemented/measured. No Rust reconstruction
is claimed in this packet; the verifier and tests
below are static byte checks only.

## Results and limitations

Machine-readable metrics: 5 exhibits, 266 bytes,
65 strict mnemonics; census 6 E8 + 2 E9, 0 LEA,
0 GOT; FDE 545B; MANIFEST 15/15; unit tests 8/8;
`make verify` exit 0; `make catalogue-check` exit 0;
`make test` 77 files attempted, 1 failed — the
single failure is the pre-existing
test_node115_catalogue Errno 18 cross-device-link
error, identical on pristine checkouts, not a
packet regression; this packet's file passes 8/8.

What remains unknown: everything in the README's
unresolved list, plus whether the six E8 caller
FDEs share one call convention (their argument
setup was inspected only enough to confirm the
call instructions, not decoded).

Next question: decode the chain helper `0x63b1b60`
end to end: what does it do with (thread, ref, pool,
dest, node, &flag), what does it return, and what
does the flag byte select?
