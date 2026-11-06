# RE-001-node115-lu-driver: evidence

- Component ID: RE-001-node115-lu-driver
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes), file `artifacts/node/115/hl-node`
- Source commit / reference commit: upstream main `05bc2de30`
  ("Integrate late node115 PRs and retain original validation
  inputs"), confirmed before analysis; the binary is byte-identical
  to the `8fd8db6` base (same git blob SHA and size), so the target
  hash is unchanged by the base move
- Claim status: observation for all decoded control flow, call
  targets, stores, and counts below; inference only where marked;
  unresolved items are listed, not filled in
- Scope included: FDE `0x63b8d90..0x63b8fd1` end to end, its
  internal calls, its census, and its immediate neighbours by
  address only
- Scope excluded: the loop caller (#233, cited), the gate
  `0x63b85f0` (cited), the completion helper `0x63d94b0` (cited),
  the contention helper `0x63bf680` (cited), the neighbouring
  callback function `0x63b8fe0..0x63b9180` (cited), all `.bss`
  contents (runtime-filled, not file-readable)

## Reproduce

Working directory: the worktree root. No execution of the node
binary at any point; all commands are byte reads and disassembly.

```
objdump -d --start-address=0x63b8d90 --stop-address=0x63b8fd1 \
  artifacts/node/115/hl-node
readelf --debug-dump=frames artifacts/node/115/hl-node  # FDE bounds
python3 tools/node115_lu_driver.py
python3 -m unittest tests.test_node115_lu_driver
```

Tool versions: system `objdump` / `readelf` as installed in the
worktree environment; Python 3 standard library only for the
verifier and tests.

## Evidence

Coordinate system: virtual addresses (VA) as shown by objdump;
`.text` file offset = VA − `0x1000`; `.data.rel.ro`/`.got` =
VA − `0x2000`; `.rodata` = VA as-is. RELATIVE `.got` slots are
zero-filled in the file, so GOT census uses `.rela.dyn` addends
(60,723 entries).

FDE bounds: `.eh_frame` entry
`pc=0x63b8d90..0x63b8fd1` (577 bytes). Entry bytes
`f3 0f 1e fa` (`endbr64`). The following bytes
`0x63b8fd1..0x63b8fe0` are `int3` padding (`cc` × 15); the next
function starts with `endbr64` at `0x63b8fe0`.

Full-FDE disassembly facts (137 strict mnemonics, single `ret`
at `0x63b8de7` through the shared epilogue at `0x63b8dc2`,
10 distinct internal jump targets, all inside the FDE):

- Guard: `cmp %rdx, 0x15f8(%rsi)` at `0x63b8db9`
  (`48 39 96 f8 15 00 00`), `jae 0x63b8df0` (`73 2e`);
  failure returns `r15 = 0`.
- Flag byte: initialised `movb $0x0, 0x37(%rsp)` at `0x63b8df8`
  (`c6 44 24 37 00`); read at `0x63b8e2a` and `0x63b8ea8`
  (`80 7c 24 37 00`); never written by this FDE.
- Round 1: loop call at `0x63b8e1a` (`e8 91 f3 ff ff` →
  `0x63b81b0`); `mov %rax, %r15` at `0x63b8e22`
  (`49 89 c7`); `cmp %rax, %rbx` at `0x63b8e25`
  (`48 39 c3`); `je` epilogue at `0x63b8e28` (`74 98`).
- Round 2 lock: `pthread_mutex_trylock@plt` call at `0x63b8e49`
  (`e8 62 89 03 00`); contention path at `0x63b8f90`
  (`mov 0x18(%rsp), %rdi`; call `0x63bf680` at `0x63b8f95`;
  `movb $0x1, 0x118(%r14)` at `0x63b8f9a`;
  `jmp 0x63b8e56`); accounting `addq $0x1, 0xe8(%r14)` at
  `0x63b8e56` (`49 83 86 e8 00 00 00 01`).
- Round 2 call: `sub %r15, %r8` at `0x63b8e8a`
  (`4d 29 f8`); loop call at `0x63b8e95`
  (`e8 16 f3 ff ff` → `0x63b81b0`); `add %rax, %r15` at
  `0x63b8e9c` (`49 01 c7`); `cmp %r15, %rbx` at `0x63b8e9f`
  (`4c 39 fb`); `je 0x63b8f70` (`0f 84 c8 00 00 00`).
- Gate: call at `0x63b8ec2` (`e8 29 f7 ff ff` →
  `0x63b85f0`); `test %rax, %rax` at `0x63b8ec7`
  (`48 85 c0`); `je 0x63b8f70` (`0f 84 a0 00 00 00`).
- Round 3 lock: `pthread_mutex_trylock@plt` call at `0x63b8eea`
  (`e8 c1 88 03 00`); contention path at `0x63b8fb0`
  (`mov 0x28(%rsp), %rdi`; call `0x63bf680` at `0x63b8fb5`;
  `movb $0x1, 0xa8(%r14)` at `0x63b8fba`;
  `jmp 0x63b8efc`); accounting `addq $0x1, 0x78(%r14)` at
  `0x63b8efc` (`49 83 46 78 01`).
- Round 3 work: remaining `sub %r15, %rbx` at `0x63b8f17`
  (`4c 29 fb`); completion call at `0x63b8f1a`
  (`e8 91 05 02 00` → `0x63d94b0`); `movb $0x0, 0xa8(%r14)`
  at `0x63b8f1f`; unlock `context+0x80` at `0x63b8f2c`;
  loop call at `0x63b8f4d` (`e8 5e f2 ff ff` →
  `0x63b81b0`); `movb $0x0, 0x118(%r14)` at `0x63b8f52`;
  `add %rax, %r15` at `0x63b8f5a` (`49 01 c7`); unlock
  `context+0xf0` at `0x63b8f62`; pops; `jmp` epilogue.
- Early-exit path at `0x63b8f70`: `movb $0x0, 0x118(%r14)`,
  unlock `context+0xf0`, `jmp` epilogue.
- Return: `mov %r15, %rax` at `0x63b8dda` (`4c 89 f8`);
  `ret` at `0x63b8de7` (`c3`).

Raw byte scan caveat (observed, not assumed away): a raw
`0xe8` byte scan of the FDE reports a 14th candidate at
`0x63b8e59`, but objdump shows that byte is the `0xe8`
displacement byte inside the `addq $0x1, 0xe8(%r14)`
instruction, not a call opcode. Call counts in this packet
are objdump-mnemonic counts, not raw-byte counts.

Census method: whole-`.text` byte scan for `E8`/`E9` rel32
and REX `LEA` rip-relative resolving to `0x63b8d90`, plus
`.rela.dyn` addend scan. Result: 0 E8, 0 E9, 1 LEA
(`0x63b90ea`, objdump-confirmed `lea -0x361(%rip), %rcx`
targeting `0x63b8d90`, in FDE `0x63b8fe0..0x63b9180`,
immediately before the `0x63b90f5` LEA loading `0x63b8820`
into `rsi`), 0 GOT addends of 60,723.

Disjointness method: all 182 `records.json` files in the new
tree (193 claimed ranges across the `exhibits` and `windows`
schemas) plus #232's FDE (`0x63b8820..0x63b8d85`) and #233's
FDE (`0x63b81b0..0x63b8517`, unmerged, from its own worktree):
zero overlaps with `0x63b8d90..0x63b8fd1`. No work-item
directory names this driver FDE (the existing `drain-driver`
and `sibling-driver` directories claim different ranges,
confirmed by the same scan).

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is part
of this packet; this is an evidence-only packet (decoder
record + static verifier + unit tests). No source mapping is
claimed: the objdump function labels are toolchain artifacts
(`_ZNKSt5ctypeIcE8do_widenEc@@Base` offsets), not identities.

## Results and limitations

Machine-readable metrics: 6 exhibits, 410 bytes, 106 strict
instructions; FDE 577 bytes, 137 strict instructions, 1 ret,
13 internal calls, 10 distinct internal jump targets, census
0 E8 / 0 E9 / 1 LEA / 0 GOT.

What remains unknown (see README "Unresolved"): the gate's
semantics; the `0x63d94b0` vs `0x63d94a0` relationship; the
neighbouring callback function's purpose and its use of the
accumulated return; the unexplained `rsi` reload on the
first-mutex contention path; whether the entry-slot chain
order is observable downstream.

Next question: decode the gate `0x63b85f0` end to end (see
README "Next question (#235)").
