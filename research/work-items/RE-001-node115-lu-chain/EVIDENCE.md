# RE-001-node115-lu-chain: the node #115 chain helper

- Component ID: RE-001-node115-lu-chain
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes, `artifacts/node/115/hl-node`)
- Source commit / reference commit: upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis)
- Claim status: observation for all decoded control flow, argument
  shapes, census, and FDE bounds below; inference only where marked
  (role labels such as "chain helper" / "next-node call" / "byte
  test" / "join pair" describe observed argument and accounting
  shapes, not proven upstream semantics); unresolved items are
  listed, not filled in.
- Scope included and excluded: included — chain-helper FDE
  `0x63b1b60..0x63b1d5a` in full (all paths traced), the
  register/frame layout, the loop head, the test-zero and
  test-nonzero branches, the retry block, the mid block,
  the exit and flag-write gating, the return-value rule,
  and the census of the helper. Excluded — internals of
  `0x63ae260`, `0x63b0780`, `0x63b1810`, `0x63adb50`,
  `0x63b0560`, the three E8 caller FDEs (`0x63b2630`,
  `0x63b38d0`, and the selector's own body beyond the
  call setup and post-call flag test), and every item in
  the README's unresolved list.

## Reproduce

Worktree `~/workspace/hl-wt-calls213-115`, branch
`codex/re-004-calls213-115`, from `origin/main` of the main
clone (HEAD untouched). Static only: `objdump -d
--start-address <VA> --stop-address <VA>` for disassembly
(VA used directly; file bytes read at VA − `0x1000` for
`.text`), byte scans in Python over `.text`
(VA `0x1419300`, file offset `0x1418300`), `.rela.dyn`
(file offset `0x6be8`, 60,723 entries of 24 bytes), and
`.eh_frame` parsing for FDE bounds (readelf
`--debug-dump=frames-interp` confirms
`0x63b1b60..0x63b1d5a`). No execution of the node
binary at any point.

## Evidence

Coordinate system: virtual addresses as printed by objdump;
`.text` file offset = VA − `0x1000`; `.data.rel.ro` /
`.got` file offset = VA − `0x2000`; `.rodata` VA as-is.

FDE bounds (`.eh_frame`, readelf frames dump): chain
helper `0x63b1b60..0x63b1d5a` (506B). Exactly one `ret`
in the FDE, at `0x63b1d35`; the bytes after it to
`0x63b1d5a` are nop padding and `int3` fill. The full
control-flow inventory inside the FDE: 11 calls
(3x `0x63ae260`, 2x `0x63b0780`, 2x `0x63b1810`,
2x `0x63adb50`, 2x `0x63b0560`), 2 `cmove`
(dest+`0x70` vs dest+`0x2628` select), branches
`je 0x63b1c5b`, `jne 0x63b1c28`, `jne 0x63b1d40`,
`je 0x63b1b90`, `jmp 0x63b1c8b`, `je 0x63b1d10`,
`jne 0x63b1cc8`, `jne 0x63b1d50`, `jmp 0x63b1b90`,
`jne 0x63b1b90`, `je 0x63b1d21`, `jmp 0x63b1d21`,
`jmp 0x63b1d24`.

Entry register provenance (hand-on's calls, #212):
loop call `0x63b3974` and single call `0x63b3a1a`
both pass (thread, ref, pool, dest, node, &flag)
in (rdi, rsi, rdx, rcx, r8, r9). Cross-checked
against the helper's own uses: r13 (thread) is
the first argument of every callee call; r12 (ref)
supplies [ref+`0xe410`]; [rsp+`0x8`] (pool) is the
third argument of both `0x63b1810` calls; rbx
(dest) supplies [dest+`0x4be0`] and
[dest+`0x4be8`]; r14 = dest+`0x70` is the first
argument of both `0x63b0780` calls and the
bit-16-clear argument of both `0x63b0560` calls;
rbp is the node carried across iterations; r15 is
each fresh next-node result; [rsp+`0x18`] is
dereferenced only at the three flag writes.

Exhibits (5, 227B, 61 strict mnemonics; strict =
address + byte field + tab + mnemonic lines, objdump
byte-continuation lines excluded — the nopl at
`0x63b1b88` is 8 bytes, its trailing `00` byte
appears on a dropped continuation line, the full
bytes are in `ch_head.hex`):
- ch_head `0x63b1b60..0x63b1b90` (48B/15): prologue,
  dest+`0x70` lea, register saves, pool and flag
  pointer saves, nopl.
- ch_next `0x63b1b90..0x63b1bbe` (46B/10): head
  next-node call setup (sixth argument 1), call,
  NULL test and branch.
- ch_mid `0x63b1c8b..0x63b1cb7` (44B/12): mid block
  `0x63b0780` call, swapped-argument `0x63b1810`
  call, test, branch, dest+`0x4be8` compare.
- ch_join `0x63b1c28..0x63b1c5b` (51B/10): join pair
  (`0x63adb50` call, dest+`0x2628` lea, bit-16
  test, cmove, `0x63b0560` call).
- ch_exit `0x63b1d10..0x63b1d36` (38B/14): exit
  block (flag compare/branch, *flag = 0 write,
  cur-to-return move, epilogue, single `ret`).

Address-cited (key-byte checked in the verifier,
not exhibited): prologue lea `0x63b1b64`
(`4c 8d 71 70`); flag-pointer save `0x63b1b83`
(`4c 89 4c 24 18`); kind load `0x63b1ba0`
(`44 8b 83 e0 4b 00 00`); head next call
`0x63b1bad` → `0x63ae260` (r9d = 1 at
`0x63b1ba7`); link call `0x63b1bc4` →
`0x63b0780`; head test call `0x63b1bda` →
`0x63b1810`; test-zero branch `0x63b1be1` +
dest+`0x4be8` compare `0x63b1be3` + `jne
0x63b1d40` (early exit A, *flag = 1 at
`0x63b1d45`); second next call `0x63b1c0a` →
`0x63ae260` (r9d = 0 at `0x63b1bf8`) + `je
0x63b1b90` (NULL → head) + local flag = 1 at
`0x63b1c1b` + `jmp 0x63b1c8b`; head-join
`0x63b1c28` (`0x63adb50` + bit-16 test
`0x63b1c48` + cmove `0x63b1c52` + `0x63b0560`
at `0x63b1c56`, fall-through to retry block);
retry next call `0x63b1c75` → `0x63ae260`
(r9d = 0 at `0x63b1c63`) + `je 0x63b1d10`
(NULL → exit) + local flag = 0 at `0x63b1c86`
+ `jmp 0x63b1c8b`; mid test call `0x63b1ca7`
→ `0x63b1810` (arguments swapped vs head) +
`jne 0x63b1cc8` (mid join, then local-flag
compare `0x63b1cfb` + `jne 0x63b1b90`) +
dest+`0x4be8` compare `0x63b1cb0` + `jne
0x63b1d50` (early exit B, *flag = 1 at
`0x63b1d55`) + cur advance `0x63b1cbd` +
`jmp 0x63b1b90`; exit flag write `0x63b1d1e`
(*flag = 0, skipped when dest+`0x4be8` == 0
via `je 0x63b1d21`).

Census method: whole-`.text` byte scan for E8/E9
rel32 and for REX + `8d` modrm-`05` LEA forms,
each hit re-checked by disassembling the site
(real instruction, correct target); `.rela.dyn`
addends scanned for the target. Results: E8
`0x63b2734` (selector FDE `0x63b2630`),
`0x63b3974` (hand-on FDE `0x63b38d0`, loop
call), `0x63b3a1a` (hand-on FDE, single call);
E9 none; LEA none; GOT none (60,723 `.rela.dyn`
entries scanned). Note: the byte scan alone also
matches immediates that merely resemble rel32
encodings; every site above was confirmed as a
genuine call by objdump, which is why the census
lists exactly these 3 sites. The selector site's
call setup (`0x63b271e..0x63b2734`: pool from
[rsp+`0x20`], node rbx, dest r12, flag pointer
lea `0x37(%rsp)` → r9) and its post-call flag
test (`cmpb $0x0,0x37(%rsp)` at `0x63b2756` +
`jne 0x63b27e0`) were inspected only as census
corroboration, not as a decode of the selector.

## Implementation and comparison

Not yet implemented/measured. No Rust reconstruction
is claimed in this packet; the verifier and tests
below are static byte checks only.

## Results and limitations

Machine-readable metrics: 5 exhibits, 227 bytes,
61 strict mnemonics; census 3 E8 + 0 E9, 0 LEA,
0 GOT; FDE 506B; MANIFEST 15/15; unit tests 8/8;
`make verify` exit 0; `make catalogue-check` exit 0;
`make test` 77 files attempted, 1 failed — the
single failure is the pre-existing
test_node115_catalogue Errno 18 cross-device-link
error, identical on pristine checkouts, not a
packet regression; this packet's file passes 8/8.

What remains unknown: everything in the README's
unresolved list, plus whether the three E8 caller
FDEs share one call convention (their argument
setup was inspected only enough to confirm the
call instructions, the flag-pointer passing, and
— for the selector — the post-call flag test,
not decoded).

Next question: decode the `0x63ae260` next-node call
end to end: what does it do with (thread,
[ref+`0xe410`], node, 0, kind, 1-or-0), what does
it return, when does it return NULL, and what does
its sixth argument select?
