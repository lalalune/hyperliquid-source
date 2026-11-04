# RE-001-node115-lu-tablefill: the writer of the size-class base and tables

- Component ID: RE-001-node115-lu-tablefill
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes), `artifacts/node/115/hl-node`
- Source commit / reference commit: upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis)
- Claim status: observation for all byte claims; inference marked
  where the code shape implies a role; unresolved items listed
  separately
- Scope included and excluded: included — the writer FDE
  `0x63e8d90..0x63e9152` only, its three `.bss` outputs, its
  single caller site. Excluded — the descriptor builder
  `0x63da080`, the size helpers, the finder, and all caller FDE
  internals beyond argument setup (cited by address only).

## Reproduce

Working directory: the worktree at upstream main `8fd8db6`.
`objdump -d --start-address=0x63e8d90 --stop-address=0x63e9152
artifacts/node/115/hl-node` reproduces the full FDE disassembly;
`readelf --debug-dump=frames-interp artifacts/node/115/hl-node`
shows `FDE pc=00000000063e8d90..00000000063e9152`.
`python3 tools/node115_lu_tablefill.py` (exit 0) and
`python3 -m unittest tests.test_node115_lu_tablefill` (10/10)
re-check every exhibit byte, strict count, key address, census
site, and MANIFEST entry. No execution of the node binary at any
point; no side effects beyond reading files.

## Evidence

Coordinate system: `.text` file offset = VA − 0x1000
(`.text` VMA `0x1419300`, file offset `0x1418300`, size
`0x4fd7700`); `.bss` addresses are runtime addresses, not file
offsets, and no `.bss` contents are quoted (they are not in the
file).

Validated boundaries (unwind table): FDE `0x63e8d90..0x63e9152`,
962 bytes, one `ret` site (`0x63e913c`, preceded by `pop %rbx;
pop %rbp`), `int3` padding from `0x63e9152` to the next FDE at
`0x63e9160`. Zero `call` instructions in the FDE (objdump
mnemonic count); all jump targets inside the FDE.

Entry (`wr_entry`, `0x63e8d90`, 40 bytes, 10 strict): `endbr64`,
`movzbl %sil,%eax`, `push %rbp`, `mov %rdi,%r8` (record),
`lea 0x19b0(%rdi),%r11` (loop-1 end), `shl $0xc,%rax`,
`push %rbx`, `xor %esi,%esi` (table index 0),
`lea 0x6728180(%rip),%r10` (table `T`),
`mov %rax,0x6728140(%rip)` (base `B := byte << 12`).

First sub-block (`wr_block`, `0x63e8dc8`, 37 bytes, 12 strict):
flag `cmpb $0,0xc(%rdi)` with `je` to the next block's check;
`mov 0x4(%rdi),%ecx` (shift1), `movslq 0x8(%rdi),%rdx`
(value), `movslq %esi,%rbx` (index), `add $0x1,%esi`,
`shl %cl,%rdx`, `mov (%rdi),%ecx` (shift2),
`shl %cl,%rbp` (`rbp` = 1), `add %rbp,%rdx`,
`mov %rdx,(%r10,%rbx,8)` — `T[i] = (value << shift1) +
(1 << shift2)`. The remaining six blocks per entry repeat this
shape at sub-block offsets `+0x1c, +0x38, +0x54, +0x70, +0x8c,
+0xa8`, with flag checks at `+0x28, +0x44, +0x60, +0x7c, +0x98,
+0xb4` (each block's `+0x0c`). Loop stride `0xe0` (`lea
0xc4(%rdx)` with `rdx` = entry `+0x1c`); 29 entries from
record `+0x50` to record `+0x19b0`.

Tail (`wr_tail`, `0x63e8f23`, 33 bytes, 7 strict):
`cmp $0xc7,%esi; jg 0x63e8f44` (skip when count > 199),
`movslq %esi,%r11`, `mov 0x40(%r8),%rsi`,
`lea 0x6728180(%rip),%r9`, `lea 0x1000(%rsi),%r10`,
`mov %r10,(%r9,%r11,8)` — `T[count] = [record+0x40] +
0x1000`. Loop 1 itself has no per-store bound check: with all
flags set it could append 29 × 7 = 203 values, past the 200
table slots; only the tail store is guarded.

Second loop (`wr_array`, `0x63e8f60`, 51 bytes, 13 strict):
sample of the unconditional expansion — `mov 0x4(%rax),%ecx`
(shift1), `movslq 0x8(%rax),%rdi` (value),
`movslq 0x24(%rax),%rsi` (next block's value),
`add $0x40,%rdx`, `add $0xe0,%rax`, `shl %cl,%rdi`,
`mov -0xe0(%rax),%ecx` (shift2), `shl %cl,%rbx`,
`mov -0xc0(%rax),%ecx` (next shift1),
`add %rbx,%rdi` (expanded value). Loop bounds: `rdx` from
`0x6727a00` to `0x6728140` (`+0x740`) in `0x40` steps — 29
iterations × 8 stores = 232 qwords, ending exactly at `B`.

Third loop (`wr_fill`, `0x63e90f6`, 31 bytes, 8 strict):
`mov %rsi,%rcx` (`rsi` = 1 throughout), `lea (%rax,%r11,1),
%rdi` (table `0x67277c0` + position), `sub %rax,%rcx`,
`movzbl %bpl,%eax` (sub-block index), `add %r9,%rcx` (fill
length = `end − pos + 1`), `imul %r10,%rax`
(`0x0101010101010101` byte replication), `cmp $0x8,%rcx`,
`jb` to the byte/word/dword tails. Preceding computation (loop
head `0x63e90b8`): `rbx = record + 28 × ebp`,
`r9 = min(512, ((value << shift1) + (1 << shift2) + 7) >> 3)`;
`jb 0x63e909d` skips when `end < pos`; otherwise the fill
runs and `rax := end + 1`, `ebp += 1`. Exit when `ebp > 231`
(`0xe7`) or `rax > 512` (`0x200`).

Callers/callees: no callees (0 calls). One direct E8 caller,
`0x634edce`, in FDE `0x634ece0..0x634f09d`: `movzbl
0x64ffb5c(%rip),%esi` (byte), `mov %rbx,%rdi` (descriptor at
`rsp+0xf0`, 0x19b0 bytes zeroed by `rep stos` then filled by
`0x63da080`), `call 0x63e8d90`; return value ignored. Whole
`.text` E8/E9 rel32 scan + `.rela.dyn` addend scan (60,723
entries, no addend equal to `0x63e8d90`) confirm 1 E8, 0 E9,
0 LEA, 0 GOT.

Analysis was complete over the FDE (all three loops traced to
their exits); `.bss` contents, the descriptor builder, and the
`0x6727a00` array's consumer are out of scope here.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed
for this helper in this packet. The verifier and unit tests check
byte-level reproduction of the exhibits only.

## Results and limitations

Metrics: 5 exhibits, 192 bytes, 50 strict mnemonics; FDE 962
bytes; census 1 E8 / 0 E9 / 0 LEA / 0 GOT; MANIFEST 15/15.
`make verify` exit 0 (29 manifests, 471 entries);
`make catalogue-check` exit 0; `make test` 77 files, 1 failure
(pre-existing catalogue Errno 18, identical on pristine
checkouts). No gate is requested by this packet alone.
Remaining unknowns are listed in README.md. Next question:
decode `0x63da080` end to end — what descriptor it builds on
the caller's stack.
