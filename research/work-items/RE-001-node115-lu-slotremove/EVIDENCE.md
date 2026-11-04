# RE-001-node115-lu-slotremove: the node #115 lu slot-remove helper

- Component ID: lu pool slot chain maintenance (remove helper `0x63acb40`).
- Target release and full SHA-256: node #115, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: upstream main
  `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (fetch-confirmed unmoved
  before analysis).
- Claim status: observation for all byte-level claims below; inference for
  the (slot, node) argument naming; unresolved for the chain invariant, the
  slot second word, and the caller-to-#222 mapping.
- Scope included and excluded: included — the remove FDE
  `0x63acb40..0x63ad582` (2626 bytes), its three direct callers, and the
  `.rela.dyn` GOT check. Excluded — caller FDE bodies (cited by address
  only), the paired callee `0x63abcf0`, and any Rust reconstruction.

## Reproduce

Working directory: the worktree root. Tools: GNU objdump/readelf (binutils),
python3 (stdlib only). No execution of the node binary at any point.

```
git worktree add ~/workspace/hl-wt-calls223-115 -b codex/re-004-calls223-115 origin/main
sha256sum artifacts/node/115/hl-node
# a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
objdump -d --start-address=0x63acb40 --stop-address=0x63ad582 artifacts/node/115/hl-node
python3 tools/node115_lu_slotremove.py   # exit 0
python3 -m unittest tests.test_node115_lu_slotremove -v   # 9/9
```

Coordinate system: `.text` file offset = VA − 0x1000 (`.text` VA
`0x1419300`, file offset `0x1418300`, size `0x4fd7700`).
`.data.rel.ro`/`.got` = VA − 0x2000, `.rodata` = VA as-is. RELATIVE
`.got` slots are zero-filled in the file, so the GOT census uses
`.rela.dyn` addends (file offset `0x6be8`, size `0x163cc8`, 60,723
entries of 24 bytes).

## Evidence

FDE bounds from `tools/fde_extents.py --release 115` (`.eh_frame`):
`0x63acb40..0x63ad582`, 2626 bytes. Entry bytes `f3 0f 1e fa`
(`endbr64`) followed by six pushes and `mov %rsi,%r9`. The FDE holds
686 strict instruction lines, zero `call` mnemonics, one `ret`
(`0x63acd43`, shared exit with six pops).

Entry dispatch (exhibit `rm_entry`, 33 bytes, 12 strict): `mov (%rdi),%r10`
then `cmp %r10,%rsi`, `je 0x63acd70` — `[slot]` against the node.

Non-head guard (exhibit `rm_nonhead`, 27 bytes, 7 strict):
`mov 0x28(%r9),%r10` (P = `[node+0x28]`), `mov 0x10(%r11),%rax`
(B = `[node+0x38]`, since `r11 = node+0x28`), `test %r10,%r10`,
`lea 0x28(%r10),%r13`, `cmp 0x38(%r10),%r9`, `je 0x63ad050` — the
fast paths require `[P+0x38] == node`.

Key idiom (exhibit `rm_signum`, 51 bytes, 16 strict): the first loop's
`+0x20` compare, `setb`/`sbb` signum, `+0x8` tiebreak, second
`setb`/`sbb`, `cmp $-1`, `je 0x63ad020`. Across the FDE there are 20
`setb` instructions forming 10 such idioms (at `0x63acbce`,
`0x63acca9`, `0x63acdf0`, `0x63aced8`, `0x63acf65`, `0x63ad097`,
`0x63ad1c5`, `0x63ad2a7`, `0x63ad38c`, `0x63ad4f8`, each with its
`+0x8` tiebreak `setb`). Every idiom compares two adjacent chain
nodes, never the target node against a searched key.

Head path (exhibit `rm_head`, 49 bytes, 11 strict): `mov 0x10(%r11),%rcx`
(`[node+0x38]`), `mov 0x8(%r11),%rdx` (`[node+0x30]`), `mov %rdi,%r8`,
`test %rcx,%rcx`, `je 0x63ad230`, `movq $0,0x8(%rdi)` (`[slot+8] := 0`),
`test %rdx,%rdx`, `je 0x63ad260`, `pxor %xmm0`, `lea 0x28(%rdx),%rdi`,
`movups %xmm0,0x28(%rsi)` (node `+0x28` pair zeroed).

Fast relink (exhibit `rm_relink`, 24 bytes, 7 strict), at `0x63acd21`:
`mov %r10,(%r8)` (`[B+0x28] := P`), `mov %rsi,0x10(%r13)`
(`[P+0x38] := B`), `mov 0x8(%r11),%r9` (`[node+0x30]`),
`mov %r9,0x8(%r8)` (`[B+0x30] := [node+0x30]`),
`test %r9,%r9`, `je 0x63acd39`, `mov %rsi,0x28(%r9)`
(successor `+0x28` := B).

Callers (whole-`.text` E8 scan with rel32-target filter, per-site objdump
confirmation): `0x636359f`, `0x6363a6f`, `0x63b0847`. No E9, no
RIP-relative LEA, no `.rela.dyn` addend equal to `0x63acb40`.
Caller FDEs: `0x6363560..0x636365a` (250 bytes),
`0x63637f0..0x6363d50` (1376 bytes), `0x63b0780..0x63b097f` (511 bytes).

Caller 1 (`0x636359f`): `shr $0x14,%rax`, `movzbl`, `lea (%rcx,%rcx,4)`,
table entry, `cmpl $0x1,0x10(%r9)`, `je` past the call, `rdi = rbx+0xc8`,
`rsi = rdx`, call, `subq $0x1,0xb8(%rbx)`.
Caller 2 (`0x6363a6f`): identical shape (`cmpl $0x1,0x10(%r9,%rdx,8)`,
`je`, `rdi = rbx+0xc8`, `rsi = r15`, call, `subq $0x1,0xb8(%rbx)`).
Caller 3 (`0x63b0847`): `rsi = rbx`, `rdi = r13` (computed slot
pointer), call, then `rdi = r13`, `call 0x63abcf0` — a paired
sequence with no `+0x10` guard.

Store-base audit: in the traced merge loops every store targets a
chain-neighbor word (`(%rdi)`, `(%r8)`, `(%rbx)`, `(%r10)`,
`0x28(%r13)`, `0x10(%r8)`, and the like, where the base walks chain
nodes). Across the whole FDE, the only stores whose base is the entry
node (`%r9`) or `node+0x28` (`%r11`) are the two rotation-block stores
at `0x63ad0d9` and `0x63ad42d`; every other `%r9`/`%r11`-based line is
a load or uses a register reassigned to a chain node (for example
`0x63acd35` stores to the successor after `r9 := [node+0x30]`).
The removed node's own link words are therefore written only on the
head path: pair-zeroed at `0x63acd9d`, and rewritten as a pair in the
`0x63ad078` rotation block (`node+0x28 := successor`,
`node+0x30 := [successor+0x38]`, `[successor+0x38] := node`,
`[slot] := successor`).

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed for this
helper, and no machine-code equivalence is asserted. The verifier is a
byte-level checker only (exhibits, key bytes, census, MANIFEST).

## Results and limitations

- 5 excerpts, 184 bytes, 53 strict mnemonics; FDE 2626 bytes, 686
  strict instruction lines, 0 calls, 1 ret, 10 signum idioms.
- Census denominators: whole `.text` (83,719,936 bytes scanned for E8/E9/
  LEA), 60,723 `.rela.dyn` entries for GOT.
- Passed: verifier exit 0, unit tests 9/9, `make verify` exit 0,
  `make catalogue-check` exit 0, full `make test` with only the known
  pre-existing catalogue Errno 18 failure.
- Unknown: chain invariant and key order direction; `[slot+8]`
  semantics; which caller is #222's collect sibling; `0x63abcf0`'s
  purpose; the `0x63b0780..0x63b097f` caller FDE's overall behaviour.
- Next question: decode the `0x63b0780..0x63b097f` caller FDE end to
  end: what it does with its slot before and after the remove call, and
  why it immediately calls `0x63abcf0` with the same slot.
