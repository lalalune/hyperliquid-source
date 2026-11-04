# RE-001-node115-lu-classmerge: the node #115 lu class-merge consumer

- Component ID: lu class-merge consumer (tail-call target of the
  class-search helper, packet #230)
- Target release and full SHA-256:
  node #115, artifacts/node/115/hl-node, 105,896,032 bytes,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `8fd8db6`
  (node-115-only migration; confirmed unmoved before analysis)
- Claim status: observation / inference / unresolved (kept separate below)
- Scope included and excluded:
  - Included: the single FDE `0x63b9690..0x63b99c8`, its entry contract,
    its chain merge and relink mechanics, its return contract, and its
    caller census. The class-search tail-call site `0x63d940a` is cited
    from packet #230, not re-claimed.
  - Excluded: the class-search helper itself (#230), the size
    representative (#227), the slot-head helper (#225), and whatever the
    caller does with the returned minimum node (next question).

## Reproduce

Static analysis only; the node binary was never executed.

- Worktree: `hl-wt-calls231-115`, branch `codex/re-004-calls231-115`,
  from upstream main `8fd8db6` (main clone HEAD untouched at `2993e46`).
- `objdump -d --start-address=0x63b9690 --stop-address=0x63b99c8
  artifacts/node/115/hl-node` (GNU objdump; `.text` file offset = VA -
  0x1000).
- FDE bounds confirmed by `.eh_frame`:
  `FDE pc=0x63b9690..0x63b99c8` (readelf frames dump); the following
  bytes `0x63b99c8..0x63b99d0` are `int3` padding and the next function
  starts with `endbr64` at `0x63b99d0`.
- Census: whole-file byte scan for `E8`/`E9` rel32 and rip-relative
  `LEA` resolving to `0x63b9690`, each candidate confirmed by objdump;
  `.rela.dyn` addend scan over 60,723 entries.
- No execution, no network, no side effects beyond reading the binary.

## Evidence

Original addresses and coordinate system (VA; `.text` file offset = VA -
0x1000). Analysis was complete over the FDE: every instruction was read;
all 28 distinct branch targets were checked to lie inside the FDE.

Entry (exhibit `cs_entry`, `0x63b9690..0x63b96c6`, 54 bytes, 16 strict):
`endbr64`; pushes `r15, r14, r13, r12, rbp, rbx`; `rbx = [rdi]` (chain
head); `je 0x63b9918` if NULL (return NULL, `[slot+8]` untouched);
`rdx = [rbx+0x30]` (second node); `r13 = rbx+0x28`; `[rdi+8] := 0`;
`rbp = rdi` (slot entry saved); `je 0x63b9918` if `rdx` NULL
(single-node chain, return head).

First pair (exhibit `cs_pair`, `0x63b9700..0x63b9758`, 88 bytes,
23 strict): `r8 = [rax+8]` (third node's key); `[second+0x30] := 0`;
third node's `+0x28` pair zeroed; two-sided `setb`/`sbb` signum of
(second key, third key); `je 0x63b9998` when second < third (third
becomes second's first child, chain continues with second); otherwise
(second's `+0x28` pair := (third, third's first child),
`[third+0x38] := second`, chain continues with third). In both arms the
smaller key stays on the chain.

Inner loop (exhibit `cs_loop`, `0x63b97d4..0x63b97f6`, 34 bytes,
9 strict): the same signum idiom on the next adjacent pair
(`[first+8]` vs `[second+8]`); `jne 0x63b9770` when second <= first
(second stays, first becomes second's child); fallthrough when second >
first (first stays, second becomes first's child). Both `+0x28` pairs
zeroed before the compare; the winner is linked via the previous
winner's `+0x30`.

Phase B (exhibit `cs_phaseb`, `0x63b9840..0x63b9887`, 71 bytes,
18 strict): compare of accumulator key vs next-winner key with the same
idiom; `je 0x63b9958` when accumulator < next (next becomes
accumulator's child); otherwise the exhibited arm: accumulator's `+0x28`
pair := (next, next's old first child), old first child's `+0x28` :=
accumulator, `[next+0x38] := accumulator`, accumulator := next. The
loop walks the winners chain via `+0x30`, severing each pair's `+0x30`
before comparing, and links accumulator generations via
`[prev-acc+0x30] = new-acc`.

Final (exhibit `cs_final`, `0x63b98d1..0x63b991b`, 74 bytes,
20 strict): `r11 = [head+8]`, `r12 = [accumulator+8]`; signum idiom;
`je 0x63b9930` when accumulator > head (accumulator becomes head's
first child, head stays); otherwise the exhibited arm: head's `+0x28`
pair := (accumulator, accumulator's old first child), old first
child's `+0x28` := head, `[accumulator+0x38] := head`, `rbx :=
accumulator`. Then `0x63b9914`: `[rbp] := rbx` (slot head rewritten),
`rax := rbx`, pops, `ret` at `0x63b9925`.

Callers/callees/indirect calls: no `call` mnemonic in the FDE (0
instructions); no indirect branch; the only incoming edge found is the
`E9` tail jump at `0x63d940a` from the class-search helper (#230).
No `E8`, no rip-relative `LEA`, no `.rela.dyn` addend targets this FDE.

Source mapping evidence: none claimed. The symbol names objdump prints
are stripped-binary artefacts (`_ZNKSt5ctypeIcE8do_widenEc@@Base`
offsets) and are not used as evidence of identity.

ABI/layout/rounding/overflow observations: the sort compares one
64-bit word (`+0x08`) with unsigned `setb`/`sbb`; no rounding, no
overflow path, no shift, no division in this FDE. The `+0x28` pair is
written with a single 16-byte `movups`, so the parent/next-sibling
update is one instruction, not two stores.

## Implementation and comparison

Not yet implemented/measured. This packet is evidence only: no Rust
reconstruction, no two-build comparison, no gate is requested. The
static verifier (`tools/node115_lu_classmerge.py`) and unit tests
(`tests/test_node115_lu_classmerge.py`) check byte identity, strict
counts, FDE bounds, the single `ret`, zero calls, the tail-jump census,
and MANIFEST coverage — they do not execute the node.

## Results and limitations

Machine-readable metrics: FDE 824 bytes; 5 exhibits, 317 bytes,
86 strict instructions; census 0 E8 / 1 E9 / 0 LEA / 0 GOT (60,723
`.rela.dyn` entries); 28 distinct internal branch targets, all inside
the FDE; 1 `ret`, 0 `call`.

What passed: verifier exit 0, unit tests pass, `make verify` exit 0,
`make catalogue-check` exit 0, full `make test` with only the
pre-existing catalogue Errno 18 failure (see README verification note).

What remains unknown (see README "Unresolved"): the caller's use of
the returned minimum node; the roles of node words this FDE never
reads; whether phase-B accumulator `+0x30` links are traversable
afterwards; why the head's `+0x28` pair is zeroed while its `+0x30`
link is left until the final attach. `.bss` contents are runtime-filled
and not readable from the file; nothing here depends on them.

Finish with a concrete next question: decode the caller that receives
this consumer's returned minimum node — what does the class-search
caller do with the merged chain's minimum, and does the returned node
leave the class's slot or stay linked there?
