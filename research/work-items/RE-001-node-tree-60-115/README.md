# RE-001: map node #115 0x60-byte tree teardown, copy, and string builder

## Bounded question

Open PR #2388 mapped the 0x30-byte list-tree copy at `0x5d4caa0`
and open PR #2386 its teardown at `0x5d4c8d0`. A neighbouring
family works on wider nodes — the large function at
`0x5d80440..0x5d81813` and its sibling consumer at
`0x5d7fc80..0x5d8043e` both use it. What is that family, end to
end: how are its nodes laid out, how does teardown free them,
how does copy rebuild them, how are their strings built, and
how do the two consumers use them?

## Answer, stated literally

Three routines, all in node #115 (digest below):

### Node layout (0x60 bytes)

- `+0x00` dword tag: copied verbatim by copy, never read by teardown.
- `+0x04..+0x07`, `+0x0c..+0x0f`: untouched by both routines; a fresh
  copy leaves them uninitialized, exactly as the 0x30-byte family does.
- `+0x08` link value: copy stores the incoming link (head) or the
  previous copy (sibling); teardown never reads it.
- `+0x10` next sibling; `+0x18` child-list head.
- `+0x20` string A: pointer at `+0x20`, size at `+0x28`,
  capacity-or-inline at `+0x30`.
- `+0x40` string B: pointer at `+0x40`, size at `+0x48`,
  capacity-or-inline at `+0x50`.

A string is inline exactly when its stored pointer equals the
address of its own capacity/inline slot (`+0x30` for A,
`+0x50` for B) — that is the comparison the binary performs.
A heap string is freed with operator delete (PLT `0x63f0d80`)
as `delete(ptr, capacity + 1)`.

### String builder 0x5d4a6a0 (FDE 0x5d4a6a0..0x5d4a743)

Takes a destination string object in `rdi`, a source begin in
`rsi`, and a source end in `rdx`; returns void. Length is
`end - begin`.

- Length at most 15 (short path): the buffer is the qword already
  stored at `dst+0x00` — the copy routines preset it to the
  destination's own inline slot before calling. Length 1 copies
  one byte, length 0 copies nothing; the tail then stores the
  length at `dst+0x08` and a NUL byte at `buffer + length`.
- Length over 15 (long path): it calls the string `_M_create`
  PLT (`0x63f0e10`) with the length, stores the returned buffer
  at `dst+0x00` and the capacity at `dst+0x10`, copies `length`
  bytes with memcpy (PLT `0x63f0a60`), then the same tail
  (size at `+0x08`, NUL at `buffer + length`).
- A stack canary is checked on return (`__stack_chk_fail` PLT
  `0x63f0d70` on mismatch). The builder never reads the
  destination's size field and never writes the capacity field
  on the short path.

Model assumption, stated explicitly: the model normalizes a
heap string's capacity to the requested length; the binary's
`_M_create` may reserve more, which changes no observable
byte, size, or NUL-terminator behaviour.

### Teardown 0x5d4cfd0 (FDE 0x5d4cfd0..0x5d4d041)

Takes one list head in `rdi`, returns void. A null head frees
nothing (explicit early return). Otherwise it loops over the
`+0x10` chain; per node, in this order:

1. Recurse into the node's `+0x18` child-list head (site
   `0x5d4cfe7`); that recursive call walks the child's own
   `+0x10` chain by the same rule.
2. Dispose string B (`+0x40`): delete unless its pointer equals
   `&node+0x50`, with size `qword at +0x50 + 1`.
3. Dispose string A (`+0x20`): delete unless its pointer equals
   `&node+0x30`, with size `qword at +0x30 + 1`.
4. Delete the node itself with size `0x60`.
5. Advance to the `+0x10` successor (loaded before the delete,
   so the chain survives the free) and repeat.

Worked order: head A with child chain C -> D (D having child
E) and sibling B frees C, E, D, A, B — children before their
node, siblings after it. Teardown writes nothing itself; every
effect is operator delete. It never reads the tag, the link,
or either string's size field.

### Copy 0x5d4d050 (FDE 0x5d4d050..0x5d4d241)

Takes a source head in `rdi` and a link value in `rsi`, returns
the head copy in `rax`. Per source node it allocates one fresh
`0x60` node (operator new, PLT `0x63f0dd0`), copies both
strings with the builder (destination presets: copy `+0x20`
points at copy `+0x30`, copy `+0x40` points at copy `+0x50`;
source end = source pointer + source size), copies the dword
at `+0x00`, stores the link at `+0x08`, and zeroes `+0x10`
and `+0x18` up front.

- Head copy link: the incoming `rsi` verbatim.
- Child: if the source `+0x18` is nonzero, a recursive copy
  (sites `0x5d4d0d3` for the head's child, `0x5d4d161` for a
  sibling's child) with the copy itself as the link value is
  stored at copy `+0x18`.
- Siblings: each source `+0x10` successor gets a fresh copy
  whose link is the previous copy; the previous copy's `+0x10`
  is set to it before that sibling's own child subtree is
  copied.

Allocation order: head, then the head's child subtree
(depth-first, siblings in order), then each sibling in order
with its own child subtree. A copy's string is inline exactly
when its length is at most 15, whatever the source form was —
a heap source string of length 10 becomes inline in the copy.
The source tree is never written.

Exception landing pads, stated literally (pad-to-region mapping
is NOT claimed): pads dispose a partially built string with
`_M_dispose` (PLT `0x63f0db0`) and/or delete the fresh `0x60`
node, then `__cxa_begin_catch` / `__cxa_rethrow` /
`__cxa_end_catch` / `_Unwind_Resume` as shown in copy.txt.
One pad (`0x5d4d205..0x5d4d212`) calls `__cxa_begin_catch`,
then teardown on the head copy in `r12` (site `0x5d4d20d`),
then `__cxa_rethrow` — so a failed copy destroys the partial
head copy with the teardown above instead of leaking it.

### Consumers (site-only; caller semantics beyond the sites are NOT claimed)

- Copy sites `0x5d80073` and `0x5d80109`, both in
  `0x5d7fc80..0x5d8043e`, each guarded by a null test on the
  source head (`[rbp+0x2e8]` and `[rbp+0x318]` respectively).
  After each call the consumer walks the copy's `+0x10` chain
  to its last node and its `+0x18` chain to its last node and
  stores the head copy, both last nodes, and a further field
  into its own object (`[rbx+0x2e8]/[rbx+0x2f0]/[rbx+0x2f8]`
  for the first site, `[rbx+0x318]/[rbx+0x320]/[rbx+0x328]` for
  the second). See sites_copy1.txt and sites_copy2.txt.
- Teardown cleanup site `0x5d8037f` in the same consumer:
  a cleanup block destroys the `[rbx+0x2e8]` list with
  teardown, then disposes three strings. See
  sites_teardown_cleanup.txt.
- Teardown loop sites `0x5d8061c` and `0x5d8067e` in
  `0x5d80440..0x5d81813`: the caller inlines the same destroy
  sequence for its own lists at `[r13+0x318]` and
  `[r13+0x2e8]` — per node it calls teardown on the node's
  `+0x18` child head, disposes the `+0x40` string, disposes
  the `+0x20` string, deletes the node with size `0x60`,
  and advances via `+0x10`. See sites_teardown_loops.txt.
- The builder's other 75 direct call sites and teardown's
  other 18 direct call sites are recorded by address and
  caller function in callers.tsv only, NOT individually
  excerpted or modelled — this PR pins the three routines
  and claims no caller semantics beyond the sites above.

## What is NOT claimed

What the nodes, tags, links, or strings denote; the
`_M_create` allocator's internals or its reserved capacity
beyond the requested length; any behaviour of copy on a null
source head (the binary dereferences it before any check —
the model raises instead, as a stated guard); any behaviour
on a cyclic tree (the binary would recurse without bound —
the model raises instead); landing-pad-to-region mapping;
caller semantics beyond the sites above; the contents of the
untouched node bytes in a fresh copy.

## Distinctness

Distinct from open PR #2386 (0x30-byte teardown `0x5d4c8d0`)
and #2388 (0x30-byte copy `0x5d4caa0`) — different routines,
different node size, different string handling — and from
open PR #2407/#2403 (the map wrapper/lookup family, disjoint
addresses). No address overlap with any open WalkCrypto PR
(code search 0 hits for `5d4cfd0`, `5d4d050`, `5d4a6a0`;
open titles 0 hits).

## Evidence

All extracted from the digest-verified node #115 work binary
(SHA-256 `a6e2897c…5301`, `work/hl-node-115.bin` hashes
exactly; full digest in records.json and verify.py, bound to
`provenance/artifacts.json`). Packet contents: semantic
records.json only (no per-instruction mnemonic list —
instruction detail lives only in the verbatim excerpts);
whole-function verbatim excerpts teardown.txt, copy.txt,
helper.txt; verbatim site excerpts sites_*.txt; frames.txt;
relocations.txt (empty — intentionally: a fresh relocation
dump has no RELATIVE line for any of the three routines, and
no stored qword for any of them in the raw binary);
callers.tsv with all 106 direct call sites (teardown 23,
copy 4, builder 79; no tail jumps); verify.py,
export_excerpts.py, census.py in the packet; MANIFEST.sha256.
The disassembly text is exactly as objdump emits it:
instruction mnemonics such as `endbr64` are genuine
instructions present in the target binary, not placeholders.

Objdump command used for the excerpts (from the repo root):

    objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin

Environment limits, stated honestly: this VM has no
cargo/rustc, no git-lfs, no Ghidra/Java. All claims above
are static disassembly plus the Python model and its tests;
no Rust reconstruction or dynamic execution is claimed.
