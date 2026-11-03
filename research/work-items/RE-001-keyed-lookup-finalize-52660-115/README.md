# RE-001: map node #115 keyed lookup finalize 0x5d52660

Bounded question: after the slot replace routine builds a
flag-zero node, what does its wrapper callee 0x606c680 do
with the node, and what does the lookup routine 0x5d52660
it calls decide from the key object's tree?

## Answer, end to end

Two whole routines, one behavior: finalize a freshly built
node from a keyed range lookup. The wrapper 0x606c680
(37 bytes, FDE 0x606c680..0x606c6a5) takes a node in rdi
and two values in rsi and rdx, which it passes through
unchanged. It reads the key pointer at node +0x68. If the
key is null, it writes 0 to node +0x60 and returns 0,
calling nothing. Otherwise it calls the lookup 0x5d52660
at 0x606c69b with (key, value1, value2, &node +0x08,
&node +0x20), stores the lookup's return byte at
node +0x60, and returns that byte in rax. The wrapper
itself has no stack canary, no indirect transfers, and
no landing pad; bytes at 0x606c6a5..0x606c6b0 are int3
padding, not part of the routine.

The lookup 0x5d52660 (261 bytes, FDE
0x5d52660..0x5d52765) takes a key object in rdi, a search
value value1 in rsi, an upper bound value2 in rdx, an
out pointer out1 in rcx, and an out pointer out2 in r8.
It runs, in order:

1. Null-out early return: if out1 or out2 is null, it
   returns 0 at once. Neither the auxiliary callee nor
   the release callee runs, and nothing is written.
2. Auxiliary call: otherwise it calls 0x606ca40 at
   0x5d526b8 with (key +0x988, value1, value2, out1,
   out2). What that callee does with those arguments is
   not pinned here; only its argument list and its
   position before the walk are.
3. Tree walk, lower-bound shape: it starts at the root
   pointer in key +0xcb0, with the header address
   key +0xca8 as the not-found sentinel. At each node
   it reads the left child (+0x10), the right child
   (+0x18), and the compared field (+0x20). If the field
   is unsigned-below value1 it goes to the right child;
   otherwise it records the node as the candidate and
   goes to the left child. A null child ends the walk
   with the last candidate, or with the sentinel when
   no candidate was recorded. An empty tree (a null
   root) ends the walk at once. All comparisons are
   unsigned (jb/jae in the binary).
4. Range failure: if the candidate is the sentinel, or
   the candidate's field is unsigned-greater-or-equal
   to value2, it calls 0x60d52f0 at 0x5d52726 with
   (key +0x988) and returns 0. The walk itself writes
   nothing on this path.
5. Range match: if the candidate's field is
   unsigned-below value2, it writes the candidate's
   field to *out1 at 0x5d52738, calls 0x5d4e140 at
   0x5d52742 with (out2, candidate + 0x28), calls
   0x60d52f0 at 0x5d5274f with (key +0x988), and
   returns 1.

So the accepted range is value1 <= matched field <
value2, with the matched field being the smallest tree
field that is >= value1. On success the node ends with
+0x08 = the matched field, +0x20 filled through the
payload callee, and +0x60 = 1. On failure the node
keeps whatever +0x08 and +0x20 it had (the walk writes
neither), and +0x60 = 0. The lookup has no stack
canary. Its landing-pad entry at 0x5d52759 (endbr64)
jumps at 0x5d52760 to the shared cleanup block at
0x5d5264c in the preceding routine, which calls
0x60d52f0 and then _Unwind_Resume; that stub is not a
normal-flow exit and its cleanup ownership is not
claimed. Bytes at 0x5d52765..0x5d52770 are int3
padding; the next routine starts at 0x5d52770.

## Consumers: one direct call, one tail jump

The census (reproduced by census.py, re-run inside
verify.py) finds the wrapper has exactly 1 direct call
and 1 tail jump, and the lookup exactly 1 direct call
and 0 tail jumps; neither routine has a stored qword
or a RELATIVE addend in the file.

- Direct call at 0x5d4cd33 in the slot replace routine
  (FDE 0x5d4cc80..0x5d4ce6a): the flag-zero path calls
  the wrapper after storing the key at node +0x68 and
  1 at node +0x60, so the wrapper overwrites +0x60
  with the lookup result. In that context value1 is
  the slot replace routine's rdx value and value2 its
  rcx value. This also answers the open question left
  by the slot replace packet: the flag-zero path's
  +0x08 slot IS written by this finalize path, but
  only on a range match, through the lookup's *out1
  write — not unconditionally.
- Tail jump at 0x606c6d6 in the routine at
  0x606c6b0..0x606c6db: that caller reads node +0x18,
  calls 0x606c190 with the node, then tail-jumps to
  the wrapper with (node, 0x606c190(node) + 1,
  node +0x18). The helper's own semantics are not
  pinned; only the argument derivation at the site is.
- The lookup's only caller is the wrapper itself, at
  0x606c69b.

## Evidence format

Instruction-level detail lives only in the raw
disassembly excerpts (wrapper.txt, lookup.txt), kept
verbatim and whole-function; the JSON in this packet
holds semantic records only, never a per-instruction
mnemonic list. Mnemonics such as `endbr64` that appear
in the excerpts are genuine instructions present in
the target binary, not placeholders: verify.py checks
every excerpt instruction byte-for-byte against the
raw binary, and the spot checks below re-verify
individual instructions against a fresh objdump run.

Tool versions: GNU objdump/readelf, Binutils 2.42;
Python 3.12.3. Reproduce from the repository root:

    python3 research/work-items/RE-001-keyed-lookup-finalize-52660-115/export_excerpts.py
    python3 research/work-items/RE-001-keyed-lookup-finalize-52660-115/census.py
    python3 research/work-items/RE-001-keyed-lookup-finalize-52660-115/verify.py
    python3 tests/test_keyed_lookup_finalize_52660_115.py

Spot instructions verified byte-for-byte against a
fresh objdump run and the raw binary (beyond the
spots verify.py checks itself): 0x606c688
(mov 0x68(%rdi),%rdi), 0x5d526e8
(cmp %rbx,0x20(%rdx)), 0x5d52738
(mov %rax,(%r15)).

## Not claimed

What the key object, the node, or the two values
denote; what the auxiliary callee 0x606ca40, the
release callee 0x60d52f0, the payload callee
0x5d4e140, or the tail-jump consumer's helper
0x606c190 do beyond their argument lists and call
order; whether 0x606ca40 writes through out1 or out2;
what the auxiliary structure at key +0x988 is; the
landing-pad cleanup semantics beyond the two visible
calls at 0x5d5264c; the purpose of the tail-jump
consumer routine beyond its site and argument
derivation; behaviour on dangling pointers, cyclic
trees, or a null node/key (the model raises on a null
node or key, and assumes a finite tree); the class or
type owning the tree (no RTTI/typeinfo parsed).
Repository-wide gates are not claimed here: the
baseline `make verify` / `make test` /
`make catalogue-check` state is affected by missing
LFS material and by the absence of cargo/rustc on
this machine, so only this packet's checker and its
model tests are claimed green.

## Next step

The flag-nonzero insert callee 0x606ef50 (FDE
0x606ef50..0x606f91f, 2511 bytes) is the remaining
half of the slot replace pair: it builds far more
than a flag byte, including a formatted string and a
call to 0x606eb60. Mapping it the same way would
close the slot replace story on both flag paths.
