# Flag-gated chain predicate, full-return and termination proof

This proof concerns node #94 `[0x51a5d60,0x51a5da8)`, 72 bytes, target SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
It establishes the returned value for every admitted normally terminating path,
and distinguishes the new safe bounds/cycle outcomes. Memory is ordinary,
readable and stable for the entire call. Target correspondence additionally
requires actual valid mappings, unchanged code and normal execution/return
behavior. Faults, MMIO, concurrent mutation or read observation, and CPU flags
are outside the claim. Symbolic test addresses do not establish target mappings.

## Complete body, CFG and caller binding

`verify_static.py` first checks all 91,774,280 target bytes against the digest.
The complete leaf body SHA-256 is
`80708970d69bcb62f58f3ae6811f4f5b13f4834362ff3c4308100775c8ff80c4`.
Its exact CIE/FDE and the neighboring `[0x51a5b20,0x51a5d52)` and
`[0x51a5db0,0x51a5f09)` FDEs distinguish the 14 leading and eight following
INT3 bytes from the selected body. The selected FDE has no LSDA.

Fresh GNU, LLVM and Capstone decodes agree on all 25 leaf instructions and all
949 instructions of the complete caller `[0x51fd4c0,0x51fe69d)`, 4,573 bytes,
SHA-256 `ed7cf74c69dd8c7e8571c108aa942006c57e8a91688f7c50cc16cf5912fc84da`.
The raw exports need no prefix grouping. All five leaf branches stay inside the
body: JNE at `0x51a5d6d` goes to `0x51a5d98`; JNE at `0x51a5d76` to
`0x51a5d88`; JMP at `0x51a5d78` and JE at `0x51a5d86` to `0x51a5da0`;
JE at `0x51a5d8d` to `0x51a5d80`. The three returns are `0x51a5d91`,
`0x51a5d9c`, and `0x51a5da7`. Internal NOPs remain in the complete body.
There are no helper calls, stores or external constant loads in the leaf.

The whole-text E8 scan finds exactly `0x51fd9e5`; it is separately confirmed at
a complete caller instruction boundary and followed by `test al,al` at
`0x51fd9ea`. The E9-relative jump scan finds no candidate. All 80,300 RELA
records have reviewed eight-byte destination kinds (1,6,7,8,18), none naming
this entry as addend or writing protected leaf/padding/caller code. This is a
bounded encoding/relocation census, not exhaustive indirect-reference discovery.
The caller's other helpers, data, purpose and source types are not reconstructed.

## Exact read order and full RAX

Let `M=2^64`, and let memory loads be little-endian. The original sequence is:

1. Load object pointer `p` from the entry RDI address.
2. Load byte `f` at `(p+112) mod M`. If nonzero, return 0.
3. Load chain head `n` from `(p+72) mod M`. If zero, return 1.
4. Load qword `v` at `(n+16) mod M`. If nonzero, return 0.
5. Load next pointer from address `n`. If zero, return 1; otherwise repeat at
   step 4 with that pointer.

There is no null-object shortcut: a numeric zero `p` is handled by its two field
addresses if the selected path needs them. A zero chain pointer is the terminal
sentinel. The byte flag and node qword have different widths. Any of their
nonzero bit patterns activates its corresponding return; signedness does not
change a comparison against zero.

The flag load MOVZX writes EDX. Entering the chain implies that EDX is exactly
zero; no instruction in the chain modifies it. A nonzero node field returns
through `mov edx,eax`, giving full RAX zero through 32-bit zero extension. The
flag-set path explicitly clears EDX before the same full-width move. The null
path writes EDX=1 then EAX=EDX. Hence every normal return has the complete
64-bit value 0 or 1, not merely a meaningful low byte.

No pointer/field is read after its earlier short-circuit return. In particular,
a nonzero flag does not demand a valid head location, and a nonzero node field
does not demand a readable node link. Object, node and wrapper regions may
overlap arbitrarily without changing this reasoning because no data is written.

## Reachability relation and nontermination

After the flag gate, treat each nonzero pointer with a readable zero field and
readable link as a vertex with one successor: that link value. A visited pointer
with a nonzero field is a terminal false result. Null is a terminal true result.
An unmapped required access has no admitted normal-return correspondence and
receives a new safe bounds error.

On a stable image the successor and field of any given pointer are constant.
If a zero-field vertex repeats before a terminal result, the subsequent walk
repeats the same successor sequence forever. It cannot newly reach null, a
nonzero field or an invalid access after the repeated prefix. Conversely, any
infinite walk in a finite image with all accesses valid must repeat a vertex.
An all-zero cycle therefore has no original normal return; returning true just
because every inspected field was zero would be incorrect.

## Image-derived bound, without an arbitrary node cap

For an image of length `L`, there are exactly `N=max(L-7,0)` possible starting
offsets for an eight-byte access: `0..L-8` when `L>=8`. Each successful link load
uses one of these addresses. This count allows byte alignment and overlapping
node storage; using `L/24` or assuming a node stride would be unjustified.

The Rust loop starts `remaining=N`. It tests the node field and reads the link
first, then checks the counter. After `k` zero-field, valid-link traversals with
`k<=N`, `remaining=N-k` and the current pointer is exactly the native successor.
If a further zero-field, valid-link node is encountered at `remaining=0`, the
trace has visited `N+1` valid qword-start addresses. By the pigeonhole principle,
some address repeats. The stable-successor argument above proves a zero cycle,
so `Cycle` is justified. Counter decrement occurs only when positive.

Checking the bound after the field and link matters. A terminal nonzero field
does not require a valid link and must return false first. A missing link must
produce its bounds error, not an unproved cycle diagnosis. This order preserves
all terminating paths: if such a path exceeded the derived bound through valid
zero-field links, it would already contain a cycle and could not terminate,
a contradiction.

Thus every successful Rust result equals the original normal-return predicate.
Every reported Cycle is a proved nonterminating original walk on the same stable
image. Every input finishes after at most `N+1` loop iterations, without dynamic
allocation or usize counter overflow. Worst-case work is O(L), including for a
short cycle in a large image; this implementation chooses that simple proved
bound rather than storing a visited-node set.

## Address admission and safe implementation

Image byte `j` denotes `image_base+j`. The last address of a nonempty image must
fit u64; an image ending at `u64::MAX` is permitted. `bytes<N>` checks address
subtraction, usize conversion, endpoint addition and slice inclusion before
reading. Each admitted range has exactly N bytes, so fixed-size conversion is
safe. All field displacement additions wrap modulo M before this span check,
matching the native effective-address calculation. The accessed range itself
must be nonwrapping and mapped by the image. For example, a node at `M-16`
has its field at address zero; a nonzero field can return without requiring
the unmapped link at `M-16`.

The library uses immutable slices and contains no unsafe code or data stores.
`Result<bool,AccessError>` is a new API. Converting successful bool to u64 gives
the original full-RAX value. ImageRange, RootSlot, Flag, Head, Field and Link
are new safe refusals, not original error returns; Cycle is a new finite
classification of an otherwise nonreturning input. Raw ABI, flags, faults,
original compiler/code generation and source identities are not reproduced.

## Independent frozen oracle

Before creating Rust, `oracle.py` froze complete input images and expected
results using graph reachability and a visited-address set. Its cycle decision
is independent of the Rust qword-start-count bound. The set contains only nodes
already observed with zero field and a valid link, so membership proves the
same stable cycle. The oracle neither decodes nor executes captured instructions,
models CPU registers, calls Rust nor reads native expected output files.

`frozen.json` binds the oracle source, target, static evidence and both streams.
The absent-source freeze guard documents local chronology, not an external
timestamp attestation. The corpus exhausts three-node successor maps, binary
zero/nonzero field assignments and all head choices, with additional widths,
short-circuit, alias, endpoint, address-wrap and longer-chain cases. Finite host
execution supports the implementation; the argument above covers the full
admitted image/value domain. Whole-caller and whole-node equivalence remain open.
