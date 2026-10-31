# RE-001: delegated output addresses across insertion and split propagation, node #94

- Component: `transport` through its already observed rate-maintenance callers.
  The helper's original source ownership, Rust name and private type are unknown.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference revision
  `999556f6e0a474b8312db96ec3149e1c44e97c23`. No imported source was changed;
  no unlicensed inferred implementation was consulted or copied.
- Status: exact instructions/metadata observed; conditional no-split and
  split-propagation output equations inferred. Object effects, aliases,
  termination, types and runtime remain unqualified.

[PR #1020](https://github.com/lalalune/hyperliquid-source/pull/1020) leaves
`0x4258c00` opaque. This packet follows one actual route of that callee, so the
used address observation can extend through a previously unresolved delegation.
It is independently based on main and requires no code from that unmerged PR.
The split extension stays within this same packet and PR; it adds a used-output
proof to the already retained helper context rather than claiming another
function or re-counting its bytes.

When the **loaded u16 count is below 11**, both local insertion subroutes
converge at a call bound to `memcpy`. Under the stated ordinary-return and
frame/ABI conditions, its destination is the same bit pattern reconstructed by
`output[0] + 608*output[16]` modulo 2^64. Output+8 receives the separately loaded
qword at the retained input pointer+8. The independent qword index is **not**
proven below 11. On the **loaded-count>=11 route**, every finite ordinary
normal-return path preserves the destination of its first insertion copy, at
`0x4259022`, across either a direct writeback or saved-result parent-loop path.
Both are address-operand relations, not valid-object or successful-copy claims.

## Reproduce

Linux x86-64, Python 3.12.14, GNU objdump 2.44, genuine pinned artifacts and seven
unchanged reference submodules. From repository root, use a new output path:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/rate_delegated_output_static.py --output work/rate-delegated-output-94
diff -ru research/work-items/RE-001-rate-delegated-output-94/observed work/rate-delegated-output-94
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p test_rate_delegated_output_static.py -v
sha256sum -c research/work-items/RE-001-rate-delegated-output-94/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The collector authenticates the complete input byte vector and derives ELF
metadata from those same bytes. GNU receives only an owned **4,354-byte** raw
slice, mode 0600 and non-executable, in a mode-0700 temporary directory. Bytes
and identity are checked before and after its use; only that owned slice is
cleaned. Native tools never reopen the original source pathname. A final source
identity and complete SHA-256 check precedes exclusive output creation;
incidental source ctime/hard-link-count changes are excluded. A real private
source-symlink replacement control exercises that refusal without copying the
91 MB artifact or changing its canonical pathname.

The native invocation, with `LC_ALL=C`, is retained in `observed/records.json`:

```sh
objdump -D -b binary -m i386:x86-64 -M intel --show-raw-insn --insn-width=16 --adjust-vma=0x4258c00 slice.bin
```

Every row must match admitted bytes and tile the complete selected FDE extent.
UTF-8 and LF output are explicit. No instruction/data normalization is applied.
The semantic-record test omits only the GNU version string; raw text is retained
for its recorded version. The maintained ELF readers plus raw field checks bind
CFI/LSDA/RELA; this does not claim a second native metadata reader. No captured
target, emulator, node service or concrete CPU execution is used.

## Exact scope and observations

| Item | Half-open linked ELF VA range | Bytes |
| --- | --- | ---: |
| Full helper FDE, retained as native context | `0x4258c00..0x4259d02` | 4,354 |
| Prologue and ordinary insertion/return-store region within it | `0x4258c00..0x4258de9` | 489 |
| Shared local return epilogue within it | `0x4259a2d..0x4259a3f` | 18 |
| Revisited caller arguments and three output loads | `0x4959067..0x4959099` | 50 |
| Revisited outer caller address consumption | `0x4956e63..0x4956e88` | 37 |

The two internal regions are subsets of the full FDE, not additional bytes or
functions. The 87 caller bytes are revisited observations from earlier packets.
None of these counts is a reconstructed-function, matched-body, completion or
equivalence denominator.

The helper maps at file offset `0x4257c00` and has SHA-256
`4262a27f04f513c5d0bafd1bd95c9ddbb81b803ca6ceeda71beaab9f99df8284`.
Actual FDE `0x12295cc`, CIE `0xfbdc2c` (`zPLR`) and LSDA `0xb24d60`
are retained byte-exactly. Native context has 866 linear instruction rows.
The no-split ordinary-return graph contains 73 of those instructions, across
two conditional insertion routes. The count>=11 ordinary graph has 683 reachable
instructions, including loops and error routes. These sets overlap at the return
tail and must not be summed; they are static graph membership, not recovered
functions or feasible-path counts.
FDE membership alone does not establish an original source function boundary.

## Count below 11: two insertion routes and the consumed words

The prologue retains incoming RSI in R15 and saves incoming output RDI at its
own frame+0x78. A call bound to `memcpy` at `0x4258c42` **precedes** these loads:

| Instruction | Observed load or branch |
| --- | --- |
| `0x4258c48` | R14 = qword `[R15]`, the base carrier |
| `0x4258c4b` | R13D = zero-extended u16 `[R14+0x1b32]`, the loaded count |
| `0x4258c53 / 0x4258c57` | compare R13 with 11; unsigned JB selects `0x4258c84` |
| `0x4258c84` | RBX = qword `[R15+16]`, an independent index carrier |
| `0x4258c88 / 0x4258c9b / 0x4258c9e` | RBP = RBX+1 modulo 2^64; unsigned `RBP <= R13` selects `0x4258cf8` |

The fallthrough at `0x4258ca0` writes the selected 24-byte metadata fields and
calls `memcpy` into a local 608-byte area before jumping to `0x4258d86`.
The taken route at `0x4258cf8` additionally supplies two calls bound to
`memmove` with metadata/payload shift operands, then reaches the same join.
It preserves RBX by a visible own-frame spill/reload while the temporary
register holds `count-index` modulo 2^64. These argument formulas do not prove
safe ranges or that a move succeeds.

Under normal import returns preserving callee-saved registers, **and the
all-write frame condition below**, both routes retain the same R14 base and
RBX index at the join. Import preservation alone is insufficient: the explicit
pointer-relative metadata stores can also alias this helper's own frame.
The collector verifies both decoded branch successors, the convergence, absence
of another terminal/cycle in the selected local graph, and common-site passage
on every route to the visible local RET. Calls use ordinary-return edges;
exceptional transfer and alternative entries are outside this claim.

At `0x4258da0`, the final selected `memcpy` call is supplied:

- RDI = `R14 + 608*RBX` modulo 2^64;
- RSI = own frame+0xa0;
- EDX = 608.

After it, the code stores the incremented count as a u16, loads RDX from
`[R15+8]`, and puts constant 2 in its own frame+0x50. It immediately loads and
compares that word with 2 without another call, selecting the output tail:

| Instruction | Output-relative write | Value at that instruction |
| --- | ---: | --- |
| `0x4258dd9` | +0, qword | same R14 base |
| `0x4258ddc` | +8, qword | qword loaded from `[R15+8]` at `0x4258dae` |
| `0x4258de0` | +16, qword | same RBX index |

It then jumps to the epilogue and local RET at `0x4259a3e`, without another
call or memory store. Consequently, output0+608*output16 reconstructs the last
copy destination argument's bit pattern under the stated conditions.

The revisited caller passes local output at frame+0x18, then loads the three
qwords into R12/RAX/RBP; its previously observed final stores and outer caller
consume the base/index relation. This packet does not requalify the entire
caller or stack layout. The actual incoming R9/output alias remains explicit:
the caller supplies R9=input+0x38, equal to its outer output pointer. There is
no explicit save/read of incoming R9 before the first opaque import; that fact
does not exclude import-mediated use or memory-alias effects.

## No-split proof domain: direct writes as well as imports

Here SP denotes the helper's own frame after `SUB RSP,0xca8`. The used-output
inference requires **all memory effects**, including explicit pointer stores
and imported copy/move effects, to preserve these live values except their
shown intended definitions:

| Own-frame word | Protected value | Live interval |
| --- | --- | --- |
| SP+0x08, 8 bytes | saved incoming RDX | store `0x4258c24` through load `0x4258d30` |
| SP+0x10, 8 bytes | saved incoming RCX | store `0x4258c3a` through load `0x4258d53` |
| SP+0x28, 8 bytes | saved original index on the shift route | store `0x4258d0e` through reload `0x4258d7b` |
| SP+0x78, 8 bytes | saved entry output RDI | store `0x4258c1c` through load `0x4258dd4` |
| SP+0xca8..SP+0xce0 | six saved-register words and return-address word | through their restores and RET |

This is an **unverified proof-domain assumption for runtime inputs**, not a
property established by the static collector. The intended own buffers at
SP+0xa0..SP+0x300 and SP+0x598..SP+0x7f8 remain writable. It does not require all
arguments to be disjoint, and does not discard the known incoming R9/output
alias in the outer caller. Saved-register ABI preservation is required in
addition to this memory condition.

A target-grounded symbolic counterexample shows why the condition is needed.
The actual LEA/ADD sequence computes R12=`base+24*index+0x1a28` modulo 2^64.
With index=0, count=0 and base=`SP+0x78-0x1a28`, the no-shift route's explicit
16-byte metadata store at `0x4258cb1` reaches SP+0x78, overwriting the saved
entry output pointer even if every import preserves it. With index=0, count=1
and base=`SP+0x28-0x1a28`, the shift route's store at `0x4258d38` can overwrite
the saved original-index slot. The tests verify these address identities from
actual encoded operands without emulating the CPU or constructing an object.
They identify a missing proof premise, **not a target bug or security claim**.
Without the all-write condition, the entry-output/caller connection and
original-index forwarding remain unqualified.

## Split propagation: preserve the first insertion destination

For the count>=11 successor at `0x4258c59`, the index is a separate qword load
at `0x4258c63`. The encoded initial branches select these numeric register
values before an opaque allocation call:

| Unsigned loaded index | Pivot register | Flag low byte | Adjusted index register |
| --- | ---: | ---: | --- |
| <5 | 4 | 0 | index |
| ==5 | 5 | 0 | 5 |
| ==6 | 5 | 1 | 0 |
| >=7 | 6 | 1 | index-7 modulo 2^64 |

These are actual branch/operand observations, not a B-tree or private-type
identification. The later count reload at `0x4258e31` follows the opaque call
and pointer-relative stores. It cannot be equated to the first count: neither
object non-aliasing nor allocator/library effects have been established. The
following equation deliberately starts from the **actual R14/RBX at the copy**,
without equating them to entry-time values or inventing a capacity invariant.

At `0x4259022`, R15 was loaded from the actual `memcpy` slot and the call receives
RDI=`R14+608*RBX` modulo 2^64, RSI=own SP+0xa0, EDX=608. A following opaque copy
at `0x425904c` must preserve those callee-saved registers for this inference.
Then `0x425905e` copies R14 to RSI and `0x4259059` loads the middle word into RDX.
A raw qword at SP+0x50 is compared with 2 at `0x425906e`; its type, provenance
through copied contents and feasible domain remain unqualified.

If that raw word equals 2, `0x4259072` reaches the direct output tail already
listed above: the same base/middle/index registers are stored at output+0/8/16.
Otherwise, the helper saves them before its parent-propagation loop:

| Save instruction | Own-frame word / width | Value | Final reload | Output store |
| --- | --- | --- | --- | --- |
| `0x4259078` | SP+0x90 / 8 | RSI = copy-base R14 | `0x4259a10` | `0x4259a18`, output+0 |
| `0x4259080` | SP+0x68 / 8 | middle RDX | `0x4259a1b` | `0x4259a20`, output+8 |
| `0x4259085` | SP+0x28 / 8 | copy-index RBX | `0x4259a24` | `0x4259a29`, output+16 |

The graph proves that the first copy site `0x4259022` dominates every local
normal return from the count>=11 successor. Each pair of direct/alternate
output+0, +8 and +16 stores is an all-return cutset. All three save instructions
dominate the alternate tail `0x4259a0b`; after those saves the direct tail cannot
be reached, and the direct tail cannot reach the alternate tail. This covers
all **finite ordinary-return paths**, including any number of loop iterations;
it does not prove that a loop terminates or that an error/exception path returns.

A width-aware census retains all 139 explicit memory-write instructions in the
full FDE, 128 on the count>=11 ordinary graph. It records raw bytes, address
operands and widths, separately from implicit push/call stack effects. After
the saves, direct SP-relative writes overlapping the result/output words are
only the three intended definitions. In particular `INC [SP+0x60]` writes eight
bytes ending at SP+0x68, the exclusive lower boundary of the middle word.
Scalar and SIMD widths matter; a mutation replacing an 8-byte SP+0x20 store
with a valid 16-byte MOVUPS reaches the protected index word and is rejected.
This census does **not** resolve indirect addresses or opaque call effects.

The split equation requires imports to preserve R14/RBX through the copy-to-
writeback/save sequence. It also requires **ALL memory effects**, including
explicit indirect stores, imported copies/moves and final output stores, to
preserve SP+0x78 (entry output pointer), the saved-register/return area and the
live result words SP+0x90/0x68/0x28 from definition through their respective
reloads, except the shown intended definitions. Other intended buffers remain
writable; known incoming R9/output aliasing remains explicit. This is an
unverified runtime proof domain, not blanket argument disjointness or observed
object safety. For example, entry output P=SP+0x20 makes the alternate output+8
store target SP+0x28 **before** the index reload. Even frame-preserving imports
do not exclude that explicit-store alias; the all-write domain is necessary.
The test checks this address identity symbolically from actual displacements,
without target/CPU execution.

Under these conditions, both output tails reconstruct the destination of the
**first split insertion copy** at `0x4259022`; later parent insertion copies do
not replace the saved address operands. Their copied values, object effects,
validity, lifetime and algorithmic meaning remain unproved. The revisited
caller still consumes the same output offsets with the 608 multiplier under
its existing conditions; no whole-caller qualification is added.

## Bound, imports and exception limits

The selected bound constrains the **loaded count** to 0..10. The index is a
separate 64-bit load; `index+1` may wrap. For example, count=0 and index=2^64-1
satisfy the arithmetic taken-branch condition while the index is outside 0..10.
This is a mathematical counterexample to an unproved invariant, not execution
of the captured target or proof of a valid concrete object. Do not infer entry-
time count, index validity, allocation capacity, lifetime or pointer safety.

The count store occurs before the output stores, which may have alias effects;
no unconditional count-at-return invariant or blanket disjointness is claimed.
Original object ownership, Rust/private type and frame/ABI contracts remain
unproved. Both ABI preservation and the all-write frame domain are explicit
conditional assumptions, not observed runtime properties.

Raw ELF64 RELA rows bind slots `0x576dfe0` to `memcpy` and `0x576e0e0` to
`memmove`. Names are selected symbol bindings, not a runtime implementation or
copy-effect proof. All six relevant calls, including the initial copy, have
return-PC-minus-one ownership in LSDA row 0. Raw call-site records are retained;
actions, types, personality behavior and exceptional feasibility remain open.
The final call in the **full** FDE at `0x4259cfc` falls through outside its end
if it returns. The split output equation does not recover the remaining split/loop memory
effects, raw tag/type, allocation/lifetime, exception behavior or termination.

## Validation and remaining work

Thirteen actual-target focused methods pass with no skips. Controls mutate the
actual count width/bound/branch, independent index source, saved index reload,
608-byte multiplier and length, base carrier, output source, local constant
and revisited alias. Actual import retargets, FDE/CFI and LSDA corruptions are
rejected. Native controls cover wrong instruction bytes, a branch to an
instruction interior, and a valid-boundary branch escaping to the split path.
Private slice mutation/cleanup, actual symlink replacement, exact repeat,
wrong full identity and real CLI preservation of empty/populated output are
also checked. Source bytes/reference pins remain unchanged. See retained
`focused-tests.txt` and `validation.txt` for actual run boundaries.
Symbolic-address controls demonstrate direct-store frame aliases and require
the explicit all-write proof domains. Actual private-slice GNU controls also
retarget a valid branch to bypass the copy/output cutset, move INC onto a
protected word, and widen a scalar store so its overlap reaches that word.

No Rust component/build, runtime differential, normalization mask, target
execution or completed component gate is requested. All four gates remain
false. Next questions are actual import/alias/frame contracts and split memory
effects needed to qualify the equations, plus raw tag/type, object validity and
lifetime, and exceptional or terminating behavior.
