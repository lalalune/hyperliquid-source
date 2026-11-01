# Conditional composition of two minute inputs

Target: node #94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Addresses are linked ELF virtual addresses. Native listings cover each complete
selected FDE; they do not establish a recovered nominal source function.

## What was already established

The existing [minute packet](../RE-001-cumulative-minute-94/README.md) establishes
the two local arithmetic sequences as `floor(n/60)` for an unsigned DWORD n,
with guards `result > 65535` and then `result >= 1441`. Its README:131–138 leaves
the producing constructor and the reachability of raw inputs86400..86459 open.

The [result-projection packet](../RE-009-state-dump-result-projection-94/README.md)
establishes the complete `0x151cba0..0x151cca5` producer. On its in-range ordinary
RET, destination+4 holds the Euclidean remainder `s mod 86400`, for a signed64
raw upstream word s. The other fields are an opaque nonzero result and a retained
raw word. Neither clock units nor a concrete date type follows from that theorem.
Those results are dependencies, not newly recovered arithmetic or code coverage.

This packet adds the two caller links, their full local control-flow conditions,
and the precise memory-preservation gap between producing and consuming the word.

## Domain of the argument

Let S be the caller's RSP after its `sub rsp,0x578` prologue. The initial live
arguments and stack are valid; pointer-based stores operate on valid regions.
The active caller frame, nested frames and unrelated live inputs do not alias
in ways that invalidate the stated transfers. Calls preserve callee-saved
registers and return to their matching continuation with the original RSP.

Only finite ordinary in-FDE control-flow traces are considered. Exceptions,
asynchronous entry, out-of-FDE transfers and subsequent reentry are excluded.
The graph includes ordinary fallthrough after **every** call, including cold
calls. No call is declared noreturn merely because it appears to report an error.
RET and explicit UD2 terminate local paths. The final producer call's possible
fallthrough is recorded as out-of-FDE, not converted into an invented RET.

If caller B takes its indexed dispatch, its original ESI low byte must be in
0..5. This is an explicit input restriction. It is not derived from a guessed
Rust enum type, and it is not required on the separate branch that bypasses the
dispatch and reaches the producer directly.

Finally, after the producer returns normally and before the selected input load,
the four bytes at S+0x48 (A) or S+0x58 (B) must remain unchanged. This includes
effects of the six possible intervening calls, arbitrary aliases of explicit
non-stack stores, previously escaped stack addresses and asynchronous mutation.
An ABI-preserving call is **not**, by that fact alone, a no-clobber call.
The inventory below exposes this unclosed premise; it does not prove it.

## Exact producer and field bindings

| Caller | Complete FDE | Destination preparation | Producer call | Input load |
| --- | --- | --- | --- | --- |
| A | `0x4925220..0x4925f0c` | `0x49255b7`: RDI=S+0x44 | `0x49255bc` | `0x4925bac`: EDX=DWORD[S+0x48] |
| B | `0x4925f10..0x4926dac` | `0x4926378`: RDI=S+0x54 | `0x492637d` | `0x4926952`: EDX=DWORD[S+0x58] |

Both six-byte `ff15` calls resolve their RIP-relative operand to slot0x576e8a0.
The unique RELA record has type8, symbol index0 and addend0x151cba0. Stored slot
bytes alone would not establish this target; the actual relocation does.

Within that producer, entry RDI is retained in RBX. Instructions0x151cc56,
0x151cc58 and0x151cc5c write DWORD fields at offsets0,4,8. The three stores
dominate the sole in-range RET0x151cc6c. The collector re-extracts the arithmetic
operands and reuses the pinned MIT `state_dump_result_projection_static.prove`
certificate. Its full-domain proof is retained in records.json. Producer failure
arms and the opaque upstream/index helpers are subject to the original theorem's
normal-return and memory premises.

Thus both input loads read destination+4, conditional on the preservation premise.
The load is zero-extending; no signed interpretation is needed for its range.

## Caller B's dispatch is an additional domain restriction

At0x4925f24, EBP receives ESI; at0x4925fdc, `movzx eax,bpl` supplies the index.
The intervening calls preserve RBP under the stated ABI premise. The retained
instructions from that zero extension through the table load do not alter EAX.
The collector pins the entry copy, inventories the three earlier calls requiring
RBP preservation, and checks the later span for register writes, XCHG and any
operation outside its reviewed mnemonic set. The exact span is retained in the
dispatch record; a changed source register or intermediate EAX write is rejected.
There is no local index bounds check before this dispatch:

| Instruction | Operation |
| --- | --- |
| `0x4926085` | RCX=table base0x700454 |
| `0x492608c` | RAX=sign-extended DWORD[RCX+RAX*4] |
| `0x4926090` | RAX+=RCX |
| `0x4926093` | JMP RAX |

For the selected input domain, the six relative entries are:

| Index | Destination |
| ---: | --- |
| 0 | `0x49260b9` |
| 1 | `0x49260e4` |
| 2 | `0x49260a2` |
| 3 | `0x49260af` |
| 4 | `0x4926095` |
| 5 | `0x4926095` |

All five distinct destinations are decoded starts in the same FDE. Their routes
join at0x4926136 and continue into the retained caller graph. A separate raw-byte
census reads1024 adjacent bytes as256 candidate signed displacements; indices6
through255 yield destinations outside this FDE. This is a data census, **not**
evidence that the actual table has256 entries or that those are valid variants.
Their target bodies and any later reentry are outside the argument.

## Structural dominance and preservation audit

The graph is built from complete native-decoded rows. Direct conditional/unconditional
branch operands are decoded from their original bytes. Every local destination must
be a decoded instruction boundary. Caller B's selected indirect destinations are
added explicitly; an unrecognized jump is rejected. Prefix-led native rows are
rejected except for the exact observed multi-byte NOP byte forms. This prevents a
prefix from hiding a jump or register write from the mnemonic-based audits. Calls
have ordinary fallthrough.

Removing A's producer-call node makes A's consumer unreachable from its FDE entry.
The same holds for B under its selected dispatch domain. This graph property is a
conservative all-local-path result, not proof that any such path executes in practice.
The entry graphs have614 and719 reachable instruction rows respectively.

The producer-to-consumer corridor is the intersection of nodes reachable after the
call and nodes that can reach the consumer, excluding the load itself. This includes
loops, alternate forward routes and every possible local path through that region.
A has295 corridor rows; B has293. Both contain53 explicit memory-destination
instructions. In each,41 have a direct constant-RSP interval and12 have unresolved
alias relationships. No direct-RSP interval overlaps its selected four input bytes,
and no explicit stack-pointer change occurs in either corridor.

The collector retains each memory write, its address/bytes/operands and any direct
stack interval in `callers.*.inventory`. This is a syntactic inventory over these
complete decoded bodies, specifically explicit first-operand memory destinations.
Indirect CALL operands are read targets, excluded from this write inventory and
retained in the separate call list. Implicit string-memory operations and explicit stack changes are rejected in the
corridors; CALL stack effects remain subject to matching-return premises. The
inventory does not infer safe heap objects or helper effects.

There are six possible intervening call sites in each corridor:

| A site | B site | Bound destination |
| --- | --- | --- |
| `0x492563f` | `0x4926401` | slot0x576e8c0 ->0x1447130 |
| `0x4925a33` | `0x49267d3` | direct0x42215a0 |
| `0x4925a67` | `0x4926807` | slot0x576dfd8 ->0x54c06b0 |
| `0x4925aec` | `0x492688c` | slots0x5776ab8 /0x5776aa8 ->0x454ea80 |
| `0x4925b77` | `0x492691d` | direct0x487c9f0 |
| `0x4925b97` | `0x492693d` | slot0x576e010 ->0x54c8cb0 |

These are possible call **sites**, not a runtime call-count bound: the corridor
contains loops. Their bodies are opaque here, including any allocator-like role.

Address exposure is not limited to calls after the producer. The exact full prefix
inventories (`prefixStackAddressFormations` and `prefixCalls`) retain19 formations
for A and20 for B. For example, A's0x49253a2 forms S+0x20,0x49253a7 stores it in
the aggregate at S+0xb8, and0x4925400/0x4925408 passes that aggregate to a helper.
B's corresponding0x492615f/0x4926164 and0x49261bd/0x49261c5 expose S+0x28 through
the aggregate. This does not prove either helper releases those pointers.
Later direct result buffers at S+0x50 (A) and S+0x60 (B) are adjacent to the
producer's12-byte output, but no transitive write-size or non-retention contract
is established merely from those different starting addresses.

## Composed result and limits

Under all the stated premises, the consumer gets `0 <= n <= 86399`. The retained
register sequence and the existing `foundation_millis.prove_division` certificates
give `floor(n/60)`, hence a minute value in0..1439. It cannot take either local
guard at65536 or1441, nor can it equal1440, **within this conditional domain**.

This does not prove actual runtime reachability, that a deployed clock produces
all or only those upstream words, or that either entire caller succeeds. The
following `result < 6` branch and the surrounding collection behavior remain
outside the recovered contract. The other twelve minute conversions in the
original packet load pointer-supplied fields and require separate producer/owner
research. No full-family input invariant, concrete Rust type, implementation,
matched-code percentage or completed component gate is claimed.
