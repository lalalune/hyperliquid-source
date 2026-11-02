# Conditional impact-notional walk

This is a manual proof over the retained complete native bodies, not an
instruction interpreter or a report of executed target cases. Addresses are
node #94 linked ELF VAs. `U = 2^64-1`, `M = 2^63-2`, and `sat(x)=min(U,x)`
for a nonnegative mathematical integer. All quantities below are raw words;
no public monetary unit, source type, or book-side name is inferred.

## Premises and result

For the main numeric theorem, the target word `T` is stable and `1 <= T <= U`.
The reachable tree and slab bytes are readable and stable, and every effective
address is nonwrapping and within its backing object. They do not overlap the
callee's writable stack. The tree is finite and structurally well formed:
height agrees with child depth, parent links/indices agree with children,
node lengths fit the eleven key/value slots, and header count is the number
of entries. Each followed slab chain terminates; this excludes link cycles.
The logical entry sequence is the tree's in-order sequence. Numerical key
ordering and bid/ask identity are unnecessary to this theorem.

Every invoked diagnostic helper returns normally with the usual preserved
register/stack contract and without changing live tree, slab, target, saved
locals or output storage. This is an assumption, not a conclusion from its
name, relocation, or digest. Nontermination, memory faults, unwind behavior
and arbitrary malformed trees are excluded. The raw parent-null path and
`T=0` domain are described separately below.

Starting with `S=0` (accumulated cost) and `Q=0` (accumulated quantity), each
in-order entry supplies `p=unsigned_magnitude(key)` and a saturated slab
quantity `q`. An absent level, invalid initial slab head, or `q=0` returns
zero after the optional diagnostic request. A full product `p*q > M` returns
zero **before partial-fill arithmetic**, including an overflowing u64 product.
Otherwise let `C=sat(S+p*q)`:

* If `C<T`, replace `S` with `C` and `Q` with `sat(Q+q)`. Continue if entries
  remain; exhausting the header count returns zero.
* If `C>=T`, compute `n=floor((T-S)/p)`, `A=S+p*n` and
  `B=sat(Q+n)`. Return zero unless `1<=B<=A`; otherwise return
  `floor(A/B)`, a nonzero u64.

The divisions in this positive-target theorem are well defined. In particular,
zero-price entries can contribute quantity before a later crossing. No claim
that `A` equals the requested notional is made: the terminal quantity is floored.

## Tree cursor and price

`0x3c027de..0x3c027ff` reads header root `+0`, count `+0x10`; either zero
returns zero without reading height. Otherwise height `+8` initializes the
descent. At `0x3c02819`, stack `+0x28` holds `S`; `R11=Q`, `R9` is the
remaining entry count, and `R10=M`. `R15=0` denotes the initial descent.

The initial loop `0x3c02840..0x3c028ce` follows child zero at `+0x1c8`
exactly `height` times. It splits the count into a remainder modulo eight
and eight-link groups, preserving the total; height zero uses the root itself.
Then `R15` is the leftmost leaf, `RBX=0`, and `RAX=0` is its height.

For a leaf cursor `(node,index)`, `0x3c02823` compares index against the
node's u16 length `+0x1c2`. An available key selects that node/index. Otherwise
`0x3c028f0..0x3c02917` climbs `parent=+0x160`, reads child index `+0x1c0`,
and increments the height once per ascent. A child index below the parent's
length selects the next parent key; an index at/above its length climbs again.
This is the ordinary in-order successor rule under the stated parent premises.

When the selected node has positive height, `0x3c02917..0x3c029d2` prepares
the next cursor by following its right edge (`+0x1d0 + 8*index`), then child
zero to a leaf. The same remainder/eight-link construction consumes exactly
the selected height. It leaves the original selected node/index in `RCX/RDX`
for the current value, while storing leaf index zero at stack `+0x20`.
For a selected leaf, `0x3c029e0` stores index+1 instead. The full-level
continuation restores that next index and resets `RAX=0` at `0x3c02b2d`.
Induction therefore consumes each logical tree entry once. Exact header count
prevents a request beyond the final entry; early numeric returns can stop sooner.

The key is the qword at `node+0x168+8*index`; values start at node+0 with
stride32. `NEG` followed by `CMOVS` at `0x3c029f8..0x3c02a02` returns the
key if it is nonnegative, its negation if negative, and raw `2^63` for
`i64::MIN`. Thus `0<=p<=2^63`; the overflow flag from `NEG` is not tested.
The prior top-order-clone packet supplies layout context, but its 64-bit slab
tag test is not substituted for this function's actual 32-bit test.

## Slab quantity and failure domains

`0x3c02a02..0x3c02a1e` requires value byte bit0 and head `< book[+0x10]`.
It saves `p`, decrements remaining entry count, reads slab base `book[+8]`,
and initializes the level accumulator to zero. At `0x3c02a30`, the slot is
`base + 0xf8*index` under the nonwrapping address premise.

Low dword tag2 stops without adding that slot. Otherwise the function reads
the qword continuation flag `+0x10`, next index `+0x18`, and quantity `+0xc8`.
`0x3c02a53..0x3c02ad8` adds the quantity; carry requests helper
`slot 0x5773190` with first argument0 and Location `0x56dfc40`, then
recomputes the addition and clamps to `U`. The saved operands and relevant
caller-saved registers are restored; `R12/R13/R14/RBP` rely on the preserved
register convention. Thus the accumulator is `min(U,sum of contributed words)`.

A zero continuation flag ends the chain. A nonzero flag continues only if
the next index is below the slab count. An out-of-range **later** next index
ends with the quantity already accumulated, unlike an invalid initial head.
The finite-chain premise supplies termination; the code does not detect cycles.

At `0x3c02ae3`, zero quantity takes the same diagnostic/zero path as missing
bit0 or an invalid initial head. That path reads live dword `0x577ab98`:
zero skips the helper; nonzero calls `slot 0x576e8b8` at `0x3c02d32` and
then explicitly clears the returned word. The arguments include the live word's
address, integer1, a stack capture referencing `0x577ab80`, table `0x5669f68`,
and Location `0x5669f50`. Table/capture relocations are bound; their transitive
callback effects and meaning are not recovered. Initial file bytes do not
establish the value of the mutable global at runtime.

## Product, target crossing and whole-quantity floor

At `0x3c02af1`, unsigned `MUL` produces the full two-word product.
`SETO` detects a nonzero high word; `SETA` compares the low word with `M`.
Their OR sends either failure to the zero return. `R8` is zero here: it was
initialized at entry, reset after a right descent or a slab overflow call,
and reset after the full-level overflow continuations. No intervening path
writes a nonzero `R8` before this guard. Consequently this guard rejects the
**whole level**, even if a smaller partial quantity would fit the target.
For positive `q`, the `i64::MIN` key is rejected by this guard.

`0x3c02b05..0x3c02bac` forms `C=sat(S+p*q)` and reads the stable target.
On carry it requests the overflow helper and recomputes/clamps the addition.
The unsigned `JAE` includes equality in the crossing branch. If `C<T`,
the cost cannot have saturated (`C=U` cannot be below a u64 target). Thus
the continuing invariant is exactly `S'=S+p*q<T`. `Q'=sat(Q+q)` follows
from the direct carry test and `0x3c02be4..0x3c02c2d`. Remaining count zero
returns zero; otherwise the cursor induction above applies. Initially `S=0<T`,
so every reached level has `0<=S<T`.

At crossing, a zero price would give `C=S<T`, a contradiction. Therefore
`p>0`. `0x3c02c50` computes `T-S` without underflow by the invariant.
`0x3c02c78..0x3c02c9b` tests `(remaining|p)>>32`: if zero it uses a 32-bit
unsigned division; otherwise a 64-bit division. The high dividend half is
zero in both cases, so both compute the same mathematical floor `n` and the
quotient fits its chosen width.

Crossing gives `T-S<=p*q`, including when the candidate addition overflowed
and saturated. Hence `0<=n<=q` and `p*n<=p*q<=M`. The second product guard
at `0x3c02c9b..0x3c02cae` is retained, but cannot fail under these premises.
Also `A=S+p*n<=T<=U`, so the final cost addition cannot overflow. The raw
remaining-underflow and final-cost-overflow helper branches remain in the
structural evidence; they are not reachable in this stable positive-target proof.

The function then computes `B=sat(Q+n)`, including the overflow continuation
`0x3c02d7e`. At `0x3c02ccb`, it rejects when unsigned `(B-1) mod 2^64 >= A`.
If `B=0`, the left side is `U`, which always rejects. For `B>=1`, acceptance
is `B-1<A`, equivalently `B<=A`. Thus acceptance is exactly `1<=B<=A`.
The final width-selected division at `0x3c02cd8..0x3c02cf8` returns
`floor(A/B)>=1`; both widths again have zero high dividend half and fit.

These integer deductions illustrate the floor without executing the target:

| Logical levels `(p,q)` | Target | Terminal `(n,A,B)` | Return |
| --- | ---: | --- | ---: |
| `(7,2)` | 6 | `(0,0,0)` | 0 |
| `(3,2),(7,2)` | 10 | `(0,6,2)` | 3 |
| `(3,2)` | 6 | `(2,6,2)` | 3 |
| `(2^63-1,1)` | 1 | full product exceeds `M` before partial fill | 0 |

These are algebraic witnesses, not a finite-test substitute for the loop proof.

## Zero target and structural failures

With `T=0`, initial cost0 crosses at the first admitted nonempty level. If
its price is positive and the full-product guard passes, remaining and terminal
quantity are zero, and the final guard returns zero. If its price is zero,
the partial division has divisor zero; there is no preceding divisor check.
Empty headers, missing/invalid heads, zero quantities and excessive full products
can return zero earlier. This identifies a raw excluded domain, not evidence
that a live caller admits it or that an exploitable fault exists. The configuration
writer packet bounds some target values but does not close every constructor or
live override, so it is not used to remove this qualification.

A parent-null climb reaches `0x3c02d44`, passing Location `0x56e9fe8`
(`alloc/.../btree/navigate.rs:534:47`) to slot `0x576e470`; if it returns,
the next instruction is `UD2`. LSDA independently maps its call-site region
`[0x3c02d3d,0x3c02d4a)` to landing `0x3c02db6`, also `UD2`. These are
instruction and call-site observations, not a proof of actual exception handling.

## Downstream use and complete call audit

The entire `0x3750ce0..0x37511c0` premium body is retained as credited
context. This packet's caller theorem starts when its valid metadata/oracle/map
path has selected a target and reaches `0x3750eb0`. It does not reconstruct
the hash helper or re-prove the existing floating formulas. The caller's input
and output storage obey the same stability/stack separation premises; impact
calls preserve the target word and the second call preserves the first result.

`0x3750ea8..0x3750eab` copies the selected target word to stack+8.
At `0x3750ec3` the arguments are `(book,&target,book+0x80)`; at
`0x3750ed9` they are `(book,&target,book+0x98)`. The first result is saved
in preserved `R14`. Both calls occur before either result is tested.
`SETE`/`SETE`/`OR` at `0x3750ede..0x3750eec` detects either zero.
That branch sets `RBX=8`, `RAX=0`, restores the output pointer, and reaches
`0x3751148`: only output+8 is written. Output+0 and +16 are inactive and
unestablished on this path; it is not a fully zeroed record. Thus the first
algebraic witness can suppress the premium despite a nonempty positive-quantity
book, on ordinary returns. This is the existing caller's missing-result sentinel.

If both results are nonzero, the already-credited formula path normally stores
its f64 bits at output+0, first raw impact at +8, and second raw impact at +16.
No bid/ask naming, monetary scaling or full funding-sample append behavior is
newly claimed. The untouched #860 packet owns the floating formula and #899
owns distribution/reset. The caller's metadata failure, oracle-zero diagnostic
and scale failure branches remain fully present in the structural tables.

All fifteen calls in the two bodies are accounted for below. RELATIVE records
require symbol index0. Opaque callee extents/body identities are retained in
`spec.json` and `records.json`; a matching hash proves identity, not behavior.

| Sites | Target / role | Premise or limit |
| --- | --- | --- |
| `3c02a97` | `5773190 -> 358dcd0`, level quantity overflow | ordinary return/noninterference; Location `qtys/mod.rs:827:1` |
| `3c02b82` | same, candidate cost overflow | same; `qtys/impl_ntl.rs:26:1` |
| `3c02bbb` | same, structural continuation after overflowing candidate below target | unreachable with stable u64 target; `qtys/mod.rs:829:1` |
| `3c02bff` | same, accumulated quantity overflow | ordinary return/noninterference; `qtys/mod.rs:827:1` |
| `3c02c6c` | same, remaining-notional underflow | unreachable by `S<T`; `qtys/impl_ntl.rs:26:1` |
| `3c02d5b` | same, final cost overflow | unreachable by `A<=T`; `qtys/mod.rs:829:1` |
| `3c02d8d` | same, final quantity overflow | ordinary return/noninterference; `qtys/mod.rs:827:1` |
| `3c02d32`, `37511a6` | `576e8b8 -> 4ee3b20`, diagnostic request | transitive callbacks/state effects opaque; zero continuation conditional on normal return |
| `3c02d44`, `3751165` | `576e470 -> 157a9f0`, failure request | no recovered panic/unwind behavior; invalid parent/metadata outside numeric theorem |
| `37511ba` | `576e150 -> 157b520`, scale failure request | valid scale path required for caller theorem |
| `3750dd6` | direct `399c4a0`, map hash | prior context only; valid selected-target entry required |
| `3750ec3`, `3750ed9` | direct `3c027d0` | new conditional impact theorem above |

There are 135 complete structural basic blocks, 109 transfers and no unrecorded
indirect control transfer in these decoded bodies. Calls have conditional
normal-return successors, including failure requests; this intentionally does
not assert that all graph edges are dynamically reachable. The three impact
LSDA call-site rows are separate from normal CFG. The premium FDE has no LSDA
pointer. Computed or transitive callers elsewhere are not excluded.
