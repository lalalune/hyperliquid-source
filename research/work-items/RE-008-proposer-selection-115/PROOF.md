# Node115 proposer selection: conditional value relation

This packet studies node115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The complete main FDE is `[0x595cb30,0x595e5b8)`: 6,792 bytes, 1,404
instructions and 57 calls. Addresses are original ELF virtual addresses.
“Proposer” is a descriptive attribution from consensus caller context, not a
recovered source symbol. Keys are opaque 20-byte strings. Weights are u64;
their protocol units and the identities of the private source types are unknown.

The result is a conditional normal-return value relation, implemented in safe
Rust, including both history lookups, diagnostics, weight preparation, event
arithmetic, ranking, replacement and output bytes. It is not complete semantic
closure of the external call graph, original source recovery, machine-code
equality, or a reconstructed node executable. Explicit helper postconditions
below are assumptions, not results of running the captured node.

## Target binding, observations and admission

`bindings.json.gz` contains the whole target digest, the inventory of 135,313
FDEs / three CIEs, and 28 complete selected bodies totaling 17,654 bytes. Each
selected body has its exact bytes, FDE/CIE records, complete instruction stream,
control edges, RIP operands and actual relocation writers. Two signed history
jump tables and seven diagnostic / floating-point data spans are also bound.
Six complete incoming caller FDEs add 20,952 bytes. The independent GNU export
covers all 34 bodies, 38,606 bytes and 8,103 instructions. The full body bytes
agree instruction by instruction with the Capstone export.

The actual naming slot is `0x64e86f0`; its file word is zero and its RELATIVE
addend is `0x595cb30`. These are different observations: the relocated pointer
is not the file word. Eight instruction-bound FF15 calls in the six complete
caller FDEs reference this slot. Direct E8/E9 and FF15/FF25 byte candidates were
validated against containing FDE instruction boundaries. This does not enumerate
all possible register-indirect callers. Caller bodies are boundary evidence,
not six more implemented functions.

At entry, RDI is the output address, RSI the state address, RDX the selection
round, and RCX the history query round. The first instructions save these two
rounds separately. Callers include current / next-round contexts, so the model
does not force them equal. All normal-return arms restore RAX to the original
output address; no other final register or flags relation is claimed. The safe
value API returns an image, not a native pointer or ABI-compatible structure.

The native premises are stable, finite, ordinary mapped memory; nonwrapping
valid allocation spans; correct tree parent/child/height/length metadata; and
distinct ordered keys. A ring has capacity C, head H and length L with L<=C,
H<C when C>0, and H=L=0 when C=0. Its L logical entries are strictly ordered.
Native state, trees, live values, stack, scratch allocations, output and control
data are disjoint. There is no MMIO, concurrent mutation, fault, unwind,
allocation failure, corrupt-tree behavior or arbitrary aliasing claim. The
safe API supplies complete ordered snapshots, strengthening availability beyond
each path's actual loads. A refusal is a safe API result, not a native panic or
error ABI. Other safe collection allocations can still panic on exhaustion.

`call-boundaries.json` enumerates all 57 calls, including unwind/fatal paths.
The material boundaries are:

* A borrowed iterator follows the observed well-formed container order. Full
  bodies `0x5133940`, `0x543ec80`, `0x5b7fca0` and inlined ring walks bind the
  filtering relation. Rebuilding via `0x4dc0200` must preserve the filtered
  ordered unique contents; its complete entry is captured, but its deeper
  allocator / sorting / rebalancing closure is not proved. Cloning extra keys
  via `0x521b4d0` and inserting via `0x51d84e0` must preserve the stated union.
  Consuming tree cursors such as `0x51dcbd0` must yield the ordered remaining
  rows and release only consumed storage. These are explicit postconditions.
* Arrays of at least 21 elements use deeper generic sorts. Complete wrappers
  `0x4f3d890`, `0x4f415f0`, `0x4f411b0` are retained. Their required result is
  a permutation ordered by the concrete comparators below. This packet does
  not prove their deeper sort implementations. Large-array fixtures test the
  conditional relation, not that external postcondition in the node.
* The actual GLOB_DAT symbol at `0x64dfb50` is `memcmp`; its required contract
  is the sign of unsigned lexicographic comparison of exactly 20 bytes, with
  ordinary return and no relevant writes.
* FP uses binary64 round-to-nearest/ties-even, masked exceptions, DAZ=FTZ=0,
  and the resolved FMA3 arm. Slot `0x64e0fd0` names the 17-byte trampoline
  `0x63f0210`; its cache `0x64ffe00` initially names resolver `0x63f06a0`.
  The six bytes at `0x63f0680` are `vfmadd213sd xmm0,xmm1,xmm2; ret`.
  The full resolver and FMA4 body are recorded but CPU-feature detection,
  software FMA `0x63f0230` and FMA4 execution are not qualified. No captured
  CPU/MXCSR state was observed.
* Clock, logging, metrics, allocator and destruction boundaries return normally
  and preserve the live selection values and supplied snapshots. Metric locks
  and timers are not reproduced. Diagnostic LOCK INC is observed statically,
  but only its sequential wrapping value projection is implemented, without
  concurrent scheduling or liveness claims. Opaque callbacks do not otherwise
  modify the diagnostic counter; this is a noninterference premise, not a
  proof of their complete side effects.

Full byte coverage must not be confused with full external semantic closure.

## Two histories and diagnostics

Main calls slot `0x64e8738` at `0x595cb67`, naming
`[0x595c3a0,0x595c5f3)`. Only success byte `0x2e` leads to the call at
`0x595cbb5` through `0x64e64b0`, naming `[0x595e5c0,0x595e80a)`.
Both receive the state and the separately saved query round r. The first
value is a set A of 20-byte keys; the second a map M from keys to u64 weights.

Before each history search, the helper computes

```
limit = max(min(stake_base+2000, MAX), min(execution+201, MAX))
warning = (r >= limit)
counter' = (counter + warning) mod 2^64.
```

Here stake_base is state+0x20, execution is state+0x60, and the diagnostic
counter is state+0x68. Both saturating additions use carry-controlled MAX
selection; the greater of the two is used. Equality warns. A warning executes
an actual LOCK INC on the counter and the opaque logging handler, then resumes
the query; it is not a rejection condition. If the first query is missing,
the second diagnostic is not performed. If both queries run, the same warning
condition can increment twice, including wrapping MAX to zero. The strings
“jailed validators” and “stakes” identify the two diagnostic subjects; they do
not establish all protocol meanings of the sets used later.

The first history is at state+0x28 with base at +0x48; the second is at state
with base at +0x20. For the applicable base b, both helpers compute

```
q = b                              if r < min(b+2000, MAX)
q = max(b, (r-200) mod 2^64)        otherwise.
```

The comparison is unsigned and the equality arm uses the latter formula.
The selected snapshot is the greatest stored round <=q; an empty prefix is
missing. The safe `history` reports q even on an empty supplied history. This
is a semantic diagnostic, not a claimed register value on an early native
empty-container path.

The complete dispatch bodies `0x4dce7b0` / `0x4dce480` distinguish a tree
only when NEG of the first qword overflows, i.e. it equals `0x8000000000000000`.
Otherwise it is the ring capacity. This does not authorize treating arbitrary
high-bit capacities as valid mapped allocations. For the tree representation,
root and height are +8/+0x10. The complete range builders `0x4d38fd0` /
`0x4d391b0`, their four-entry signed jump tables, and back-edge extractors
`0x51f5470` / `0x51f5620` bind inclusive upper-bound search. Key equality
advances beyond the matching key; descending and then ascending parent links
returns its predecessor. Induction on valid tree height yields the maximal
key <=q. First-history values have stride 24, second-history values stride
56; their value regions start at node+0x60. The key region begins at node+8.

For rings, buffer/head/length are +8/+0x10/+0x18. The complete upper-bound
helpers `0x57f2b50` / `0x57f35c0` split the logical sequence at the capacity
boundary, using record strides 32 / 64. They keep the prefix whose rounds are
<=q. The last nonempty segment supplies its last record, with payload +8.
Logical order is the first segment followed by the wrapped segment. Therefore
the independent logical-index binary search in `ring_history` returns the
same prefix length and physical predecessor. Unused capacity keys need not
be ordered. The safe model does not reproduce raw pointer representation.

Either missing history helper writes byte `0x28` at scratch+0 and r at
scratch+8..16. On success it writes only byte `0x2e` and the value pointer at
+8, so a subsequent missing result replaces both active fields. Main's
`0x595cbfd..0x595cc49` copy covers all 72 scratch bytes: overlapping dwords
cover offsets 1..8, the tag covers 0, qword covers 8..16, vector stores cover
16..64 and a qword covers 64..72. Consequently missing output padding comes
from the entry scratch image, not the caller's output image. The API supplies
these images separately. Scratch bytes are arbitrary supplied values, not
assumed zero or language-level initialized padding. Successful selection uses
the separate caller output image below.

## Filter, union and saturated weights

The collector / predicate exclude equality in A, yielding D=M\A in increasing
20-byte key order. They retain every surviving row, including zero weights.
The extra set E is at state+0x70 (root), +0x78 (height), +0x80 (length).
Clone plus insertion yields U=A union E; overlapping keys count once, and keys
absent from D still count in |U|. The subsequent U-to-D lookup walk has no
effect on selected values: its found and absent arms both advance U. The ring
lookup `0x57f54e0` has only stack writes and memcmp calls; no hidden map-value
mutation is assumed. Valid mapping is still required for its reads.

Both ring and tree accumulation arms use ADD followed by carry-controlled
MAX selection (`0x595d440` and `0x595d546`). For nonnegative weights, induction
gives W=min(sum of D weights,MAX), not a checked-sum panic restriction. Then

```
h = 0                               if U is empty
h = floor(max(W-1000,0) / |U|)       otherwise
v(k) = max(w(k)-h,0)                if k in U
v(k) = min(3*w(k),MAX)              otherwise.
```

The full `0x5acae30` transforms D while retaining order and zeros.
The full `0x5acbdf0` keeps only U members and emits fallback pairs
`(min(3*v(k),MAX),k)`. Equality is the emitting arm; U is not an “excluded” set.
Fallback order is unsigned count descending, then all 20 key bytes descending,
as established by the complete short sort `0x53eaec0`.
The 32-bit division fast path is taken only with zero high halves and yields
the same unsigned quotient as the 64-bit path. Saturating product uses the
overflow test rather than wrapped multiplication. Zero fallback counts remain
until the first applicable replacement batch has finished.

## Binary64 events and comparator

Let n=|D| and i be a row's zero-based D index, including zero-weight rows.
For v>0 and every j in 0..v-1, the instruction sequence is

```
a = RN(1 / RN(v))
p = RN(RN(i) * a)
b = RN(p / RN(n))
t = RN(a * RN(j) + b)              # one fused rounding here
event = (t, None)                  if key in U
event = (t, Some(key))             otherwise.
```

The constants at `0x451210`, `0x450170` reconstruct u64 conversion from low /
high parts; `0x4592b0` is binary64 1.0. The i conversion is signed CVTSI2SD.
A valid materialized stride-32 allocation gives i<2^58, so its signed and
unsigned values agree. Separate MULSD and DIVSD precede the FMA call: exact
rational simplification or unfused multiply-add is a different computation.
The larger `event_bits` admission (i<=I64_MAX,i<n,j<v,n,v>0) qualifies this
arithmetic stage only. Its huge-number fixtures do not assert feasible native
allocations or reachability in a full schedule.

Complete short comparator `0x53ddc30` orders raw binary64 bits x by the
unsigned key ~x if negative, otherwise x|2^63. Equal float words order None
before Some; two Some payloads compare all 20 bytes ascending. This equals
Rust `total_cmp` then `Option<Key>` order, including signed zero and NaN words.
Generated events are finite and nonnegative. Raw Q fixtures exercise the
comparator's wider domain separately, not target-generated NaNs. Equal None
events have identical downstream effects, so their stability is immaterial.

## Replacement and output

Each Some event appends its key. Each None event with a nonempty fallback pool
of length m selects indices 0, 1 mod m, 2 mod m in that fixed order, without
reranking between the three selections. It snapshots each key and saturating-
decrements that entry, so m=1 selects one key three times, and m=2 selects
first/second/first. A zero-count key can be selected during this batch. Only
after the batch does the target sort descending count/key and remove all
trailing zero counts. It appends the three snapshots. None with an empty pool
appends nothing. Arbitrary raw event tags are not admitted; the generated
event domain has only None/Some, making the raw tag-2 loop exit irrelevant.

The reservation counts 1 for Some and 3 for None even if the latter later
emits nothing. Valid normal-return allocation bounds are explicit. The Rust
model checks representable counts and uses `try_reserve_exact` for event and
output arrays; it imposes no invented step budget. Other collection operations
can still panic on resource exhaustion. All input images are passed by value,
so a returned refusal cannot partially change a caller image.

Let L be the resulting sequence. Empty L writes only output byte 0=`0x0f`.
Otherwise the full selection round s from entry RDX selects L[s mod |L|]; the
key is written at output+1..21 and byte 0 becomes `0x2e`. Other caller-output
bytes retain their supplied values. The query round r from entry RCX does not
replace s here. The 32-bit DIV arm has the same high-half precondition as the
threshold division. Main then returns the original output address in RAX.

## Migration and evidence independence

Historical node94 work remains only in Git commit
`b930b69f793f8e3676d60c0ceceb683b8c94ef8f`. Its independent mathematical
implementation was migration input, not evidence that node115 behavior was
unchanged. New full target, FDE, caller, slot, helper, data and CFG records were
derived. Material changes include separate rounds, ring histories, diagnostic
MAX/LOCK INC behavior, saturating total, byte tags, and 72-byte missing-copy
semantics. No old target digest or helper module is a runtime dependency.

`oracle.py` was frozen before the first node115 Rust adaptation, after the
historical source had existed and been inspected. This is not a claim that no
Rust ancestor existed. Its binary64 arithmetic uses integer-ratio ties-to-even
rounding and exact Fraction multiply-add, not host FMA. Histories use maximal
eligible values; ring expectations enumerate logical entries; weight totals
use unbounded sums then min; replacement uses a key/count map and mathematical
ranking. All 9,243 expected records were frozen together, including previously
learned union-counterexample shapes. No post-node115-source supplement exists.
The input-only client receives inputs alone. Only new Rust executables run.
No captured code, instruction emulator or target-output oracle is involved.

Official Hyperliquid documentation corroborates only high-level stake-weighted
consensus and distinguishes rounds from execution. It does not independently
confirm this exact 2000/200/201/1000/FMA/batch relation. Licensed Rust sources
corroborate primitive contracts only, not this private function's source or
compiler identity. Binary findings remain local findings, with no independent
external replication of the complete algorithm. See `research-handoff.json`.

The initial qualification matched all four correct runs, then stopped after
39 effective mutants at a missing text anchor for a rustfmt-split diagnostic
expression. Its exact partial archive and original validator remain retained.
Only that validator anchor changed; source, client, oracle and corpus stayed
fixed. The final run matched all 36,972 correct observations and detected all
47 compiled controls by normal-return value differences. No initial failed
anchor is counted as a successful mutation control.
