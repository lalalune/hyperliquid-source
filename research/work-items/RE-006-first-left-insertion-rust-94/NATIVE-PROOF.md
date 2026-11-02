# RE-006 intake: one native first-left insertion

Historical pre-Rust intake record. Its statements about absent Rust/model
execution describe that stage. The immutable vectors/control predictions are
preserved; the later equality-classification counterexample is recorded in
`INITIAL-CLASSIFICATION-FAILURE.json`, and the current Rust results are in the
packet README and compiled receipt.

This is a local, unpublished native finding, separate from the completed
monotone module in #1455. No Rust insertion model, captured execution,
instruction evaluator, general sorting result or component gate is claimed.

Target node94 SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Linked ELF virtual addresses; half-open ranges. Upstream main remains
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. The live check inspected 143 open
PR bodies through #1495; only #1455 names the sort core, and none names this
short-run insertion or its helper addresses. The worktree has no tracked edits.

## Native boundaries and call chain

| Body | Range | FDE / CIE | LSDA |
| --- | --- | --- | --- |
| Credited core | `4dbd490..4dbdb5e` | `f4b840 / ce1518` | none |
| Adapter | `4497a90..4498022` | `ed52f0 / ce1518` | none |
| Small-count delegate | `4918d30..49190b7` | `12a6ee4 / fbdc2c` | `b8638c` |
| Opaque seed dependency | `4912a50..4912d13` | `f17fcc / ce1518` | none |

The four complete body hashes, FDE extents and direct call operands were
revalidated against the authenticated image. Earlier dual native decoding
agreed on their complete partitions. This intake independently regenerates
both decoders for the claimed 94-byte / 26-instruction envelope
`4918eef..4918f4d`, SHA-256
`43e12e83dde89dd8e7b05aec44cc43f8732c4b846e5a64192c087ec1ea5ad223`.

On the first core iteration for `21 <= n <= 32`, let `c=ceil(n/2)`,
`h=floor(n/2)`, A be the input pointer and S the scratch pointer.
The known wrapper supplies a true small-count flag and scratch capacity 512.
If the first natural run has length less than c, unsigned JB at `4dbd6f1`
takes `4dbd593`. The selected call at `4dbd5d1` uses slot `57768a0`, whose
RELATIVE entry is type8/symbol0/addend `4497a90`.

The adapter's `n<33` arm calls `4918d30` at `4497acd`. The core's observed
register arguments are A, n, S, capacity, zero, zero, plus an opaque stack
argument copied from the incoming core r9. The adapter forwards A, n, S and
capacity in rdi/rsi/rdx/rcx; its fifth register argument is that opaque value.
These are register facts, not recovered source types or a Rust ABI.

At `4918d48..4918d4f`, the delegate requires capacity >= n+16 qwords;
otherwise the branch reaches UD2 at `4919097`. In the selected domain the
wrapper supplies 512 >= 37..48. The delegate sets h=n>>1 and calls `4912a50`
twice, at `4918d71` and `4918d86`:

| Call | rdi | rsi | rdx |
| --- | --- | --- | --- |
| first | A | S | S+8*n |
| second | A+8*h | S+8*h | S+8*n+64 |

The seed helper's value semantics remain opaque here. After ordinary returns,
RCX is 8 and `8<h` for every admitted count, so `4918d99` reaches `4918eef`.
The code initializes RSI=8 and EAX=64, then jumps to `4918f12`.

## Closed local array effect

The claim ends at the first arrival at `4918f06`, before incrementing j.
It does not claim a function return or the effects of later iterations.

Let p0..p7 be whatever eight qwords the ordinary seed returns left in S, and
x=A[8]. The local relation does **not** require these eight words to be sorted.
Define k as one plus the greatest index i in 0..7 with pi<=x, or zero when
there is no such index. Then this step leaves:

```text
S[0..9) = [p0, ..., p(k-1), x, pk, ..., p7]
```

Only the maximal contiguous suffix strictly greater than x moves right.
Earlier words remain in their original order even when they are greater than
x. For example `[8,0,7,1,6,2,9,10]` with x=5 becomes
`[8,0,7,1,6,2,5,9,10]`; this is not a general sorting operation.

Native proof anchors:

- `4918f12` loads one full qword from A+8*j; `4918f16` first writes x to
  S[j]. Neither instruction changes or validates x's bits.
- `4918f1a..4918f22` reads the preceding qword and uses unsigned JAE.
  Equality takes the direct join at `4918f06`: exactly the initial S[8]
  write, with no predecessor shift or lower prefix read.
- Otherwise byte offset R8=64. `4918f30` shifts the predecessor one qword
  right. `4918f34/38` tests offset8 before any lower read, and reaches the
  front store through `4918f00/03` without reading S[-1].
- For larger offsets, `4918f3a` loads S+offset-16, `4918f3f` subtracts8,
  and unsigned JB at `4918f46` repeats only for x<predecessor. Equality
  stops, preserving old equal words before x.
- `4918f48..4918f4b` forms the final scratch address and joins the same
  full-qword x store at `4918f03`.

The offset decreases from64 to8 by8, so at most eight predecessor shifts
occur. All scratch reads lie in S[0..8), and all scratch stores lie in
S[0..9). There is one initial S[8]=x store; if k<8 it is followed by stores
to indices 8 down through k+1 and finally k. The envelope contains no call.
A and all scratch outside these nine words remain unchanged under valid,
stable, nonwrapping storage disjoint from each other and the native stack.
Sorting follows only if the prefix is separately proved sorted.

## Frozen controls and limits

The first historical freeze remains unchanged, SHA-256
`aa467f623ad8d610d1d22e7dddde3fc01c1e66937f8996b4d08553c228dc90df`.
The second pre-model freeze adds six unsorted-prefix states to its twelve
unique/high-bit/tie cases, binding all 18 literal expectations and nine native
mutations before any insertion model:

`FIRST-INSERTION-V2-FREEZE.json`, SHA-256
`d6c3e42b061125f42a420b3b3e08e94bd896f4eae020e2b355f752282cbe50e4`.

All nine mutations were written individually as inert mode0600 ELF copies,
decoded with both GNU and LLVM, and rejected by the corresponding width,
address, progress, front-guard or unsigned-branch property with target/frozen
byte guards bypassed. The original was never changed or executed. These are
static operand/CFG distinctions, not execution results. The last two equality
controls concern trace/index boundaries; equal-valued arrays can remain equal.
The dword-width control concerns the initial store even when later shifts
overwrite it; an append case with the frozen nonzero S[8] sentinel also makes
that width difference visible in the final array.

`FIRST-INSERTION-STATIC-CONTROLS.json`, SHA-256
`84aa1680d7380cb1bb319f893b43954e4f89de5771187779e9e78f95d9544ae0`,
records the exact bytes, reasons and decoder agreement. The 18 state vectors
are frozen expectations; no consequence model or compiled candidate has yet
been run against them. The freeze is a local sequence record, not an external
timestamp attestation.

Remaining gaps: seed output semantics, actual complete-call state reachability,
later left insertions, right-half extension, final bidirectional merge, seed
failure/unwind and the remainder of generic sort. No conclusion about these
is supplied by this local proof.
