# RE-009: a used result overwrites the former path slot, node #94

The state-dump route packet [#1019](https://github.com/lalalune/hyperliquid-source/pull/1019)
leaves the shared call at `0x46ced31` opaque. It receives the address where
path words were previously stored. This packet identifies the callee's actual
12-byte output stores, proves the second field's integer projection over the
entire signed64 domain, and follows those fields into the real caller.

Conditional on reaching the in-range normal RET under the assumptions below,
the three DWORDs are **opaque nonzero EAX, `s mod 86400`, raw component word**.
The modulo is Euclidean: the result is in0..86399 even for negative s. This is
an integer/field-transfer contract; no clock units, calendar semantics,
original Rust layout or filesystem effect is inferred.

## Target, source ownership and scope

- Task/component: RE-009, one used storage-path result dependency.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Node #94: `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Full helper FDE: `0x151cba0..0x151cca5`,261 bytes; FDE `0xcf6258`, CIE
  `0xce1518`; no recorded LSDA. An absent LSDA is not a nounwind proof.
- Actual consumer slice: `0x46ced2c..0x46ced5a`,46 bytes, inside the
  `0x46cea60..0x46cf026` FDE already retained by #1019. Its full-frame hash
  and CFI are metadata context only here.
- Total selected native scope: **307 bytes / 71 instructions** (64 helper,
  seven consumer), six calls, three conditional branches, one RET.

[#521](https://github.com/lalalune/hyperliquid-source/pull/521), head
`2a76b70a2efc70f60b2914c9982c10160e360f6b`, already retains the64-byte prefix
`0x151cba0..0x151cbe0` for its clock-source/epoch-subtraction study. That
attribution and the prefix are credited context, **not new recovery**. The
197-byte tail `0x151cbe0..0x151cca5` supplies the projection/stores studied
here. The46-byte caller is also reused context, not newly recovered code.
The index-callee body `0x151f6f0`, upstream `0x326aec0` and all other helpers
remain excluded. No inferred reference implementation was copied.

## Source-derived equations

The preceding opaque helper writes a temporary result. The code loads a
signed64 raw word **s** at `0x151cbe0` and a raw DWORD **n** at `0x151cbe5`.
The first temporary DWORD is compared with1. Its equal branch goes to a cold
call arm; no original Result/error type is assigned to it.

On the projection arm, the exact instructions derive:

```
M = 0x1845c8a0ce512957 = 1749024623285053783
D = 0x15180 = 86400
h = signed_high64(s * M)
q0 = (h SAR 13) + (unsigned64(h) SHR 63)
r0 = s - q0 * D
sigma = r0 SAR 63
q = q0 + sigma
field1 = low32(low32(r0) + (sigma AND D))
```

These are closed integer equations from decoded operands, not concrete CPU
execution or an instruction interpreter. In particular, quotient truncation
is proved from the multiply/shift/sign expression, rather than assumed.

### Whole-domain quotient and remainder proof

For `-2^63 <= s <= 2^63-1`, signed64 multiplication by positive signed64 M
fits signed128. Its signed high word is `floor(s*M/2^64)`. Composing the two
arithmetic shifts gives `floor(s*M/2^77)`.

The exact source-derived identity is:

```
M * D = 2^77 + delta
delta = 12928 < 2^14
2^63 * delta < 2^77
```

For every integer `0 <= a <= 2^63`, therefore:

```
0 <= a*M/2^77 - a/D = a*delta/(D*2^77) < 1/D
```

The fractional parts of `a/D` are integer multiples of `1/D`, so this error
cannot cross the next integer. Thus `floor(a*M/2^77) = floor(a/D)` for the
entire magnitude domain. For negative `s=-a`, M is odd and
`0<a<=2^63<2^77`, so `a*M` is not divisible by `2^77`. The observed unsigned
high-word sign bit adds1: `floor(-a*M/2^77)+1 = -floor(a/D)`. Zero gives0.
Consequently q0 is exactly truncation toward zero for every stated s.

The product q0*D remains within signed64 and `-D<r0<D`, so the observed
multiply/subtract is exact in that domain. Sigma is0 for nonnegative r0 and
-1 for negative r0. The AND-with-D adds either0 or D; hence field1 is exactly
the Euclidean remainder, in `[0,D)`. It fits DWORD width. This is an algebraic
proof of the entire domain; endpoint/random comparisons are supporting checks,
not the justification for quantifying all64-bit inputs.

### Actual index guard and remaining unknown field

The source also derives an index argument, without establishing its meaning.
Let `A=719163`, `B=A-2^31=-2146764485`. The unsigned guard compares
`low64(q+B)` with `2^64-2^32` and rejects the below case. The proven q bound
ensures q+B is within signed64, so the accepted interval is equivalent to:

```
-2^31 <= q + A <= 2^31-1
```

The opaque callee receives the zero-extended low32 representation of q+A.
Its EAX is tested against zero. Only the nonzero route reaches the three
stores. Field0 is that opaque EAX; field2 is the retained n. No calendar
encoding, units or original argument/return type is inferred.

## Actual output and used consumer

Entry RDI is retained in RBX. The full native body has exactly three direct
memory references through that saved destination, all DWORD stores:

| Instruction | Offset | Source |
| --- | ---: | --- |
| `0x151cc56` | 0 | opaque EAX, nonzero on the RET arm |
| `0x151cc58` | 4 | derived Euclidean remainder |
| `0x151cc5c` | 8 | retained raw DWORD n |

All three dominate the sole in-range RET at `0x151cc6c` in the local
normal-return graph. RAX receives the saved pointer. No direct destination
load appears in the selected body; that does **not** prove transitive
read-freedom or rule out aliases/concurrent effects of opaque helpers.

The caller supplies `RSP+0x60`. After return, `0x46ced37` reads the first
DWORD and `0x46ced4d` reads the next two as a QWORD. Stores at `0x46ced3b`,
`0x46ced42`, `0x46ced52` form the16-byte region at `RSP+0xb0`:

```
[ numeric1, field1, field2, field0 ]
```

Thus the prior path slot is visibly overwritten for12 bytes; the selected
consumer reads those12 bytes, not its remaining four old bytes. No private
Option/DateTime/record ABI or downstream formatter behavior follows from
this raw permutation.

## Failure and alias limits

The raw status-equals1 branch targets `0x151cc6d`; index-bound failure and
opaque-EAX-equals0 both target `0x151cc98`. The two cold call targets and their
relocations are retained. Those arms have no in-range RET, but their calls'
return, unwind, abort and out-of-FDE behavior are unknown. CFI/branch bounds
do not prove noreturn or nounwind.

The conditional result relation assumes normally returning helpers honor
callee-saved registers/private frames, the destination is a valid live region
distinct from those frames, and no alias/concurrent mutation clobbers the
destination or frame. Source helper results s/n are abstract raw words;
the proof does not claim that every signed s occurs in a live execution or
passes the raw status/index/callee-result guards.

## Reproduce and controls

Python3 standard library and GNU objdump are required. Recorded native text
uses GNU binutils2.44 on Linux x86-64. The whole captured ELF is authenticated
before and after analysis. Native objdump sees only private read-only261-byte
and46-byte slices with original virtual origins; it never reopens the ELF
pathname. No full image copy or target/emulator/concrete CPU execution occurs.
Only the private filename in native headers is normalized; addresses,
instruction bytes and operands are unchanged.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/state_dump_result_projection_static.py \
  --output /tmp/result-projection-new
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest tests.test_state_dump_result_projection_static -v
(cd research/work-items/RE-009-state-dump-result-projection-94 && sha256sum -c MANIFEST.sha256)
make doctor verify test catalogue-check reproduce
```

Actual-byte counterfactuals include M-1 at s=86400, high-shift12 at s=172800,
and quotient-sign-shift62 at s=-86400. They produce a wrong extracted second
field **before** local rejection; M+1-only rejection is not used as a semantic
counterexample. Other controls alter the repair mask, store/consumer offsets,
call/branch destinations, source transfers, both FDEs, all five RELA bindings
and whole input identity. The proof conditions and index-boundary identities
are checked separately from supporting signed-edge/random examples.
The chosen counterfactual witnesses keep the examined intermediate integers
within their source widths. They demonstrate a changed conditional field,
not live reachability or execution of an altered target.

Real native exports repeat byte for byte on one toolchain; normalized records
permit only the GNU version string to differ. Raw text parity across different
versions is not asserted. A source-name substitution control verifies that
native tools continue using the admitted tiny slices. No progress gate,
reconstructed Rust, filesystem action or whole-node equivalence is claimed.
