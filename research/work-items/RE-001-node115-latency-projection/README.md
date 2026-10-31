# RE-001: node #115 latency observer and record argument projections

- Component: node instrumentation / ABCI latency; bounded static mapping.
- Target: node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source revision: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Question: which local guards and numeric projections feed the two observer calls and subsequent record helper in the #115 source-associated body?
- Observations: the optional first observer receives an unclipped nonnegative value; the second observer receives a value capped at 60.0; the second value is separately retained before the cap and passed to a record helper without that cap.
- No complete clock, metrics, persistence, Rust implementation or component gate is claimed.

## Prior work and distinct scope

PR #625 studies **node #94** ABCI sampler construction, begin/commit, elapsed and writer helpers, including its uncapped row value. PR #44 studies a **node #94** begin-sample update. Those findings are credited as prior research, not claimed anew here. This packet authenticates a different capture, validates #115's actual source Location, FDE and calls, and bounds its inlined signed-pair normalization and pre-cap argument preservation. It does not import #94 addresses, helper semantics, source names or time units into #115, or claim a release difference solely because addresses differ.

## Evidence denominator and bindings

One full actual FDE: **`0x51c9a70..0x51c9cad`, 573 bytes / 143 native instructions**, original ELF VAs. `records.json` retains the body SHA-256, file offset, raw FDE/CIE records and call/relocation bindings. GNU readelf independently confirms the full range. Native objdump covers the complete body without normalization or interior-window substitution.

Locations `0x64a3618` and `0x64a3630` relocate to the actual 32-byte path `node/src/abci_latency_sampler.rs`, lines **70:38** and **73:48**. Their native LEAs feed the two calls through slot `0x64e1010 -> 0x1547530`. This establishes bounded source association and two actual call sites, not recovered public names or a complete observer ABI.

Other retained slots are `0x64e0990 -> 0x1629690` (initial tuple provider) and `0x64e0fc0 -> 0x162a290` (pair provider used twice). Those helper bodies remain opaque. No claim about UTC/monotonic time, precision, concrete timestamp type or actual provider return domain is made.

## Control and numeric dataflow

The initial tuple-provider call at `0x51c9a99` occurs **before** the anchor dword at object `+0x7d0` is tested for zero. A zero anchor returns through the epilogue, but is not a no-call route. Conditional on a nonzero anchor, the low input EDX byte independently controls the first observer.

The optional first path compares three 32-bit words lexicographically: first signed, second and third unsigned. If the anchor sorts before the incoming tuple, it supplies zero; otherwise it calls the pair provider with the copied anchor and incoming tuple at input `+0x18`. The first observer is passed object `+0x260`, raw ESI 1, Location 70:38 and the projected value in XMM0. It has no corresponding local 60.0 MINSD.

On both inlined numeric paths, let returned RAX and EDX be abstract signed components `(s,n)` in i64/i32, conditional on that ABI interpretation and ordinary nontrapping floating-point operation. The native tests and conditional moves select:

```
if s < 0 and n > 0:
    s1, n1 = s+1, n-1_000_000_000
else:
    s1, n1 = s, n
```

The selected correction is exact rationally: `s1+n1/10^9 = s+n/10^9` for all raw i64/i32 pairs. On the corrected branch, `s+1` cannot overflow and `n-10^9` stays in i32. The unselected LEA result need not be interpreted as a signed value. Both integer components are converted with CVTSI2SD, divided/added using the actual binary64 **1e9** constant at `0x458d50`, then subjected to MAXSD with positive zero. The compare against actual **+Infinity** at `0x459010` leaves zero on the equality/unordered route.

For this restricted raw integer-pair model with ordinary binary64 rounding, conversions and arithmetic remain finite and cannot create NaN or infinity. Therefore the model's nonnegative result is `v=max(0,float(s1)+float(n1)/1e9)`; this is **not** a proof of real clock-helper return semantics, elapsed units, signed subtraction or original timestamp validity. Rounding of the rational result to a final binary64 value is not asserted exact. Nondefault FP environments, exceptions and full helper behavior remain outside the model.

The normal second path calls the pair provider with the initial tuple and retained anchor. It saves v at **RSP+0x48** (`0x51c9bed`) before computing its observer argument:

- `0x51c9bf3`: object `+0x4c0`;
- `0x51c9bfa`: load actual binary64 **60.0** from `0x459718`;
- `0x51c9c02`: MINSD with v;
- `0x51c9c06`: Location 73:48;
- `0x51c9c12`: observer call, raw ESI 1, XMM0 `min(60.0,v)`.

After that opaque call, `0x51c9c4f` reloads saved v from RSP+0x48 and `0x51c9c55` stores it at **RSP+0x28**. Record base is **RSP+0x10**, passed in RDX at `0x51c9c5b`; hence the value's **record-relative offset is +0x18**. Call `0x51c9c63 -> 0x4e3d2c0` receives object `+0x720`, the initial tuple and this record. For the abstract pair `(120,0)`, the local observer argument is 60.0 while the record argument contains 120.0. Whether the helper stores, serializes or discards the value is unproved; it is not called a persisted history/JSON field here.

The remaining optional tail and calls `0x14c3950`, `0x1533e80`, `0x14c4d00` are retained but not assigned writer/flush/type semantics. Valid input memory, normal helper returns and ABI preservation are assumptions of the local dataflow description. Complete callers and unwind effects remain unclosed.

## Reproduce and counterfactual controls

macOS arm64; Python 3.12.14; GNU readelf/objdump 2.47.20260726. With materialized captures and native GNU tools on PATH:

```sh
python3 -B tools/latency_projection_static.py --output work/latency-projection-check
# Compare generated files with this packet except README/manifest.
python3 -B -m unittest discover -s tests -p test_latency_projection_static.py -v
make doctor verify test catalogue-check
make reproduce
(cd research/work-items/RE-001-node115-latency-projection && shasum -a 256 -c MANIFEST.sha256)
```

Full identity is verified before parsing, output or native calls; readelf/objdump operate on private byte-identical snapshots. Full native instructions, selected original relocations, raw unwind records and deterministic UTF-8/LF records are retained.

Six focused tests regenerate native evidence, check exact rational correction at signed extremes and selected boundary pairs, and alter actual target operands. Changing the actual 60.0 literal to 120.0 changes the `(120,0)` observer projection to 120 while leaving its record value 120; changing actual divisor 1e9 to 1e6 changes `(1,500000000)` from 1.5 to 501 before the cap. Both are rejected by evidence validation after their extracted projections demonstrably change. Additional controls change the real guards, signed tests, correction/stack offsets, MINSD/MAXSD operands, object offsets, call/LEA displacements, source metadata, relocation addends and actual FDE bounds. Wrong-release, same-size modified and truncated captures fail the public gate before output creation.

Before: main has no #115 packet binding this body and its pre-cap value to these source/argument paths. After: these local facts and the conditional numeric relation can be independently regenerated and checked without assuming #94 behavior. There is no source implementation, target/emulator execution, clock/metrics integration test, network, wallet, signing or chain action. No unlicensed inferred source is copied. Imports/pins and every component gate remain unchanged. No hosted CI, runtime equivalence or protocol/security finding is claimed.

Next question: close the #115 pair and record helpers before assigning timebase, units, exact elapsed semantics or persistence behavior.

Observed local validation: **six focused tests passed in 15.352s**.
`make doctor verify test catalogue-check` passed **437 tests in 167.484s**;
`make reproduce` passed. Packet manifest and staged whitespace checks passed.
No hosted-CI result is claimed.
