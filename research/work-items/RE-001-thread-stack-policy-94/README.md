# RE-001: node94 thread stack policy and worker handoff

This bounded static packet recovers the production constructor's explicit,
cached and environment-derived stack-size selection, its join-result layout,
and its fixed worker callback. The selected native bodies are
`0x1448270..0x1448820` (1,456 bytes) and `0x1451a90..0x1451bed` (349 bytes).
The comparison denominator is two complete FDEs / 1,805 bytes, not a Rust build
or component-completion claim. `PROOF.md` gives the instruction-address argument; `overlap.json` and
`validation.json` preserve the audit and observed results.

Target: node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `966865f1637a29ce75b019e1bf11d5529cc6f519`.
Reference pin: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
All coordinates are ELF virtual addresses with exclusive ends. New evidence
and verifier code are independently authored under MIT; original binary
excerpts retain their own rights. The shared native pthread adapter is already
covered by #1640 and is not recovered again here. No target execution or
emulation, live network, signing, or progress-gate change is requested.


## New findings and scope

Component allocation: **RE-001 / foundation, node-runtime integration**.
These are thread-support and callback integration bodies; they are not claimed
as exclusively first-party source or reconstructed implementation bytes.

The previous #1409 production-cycle packet leaves this constructor opaque.
This independent branch supplies its actual explicit-stack precedence, encoded
cache, environment/text-result gates, decimal overflow decisions, constructor
output writes and fixed callback handoff. A separate incoming call also exists,
so the constructor is not claimed to be exclusive to the production poll.

- Explicit DL bit 0 selects RCX without consulting the cache or environment.
- A nonzero cache word encodes size+1; otherwise `RUST_MIN_STACK` is requested.
  The caller defaults to 2,097,152 for its observed absent/error/invalid cases.
- Under a valid text-helper result, parsing admits an optional leading `+`,
  ASCII digits and leading zeros, with checked u64 overflow. No trimming occurs.
  The maximum u64 parses but wraps the encoded cache word to zero.
- The constructor supplies a 40-byte worker and a 24-byte envelope, then
  projects the native result based on AL bit 0 into its output record.
- The callback calls `0x13ffc40` followed by `0x1400e90`, then updates the join
  record. A normal completion writes a zero first payload word but does not
  establish a zero second payload word. Full worker purpose remains unresolved.

The bounded proof assumes stable valid buffers, normal helpers and successful
allocations. No actual environment value, stack allocation, native thread,
application effect, Rust ABI equivalence or whole-function completion is claimed.
This resolves a concrete startup dependency while preserving all component gates.

## Retained evidence and reproduction

| Complete owning FDE | Bytes | Instructions |
| --- | ---: | ---: |
| Constructor 0x1448270..0x1448820 | 1,456 | 350 |
| Callback 0x1451a90..0x1451bed | 349 | 92 |

`records.json` includes body hashes, file offsets, CIE/FDE/LSDA addresses,
all explicit calls, 19 RELATIVE bindings, the undefined dynamic `malloc`
import, both literal/data records, and the qualified incoming-call census.
Selected instruction obligations cover 35 spans. GNU and LLVM exports are
complete and byte-identical on regeneration; GNU readelf independently agrees
on the two FDE headers. No source attribution or original compiler identity is
inferred from the nearest symbol labels printed by a disassembler.

From repository root with the pinned inputs materialized:

```sh
packet=research/work-items/RE-001-thread-stack-policy-94
python3 "$packet/export_disassembly.py"
python3 "$packet/verify.py" --controls
python3 "$packet/arithmetic.py"
python3 -m unittest tests.test_thread_stack_policy -v
make doctor verify test catalogue-check reproduce
(cd "$packet" && shasum -a 256 -c MANIFEST.sha256)
```

Recorded local tools: Python 3.14.7, Capstone 5.0.7, GNU objdump/readelf
2.47.20260726, LLVM objdump 18.1.4, macOS arm64. Put GNU and LLVM tools ahead
of the system utilities on PATH. The exporter invokes only static disassemblers
and readelf, never the captured code. Image/export plumbing is adapted from our
MIT-authored #1547 packet; this branch has no dependency on that PR.

**62 actual-byte corruption controls** bypass the whole-image/body digest and
export guards: 35 semantic spans, 19 relative addends, two literals/data records,
two FDE ranges and four dynamic-import fields. An additional prologue mutation
outside those spans checks each integrity guard individually. All mutations
are in memory; the input file is neither changed nor executed.

The arithmetic checks cover 256 byte classifications, 16 unchecked-length
bounds, 60 checked decimal updates, 4,101 cache values and nine decimal boundary
records. They support the written argument and are not a parser implementation,
captured instruction evaluator or target equivalence test. Four focused tests
cover authentic records, corruptions, independent guards and these lemmas.
Full repository results, exact tested source and per-module log hashes are
retained in `validation.json` and `suite-results.json.gz`. Skips are not passes;
no hosted CI success is claimed from local results.

## Overlap and remaining gaps

`overlap.json` records all-state PR metadata searches and available patches for
all open and closed-unmerged PRs plus related merged work, with exact heads and
hashes. #1409 calls this constructor but explicitly leaves it unresolved.
#1640 covers a distinct slow-ABCI constructor/callback and the **shared** native
adapter `0x4ee4ab0`, native entry `0x4ee48b0`, and counter failure helper
`0x4eeb8a0`; none of those bodies is reclaimed or exported here. The temporary
path candidate was discarded because #1588 already covers it. No competing
recovery of the two selected bodies was found in the recorded audit.

Unknowns include environment/text/name helper closure, hook effects, the fixed
worker's purpose, concrete ownership/result types, dynamic destructor targets,
OS behavior, full exceptional control flow, and source/compiler provenance.
Next bind the two worker-call helpers and the LSDA/personality selection before
assigning an application purpose or a full completion/error contract.
