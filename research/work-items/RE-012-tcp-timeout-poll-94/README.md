# RE-012: node #94 write/timeout result ordering and caller cleanup

The unresolved `0x2036460` controller consults its timer only after its lower
write adapter returns raw `RAX=2`. An empty or completed write and a write error
return directly. The writer at `0x204b340` preserves the controller subobject
on raw result 2; results 0 and 1 pass through `0x1fb6110` before the caller
distinguishes the payload path from its diagnostic-construction path.

This is a conditional static result, not an elapsed-time, liveness, Rust type,
or complete ownership proof. [PROOF.md](PROOF.md) specifies the valid-state and
callee assumptions and the exact branches that establish it.

- Task/component: RE-012 / `transport`; map an existing frame path and its writes
  and external-call boundaries. Partial progress only; every gate stays false.
- Target: `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Main examined: `d3af75257a396c85d20857f421c370ddb8cb40e5`. Working source
  revision: `f86495a9e35d5cb233088cecf8016a49e71ca4df` (the separate Visor packet
  adds no transport implementation). Reference lead: `references/can1357-hl`
  at `999556f6e0a474b8312db96ec3149e1c44e97c23`, `net_utils/tcp/write.rs` and
  `tcp_stream.rs`. Its names and async types are hypotheses, not evidence.
- Claim status: bytes, branches, data writes, FDE records, and call slots are
  observations; “write,” “timer,” “cleanup,” and “diagnostic” are descriptive
  roles supported by the surrounding path. No source type is recovered here.
- New question resolved: raw result production, timer priority, saved progress,
  and this caller's normal cleanup boundary. The older
  [frame-write packet](../transport-tcp-frame-write-94/README.md) explicitly
  excludes the controller. Credit that packet's writer/context exports,
  compression/chunk/default-duration findings and the reference's seed/loop
  observations; those are not new recoveries or independent confirmations.

## Scope and evidence

Coordinates are linked ELF virtual addresses and half-open extents. Each range
comes from its actual `.eh_frame` FDE, cross-checked against the corresponding
`.eh_frame_hdr` entry; no next-entry subtraction is used to invent an end.
FDE extents are unwind-described ranges, not a whole-program function census.

| Role | FDE range | Bytes | Normalized instruction rows | Claim scope |
| --- | --- | ---: | ---: | --- |
| Controller | `0x2036460..0x20367c3` | 867 | 191 | Primary control/state relation |
| Timer adapter | `0x4f68f00..0x4f6903e` | 318 | 84 | Normal-return AL domain and TLS branch |
| Write adapter | `0x4f7d1a0..0x4f7d34b` | 427 | 117 | Normal-return RAX domain, opaque dependencies |
| Error adapter | `0x288d0d0..0x288d134` | 100 | 24 | Opaque conversion boundary, not error-type closure |
| Cleanup context | `0x1fb6110..0x1fb61f8` | 232 | 66 | Called boundary and unresolved indirect targets |
| Writer context | `0x204b340..0x204c216` | 3,798 | 743 | Consumption at `0x204be81`; rest retained as context |
| Total export/comparison denominator | 6 FDE ranges | 5,742 | 1,225 | Not a semantic-equivalence denominator |

`observed/records.json` retains the FDE/CIE bytes, LSDA call-site prefixes,
two four-entry dispatch tables, six selected relocation bindings, fixed byte
witnesses, instruction partitions, and structural control edges. Direct
transfers have decoded targets; RIP-relative indirect calls retain slot
addresses. The six selected bindings require `R_X86_64_RELATIVE`, symbol index
zero, and the exact addend. Other indirect slots remain dependencies.

The complete native exports are `observed/<role>.gnu.txt` and
`observed/<role>.llvm.txt`. GNU's nearest-symbol labels are unrelated symbol
offsets, not function identities. LSDA records stay separate from normal CFG
edges; type/action chains and actual unwinder behavior are unresolved.

## Reproduce

From the repository root, with Python 3 and the two native disassemblers:

```sh
python3 -B research/work-items/RE-012-tcp-timeout-poll-94/collect.py --out /tmp/tcp-timeout-new-evidence
python3 -B research/work-items/RE-012-tcp-timeout-poll-94/verify.py
python3 -O -B research/work-items/RE-012-tcp-timeout-poll-94/verify.py
```

The export destination must not already exist. Override `--gnu` and `--llvm`
when installed paths differ. Recorded tools: Python 3.14.3 on macOS arm64,
GNU objdump `2.47.20260726`, Apple LLVM objdump `21.0.0`. Exact flags are in
`collect.py`; both use Intel syntax and explicit start/stop addresses.

The collector authenticates the entire original input, creates one private,
read-only temporary `hl-node` copy of those bytes, and checks that full copy's
digest before and after both tools export all six ranges. Both tools receive
that same copy; it is never executed. Raw exports name `hl-node` and omit the
temporary directory. Parsing and disassembly are the only target operations.
The snapshot is a reproducibility control, not protection against a hostile
same-user process or a compromised disassembler.

The existing pure ELF/FDE parsers are reused with their hashes recorded. No
shared tool, catalogue, progress record, reference or target is modified.
Task-local scripts exist to make this specific binary finding reproducible.

GNU emits a single LOCK-prefixed instruction where LLVM prints a standalone
`f0`/`lock` row and the following instruction separately. The only grouping
rule joins those adjacent rows. Their full bytes and the next instruction
boundary must agree; no byte, address or operand is masked. The 1,225-row
partition agrees across all 5,742 bytes. This is two disassemblers reading one
binary, not two independent semantic implementations or compiled Rust matches.

## Verification and limits

[VALIDATION.md](VALIDATION.md) records actual commands, results and the initial
LOCK-row mismatch. `validation.json` retains the negative-control results.
Controls run below the whole-image hash gate where applicable: all fixed
witnesses, both tables, selected relocation addends and symbol indexes, every
selected FDE range, unwind-index encoding, LSDA call-site facts, malformed
native exports, wrong target, and existing output. Two fresh regenerations
must equal all retained exports and metadata. A changed byte outside the fixed
witnesses passes that subset checker but fails complete native byte comparison.

No Rust reconstruction, compiler comparison, target execution, instruction
interpreter, network I/O, timer measurement, or whole-node acceptance test is
claimed. Raw-equal / normalized-only / unmatched **compiled reconstruction**
counts are not yet measured. The caller's three pre-existing computed state
dispatches and the cleanup context's indirect callbacks remain unresolved in
the structural CFG, and are outside the selected downstream relation. The
controller's two dispatch tables are resolved only for indexes 0 through 3.

The next question is to close `0x4f79620` and the readiness slot `0x576f158`
against their scheduler/data contracts, including wake registration and timer
expiration. Until then raw controller result 1 identifies this caller's
timer-selected diagnostic path, not a measured wall-clock deadline or a
recovered source enum.
