# RE-010: node #115 link-staking finalize unwind boundary

- Component ID: `action-dispatch` / `staking`.
- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes).
- Source base: `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
- Claim status: call instructions, unwind rows and landing-pad presence are
  observations; absence of an in-frame rollback is a bounded inference; outer
  transaction handling and persistent state are unresolved.
- Scope: the selected finalize core, its action wrapper/dispatch/parent call
  sites, and the relationship writer's exception-table rows. No progress gate
  is requested.

## Reproduce

With Python 3.12 or newer and Capstone 5.0.7 installed, from the repository root:

```sh
python3 research/work-items/RE-010-node115-staking-finalize-unwind-boundary/verify.py
python3 research/work-items/RE-010-node115-staking-conversion-cleanup/verify.py
```

The checker preserves the historical Python version in `verification.json`,
compares all stable byte/semantic results and corruption controls, and reports
a current Python patch-version difference separately. A separate current-host
report can be retained with `--write --out work/staking-finalize-unwind-verification`
without replacing the historical provenance. The second command independently
revalidates the linked local conversion-cleanup evidence. The captured node is parsed as data only; no
captured code is executed or emulated. The evidence was checked with Python
3.12.13, Capstone 5.0.7 and Apple LLVM `llvm-objdump` 21.0.0.

## Evidence

Coordinates are linked ELF virtual addresses. The verifier authenticates the
full target digest and size, parses `.eh_frame` through the repository's pinned
ELF helpers, decodes seven byte-complete instruction windows, and checks three
LSDA call-site tables. The retained evidence covers five selected FDEs, six
direct calls, one relocation-backed indirect call, and four exceptional
call-site rows. These are selected-site counts, not a function or component
denominator.

In `finalize_core` (`0x469fe90..0x46a02ea`), the normal success path calls the
relationship upsert at `0x3ce1080` twice. It constructs tag 1 for the first
record and tag 2 for the reciprocal record, passes the same descriptor pointer
in `r13` to both calls, and has no conditional branch or return between them.
The existing #2126 packet maps these as the two normal relationship writes.
The finalizer FDE has no LSDA. Its action wrapper
(`0x58c07d0..0x58c08b8`) also has no LSDA; the wrapper's indirect call resolves
through slot `0x64e7a80` to the finalizer.

The dispatch call to the wrapper at `0x55f9f10` lies in the LSDA row
`0x55f99b0..0x55fa86a`, whose landing pad and action are both zero. The parent
call to dispatch at `0x5536e14` lies in row `0x5536d94..0x553703e`, also with
no landing pad or action. Other rows in those two functions do have landing
pads; the recorded call sites do not fall in them.

The relationship writer LSDA at `0x3001e8` protects two representation
conversion iterator calls: `0x3ce11c6` transfers to landing pad `0x3ce158e`,
and `0x3ce13a6` transfers to `0x3ce156b`. The linked #4288 packet verifies
that these pads publish the computed map representation fields and call
`_Unwind_Resume`; they do not restore the prior descriptor or catch the
exception. The other writer call-site rows have no local landing pad.

## Implementation and comparison

No Rust transition or exception model is added. The open #5114 implementation
explicitly excludes allocation and unwind behavior, so this packet preserves
that boundary instead of encoding an unsupported atomicity assumption. The
focused verifier includes four in-memory corruption controls; each must be
rejected. The retained `verification.json` records their results.

## Results and limitations

The inspected frames contain no compensating action at the selected second
upsert call site. If an exception propagates from that call, this evidence is
consistent with a partially mutated in-memory map; it does not prove that a
particular exception occurs. It also does not establish whether an outer
transaction catches the unwind, restores state, aborts the process, or persists
any state. Allocator behavior, the caller chain above the selected parent,
runtime unwind behavior and external persistence remain unknown. No component
gate is advanced.

Next question: trace the caller above `parent_caller` to determine whether it
establishes a transaction boundary or rollback for a propagated exception.

Made via @slopdotcash
AI provider/model: OpenAI / GPT-6
Client / agent tooling: Codex
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— [contributor]
<!-- slop-contribution-attribution:v1 {"provider":"OpenAI","model":"GPT-6","client":"Codex","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->
