# RE-014: node #115 newline adapter protocol

This qualifies the complete 630-byte helper that
[the prior drift packet](../RE-014-node115-field-adapter-drift/README.md)
left opaque. Under explicit memory/callback premises, it scans for the first
LF, requests nonempty LF-terminated pieces and a final tail, conditionally
requests four spaces, writes the LF flag before each payload, and stops on
nonzero callback AL. Empty input performs no flag-directed access or callback.

The #115 operand and lifetime proof is independent. The earlier protocol and
its safe-skip byte/borrow lemma are historical mathematical context, available
[in Git history](https://github.com/lalalune/hyperliquid-source/blob/56c0ec672bd8fdcfaa80f2db700a61e6240b3663/research/work-items/RE-005-diagnostic-field-trace-94/SCAN-AND-PRETTY-PROOF.md).
Reproducing this packet requires only the authenticated #115 capture. The
historical comparison is optional and supplies no additional recovery credit.

Task/component: RE-014 / foundation. Authoring base
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.

| Active target | Full capture SHA-256 | Bytes |
|---|---|---:|
| Node #115 | `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` |105,896,032|

| Complete FDE extent (ELF VA) | Bytes / rows | Role |
|---|---:|---|
| #115 `0x1686bd0..0x1686e46` |630 /173|qualified helper|
| #115 `0x167d950..0x167dad6` |390 /109|actual fixed parent/table edges|

GNU and LLVM agree on all **282 instruction byte partitions across 1,020 bytes
and two complete #115 FDEs**.
These are reused observed ranges; **new recovered-byte credit is zero**.
No normalized-byte equivalence, original compiler/type/ABI, Rust build or
complete component gate is claimed.

## Conditional result and changed code

[PROOF.md](PROOF.md) covers all 32 branches, both indirect calls, the only RET,
the scan's scalar/alignment/two-word/tail paths and their progress argument.
The record accounts for all 173 #115 rows with named operand witnesses,
branch relations or 11 exact NOP forms.

The #115 frame allocation is 0x38. Its live emitted cursor is R15,
its search cursor is R14, and R13 materializes the C word only during a long
scan before becoming a piece-end carrier. The payload TEST/MOV/JNE chain retains
callback AL flags across an EAX reload; final-tail success tests its continuation bit before reusing the
deliberately restored old cursor.

D/V/B pointer values are cached after the prologue. Each callback still loads
the current method from V+0x18. The proof permits callback edits to the flag
and method entry within its protected-memory conditions. It does not silently
infer an unchanged final flag or stable callback identity. Input immutability,
nonwrapping arithmetic, valid/nonaliasing storage, protected frames/returns
and ordinary callback preservation are explicit premises. Empty input still
writes its own frame, so physical flag preservation requires separation.

Actual #115 edges bind parent slot 0x64e00a0 and table 0x6407910 to 0x1686bd0.
The four-space literal is at 0x45a128. Table+32/+40 targets remain opaque.
The generic adapter's incoming underlying writer V is distinct as a role
from this fixed parent adapter table. Static RELATIVE records are not observed
runtime pointers.

## Reproduce

Python 3 plus GNU binutils and LLVM; use fresh output paths from repository root:

```sh
packet=research/work-items/RE-014-node115-newline-protocol
python3 "$packet/collect.py" --output work/node115-newline-native
python3 "$packet/algebra.py" --output work/node115-newline-native/algebra.json
python3 "$packet/verify.py" --output work/node115-newline-check.json
python3 -O "$packet/verify.py" --output work/node115-newline-optimized.json
```

The collector/verifier accept `--objdump`, `--readelf` and `--llvm`.
Retained runs used GNU binutils 2.47.20260726 under
`/opt/homebrew/opt/binutils/bin/` and Apple LLVM 21's
`/Library/Developer/CommandLineTools/usr/bin/llvm-objdump`.
Exact native text/version regeneration requires the recorded providers.
All scripts authenticate the complete #115 image before parsing production input.
Only native parsers/decoders receive non-executable copies.

Current normal and `-O` verification reproduce 8 retained outputs and reject 35 controls:
3 image-identity, 22 fresh native mutant bindings, 8 lower-level data/RELA/unwind
bindings and 2 record controls. No whole-image/body hash masks the latter
checks. The native mutants include a prefixed NOP replaced by an AX write and
a MOV changed to ADD that would clobber the payload-result flags.

Three changed word constants additionally have actual mathematical
false-negative LF vectors; threshold/stride changes have overread/unread
interval witnesses. The baseline checks 15 byte/borrow cases and 320 finite
interval partitions covering 9,096 positions. These are scalar mathematics,
not a captured scanner, register machine or callback evaluator.
Exact binding rejection alone is not changed-program semantic validation.

[migration-validation.json](migration-validation.json) records the current
#115-only collector and verifier results, native-export equality checks and
source hashes. The original [VALIDATION.json](VALIDATION.json),
[ROOT_REVIEW.json](ROOT_REVIEW.json), [validation/normal.json](validation/normal.json)
and [validation/optimized.json](validation/optimized.json) are preserved historical
receipts from before retirement; their 11-file count and collector hash do not
describe the current collector. [PROOF.md](PROOF.md) remains the original manual
argument, including explicitly historical comparison passages.

The manual native-to-formula and higher-order argument remains necessary. No
target process, instruction emulator, physical renderer, build or hosted CI is
implied by this migration. The current six native #115 exports are byte-identical
to the original exports; only the retired capture and its three exports were
removed from the active collection. No new byte credit is claimed.

## Provenance and remaining question

ELF/native record mechanics use the same standard-library parsing approach
as the project's MIT static surveys; no shared tool was modified or imported
as an unmerged dependency. No inferred unlicensed source or official libcore
implementation was copied into this packet. The historical protocol proof is
mathematical and conceptual precedent; actual #115 constants, operands, frame lifetimes
and edges are separately bound here.

Real callbacks, original nominal layouts, arbitrary aliasing/clobbers, concurrent
input changes, unwinding, whole-node behavior and implementation compatibility
remain unqualified. The next question is which concrete #115 callers and
writers establish this generic protocol's storage and preservation premises.
