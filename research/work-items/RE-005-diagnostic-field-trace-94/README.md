# RE-005: conditional diagnostic-field and newline-adapter contracts

- Component: serialization, RE-005 prerequisite research.
- Target: Linux x86-64 node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, 91,774,280 bytes.
- Maintained source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Scope: conditional static call/state contracts for the field helper and its actually used newline adapter. No component gate change, Rust crate or target-runtime equivalence claim.
- Pair denominator: 1,012 bytes / 285 native rows across two authenticated FDEs; this is an inspected-byte denominator, not source-reconstruction progress.

## Question and evidence

The integer diagnostic-field/name association in [#1015](https://github.com/lalalune/hyperliquid-source/pull/1015) leaves field helper 0x1571f50 opaque. This packet independently derives its flat and pretty callback/state contracts and the used adapter's first-newline scan/write-request protocol. It does not require #1015's unmerged files, change the wire-codec work in #48/#253/#371, or copy an unlicensed inferred reference implementation.

| Selected body | VA range | File offset | Bytes / native rows | FDE / CIE |
| --- | --- | --- | --- | --- |
| Field helper | [0x1571f50,0x15720d6) | 0x1570f50 | 390 / 109 | 0xcfa5b0 / 0xce1518 |
| Used adapter | [0x157d000,0x157d26e) | 0x157c000 | 622 / 176 | 0xcfb300 / 0xce1518 |

Helper SHA-256: `e6aec76f57413451c7a873712558e50e18c6f30b2001b6777c3fd29fda32388d`.
Adapter SHA-256: `d62080d0724a750e0162d6a0563c7a056ae76e2212fd48310f89bcf8809dfde4`.

Actual RELATIVE records bind slot 0x576e2c8 to the field helper and slots 0x576e330/0x5674228 to the adapter. Raw records, FDE/CIE bytes, branch destinations, literal slices and source coordinates are in `observed/records.json`. Complete raw GNU listings are retained for both bodies. Every native row tiles and equals its copied authenticated bytes. Every one of the adapter's 176 rows has a named dataflow, branch or exact-no-op proof role; all 32 encoded branch targets are independently decoded. The adapter has only two underlying-writer call sites and one RET, with no direct shared panic/lifecycle dependency.

## Field helper contracts

Read [ASSUMPTIONS.md](ASSUMPTIONS.md) and [SCAN-AND-PRETTY-PROOF.md](SCAN-AND-PRETTY-PROOF.md) before applying these statements. S is entry RDI, E=byte(S+8), H=byte(S+9), F=load64(S). These are observed accesses, not a nominal Rust layout. For nonsticky paths, H is qualified only over 0/1; the sampled bit 0x80 at F+0x12 selects the mode. The shared E!=0 route uses no formatter or callbacks, writes raw error byte 1, then byte(S+9)=1, and returns S.

The flat domain has five normal-return termination routes including that shared route. Otherwise it calls prefix, name, colon and value in order. H0 selects bytes 207b20 (`" { "`), H1 bytes 2c20 (`", "`); colon is 3a20 (`": "`). Each of the first three writer sites freshly reloads F's destination/vtable and stops on nonzero AL, normalizing the error to 1. The final value callback receives the saved incoming data, original F pointer and saved descriptor+0x18; its low EAX byte is captured without another flat success/error test.

The pretty E=0 domain adds nine actual routes. H0 first requests bytes 207b0a (`" {\n"`) through the original F writer; H1 skips that opening. After a successful opening, or directly for H1, the helper samples the CURRENT F destination/vtable and F+16 qword into local records A/L, with a local flag N initially 1. These samples occur AFTER the optional opening callback, rather than assuming entry F values stayed unchanged. Name and colon call the fixed adapter. The value callback receives local L. Its failure is normalized to 1; on success, the suffix requests bytes 2c0a (`",\n"`) through freshly reloaded L fields. Identifying that last callee as the known adapter requires preserving local metadata.

All 14 parent routes require actual ordered input/status/store/return witnesses: byte(S+8), then byte(S+9)=1, then the pointer-return MOV and RET. No effects are synthesized merely because a path reaches RET. Status provenance includes the opening's R12 name-pointer clobber and the later R12b=1 reset. The suffix captures its returned AL; higher result bits and original Result types are unqualified.

## Adapter scan and state contract

At its actual post-prologue loads, the adapter caches destination D, vtable pointer V and flag pointer B from A. Each call still reads the current method entry at V+0x18. A finite immutable input is split into nonempty pieces ending at the first LF inclusive, or a final nonempty tail. A nonzero current byte(B) requests the actual four-space slice 20202020 before a piece. Indentation failure returns AL=1 before this piece's flag store or payload call. Otherwise the helper stores whether the piece's last byte is LF BEFORE requesting the payload. Payload failure returns AL=1 after that pre-callback store. All-success normal return clears EAX; failure sets AL=1 only, with no general claim about higher RAX bits.

The proof binds scalar compare-before-increment order, alignment prefixes, two contiguous eight-byte reads,16-byte skip progress, and exact scalar fallback. The extracted word predicate has a 15-case byte/borrow certificate showing that a skipped block cannot contain LF. False positives are allowed: candidates return to exact scalar scanning. Offset inequalities establish in-bounds loads and first-LF order, and selected chunk ends strictly advance. A final-tail success exits on its saved continuation bit before reusing the old emitted cursor.

Empty input and an empty tail after terminal LF make no B-directed protocol access or callbacks. The adapter still loads A's fields and writes its own frame. Therefore unchanged physical N needs the stated frame/alias separation, not just absence of protocol stores. Final flag contents also need callbacks to preserve the flag; otherwise the claim is the ordered PRE-callback store. The actual parent's N is at adapter RBP+87 for direct calls, above the adapter's private/saved/return intervals under the observed normal stack conditions.

## Reproduce

From the repository root, choose fresh output directories:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/bincode_diagnostic_field_static.py --output work/re005-field-pair
PYTHONDONTWRITEBYTECODE=1 python3 -B research/work-items/RE-005-diagnostic-field-trace-94/controls.py --output work/re005-field-controls
PYTHONDONTWRITEBYTECODE=1 python3 -B research/work-items/RE-005-diagnostic-field-trace-94/pretty_controls.py --output work/re005-pretty-controls
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest tests.test_bincode_diagnostic_field_static tests.test_bincode_diagnostic_pretty_static -v
```

The producer authenticates all node #94 bytes before parsing. GNU objdump receives only owned, non-executable 390/622-byte raw copies with `-D -b binary -m i386:x86-64 -M intel --insn-width=16` and the actual VA adjustment. Only ephemeral raw filenames are normalized. Native decoding, finite CFG predicates, static operand/def-use relations, interval inequalities and word/borrow equations are used. There is no captured execution, instruction/register/memory interpreter, renderer emulator or real callback invocation.

## Controls and validation limits

All 29 focused tests passed; the retained log is `observed/focused-tests.txt`. There are 58 actual copied-byte controls: the original 18 flat controls and 40 pretty/adapter controls. Each retains its original instruction/call/conditional-branch/jump/RET counts while failing a specific relation. Word-constant mutants have actual mathematical false-negative byte vectors; load/threshold/stride mutants have concrete unread-LF or overread intervals. Other controls alter callback order, argument/setup sampling, flag writes, result propagation, or the TEST/MOV/branch chain. The controls preserve complete mutant native listings in their fresh output directories; compact checked-in ledgers retain edits, hashes and failures.

The first frozen checker incorrectly assigned common stores and return S to a direct-RET counterfactual. The actual regression fails before that correction and passes after it; both logs remain in this packet. The new pretty direct-RET mutant likewise reports no stores and an unresolved return, then rejects it. Initial published flat-only commit 61e91dbc and its tested evidence are preserved before this same-PR amendment.

`INPUTS-AND-TOOLS.json` records exact source/tool/input identities. `MANIFEST.sha256` hashes all source, tests and packet members. Final exact-commit repository checks and independent review are reported separately. Tests validate the static tooling and certificates; they do not establish runtime equivalence.

Actual writer/value callback implementations, physical output, arbitrary aliases/clobbers, original Rust types/ABI, application reachability and complete source reconstruction remain unqualified. All component gates stay false. The next concrete question is which real callers establish the generic input/flag/metadata conditions and which value callbacks use the local formatter; this packet does not invent those caller contracts.
