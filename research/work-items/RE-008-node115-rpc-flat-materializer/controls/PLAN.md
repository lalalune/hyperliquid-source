# Independent RPC host-transport controls — unexecuted draft

This plan and `generate_controls.py` specify input bytes and literal expected
child status/stdout only. They are independent of future Rust source and do
not import the mathematical reference, any native decoder, repository module,
captured artifact or client. Neither generator nor client was run by this
author. Root must review this exact source/effects and separately admit fixture
generation and later execution of an explicitly source-built client. The Rust
author should remain blind to this control file while implementing the already
fixed interface.

Normative chosen host policy is `RPC-HOST-TRANSPORT.v1.md`, SHA256
`2838931cd554744a81bb88d58beefb7646db829b1a5d633007132c6816098e52`.
The conditional native value contract remains v3; none of these malformed-host
refusals is a native error, reference-count, lifetime or allocator result.

## Expectations and separate execution cases

Each generated case is a separate future process invocation, with its own
stdin file, argument suffix, expected exit code and exact expected stdout file.
An invocation marked refusal expects exit2 and completely empty stdout. Its
stderr contents are unconstrained but must be retained by any later runner.
An admitted ordinary success expects exit0 and the manually specified bytes.
There is deliberately no child runner in this draft.

The seven input fields are ID, S/M, capacity, head, live length, full physical
rows, queries. Input bytes are never inferred from expected output. Positive
outputs use only empty live sequences, a literal singleton, a two-row wrapped
view with obvious indices, and repeated copies of one supplied value. No search
algorithm or reference implementation calculates them. Opaque values are
literal u64s and are never dereferenced or interpreted as counts.

The required checks are grouped by distinct policy, not an arbitrary target
number of cases:

| Requirement | Fixture scope / expected distinction |
| --- | --- |
| ASCII, LF-only, final LF, no empty rows | Empty stream; missing LF; CRLF; bare CR; leading/trailing blank row; invalid UTF-8 byte; valid UTF-8 non-ASCII ID; NUL ID; VT/FF/FS/GS/RS between otherwise valid rows. These controls must not be treated as line separators. |
| Exact arity and ID | Six/eight fields; empty ID;65-byte ID; dot; duplicate IDs. Positive64-character alphanumeric/underscore/hyphen ID is accepted. |
| Canonical numbers | Leading zero on nonzero capacity, double zero, head/live-length leading zeros, plus/minus zero, leading/trailing spaces, fraction, exponent and empty field. Every such replacement otherwise has compatible fields. A canonical u64-plus-one capacity is safely refused, without claiming a particular overflow path. |
| Lowercase fixed-width hex/lists | Uppercase key, value and query; nonhex in each; short/long row/query; empty comma elements. |
| Row allocation and operation | Dash/positive-capacity mismatch, nonempty row at zero capacity, missing/extra physical slots, unknown/lowercase operation, S with zero/two queries. Capacity/row-count mismatch is a record-loader error, not a representable slice-backed RingView state. |
| Resource query/capacity bounds | Separate32-query positive and33-query refusal;256-slot positive and257-slot refusal. The257-slot zero-live ring is otherwise a valid logical view; rejection is driver policy. |
| Host ring domain | Zero-capacity head/live violations, head==capacity, live length>capacity, contiguous or wrapped logical disorder, zero live value. |
| Unused row allowance | Positive view has inactive zero values and out-of-order inactive keys. Another positive has physically descending rows but sorted wrapped logical live order. |
| Whole-input prevalidation | Valid row(s) followed by malformed syntax, invalid host domain or missing final LF must still yield empty stdout. Duplicate ID also exercises a late whole-input refusal. |
| Arguments | `extra`, `--help`, `--version` are separately rejected: the chosen client takes stdin only and accepts no arguments. |
| Record bound | Separate16,384-valid-row success and16,385-valid-row refusal, both far below the raw-byte bound. |
| Raw byte bound | Separate exactly16,777,216-byte success and16,777,217-byte refusal, both809 otherwise valid rows. |

The ordered mixed positive fixture has four results in order: a literal hit,
an insertion0 miss, two repeated successful values, and a legitimate M failure
`F`. The final F is a valid value result with exit0, distinct from transport or
host-domain refusal with exit2.

## Exact resource-bound constructions

**Record cases:** IDs `r00000` through `r16383` each name a valid zero-capacity
M/empty record. Each stdin row is19 bytes, including LF. The positive therefore
has311,296 bytes and exactly16,384 records. Adding the next unique valid row
produces311,315 bytes and exactly16,385 records. Expected positive stdout is
one `id<TAB>V<TAB>-<LF>` row per ID; no reference call is needed. Labels are
`records-16384-positive` and `records-16385-refusal`.

**Byte cases:**808 valid M records use capacity256, head0, length0,256 zero
inactive rows and empty queries. Their IDs `b0000`..`b0807` have length5; each
frame is20,754 bytes. A last capacity98/head0/length0 frame has a34-character
ID (`tail_` plus29 x characters) and7,984 bytes. Thus
`808*20,754 + 7,984 = 16,777,216`. There are809 valid unique records and no
garbage padding. Every output is a literal empty successful vector.

The +1 fixture adds one x to the last ID, which remains a valid35-character ID.
Everything except raw total size remains admitted:16,777,217 bytes and809 rows.
The generator checks both exact lengths before writing fixtures. Labels are
`bytes-16777216-positive` and `bytes-16777217-refusal`. These are independent
invocations, never concatenated with other tests. A limit comparison using
`>=` instead of `>` would incorrectly refuse the exact-bound positive case.

Those arithmetic descriptions are authoring analysis, not observed process
results. Future generation records actual file lengths and hashes. No truncation,
newline normalization or boundary-case fallback is allowed.

## Effects, format and future use

The generator accepts only `--output <fresh-directory>`. Its imports are Python
stdlib argparse/hashlib/json/pathlib/re. It reads only its own source and this
plan for provenance hashes. It constructs fixed supplied data, verifies simple
shape/identity/length assertions, and writes one `.stdin` and one
`.expected-stdout` file per case plus `cases.json`. Files use exclusive creation;
existing output directories are rejected. Generated input/stdout payload volume
is checked below40MiB. No timestamps, random seeds, filesystem enumeration,
private paths, environment variables or source-derived expectations enter data.

`cases.json` records each case ID/family/reason, argument suffix, expected exit,
stdin and expected-stdout paths/byte lengths/hashes, stderr policy and literal
expectation provenance. Its status explicitly says fixture data only, not client
execution. A successful generator run would prove file construction, not that
any transport control passed. The generator does not parse child output or
launch a child.

Before the later client run, root must bind generator/plan identities and the
chosen source-built executable. A separately reviewed runner may pass only
the specified stdin and argument suffix to that executable under a clean
environment, preserve all actual stdout/stderr/status and compare against these
parent-side expectations. A timeout, launch failure, signal, incomplete output,
unexpected status or build failure is not a valid semantic/transport pass. Run
the record and byte resource cases with distinct labels and retain each receipt.
No captured node, native evaluator, installed service or downloaded code is
admitted by this plan.

The empty-stdout requirement applies to input/argument/domain refusals that the
contract says must be found before the first write. **I/O failure after output
begins may leave partial stdout.** This draft does not induce broken pipes,
output-device errors, allocator failures or OOM, and does not claim to establish
their behavior. Host resource bounds are policy arithmetic, not native memory
allocation semantics. It also does not prove native or Linux execution, reference
counting, dropping, concurrency or whole-RPC equivalence.

## EXPAND

After exact source/effects review, root can admit generation, inspect actual
fixture identities and then qualify only the authored client. Preserve original
fixture source and expected bytes if a mismatch occurs; investigate the policy
or implementation rather than editing an expectation to fit observed output.
