# RE-012: greeting-send deadline selection on node #115

- Component: `transport`; bounded conditional frame/caller research.
- Target: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Baseline: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Status: observed instruction/data bindings and a conditional interpretation.
  No Rust implementation, source-build comparison or acceptance gate is requested.

The measured greeting caller supplies a zero first word beside binary64 **60.0**.
The sender's chunk-local selector tests the first word's low byte: zero loads
binary64 **20.0**, while nonzero retains the supplied word. Consequently, the
adjacent 60.0 is not the selected value for this measured call setup. The selected
word is retained in the per-chunk future and reaches the bound conversion helper
before clock addition. This closes a concrete input-to-deadline-creation question
that the existing prefix evidence leaves unresolved.

## Scope and ownership

The caller is `0x2b67e50..0x2b69279`; literal-interior LEAs at `0x2b685d5`
and `0x2b68d1d` reference the send-failure/retry and received-ABCI-greeting text.
Their pointers precede the readable strings by one and three bytes respectively.
The prefix encoding and complete logging ABI are unresolved. A visible
`abci_stream send tcp greeting` label setup is context, not proof that its
callee consumes that label or proof of a recovered source function name.

PR #2068 owns the sender/reader prefix and numeric-outcome mapping; #2076 owns
the reader's header admission/chunk plan. This packet uses the complete sender
`0x2b7a290..0x2b7b523` as shared context and does not reclaim their framing work.
The new question is its selected deadline operand, its actual greeting call
setup, and the conversion route `0x15ed960..0x15edb81`. Fresh ownership must be
rechecked before submission. No historical #94 implementation is imported.

## Bindings and conditional interpretation

All addresses are linked ELF virtual addresses, before load bias. `records.json`
records exact file offsets, FDE record addresses, body hashes and native exports.
Three complete FDE intervals cover **10,461 bytes / 1,972 instruction rows**.
That is the exported-context denominator, not recovered or matching-code coverage.
GNU/LLVM byte columns match the target and Capstone boundaries; five standalone
LLVM LOCK display prefixes join their following rows without masking any bytes.
Nearest-symbol names printed by native tools do not identify these stripped bodies.

The actual caller stores zero at `caller+0x220` and the 60.0 bits at `+0x228`.
It initializes the callee's state byte at `caller+0x530` to zero and calls the
sender with `RDI = caller+0x220`. The zero-state dispatch entry at `0x604cbc`
lands at `0x2b7a2ca`. The sender copies the words through `+0x28/+0x30` and
`+0x58/+0x60`; the collector inventories all directly encoded RBX-relative
accesses to the latter fields. Four directly encoded stores form the initial
copy pair and the resume copy pair at `0x2b7a4a0/0x2b7a4a4`; the latter reloads
the retained `+0x28/+0x30` words. The first inventory incorrectly expected only
the initial pair and failed on the real resume pair. That failed assumption
and its correction are retained in the validation evidence. This inventory
does not close indirect aliases or helper effects.
`audit_overlap.py` separately checks byte-interval overlap, including wider
operands starting before either field, and reports the same four writes. This
is a same-author predicate cross-check using the same decoder, not independent
peer review. Its frozen output is `field-audit.json`.

At `0x2b7b291`, the low byte of `sender+0x58` selects the provided word or the
eight bytes at `0x459b70`, exactly `0x4034000000000000` (20.0). The selected word
is stored at `sender+0x160`, passes through `+0x2e8` and `+0x2f0`, then reaches
XMM0 at `0x2b7ac6c`. The call at `0x2b7ac74` resolves through the **unique**
RELATIVE writer at `0x64e0f70` to the complete 545-byte conversion interval.

The conversion body's positive integral paths and an independent IEEE-binary64
arithmetic worksheet give the integer examples 20 and 60 with zero fractional
nanoseconds. These positive inputs take `0x15eda39`, have biased exponents
`0x403/0x404`, and enter `0x15edaef`. The significand shifts at `0x15edafd`
are 48/47 bits, producing 20/60. The masked fractional word at `0x15edb08`
is zero for both; its multiply and rounding path produce zero EDX and no
seconds carry before `0x15edb6d`. This is a static two-input derivation.
The caller adds its returned RAX/EDX pair to the pair returned by `0x5c842e0`
and normalizes at 1,000,000,000. Reading these as seconds/nanoseconds and a
clock-relative deadline is an inference; that helper's clock/source contract
is not closed here. The conversion helper's source identity and general behavior
for negative values, NaNs, infinities or fractional rounding are not recovered.
The worksheet is arithmetic corroboration, not target execution or an independent
source-equivalence test.

The selector lies in the chunk-construction loop, after the remaining-span check
at `0x2b7b21d`. The new chunk future starts at state zero, and the branch at
`0x2b7b315` returns to its construction continuation at `0x2b7aa93`. This is a
chunk-local selected-duration binding, not a single whole-frame time budget.
Actual provider writes, readiness, scheduling progress, timer firing, error
translation and unwind behavior remain unclosed.

This interpretation is conditional on reaching the measured call/normal
construction route, ordinary helper returns, preservation of unrelated storage,
and the observed caller/callee storage relationship. It does not establish that
the outer caller is reachable for every runtime state or that a network greeting
completes, retries, or expires after a measured wall-clock duration.

## Reproduce and validation

Use authentic materialized inputs and pinned source repositories. Python3.12.3,
GNU binutils2.42, LLVM18.1.3 and isolated Capstone5.0.6/CI-pinned5.0.7 were used. `versions.json`
retains the native version output. The original exports were produced with:

```sh
objdump -d -z --insn-width=16 --start-address=START --stop-address=END artifacts/node/115/hl-node
llvm-objdump -d --disassemble-zeroes --start-address=START --stop-address=END artifacts/node/115/hl-node
```

Use each complete start/end pair in `records.json`. Raw native files are unedited.
From the repository root:

```sh
python3 -B research/work-items/RE-012-greeting-deadline-115/collect.py . research/work-items/RE-012-greeting-deadline-115
python3 -B -m unittest tests.test_greeting_deadline_115 -v
python3 -B research/work-items/RE-012-greeting-deadline-115/audit_overlap.py .
make doctor verify test catalogue-check reproduce
```

Final `make doctor verify test catalogue-check reproduce` passes under the
CI-pinned Capstone5.0.7: 77 isolated files / 386 reported cases,
0 failed files and 4 explicit optional skips. The skipped checks need an
explicitly supplied libcore archive, the separate nonce-ring Rust qualifier,
or native macOS JDK resolution (two cases); none is claimed as qualified.
The earlier full5.0.6 run also passed. After the producer-metadata correction,
both real decoder versions reproduce identical final records. Final focused
methods pass4/4 normally and under optimized Python; all12 corruption controls
are rejected. Exact source/log fingerprints and original corrections are in
`validation.json`. The tests bypass the outer artifact
digest guard only in memory to challenge actual caller/state/selector/constant/
dispatch/arithmetic bindings and duplicate real relocation records. A truncated
native export must also fail. No captured instruction execution, CPU emulator,
live socket, chain action or signing is part of these checks.

## Remaining work

All 92 component gates remain unchanged. No source byte-window comparison or
Rust area is registered. New collector/tests/docs use MIT; target evidence keeps
its existing rights. This minimal packet-local collector addresses the missing
RE-012 operand/caller binding; it changes no shared tooling or runtime code.
Next: close the actual write-provider and timer contracts, legal outer caller
states, aliases and exceptional continuations before implementing an integrated
greeting exchange or claiming runtime timeout behavior.
