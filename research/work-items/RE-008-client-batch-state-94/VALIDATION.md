# Pre-Rust validation

Author static checks passed in ordinary Python and with `python3 -O`.
Each run regenerated two full native-export/value-fixture trees and compared
all outputs byte-for-byte with the retained packet. Both result files are
identical: SHA256 `01f9a35ceede4946c4bc25de2b476a9f2690633f3ea441248134f61b03685287`.
Receipts are under `static-validation/`; executable hashes and actual provider
versions are in `NATIVE-PROVIDERS.json`. Logical names replace host paths in public
metadata; the collector's defaults document the recorded macOS installations.

The checks cover16 complete FDEs,10,566 bytes,2,320 rows,1,451 instruction
obligations, one literal,144 calls and35 direct-call relocation slots. The76
negative controls reject identity/size/scope/partition damage,59 fresh
GNU+LLVM body edits below target/body-hash admission, raw RELA/import/FDE changes,
a changed text literal, two CFG ordering bypasses checked without byte pins,
and a `data16`-prefixed AX write. They test evidence admission and necessary
structural facts, not execution semantics. Instruction pins support the manual
proof; the count is not byte coverage or a progress gate.

The221 independently derived cases cover all local batch tags, transaction
bytes across rate boundaries, every byte of link/digest comparisons, raw time,
proof/round/admission precedence, the repeated digest boundary calls, retained
errors,99/100/101/102 no-proof counts, a proof flush of101, and accepted prefixes
when a channel closes. The empty-stake direct-call witness produces tag28(1),
then tag1a, with last_received2, confirmed0, pending2 and no authenticator calls.
Fixture authentication is explicitly conditional test input arithmetic; it is
not a cryptographic or native-preimage oracle. No competing TC failures are
included. The mathematical generator parses only the hash-bound pure Keccak
function/constants and never imports the old captured evaluator module.

To reproduce before formal freeze (only while PRE-RUST-FREEZE.json is absent):

```sh
python3 research/work-items/RE-008-client-batch-state-94/verify.py \
  --pre-freeze-check --out /tmp/client-batch-new-check
python3 -O research/work-items/RE-008-client-batch-state-94/verify.py \
  --pre-freeze-check --out /tmp/client-batch-new-optimized-check
```

After freeze, omit `--pre-freeze-check`; the verifier checks every frozen file
first. Outputs must be new directories. For another provider installation add
`--gnu /path/to/objdump --llvm /path/to/llvm-objdump`; printed native text remains
provider/version-sensitive. To collect static exports alone:

```sh
python3 research/work-items/RE-008-client-batch-state-94/evidence.py \
  --binary artifacts/node/94/hl-node --out /tmp/client-batch-new-export
python3 research/work-items/RE-008-client-batch-state-94/corpus.py \
  --out /tmp/client-batch-new-values
```

No new Rust, input client, compiled mutation, full make test, captured binary or
instruction emulator was run at this pre-code stage. The actual source graph
will use a separate clean baseline integration checkout after parent review;
unmerged block/QC/bincode code is not a dependency. Later source validation is a
separate dated/frozen phase and must not be described as preceding this receipt.
