# RE-008: node115 checked selected-key first fold

The existing Rust weighted_gate accepts the first provider's status and basis as caller-supplied inputs. This contribution reconstructs that missing first fold from a real key-tree cursor and either physical wrapped-map rows or map-tree nodes. It preserves representation-specific duplicate choice and the consumed cursor after overflow. This is a bounded consensus/weighted-selection research contribution under the approved independent-Rust/static-evidence scope; it does not complete RE-008 or the full caller.

Target: Linux x86-64 node115,105896032 bytes,SHA256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base:05bc2de303c05525b71e7e257426e741bc66a390. Addresses are original ELF virtual addresses. New source/docs are independently authored MIT; captured inputs retain upstream rights and are not copied into the source implementation.

## Result and scope

- First fold:0x43516d0..0x4351882,434 bytes/111 rows.
- Flat lookup:0x4553fd0..0x455419b,459 bytes/137 rows.
- Key iterator:0x37c5980..0x37c5b96,534 bytes/126 rows.

The three full FDE bodies total1427 bytes/374 rows. This denominator describes the analyzed bodies, not recovered first-party byte coverage. Complete helper/control/data bindings and conditional reasoning are in [PROOF.md](PROOF.md); exact records and GNU exports are under observed/. The fixed static collector and corruption checks are packet-local evidence support, not a general ELF or behavioral verifier.

The source extends src/node115-weighted-fastfold with a no_std selected module, borrowed validated map/key-tree views and resumable KeyCursor. Existing weighted_gate behavior is unchanged. The implementation uses no allocator, unsafe code, FFI, dependency download, callback oracle or invented Cargo graph. Flat seam equality deliberately differs from last-equal segment search; tree lookup chooses the first equality in the first visited node. Overflow returns the wrapped new sum and leaves the cursor after the consumed failing key. A later call resumes with a fresh zero sum.

## Evidence and observed checks

See [VALIDATION.md](VALIDATION.md) for commands and explicit limitations. Frozen inputs comprise29 concrete structures,32 fold observations and12 constructor refusals. Direct host builds at opt-level0/3 each passed42 tests, including the original14-row smoke test;9 compiled semantic mutants were detected. Two Linux-target rlib builds were byte-identical and were never executed. Static normal/-O controls each passed101/101, including42 encoded-byte mutations, and a second GNU collection matched all six native files and semantic records.

The existing harness's copied mutation source omitted the new modules and produced E0583. One explicit module-copy loop fixes that blocked compile path. Its isolated copy effect and the three original Rust mutation smoke failures were verified without importing or executing the surrounding native instruction evaluator.

make doctor, make verify, make reproduce, make catalogue and make catalogue-check all passed; exact receipts are retained under validation/integration-checks-01. Full make test and the prior instruction evaluator were not run because captured-instruction evaluation is outside this static-only authorization. Hosted CI, native execution and runtime differential equivalence are not claimed. All92 acceptance gates remain false and no byte-window registration is added.

## Prior work and boundaries

Credit [PR987](https://github.com/lalalune/hyperliquid-source/pull/987) for the original first-fold/outer comparison evidence, [PR1928](https://github.com/lalalune/hyperliquid-source/pull/1928) for the independently authored supplied-span suffix, and [PR2402](https://github.com/lalalune/hyperliquid-source/pull/2402) for the distinct valued-iterator work. Related map/iterator observations in PR2716 and PR2750 are not claimed as discoveries here. The new result closes the first-provider implementation gap over admitted actual structures; it does not take over their distinct pending scopes.

The full native domain, collection construction, imported memcmp implementation, pointer provenance and original ABI remain unresolved. The explicit host refusal order is in [HOST-POLICY.md](fixtures/HOST-POLICY.md). Fixture hashes and source identities are recorded separately. Path-only receipt projections are disclosed in PATH-PROJECTIONS.json; static exports and literal fixtures remain byte-exact. The next step is caller/storage integration under separately established premises, not expanding this conditional claim to a complete consensus implementation.
