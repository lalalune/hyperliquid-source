# Greeting source qualification

This additive directory qualifies the actual MIT package
`src/node94-abci-greeting-values` with the unchanged merged `hl-bincode-varint`
provider. The original165 pre-code files remain immutable. SOURCE-PROOF.md
connects the safe API to that conditional native relation; it does not claim a
network handshake, target execution, native ABI or a complete component gate.

The source/harness freeze precedes compilation. At this stage only eight
version/metadata/format preparation commands have run. The intended qualification
is205 commands:16 focused integration tests per profile,54 full18,290-frame
streams across three correct builds and24 compiling mutants in both profiles,
12 comparator controls and23 malformed frames plus extra-argument/empty-input
checks. Planned counts and mutation definitions are not successful results.
The old provider's integration fixtures/tests are pinned but not rerun.

After independent source/build admission, from the real repository root:

```sh
python3 -B research/work-items/RE-012-abci-stream-greeting-values-94/rust-validation/build.py \
  --toolchain /path/to/pinned/1.94.1-aarch64-apple-darwin \
  --out /tmp/hl-greeting-fresh-run \
  --private-map /path/to/private/fresh-map.json \
  --source-freeze-sha SHA256_OF_SOURCE_FREEZE_JSON
```

The output path must be fresh and directly under `/tmp`; the private mapping
must not exist or be inside this packet. TOOLCHAIN-PINS.json binds the exact97
bin/lib payload files and links. The native capture prerequisite is91774280 bytes,
SHA256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
at `artifacts/node/94/hl-node`; it is only read by the unchanged static checker.
GNU and Apple LLVM disassemblers must be available at the recorded paths.

The harness checks the real graph/configuration, makes exact source/provider
copies and uses offline/locked Cargo with a fresh Cargo home. It does not run
captured code, an evaluator, the whole repository test suite or provider tests.
Only input frames reach the client. Expected frames are opened by the parent
comparator, and no expected values are passed to source, client or mutants.

`receipts/commands.json` records launches, completion/exit and exact raw-stream
references before validation. A first failure stops the run and all evidence
is retained; do not retry by modifying the frozen contract or expectations.
Compiled rlibs/clients are retained under private `compiled-private` before any
clean rebuild deletion, with hashes/reference metadata. They may contain private
host paths and are not public packet payloads. Command metadata uses declared
logical path labels; raw stdout/stderr and compiled bytes are never normalized.
The private preparation streams are identified in PREPARATION.json and remain
private because actual Cargo metadata contains checkout paths.

Same-path rebuild equality is checked for both rlibs and the client in debug and
release. Other-directory identities are reported independently, without masks or
an inferred explanation. All finite corpus matches remain qualified by the
original resource/frame/native-state premises and the source proof.
