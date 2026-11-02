# RE-012: implement the established node94 startup height decisions in Rust

- Component: `node-runtime`; bounded implementation of existing height-map
  selection and local-height decision evidence. Not whole-function recovery.
- Target: Linux x86-64 node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source baseline: `e5c9b6436876b2a4a39daef813171f9879317699`.
  The can1357 reference pin stays
  `999556f6e0a474b8312db96ec3149e1c44e97c23`; no inferred reference code was
  copied or consulted as implementation authority.
- Before: the [maintained static packet](../local-abci-gates-94/README.md)
  establishes these decisions and Python models, but `src/` has no independent
  implementation of this selected height path. After: a buildable safe Rust
  module, external comparison harness and reproducible implementation checks.
- New files are confined to `src/node94-local-height/` and this packet.
  Imported evidence, tools, pins and progress gates are unchanged.

## Evidence and scope

All coordinates are original ELF VAs, without load bias. The containing FDE is
`[0x22689f0, 0x226b503)`, 11,027 bytes; its body SHA-256 is
`cc7958c8348146f55ce6e1be694987407e96b2142a737b136f03b87fea817b94`.
The FDE is an unwind extent, not proof of complete source function ownership.

The maintained `tools/local_abci_gates_static.py` checks the length/one-peer
branches, iterator calls, comparison sequence, result handoff, status-log
argument mapping and height-gate instruction/data operands. `verify.py` reuses
those checks over the authenticated capture, retains their relevant output in
`evidence.json`, and requires exactly the expected overlapping FDE. It does not
change the existing packet or repeat its discovery claim.

The selection window `[0x226a53f, 0x226a6b8)` is 377 bytes / 70 instructions.
The status/height window `[0x226a974, 0x226ab88)` is 532 bytes / 82 instructions.
Full selected-range Capstone and Apple LLVM exports agree on every byte and
instruction boundary; the verifier checks contiguous byte coverage against the
capture. Mnemonic interpretations are review inputs, not proven by that parser.
Use the original packet for the result handoff/iterator helper closure evidence.

The selection keeps the current pair only when its first unsigned word is
greater, or its first word is equal and its second word is greater. Otherwise
both words are replaced. An equal pair is replaced with equal words; this API
does not expose source identity. The resulting scalar pair is lexicographic max.
It is not a coordinatewise maximum. The initial length guard rejects an empty
map and rejects a singleton unless the queried-peer count equals one.

The later height decision uses unsigned addition saturated at `u64::MAX` and
tests `limit <= latest` before `local < initial`. Thus local/latest both MAX
select the first reason; replacing saturation with wrapping addition, equality
with a strict latest comparison or the lag constant with 200 changes behavior.
`Continue` names the selected exit only. Other startup gates remain excluded.

## Build, compare and controls

New implementation: `src/node94-local-height/lib.rs`. It uses no dependencies,
unsafe code, build script, Cargo workspace, original bytes or fabricated ABI.
There is no Cargo.lock because builds invoke rustc directly. Host build pin:
rustc 1.94.1 (`e408947bf`, LLVM 21.1.8), edition 2021, warnings denied, overflow
checks on, optimization levels 0 and 3. Host: macOS arm64, Python 3.11.15.
Host ARM code is not compared with the captured x86-64 machine code.

From the repository root with pinned LFS inputs materialized:

```sh
python3 -B research/work-items/RE-012-local-height-rust-94/verify.py \
  --rustc /path/to/rustc-1.94.1 --output work/local-height-new --controls
python3 -m unittest discover -s tests -p test_local_abci_gates_static.py -v
make PYTHON=python3 verify test catalogue-check
make PYTHON=python3 reproduce
```

Use a new validation directory. The harness links the production library and
receives input words only; Python compares its output with a separate expected
stream. This is a data-flow separation, not OS sandbox isolation. Expected
selection uses Python tuple ordering; the gate uses carry/wrapped-sum selection
checked against arbitrary-precision min/add. Both are also cross-checked with
the existing target-bound Python models. These are static-derived scalar
expectations, not original node execution or an independent runtime oracle.

The deterministic corpus includes a 12-point boundary set (zero, 20000 and
neighbors, the signed boundary, the saturation crossover and MAX), every ordered
pair of pairs from that set, singleton/empty cases, every triple from the set,
adjacent decision thresholds and seeded longer lists/random triples. These
25,135 cases are finite scalar tests, not exhaustive u64 coverage or reachable
node inputs. The input and expected streams are regenerated, not shipped as
an opaque fixture; output digests and counts are in `results.json`.

Observed validation:

- Debug, optimized and repeated optimized runners: 25,135 / 25,135 cases each,
  zero mismatches. The two own optimized `.rlib` builds are byte-identical;
  this is reproducibility of this new host library only.
- Three Rust unit tests pass, including correlated-pair selection, singleton
  admission, reason precedence, equality and saturation.
- Eight independently compiled semantic mutants are detected: incorrect
  single-peer exception, lexicographic minimum, wrong second-field handoff,
  coordinatewise maximum, wrapping addition, strict latest boundary, inclusive
  hardfork boundary and wrong lag constant. Counts are in `results.json`.
- The existing 73 static-gate tests pass unchanged. Their retained original
  evidence/model is the basis; no source/helper ABI closure is newly claimed.

Initial repository checks on this host (subsequently completed; see
[VALIDATION.md](VALIDATION.md) and `validation-results.json`):

| Check | Observed result |
| --- | --- |
| `make doctor` | Not ready: GPG and GNU objdump/readelf absent; Apple LLVM is used only for selected exports |
| `make verify` | All eight artifact size/SHA checks pass; signature step fails because GPG is absent |
| `python3 tools/verify_imports.py` | Pass: 38 imported files and all pinned source repositories |
| `make catalogue-check` | Pass after pinned inputs and submodules were materialized |
| `make reproduce` | Stops at the same missing-GPG verification step |
| `make test` | Attempted; interrupted in file 69 of 971 after failures/errors in existing tests; incomplete, not a passing full suite |

The initial whole-suite attempt started before all LFS/submodule inputs were
materialized and without native GNU tools or a PATH-visible Rust toolchain.
It cannot serve as a clean baseline or completed regression run. It was halted
rather than treating those results as successful validation. The targeted
checks above use the verified node94 input and the explicitly selected compiler.
Running the full suite in the project's complete research environment remains
required before relying on broad regression coverage. No hosted CI result is
claimed. A second focused runner invocation with Python `-O` also passed all
three builds and unit tests; its checks do not rely on Python assertions.

Decoder exports were produced with Capstone 5.0.6 and Apple LLVM 21.0.0:

```sh
objdump -d --x86-asm-syntax=intel --start-address=0x226a53f \
  --stop-address=0x226a6b8 artifacts/node/94/hl-node
objdump -d --x86-asm-syntax=intel --start-address=0x226a974 \
  --stop-address=0x226ab88 artifacts/node/94/hl-node
```

## Limits and next question

This implements selected numeric semantics over valid slices of already
collected map values. It does not reconstruct map ownership/layout, distinct-peer
collection, iterator behavior on inconsistent metadata, logging, allocations,
async control flow, the age gate, request/reply codecs or the node. Runtime
reachability and downstream safety are unproved. No captured node/visor,
instruction emulator, network/chain action or signing operation was run.
No machine-code normalization, original ELF comparison or component gate change.

Next question: recover a compatible independently authored map-value producer
and its request/reply codec before connecting this scalar selection to startup.
