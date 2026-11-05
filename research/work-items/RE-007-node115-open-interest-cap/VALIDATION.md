# Validation record

The starting revision is `05bc2de303c05525b71e7e257426e741bc66a390`.
The base caller packet explicitly leaves `0x447c620` opaque; the new Rust and
packet paths are absent there. This is a new bounded reconstruction, not a
claimed production-node defect or a manufactured failing implementation test.
`validation/base-gap.json` retains the actual Git path checks.

## Actual checks

| Check | Observed result |
| --- | --- |
| Base `make doctor` | Exit 0; required static tools available. |
| Base `make verify` | Exit 0; signatures, 32 imported files, six pinned submodules, 558 manifests / 7,154 entries verified. |
| Full post-change `make verify` before final receipt seal | Exit 0; 559 manifests / 7,225 entries, no dangling rows. Final packet verification follows the seal. |
| Rust debug tests | 9 passed, 0 failed. |
| Rust release tests | 9 passed, 0 failed. |
| Two Linux x86-64 release library builds | Both exit 0; each 25,324 bytes, identical SHA-256 `6f08138f2765d21a2cd2a84bfdc5032a54a7a6a042dfa01ab8dae9c26641614a`. No captured-body comparison. |
| Initial static collection | Exit 0; five complete FDE bodies, 1,434 bytes / 343 instruction rows. The selected helper contributes 420 bytes / 101 rows; the caller and formatting context are credited separately. |
| Python focused evidence tests | 9 passed in 5.231 seconds. Includes exact native replay and corruption controls below the whole-target digest. |
| Exact-rational witnesses | All 11 retained rows regenerate; four distinguish two rounding operations from one exact-ratio rounding. |
| `make reproduce` | Exit 0; authenticated node115 and visor inventories reproduced. No captured execution. |
| Initial `make catalogue-check` | Exit 2: base README was stale. The recorded generator comparison also identified the matching SVG work-item count drift. |
| `make catalogue`, then `make catalogue-check` | Both exit 0 after staging the new source/packet. Generated inventory is 35 Rust areas / 20 Cargo manifests / 561 work items. All component gates and registered byte comparisons are unchanged. |

The old generated README/SVG listed 559 work items; the base index actually had 560.
This PR adds one work item, one Rust area and one manifest. Regeneration accounts
for those additions and the existing one-item discrepancy. Only the generated
inventory values change; no acceptance percentage is advanced.

The first local Cargo attempts failed before compilation because toolchain
proxies were absent from PATH. `rustup run` alone also left Cargo unable to find
rustc. These original errors are retained. Adding the installed toolchain's bin
directory to PATH resolved the environment issue; the successful tests and
builds use unchanged library/test source. No dependency download or installation
was performed. `cargo fmt` then succeeded with the same toolchain path.

Rust 1.95.0 commit `59807616e1fa2540724bfbac14d7976d7e4a3860`, LLVM 22.1.2;
host `aarch64-apple-darwin`. The Linux build target is
`x86_64-unknown-linux-gnu`; those libraries were built, not executed. GNU objdump
2.47 performed the static exports; its executable digest and exact command
streams are in `records.json` and `commands.json`. Python 3.14 was the host test
runner. Full `make test` and hosted CI were not run: the broad suite includes
captured-instruction evaluators outside the authorized static-only scope.

## Native evidence controls

The focused tests mutate first/last bytes of all 155 instruction groups, all 15
data-pin tails, each of 18 relocations' type/symbol/addend fields, unique selected
FDE/CIE tails, and section/file mapping. These call `validate_inner` directly,
so rejection is not explained merely by a changed outer target digest.
Separate tests prove wrong target rejection precedes any native subprocess or
output directory, and that the tool-provenance exception cannot hide a changed
native record. These are static evidence-integrity checks, not behavioral
equivalence or instruction evaluation.

Native export files, CFI/data/relocation records and native command hashes are
compared exactly. Only installed-tool SHA/version and version-command raw streams
and their hashes are permitted to differ as declared run provenance. Each
version stream is still checked against its own recorded hash. Native text is
not normalized; a different disassembler version can therefore fail the exact
export comparison. This is not a cross-disassembler equivalence claim.

## Reproduce

Use a fresh output directory and put the installed GNU objdump first on PATH:

```sh
python3 research/work-items/RE-007-node115-open-interest-cap/collect.py --output work/open-interest-cap/replay --check
python3 -m unittest discover -s tests -p test_node115_open_interest_cap.py -v
python3 research/work-items/RE-007-node115-open-interest-cap/rounding.py --check
```

The component README gives pinned-toolchain Rust commands. `RUN-RECEIPTS.json`
indexes actual command metadata and streams. The declared checkout/research/
toolchain/tool/home path prefixes are projected in public copies; original and
stored hashes/sizes are recorded separately. The two Rust test stdout copies
also remove declared trailing blank lines; native exports are unchanged.
Internal stream SHA fields in a
projected command receipt identify the original private stream. No binary,
credential, personal runtime trace or unrelated workspace file is published.

The retained independent reviews are second-agent analyses with exact reviewed
source hashes. They are not external maintainer approvals or independent capture
lineages. README spacing changes after review do not change library/test bytes.
Callback effects, ABI/layout, rendered strings, unwind behavior and the actual
runtime floating environment remain limits. No whole-node or complete component
claim is made.
