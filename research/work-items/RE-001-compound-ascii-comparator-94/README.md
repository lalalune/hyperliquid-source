# RE-001: HTTP-scheme context and a compound ASCII comparator

- Component: foundation/transport support. Bounded question: which tagged fields
  and byte-fold operations does the candidate at `0x284b430` actually compare?
- Node #94 SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`; unchanged reference
  `999556f6e0a474b8312db96ec3149e1c44e97c23`.
- Status: instruction/data observations and conditional abstract-field models;
  original private function name and complete Rust type remain unresolved.

The reference `node/consensus/config.rs` suggests a pending node-IP comparison
rename. Its compact tag/u32 descriptor elsewhere does not establish this
candidate's ABI: this body reads an indirect byte component and a common second
byte component, and its unreachable arm names HTTP scheme code. No imported
annotation or reference implementation is changed or copied.

## Reproduce

Repository root, CPython 3.12.14 on Windows:

```sh
python tools/compound_ascii_static.py --out work/compound-ascii-94.json
python -m unittest discover -s tests -p test_compound_ascii_static.py -v
python research/work-items/RE-001-compound-ascii-comparator-94/export_disassembly.py
```

Verifier/model/tests use the standard library. The optional full export uses
Capstone 5.0.6, x86-64 Intel syntax. Inspected Windows wheel SHA-256:
`761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064`
(`capstone-5.0.6-py3-none-win_amd64.whl`). No captured code or network operation runs.

`window.capstone.txt` retains all **283 bytes / 83 instructions** in the exact
FDE `[0x284b430,0x284b54b)`, original FDE/CIE records, and contiguous full-byte
consumption. All selected observations are checked to be instruction starts.
Body SHA-256: `50e4f0f9f5fd62dacfee715eaad7581abe496c1e3375d0e2c022a4248ab845c4`.
ELF VAs are unrelocated; the `.text` file offset is VA minus `0x1000`.

## Captured field/control facts

| Path | Observed reads and result |
| --- | --- |
| Tag 1 on both sides | Compare whether each byte at object `+1` is zero. Matching zero/nonzero classes continue to the common component. |
| Tag 2 on both sides | Follow each pointer at object `+8`; compare lengths at indirect header `+0x10`, then buffers at header `+8` using ASCII-folded bytes. Equal components continue. |
| Different modeled tags | Return a false low byte without the common comparison. |
| Common component | Compare lengths at object `+0x20`, then buffers at object `+0x18` using the second ASCII loop. |
| Return | AL is the observed 0/1 result. Upper RAX bits are not promised to be a canonical full-width boolean. |

The tag-0/unreachable path is exported but outside the abstract model's tag-1/2
domain. No reachability or parsing policy is inferred for other representations.
Valid backing memory is assumed; these are field observations, not a portable
Rust object layout or a public URI/IP parser.

Four inline byte-fold sequences have identical operands: add -65 modulo 256,
unsigned compare against 26, SETB, shift that bit by 5, then OR with the original
byte. Thus only bytes A..Z gain bit 5; all other byte values remain unchanged.
Both component comparisons also require equal lengths.

## Source context and comparison limits

RELATIVE slot `0x56c9370` points to the captured source path ending
`http-0.2.12/src/uri/scheme.rs`, line 136, column 40. Slot `0x576e108` binds the
unreachable callee to `0x157b7f0`. The public tagged
[HTTP 0.2.12 scheme equality source](https://github.com/hyperium/http/blob/v0.2.12/src/uri/scheme.rs#L125-L139)
corroborates a scheme portion with standard/other/empty cases and this invariant
Location. It does not establish the complete enclosing private object or caller.
The source was consulted only as corroboration; downloaded file SHA-256:
`59e6f12d3e1e1ee982e68a4a6556f25e94073ca3d77c372b6d8d71daf8f62f2a`.
No upstream implementation is copied into the new model.

An independent integer range form agrees with the captured fold sequence for
**256 byte inputs and all 65,536 byte pairs**, with **0 mismatches**. This is
exhaustive for that byte primitive only. It is not a count of executed node
calls, complete-object values, URI normalization cases or reachable runtime states.

The compound model checks tag-class compatibility and both selected byte
components. Tests include mismatched tags/subtypes, unequal component lengths,
ASCII boundaries, unchanged non-ASCII bytes and embedded zero bytes as raw-buffer
probes. They do not assert that every probe is a legal parsed HTTP value.

## Controls and required checks

Six focused test methods pass. Actual-capture controls change the ASCII bias,
bound, shift, range condition, indirect/common offsets, tag-1 zero test, source
relocation, FDE length and target identity. Models are grounded in the retained
operands/control flow, not mocked calls or a guessed node-IP implementation.

Make is absent; its Python commands were invoked directly. Full suite:
**363 tests in 149.500 seconds; 7 failures, 16 errors, 21 skips**. All six new
tests pass. This independent main-based branch excludes unmerged #227; native
binutils, Windows output/path and temporary-directory problems remain. Neither
full-suite nor hosted-CI success is claimed.

Doctor reports missing prerequisites. Eight artifact size/digest checks pass,
then GPG absence prevents signature verification. Imports reject the Windows
reference checkout (reserved `node/aux.rs`, hydrated LFS inputs retained unstaged).
Catalogue fails on native backslash paths. Reproduce is attempted and stops at
artifact verification; no original imports, pins, expected packets or gates change.

No complete Rust/URI/IP type, hostname policy, private function name, caller
closure, build or equivalence is established. No captured code, TLS request,
network/chain action or progress gate. Next question: trace actual callers and
object producers before applying a recovered private type/function label.
