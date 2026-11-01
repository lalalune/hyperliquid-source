# RE-001 / consensus: What bytes does the LocalNode value branch emit, and what Ip array stage is prepared under selected serializer flags?

Bounded maintainer task-queue static research. Target node94
`artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `15f79350f790a04aed73b5fc9319f85b535f8282`. Unlicensed reference can1357-hl revision
`999556f6e0a474b8312db96ec3149e1c44e97c23`, `node/consensus/node_ips.rs` supplied seeds
only. No reference implementation was copied; new code/docs are independently
authored under the repository MIT license. Captures retain upstream rights.

## Observations, inference and scope

Complete FDE-described ranges, ELF virtual addresses: 0x45bc960..0x45bccfb, 0x45bcd00..0x45bcf4c, 0x4aec6c0..0x4aeca45, 0x4aa4230..0x4aa4616.
The records contain full owner hashes and FDE/CIE identities. Full disassembly
exports are distinct from the bounded models; no normalization masks are used.

Four complete owners: 0x45bc960 (JSON-shaped formatter context), 0x45bcd00 (variant-key serializer), 0x4aec6c0 (unsigned integer helper), and 0x4aa4230 (Ip value helper). The raw input tag compared with 1 selects LocalNode; other input-tag validity is not reconstructed.

Under sufficient-capacity normal-path assumptions the LocalNode branch writes 0x81, 0xa9, nine inline LocalNode bytes, then the zero-extended payload byte via the unsigned helper. The helper tests the signed high bit of that byte: values through 127 use one byte, while 128..255 use 0xcc plus the payload. Original immediate stores and branch operands drive the bounded lowering; it is not native serializer execution.

In the JSON-shaped owner, only the decimal payload is closed: thresholds 9/99, the original scale/shift/remainder arithmetic and 100 digit pairs produce one to three ASCII bytes. The key escaping helper and complete JSON output remain opaque.

The Ip helper's raw serializer flag +0x1a selects text versus nontext preparation. Within the nontext route, +0x1c unequal to 2 prepares an array marker and four unsigned-octet helper calls. Native little-endian word loads and shifts 0/8/16/24 determine order. The model stops before 0x43fa0b0 finalization; this is not a claim about complete Ip wire output, other flag modes or their reachability. Related variant paths are grouped here, not separate quota items.

The official MessagePack specification identifies fixmap/fixstr, positive fixint and uint8 bytes (https://github.com/msgpack/msgpack/blob/master/spec.md). This supports interpretation of observed bytes, not a library version or native equivalence. Existing #702 concerns validator/configuration admission, not these selected value encoders.

## Reproduce and controls

Python 3.12.14; stdlib ELF readers and bounded synthetic models. Capstone 5.0.6
x86-64 Intel generates complete exports; no captured executable, external
service, real runtime state, signing or private data is used.

```
python tools/nodeip_value_encoding.py --out research/work-items/RE-001-nodeip-value-encoding-94/records.json
python research/work-items/RE-001-nodeip-value-encoding-94/export_disassembly.py
python -m unittest discover -s tests -p test_nodeip_value_encoding.py -v
```

Controls cover all 256 LocalNode values in two numeric representations, 1024 single-octet variations of selected Ip preparation, independent expected bytes, actual signed-branch/hundred-threshold/octet-shift and map/key-store mutations, literal/call/identity corruption and domain rejection. The packet is regenerated from the full
digest-bound capture. Actual instruction changes are rejected even when a
synthetic comparison otherwise looks plausible. Before this packet main had
unverified seeds, not this bounded comparator; afterward it has original owner
exports and explicit conditional evidence. This is not a source-equivalence
comparison, recovered Rust or a fixed live defect.

## Results and limitations

Base `15f79350f790a04aed73b5fc9319f85b535f8282`, Windows, Python 3.12.14. The current Makefile's
`python tools/run_tests.py` executes each flat test file in a fresh interpreter.
Before: 891 isolated files / 13994 tests; 106 failing files, 73 failures, 177 errors, 275 skips.
After: 892 isolated files / 14000 tests; 106 failing files, 73 failures, 177 errors, 275 skips.
Before/after FAIL and ERROR header multisets are identical; all six new methods
also pass inside the full isolated run. This is an observed delta, not a clean
full-suite result or native equivalence. Total changed-tree runner wall time:
6877.422 seconds. Focused six controls pass in 2.130 seconds.

Required Makefile-equivalent commands (Make is unavailable): doctor exit 1; verify exit 1; imports exit 1; catalogue exit 1; reproduce exit 1; full-tests exit 1.
Doctor, verification/import, catalogue and reproduce limitations are retained in
the original work logs. Missing native prerequisites/signature validation and
the Windows imported checkout/catalogue state are not counted as passes.
Per-file totals are summed only after the runner's final inventory footer;
an interrupted or partial log does not qualify. Full private environment logs
remain outside the PR; portable passing focused controls are retained here.
No imported inputs/pins or generated progress gates are changed. Hosted CI,
signature success, recovered Rust and whole-node equivalence are not claimed.

Selected sufficient-capacity normal paths only. Ip finalizer and other serializer flags, full JSON rendering, buffer growth/errors, application-valid enum values, ownership and caller/transport behavior remain unclosed. No Rust/native equivalence, full CFG recovery, complete component
or progress gate is claimed. Next: close Ip finalization and serializer flag construction before assigning an end-to-end wire schema.

## Upstream integration validation

This source branch started from main `15f79350f790a04aed73b5fc9319f85b535f8282`. While its complete
before/after checks ran, upstream advanced to `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. Fresh scope review found
no competing claim. Candidate files, contribution policy, runner and other
reviewed dependencies remain unchanged. Two imported files changed only their
`generate`/`main` command-line output guards: `tools/elf_index.py` and
`tools/fde_extents.py`. Their other module state, imports and function ASTs are
identical. All six focused controls were replayed with snapshots of those two
upstream modules and pass in2.088s, including exact retained-record agreement.

The complete13,994/14,000 before/after results above describe the exact source
branch, not the later integration tree. Additional upstream tests and hosted CI
have not been run successfully here. The compatibility replay is a separate
bounded observation and does not replace or relabel the full source-branch run.
