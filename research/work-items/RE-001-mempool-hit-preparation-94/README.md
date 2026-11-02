# RE-001: conditional key-hit preparation in add_tx

Component: consensus. Question: after an already-matched key, which marker
continues the second lookup, and what do the two selected hit paths prepare?
This is a partial static research packet, with no requested progress gate.

Target: node #94, `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Research base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
The unlicensed can1357 reference at
`999556f6e0a474b8312db96ec3149e1c44e97c23`,
`node/consensus/mempool.rs`, supplied a seed only. No inferred implementation
was copied. New code/docs are independently authored under MIT; captures
retain upstream rights.

## Observations

All coordinates are ELF virtual addresses. The complete FDE-described owner
is `0x44b9a50..0x44ba838`: 3,560 bytes / 667 contiguous instructions.
`records.json` binds its full hash and FDE/CIE; `owners.capstone.txt` retains
the complete Capstone 5.0.6 x86-64 Intel export without masks.

- At `0x44b9b40`, an already-matched first-tree entry is compared with raw
  word `0x8000000000000001`. Equality continues into the second lookup;
  inequality reaches the first preparation at `0x44b9c01`.
- The first preparation forms `0x8000000000000023`; a second-tree match at
  `0x44b9be8` forms `0x8000000000000024`. Names/types for these tags are unknown.
- Stores at `0x44b9c14`, `0x44b9c19`, `0x44b9c29` and `0x44b9c2e` define
  41 bytes: an eight-byte tag at stack `+0x40`, one opaque byte at `+0x48`,
  then the 32-byte input key at `+0x49..+0x68`.
- Assuming the intervening destructor returns normally, the comparison at
  `0x44b9c52` is against `0x800000000000002a`. Both prepared tags therefore
  select the branch labelled `err`, with metric text `add_tx`. The normal
  helper return joins the native return at `0x44b9daf`, before the later
  validation region starting at `0x44b9db0`.

The model lowers the actual constants, LEA displacements, stores, comparison
and Jcc operands on synthetic inputs. It does not execute native instructions
or treat a synthetic key hit as proof of real tree membership. Only the
41 defined pre-helper bytes are returned; the remaining bytes of the native
80-byte result are unknown, not normalized to zero.

Related work is preserved: the merged auto-jail packet records the later
accepted-bundle write at `0x44ba1f8`; commit-walk and block-proposal packets
list this function as a callee. Their findings are not recounted here.

## Reproduce and controls

Python 3.12.14; Capstone 5.0.6 for disassembly. No captured execution, network,
real runtime state, private data, signing or chain action is used.

```sh
python tools/mempool_hit_preparation.py --out research/work-items/RE-001-mempool-hit-preparation-94/records.json
python research/work-items/RE-001-mempool-hit-preparation-94/export_disassembly.py
python -m unittest discover -s tests -p test_mempool_hit_preparation.py -v
```

Controls cover all 256 payload bytes for both kinds, varying synthetic keys,
canary independence, marker boundaries, original Jcc inversion, a tag LEA
counterexample, swapped key-store offsets, undefined-read rejection, full-owner
and literal/call/digest corruption, and retained-record reproduction.

## Results and limitations

Base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. Windows, Python 3.12.14. Required Makefile-equivalent
commands ran because Make is unavailable. The current `tools/run_tests.py`
runner executes each flat unittest file in a fresh interpreter.
Before: 971 isolated files / 15162 tests; 121 failing files, 83 failures, 188 errors and 284 skips.
After: 972 isolated files / 15168 tests; 121 failing files, 83 failures, 188 errors and 284 skips.
FAIL and ERROR header multisets are identical. All 6
new methods also pass in the full run. Focused controls pass in 2.406 seconds.
Changed-tree full runner wall time: 6982.985 seconds.

Actual check exits: doctor=1; verify=1; imports=1; catalogue=1; reproduce=1; full-tests=1.
This is not a full-suite pass. Missing native/signature prerequisites, Windows
reference-checkout failures and catalogue drift remain recorded as failures;
their original private logs are preserved. No hosted CI, signature success,
whole-node identity or complete component gate is claimed.
No imported inputs/pins or generated progress files change in this PR.

Tree validity/membership, payload meaning, destructor and logger behavior,
post-helper mutation, the complete return ABI and transaction acceptance are
unclosed. This is not recovered Rust or native equivalence. Next: establish
real tree membership and the payload's identity before naming error variants.
