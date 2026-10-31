# RE-001 / foundation: build-mode and program-name priority

Question: where does the special program-name path sit relative to raw mode
validation, and which output byte is stored? Scope: selector, formatter operands,
controls and packet, not command execution or a complete build-path implementation.

Target node94 `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
Unlicensed reference lead: can1357-hl
`999556f6e0a474b8312db96ec3149e1c44e97c23`, `base/build_mode.rs`,
seed `0x13cd410`; no implementation is copied.

## Observations

ELF virtual addresses, no masks. Actual FDE `0x13cd410..0x13cd6cb`:
**699 bytes / 156 instructions**, complete export, raw FDE/CIE, full body hash
and selected branch boundaries. Only selected raw-byte/name/tag behavior is modeled.

The byte in CL and byte in R8B are ORed at `0x13cd42b`; zero goes directly
to the local copy path, including for program `run-client`. Otherwise a length-10
check, an eight-byte XOR and a two-byte XOR test exactly the bytes `run-client`.
That match branches to `0x13cd596` **before** the kind-byte checks.
Only nonmatching names reach CL==1 (`debug`), CL==2 (`release`), or the failure
at `0x13cd636`. Thus raw unknown kind bytes can take the special name branch;
this does not assert that those bytes are valid or reachable original Rust enums.

| Selected raw condition, in order | Route | Output byte +0x18 |
| --- | --- | ---: |
| Both bytes zero | Local copy | 0 |
| Otherwise exact `run-client` | Special formatter | 0 |
| Otherwise kind 1 | Debug formatter | 1 |
| Otherwise kind 2 | Release formatter | 1 |
| Otherwise | Invalid-kind failure | No normal output claimed |

The profile/program formatter result feeds another formatter with the captured
`/aws_build/` template. The special path uses `/code/run-client`. Both also
pass an argument derived from relocated global context `+0x18`; the captured
context's contents are not read at runtime or assumed to be an empty root.
Formatter slot `0x576e040` resolves to `0x1344760`. Global root contents,
complete formatter semantics and final path strings remain unclosed. The failure
Location resolves to `base/src/build_mode.rs:199:30`, not an assumed reference
line. Allocation, lazy initialization, copying/freeing and unwind are unmodeled.

## Inferences and limits

Mode/build names follow literals and source context. The reference's source enum
restricts the special path to its Debug/Release match arms, whereas the selected
machine path first tests the special name after the two-byte zero test. The raw
predicate is established; valid typed enum domains and caller-populated values
are not. This is not a vulnerability or a command/build execution claim.
No filesystem, global runtime state, compiler, captured node or process executes.
Before: source narrative of mode-specific path selection. After: exact priority,
literals, argument origins and output tag stores are byte-bound. Next question:
close caller value domains and formatter/global-root semantics before assigning
a typed path API.

## Reproduction and checks

Python 3.12.14, stdlib static readers; optional Capstone 5.0.6 x86-64 Intel.

```
python tools/build_mode_selector.py --out research/work-items/RE-001-build-mode-selector-94/records.json
python research/work-items/RE-001-build-mode-selector-94/export_disassembly.py
python -m unittest tests.test_build_mode_selector -v
```

Six focused methods pass in 1.332 seconds: all 131,072 declared raw mode/name
classes, all 2,560 single-byte name mutations, zero-mode precedence, real name/
kind immediate mutations that change derived routes, and capture controls for
guards, tags, templates, global/formatter operands, source, FDE and identity.
Those raw domains include invalid/unreachable original representations. Make is
unavailable; required Python commands ran directly. Full suite: **363 tests in
107.836 seconds; 7 failures, 16 errors, 21 skips**. All six new methods pass.
Existing Windows newline/POSIX-path/native-tool constraints remain; this branch
excludes unmerged #227. Doctor reports missing prerequisites. Eight artifact
sizes/digests pass before missing GPG prevents signature verification. Imports
reject the Windows reference checkout; catalogue-check rejects backslash paths.
Reproduce stops at artifact verification. No full-suite/signature/hosted-CI or
native-equivalence success is claimed; no gate is requested.
