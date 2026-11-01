# RE-013: metadata request, probe and cache decisions

Base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; separate Visor capture
SHA-256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`,
8,305,392 bytes. Addresses are linked ELF virtual addresses before load bias.

The prepared-path/prefix/preparation packets leave native metadata requests
opaque. This packet qualifies the request/cache/probe relation in689980 and
the wrapper's conditional tag/mode projection **after pathname admission**.
It distinguishes a failed main request from the later availability probe,
preserves the original error only on the specified helper tag2 routes, and
keeps entry/reloaded cache samples distinct.

| Condition | Helper tag | Explicit cache store | Error |
| --- | ---: | --- | --- |
| Entry byte2 | 3; no request | none | unqualified |
| Main EAX!=-1 | 1 | 1 only if entry byte0 | not an error |
| Failed main, reloaded byte1 | 2; no probe | none | original |
| Failed main, other reloaded byte, failed probe errno14 | 2 | 1 | original |
| Other probe outcome | 3 | 2 | unqualified |

Optional weak `statx` vs numeric `syscall(0x14c,...)` dispatch is bound to
actual import slots and raw register arguments. This is not a test of the
loaded symbol, running kernel/libc or actual filesystem. The cache is writable
NOBITS .bss; no actual runtime initial value or synchronization is claimed.
Tag3 causes the wrapper's stat64 fallback. A failed fallback returns its own
later error, so original-error preservation must not be generalized across
the entire wrapper.

`PROOF.md` gives the addressed conditional argument, valid frame/storage/call
premises, untouched/unqualified-field distinctions and the limited mode-field
projection. The returning RAX, complete payload ABI, pathname admission,
concurrency, actual metadata values and filesystem effects remain unproved.

## Evidence, validation and reuse

Three complete FDE extents retain1,533 bytes /366 instruction rows: core
`689980..689c97` (791), wrapper context `686d10..686f28` (536), and credited
cleanup `65f260..65f32e` (206). GNU2.42 and LLVM18.1.3 raw address/byte
partitions agree without masks. Full FDE/CIE records,9 RELA bindings,7 direct
calls, optional weak dynamic-symbol data and writable cache section membership
are retained. No raw bytes or runtime initial value are invented for .bss.

Normal/optimized integrity checks each regenerate records twice and reject10
identity/record/preservation controls. Binding checks reject28 addressed
instruction-byte and5 RELA-addend mutations below image identity. Their366-row
identity inventory is not366 independent semantic proofs or mutated target
execution. Normal/optimized receipts agree. Abstract procedural/declarative
decision specifications agree on458,752 cache-pair/scenario rows,7 explicit
protocol fixtures,65,536 integer mode projections and3 wrapper fixtures;
eight concrete witnesses refute false simplifications. These are high-level
tables/integer support for the manual argument, not a CPU/instruction model
or target behavioral comparator. Abstract None means no qualified field/store,
not a stored zero.

Reuse and credit accepted base `RE-013-visor-descriptor-wait/PROOF.md` section4
for cleanup of locally packed low-tag2 errors. That specific route returns
without heap callbacks/result writes; arbitrary heap-tag/unwind behavior is
not claimed. Wrapper context is revisited from draft1437 at frozen public head
`a486efada6ef6e533d2f047be81591226daf82ea`. This author's MIT static utility
code is adapted from1437/1469; new code/prose is MIT. Capture exports retain
upstream rights. No unlicensed inferred source is used or copied. No new
recovered-byte/function count or component gate is claimed; the new outcome
is the bounded metadata request/probe/cache relation.

## Reproduction

Materialize pinned inputs using repository instructions. From this packet
directory use the admitted, nonexecutable Visor artifact and new output paths:

```sh
B=../../../artifacts/visor/captured/hl-visor
python3 -B survey.py --binary "$B" --output /tmp/visor-metadata-fresh
python3 -B verify.py --binary "$B" --receipt /tmp/visor-metadata-integrity.json
python3 -O -B verify.py --binary "$B" --receipt /tmp/visor-metadata-integrity-opt.json
cmp /tmp/visor-metadata-integrity.json /tmp/visor-metadata-integrity-opt.json
python3 -B crosscheck_llvm.py --binary "$B" --output /tmp/visor-metadata-llvm
python3 -B check_language.py
python3 -O -B check_language.py
python3 -B check_bindings.py --binary "$B" --receipt /tmp/visor-metadata-bindings.json
python3 -O -B check_bindings.py --binary "$B" --receipt /tmp/visor-metadata-bindings-opt.json
cmp /tmp/visor-metadata-bindings.json /tmp/visor-metadata-bindings-opt.json
```

Exact commands, source hashes and observed root `make doctor`, `make verify`,
`make catalogue-check` and `make reproduce` results are in `VALIDATION.json`.
Full `make test` is NOT RUN because flat discovery includes captured-instruction
evaluators outside static-only authorization. Hosted CI, container/full Rust
builds, captured execution/emulation, target networking and component gates
are not claimed. Draft/title/commit use `[skip ci]`; pinned inputs and existing
progress/gate files are unchanged.
