# RE-001: consensus latency labels and conditional remainder gate, node94

Task/component: RE-001, consensus static seed/call/data binding. Maintainer task docs/TASKS.md asks for target-bound ranges and xrefs. Question: what do the consensus latency label dispatcher and its selected gate actually establish? This is a static research contribution, not a reproduced live defect or recovered Rust implementation.

Target: node #94, 91,774,280 bytes, SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f. Base 1f8c67c63ca4794c9689235471c60297f8a5c985. The pinned can1357 commit999556f6e0a474b8312db96ec3149e1c44e97c23, node/consensus/latency_samplers.rs, was a lead only. It labels this path and describes one-in-fifty sampling. No inferred Rust is copied, built, or treated as verified source. The existing latency PR44 covers a different net_utils update frame (375 bytes); PR181 covers bucket-guard frames. Neither selected frame here is counted there.

## Original observations

records.json contains complete raw body/FDE/CIE bytes and hashes for two FDE-described scopes:

| Linked VA interval, end exclusive | Bytes | Capstone instructions | Body SHA-256 |
| --- | ---: | ---: | --- |
| 0x4a11410..0x4a117be | 942 | 194 | 7a210561ffe1b422213784ba54a1605d438e727965404d4cffe7d3e74c0b90c1 |
| 0x13c9e20..0x13c9ff5 | 469 | 107 | 89a52af2b60e717ace437a4178af9ac57c4e7e66cf895bf41609f6fbdfb279fb |

Coordinates are linked ELF VAs, not runtime addresses; file offsets are resolved through unique file-backed section mappings. FDE scope is not a proof of all functions or source ownership. Complete native exports are in capstone-5.0.6.txt; decoding starts at each FDE start, consumes all1,411 bytes without gaps, and reproduces byte-for-byte with verify_native.py.

The initial byte is zero-extended. IDs below15 select table index0; otherwise the index is id-14. The six signed relative table entries at VA0x703834 resolve to the six recorded arms. The scoped raw domain is0..19, not a promise that the caller admits exactly that domain. Larger byte values and enum admission are unresolved.

| Raw IDs in scoped domain | Observed label material | Bytes set at stack+6 / stack+5 before builder call |
| --- | --- | --- |
| 0..14 | HandleStateInput:: format template plus raw byte argument | 1 /0 |
| 15 | HandleAllStateInputs | 1 /1 |
| 16 | BlockGap | 0 /0 |
| 17 | WallClockBlockGap | 0 /0 |
| 18 | TxCommit | 0 /0 |
| 19 | ExpensiveStatus | 1 /0 |

Fixed strings are bound to actual immediate stores and RIP-relative data, not copied from the reference. A separate template contains consensus/. Complete formatted names and the external formatter's ABI are not reimplemented here. Addresses of both flag bytes escape to the opaque builder at0x4957d90; preservation of those bytes across its calls is NOT proved.

After the builder returns, the code tests stack+5. Zero branches directly to the metric call; otherwise it passes EDI=50 through slot0x576e8f8, tests AL, and bypasses the metric call on zero. RELA type8 binds that slot to0x13c9e20. The metric call slot0x576efb0 resolves to0x14027b0; its behavior and units remain out of scope. Source Location slot0x5736728 binds the actual path node/src/consensus/latency_samplers.rs:38:21. Both data relationships and their original zero pointer slots are checked.

On the gate helper's normal-return tail, R14 holds an opaque TLS-derived word and RBX the input divisor. `(R14 | RBX) >>32 ==0` selects unsigned32 division; otherwise unsigned64 division is used. Both clear EDX, divide, and return AL=1 iff RDX is zero. With observed divisor50, this establishes the remainder-zero rule on a normal-return path. TLS initialization/refill calls, generator identity, distribution, abnormal paths, and exact1/50 probability are not established. The reference's random_range abstraction is not proved equivalent. Even a hypothetical uniform64-bit word has 2**64=50*q+16 values, so modulo50 alone would not imply exact1/50 probability; that is a conditional arithmetic observation, not a measured distribution or vulnerability claim.

## Reproduce

Python3.12.14 on Windows; PYTHONUTF8=1, PYTHONIOENCODING=utf-8. From repository root:

```text
python tools/consensus_latency_gate.py --check research/work-items/RE-001-consensus-latency-gate-94/records.json
python -m unittest discover -s tests -p test_consensus_latency_gate.py -v
python research/work-items/RE-001-consensus-latency-gate-94/verify_native.py
python -O research/work-items/RE-001-consensus-latency-gate-94/verify_native.py
python -m unittest discover -s tests -v
python tools/doctor.py
python tools/artifacts.py verify
python tools/verify_imports.py
python tools/catalogue.py --check
python tools/reproduce.py
git diff --check
```

The ordinary analyzer/tests use stdlib only. The optional native replay needs Capstone5.0.6 on PYTHONPATH. The actual Windows wheel was obtained from https://pypi.org/pypi/capstone/5.0.6/json, its published SHA-256 verified before unpacking: capstone-5.0.6-py3-none-win_amd64.whl, 761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064. Only the analysis library runs; no captured instruction or random generator is executed. No package hook or project dependency/lockfile changes.

## Validation and limits

Six focused tests pass. They reproduce the complete report, reject altered input identity, challenge11 actual instruction bytes below the digest gate, six table/label/path/Location bytes, three scoped RELA retargets, and independently bind all retained native export bytes to the capture. A first draft missed a mutation of the builder return-to-RBX move; its control was added before submission. A failure excerpt from the original tool transcript is preserved separately from the final logs (the original test log was overwritten by the successful rerun). Native replay passes normally and under -O, with301 instructions/1,411 bytes equal. No synthetic execution, RNG oracle, model-backed execution, statistical sampling, target VM or recovered compiler result is claimed.

Required make commands were invoked via their Python commands because make is absent. Full tooling is not claimed green. Doctor lacks GPG, objdump/readelf, Ghidra/Java and Rust toolchains; Capstone availability does not change those requirements. Artifact byte hashes pass before missing GPG prevents signature verification. Imports fail on the partial Windows reference checkout (reserved node/aux.rs); catalogue-check is stale and reproduce stops at artifact verification. The full-suite result is recorded after completion in the PR. Original logs are retained outside the contribution under consensus-latency-*.

Full suite completed: 287 tests in109.805s, seven failures,32 errors,nine skips, the same failure counts as the baseline281. git diff --check passes. Signature/native setup failures are not bypassed or relabelled successful.

No progress gate, whole-program equivalence, full caller census, complete metric/map ABI, elapsed-time units, live network behavior or source recovery is claimed. Captures, imports, source pins and generated catalogues remain unchanged. Machine-code excerpts retain the captured artifact's rights; new tooling/text is independently authored. Next: validate builder flag preservation and the TLS refill implementation before asserting sampling probability or reconstructing a sampler API.
