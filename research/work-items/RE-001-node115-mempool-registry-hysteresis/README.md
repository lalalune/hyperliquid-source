# RE-001: node115 mempool accepted-insertion registry representation hysteresis

Component: consensus. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The complete add-transaction FDE at `0x2e1a120` contains a separate representation-maintenance decision after registration helper `0x57bbfd0` returns raw byte0x2e. This packet addresses that decision at owner+0x280, not the transaction admission or conflict rules preceding it.

Call the signed-minimum first-word representation A and the alternative B. **A converts to B when the count at owner+0x298 is below32.** Equality32 retains A. The caller detaches the old root and count, invokes collector `0x234cae0`, releases the old representation, and installs the returned descriptor, explicitly zeroing owner+0x290. The converter's element order and semantic preservation remain unresolved.

The subsequent B path calls lookup `0x24c87d0`. **B converts to A only when lookup RAX is nonzero and the current count is above63.** Equality63 retains B. A zero lookup status also retains B even at64 or higher. The conversion detaches the descriptor into temporary storage, installs empty B fields, invokes `0x23b39d0`, releases the old storage, then publishes the signed-minimum A marker and returned root/header. The new count after a downsize conversion comes from its returned descriptor; relations deliberately evaluate each decision at its own supplied boundary rather than assume the converter preserves count.

These are asymmetric32/64 representation thresholds with an additional lookup gate on expansion. A/B are raw representation names; tree-like and contiguous storage operations provide context but do not establish a public Rust container type. Subsequent insertion/replacement code and all earlier validation remain exported context, not additional reconstructed semantics.

Prior #2081 studies found-key transaction conflict behavior, #613 predecessor selection, and #890 block proposal. They do not establish this accepted-path representation conversion policy. The native obligations, complete5247-byte export and operand-derived boundary checks preserve the gap between proving caller policy and proving converter behavior. No captured code is executed or emulated.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| add_tx | `0x2e1a120..0x2e1b59f` | 5247 | 919 |

The denominator is 1 complete FDEs, **5247 bytes /919 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **37 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-mempool-registry-hysteresis/export_disassembly.py
python3 research/work-items/RE-001-node115-mempool-registry-hysteresis/verify.py --controls
python3 research/work-items/RE-001-node115-mempool-registry-hysteresis/relations.py
python3 -m unittest discover -s tests -p test_node115_mempool_registry_hysteresis.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
