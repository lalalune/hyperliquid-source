# action-dispatch: reconstruct the node #115 prior-key handler wrapper template (ten clones)

A reconstruction can now treat ten of the action handler entry points of node #115 (`0x2c05370`, `0x2c05c70`, `0x2c0e9a0`, `0x2c13570`, `0x2c14de0`, `0x2c15220`, `0x2c16020`, `0x2c182b0`, `0x2c1aee0`, `0x2c1c240`) as one 1087-byte wrapper written once: it resolves an alias for a 20-byte account key, rejects the action with result tag `0xf` / code `0x120` when the key or its alias is already in a B-tree set, runs two checks, and only then tail-calls a per-clone handler body; the template's whole behaviour is restated as a short Python model that the tool proves equal to the interpreted bytes on 11,000 generated machine states.

- Component ID: `action-dispatch`.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference-source code is used.
- Claim status: observation for the byte-level behaviour and the clone relation; inference for every semantic name (alias, prior key, set); the callee bodies are unresolved.
- Scope included and excluded: the ten wrapper bodies themselves, their control flow, memory layout accesses, argument handoff to each callee and the failure paths. Excluded: the bodies of the callees (`0x2a8ab70`, `0x4717440`, `0x3ed25b0`, `0x2c202b0`, `0x2c206b0`, `0x2443a40`, the ten sink handlers), the router that calls the wrappers, the other ~75 handler wrappers of the same router, and any execution of the binary.

## Reproduce

From the repository root, Python 3.10 or newer, with the authenticated target present:

```sh
python3 tools/action_prior_key_wrapper_115.py --out research/work-items/action-dispatch-prior-key-wrapper-115
python3 -m unittest tests.test_action_prior_key_wrapper_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

The tool checks the input digest first, reads `.text` through the shared `tools/elf_index.py` section parser and neither runs the binary nor calls another program. Peak memory is a few tens of MB: cases are generated, interpreted, compared and dropped one at a time. `MANIFEST.sha256` hashes every file in this folder. Investigative disassembly used GNU objdump only to read the listing; the generator and tests do not use it.

## Evidence

Coordinates are virtual addresses in `.text` (file offsets are derived through the section header).

- `template.tsv`: for each clone, the number of bytes that differ from the first clone, how many of them lie inside a rel32 / rip-displacement field that the interpreter decoded while running, how many do not, the absolute target of the final call (the per-clone sink) and the SHA-256 of the 1087-byte body. All clones are 1087 bytes by their FDE extents; the bodies differ only in position-dependent displacements and in the final call target. The nine bytes at offsets `0x42d..0x42f`, `0x435..0x437`, `0x43b..0x43d` that fall outside the decoded fields belong to the three displacement fields of the unwind landing pad (cleanup call, resume call, abort slot call), which the interpreter never reaches because the bounds panic does not return (listed in `summary.json`).
- `cases-sample.tsv`: every 14th generated machine state for every clone (790 rows: clone, state seed, outcome, sink, number of recorded callee calls, digest of the full behaviour tuple). All 11,000 cases are regenerated from their seeds by the tool.
- `controls.tsv`: the 49 negative controls and whether each was detected.
- `summary.json`, `measure.json`: totals (11,000 cases, 0 mismatches, 9,930 valid-tree semantic checks with 0 failures, outcome histogram, the decoded displacement fields and the 18 executed conditional jumps).

Observed behaviour of the template (entry arguments `rdi` = output slot, `rsi` = context, `rdx` = pointer to the 20-byte key, `rcx` = opaque fourth argument forwarded to the sink; frame `0xf8` bytes below six pushed registers):

1. Call `0x2a8ab70` with a scratch slot. If its first byte is 1 the 20 bytes after it replace the key as the working value `v`, and the next step is 4.
2. Otherwise `v` is the key. When the table count at `ctx+0x3cb0` is 1, `v` is replaced by the 20 bytes at `entry+0x1c` of the single 48-byte entry at `[ctx+0x3ca8]` if the 20 bytes at `entry+8` equal the key. When it is greater than 1, the key is hashed with `0x4717440` (`[ctx+0x3cd8]`, `[ctx+0x3ce0]`, key) and probed with `0x3ed25b0` (`ctx+0x3ca0`, hash, key); a hit yields an index which must be below the count, otherwise the code takes a bounds-panic path that does not return; a hit replaces `v` by the 20 bytes at `[ctx+0x3ca8] + 48*index + 0x1c`.
3. The B-tree root is `[ctx+0xb78]` and its height `[ctx+0xb80]`. Nodes hold keys of 20 bytes from `node+8`, a `u16` count at `node+0xe6` and child pointers from `node+0xe8`. A node is searched linearly with `memcmp` of 20 bytes (greater: continue; less: stop; equal: found), then the child at the stop index is entered while the height counter does not underflow. The walk runs for the original key, then for `v`. A hit in either writes result code `0x120` at `out+0x10`, tag `0xf` at `out+0` and returns. With a null root both walks are skipped.
4. `0x2c202b0(slot, ctx, &v, scratch)` and `0x2c206b0(slot, ctx, &copy_of_v, scratch, 0)` follow; each leaves a 16-bit word at the slot start, and the value `0x1a2` means success. Any other value copies the `0x70` result bytes from the slot to `out+0x10..0x80`, sets tag `0xf`, and (first call only) calls `0x2443a40(&copy_of_v, slot)` once before returning.
5. On success the per-clone sink is tail-called as `sink(out, arg4, &key_copy, ctx)`; the wrapper writes nothing to `out` itself.

## Implementation and comparison

`tools/action_prior_key_wrapper_115.py` contains three independent pieces:

- an x86-64 interpreter for exactly the instruction forms used by the template (prefix, REX, ModRM/SIB decoding, the ALU and flag rules used by the compares and conditional jumps, `lea`, `movzx`, `setcc`, the SSE moves, `pcmpeqb`, `pand`, `pmovmskb`, rel32 calls and rip-relative indirect calls). Any other opcode raises an error; a callee that is not modelled raises an error; unbalanced stack or callee-saved registers raise an error;
- recording stubs for every callee, driven by the generated state (lookup tag and payload, hash value, probe hit and index, result words of the two checks, `memcmp` implemented for real on the interpreted memory);
- a pure Python `model()` that states the five steps above, and `tree_has()` for the B-tree walk.

Each of the 11,000 cases (1,100 seeded states for each of the ten clones, the same state for each clone) lays out a context, a key, an alias table and a randomly built valid B-tree of height 0, 1 or 2 (also sparse internal nodes and 8% null roots), interprets the clone bytes, and compares the output slot (sentinel-filled), the list of callee calls with their normalised arguments, and the panic flag with the model. Valid trees additionally check the semantic claim: the action is rejected exactly when the key or the effective value is a stored key (9,930 checks). The five outcomes are all exercised: rejected 5,240, dispatched 3,090, first-check failure 1,430, second-check failure 1,030, bounds panic 210.

Negative controls (49, all detected): 18 changed models (wrong code or tag, skipped or reversed walks, ignored equality, wrong height, shortened count-1 comparison, wrong bounds test, ignored override, alias ignored, swapped or skipped checks, missing drop call, missing hash call, wrong forwarded key); 8 byte patterns patched in the real bytes (reject code immediate, memcmp length, count offset, node length offset, reject tag, success code, root offset); inversion of each of the 18 executed conditional jumps; 6 out-of-range inputs (entry outside `.text`, entry past the section end, wrong sink address in the stub table, a binary with a changed digest, `int3` at entry, damaged tail opcode). Detection means at least one of the first 300 states differs or the interpreter refuses.

## Results and limitations

- 11,000 cases, 0 mismatches; 49 negative controls, 49 detected (`measure.json`).
- The interpreter covers only this template. The callees are stubs: the claims concern the wrapper, not what the callees compute.
- The wrapper is described from its arguments and memory layout. Names such as alias, prior key or set are inferences. The result code `0x120` (288) equals the prior-key rejection word used in the existing display-name decision work for `0x2392200`/`0x2c76380`; whether this wrapper is that predicate is not established here.
- The nine unwind-pad displacement bytes are accounted for by position, not by execution.
- That the ten functions are the ones the router at `0x2bda7c0` calls was seen in a listing; the router is not part of this packet and no gate is requested.
- No component gate is requested.

Next question: the callee at `0x2a8ab70` (what writes the override tag and 20-byte payload), then the shared pair `0x2c202b0` / `0x2c206b0` that every one of the ten clones calls.
