# RE-018: do the five contested [0x5773aa8] call sites share one four-pointer materializer ABI?

- Component ID: RE-018-materializer-call-abi-94
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Source commit / reference commit: base origin/main 1f8c67c63ca4794c9689235471c60297f8a5c985. No reference source is used.
- Claim status: observation for the caller pass, the five call sites, their FDE starts, the pinned lea/mov/call/post bytes, and the five [-0x40,+6) window hashes. That the four pointers are "the same ABI as RE-017" and what each buffer means are inferences; see limitations.
- Scope included and excluded: included a whole-section `ff15` pass over .text/.init/.fini/.plt for GOT slot 0x5773aa8; for each of the five contested sites (0x226685a, 0x2268f61, 0x4359d34, 0x4746097, 0x4b2c8e2) the 0x40-byte pre-call window, the 6-byte call, the pinned arg-setup lea/mov instructions, and the immediate post-call `mov byte [reg+imm32], imm8` where present; the .eh_frame_hdr FDE start for each site (and for the cited sixth site 0x3273920). Excluded: the whole FDE byte extents (those are claimed by RE-009/#334/#352 for other reasons), the body of 0x3273920 (RE-017), the internals of 0x3751e80 (RE-016), and any Location census inside the five FDEs. RE-016 lists the six call sites; this packet adds the arg-setup ABI and does not restate RE-016's chain.

## Reproduce

```
python3 -I -B research/work-items/RE-018-materializer-call-abi-94/verify.py
python3 -O -B research/work-items/RE-018-materializer-call-abi-94/verify.py
python3 -B research/work-items/RE-018-materializer-call-abi-94/independent_verify.py
python3 -B -m unittest tests.test_materializer_call_abi
for s in 0 7 99; do PYTHONHASHSEED=$s python3 -B tools/materializer_call_abi.py | sha256sum; done
python3 -O -B tools/materializer_call_abi.py | sha256sum
```

Tool: Python 3.13 standard library only (no objdump, no pyelftools). Linux x86-64, working directory = repository root. No network, no execution of the target, no side effects; the tool reads the binary and writes only `--out` (or stdout).

Output: materializer-call-abi.json, sha256 4789cdd0cb2dd7af93b0a20b50cd976da3b3fc18fe0307505d0b25a98c6f52f0. It is byte-identical for seeds 0, 7 and 99 and under -O. The tool emits nothing unless every exact expectation holds. File hashes are in MANIFEST.sha256.

## Evidence

All coordinates are virtual addresses (VAs) mapped through the PT_LOAD program headers. Analysis is complete for the listed ranges; nothing timed out.

1. **Caller pass.** Every byte offset of .text, .init, .fini and .plt is tried as `ff15` (slot = site+6+disp32). Exact pinned result for slot 0x5773aa8: **6** sites — 0x226685a, 0x2268f61, 0x3273920, 0x4359d34, 0x4746097, 0x4b2c8e2. This packet owns the five outside 0x3273810; 0x3273920 is cited only.

2. **FDE starts** (via .eh_frame_hdr datarel sdata4 table): 0x226685a→0x22615b0, 0x2268f61→0x22689f0, 0x3273920→0x3273810, 0x4359d34→0x4356c90, 0x4746097→0x4744160, 0x4b2c8e2→0x4b29760. The whole extents of those FDEs are not hashed here.

3. **Four-pointer arg setup (bytes).** Immediately before each of the five calls, the code loads four pointers into rdi/rsi/rdx/rcx (sometimes via a scratch like r14) and then `call [0x5773aa8]`:

   - **0x226685a** (`ff 15 48 d2 50 03`): `lea rdi,[rsp+0x4b40]`; `lea rsi,[rsp+0xa50]`; `lea r14,[rsp+0x120]`; `lea rcx,[rsp+0x50]`; `mov rdx,r14`. Post: `mov byte [rbx+0x82a],0` at 0x2266860. Window [-0x40,+6) sha256 075b66c4…72fb.
   - **0x2268f61** (`ff 15 41 ab 50 03`): earlier `mov edx,0x1fc8`; then `mov [rsp+0x7700],r12`; `mov [rsp+0x7708],r14`; `lea r12,[rsp+0x7700]`; `lea rcx,[rsp+0xf0]`; `mov [rsp+0x18],rdi`; `mov rsi,r13`; `mov rdx,r12`. Post: `mov byte [rbx+0x49f0],1` at 0x2268f67. Window sha256 3e65fcde…222e.
   - **0x4359d34** (`ff 15 6e 9d 41 01`): `lea rdi,[rsp+0x4a80]`; `lea rsi,[rsp+0xa30]`; `lea rdx,[rsp+0x170]`; `lea r14,[rsp+0xe0]`; `mov rcx,r14`. Post: `mov byte [r13+0x82a],0` at 0x4359d3a. Window sha256 4fa51f80…3299.
   - **0x4746097** (`ff 15 0b da 02 01`): `lea rdi,[rsp+0x4400]`; `lea rsi,[rsp+0x440]`; `lea rdx,[rsp+0xf0]`; `lea rcx,[rsp+0x30]`. Post: `mov byte [rbx+0x64a],0` at 0x474609d. Window sha256 19866752…70f6.
   - **0x4b2c8e2** (`ff 15 c0 71 c4 00`): `lea rdi,[rsp+0x4aa0]`; `lea rsi,[rsp+0x9a0]`; `lea rdx,[rsp+0x180]`; `lea r14,[rsp+0x100]`; `mov rcx,r14`. Post: `mov byte [rbx+0x82a],0` at 0x4b2c8e8. Window sha256 4045a5ab…f918.

4. **38 key instructions** pinned byte-for-byte across the five windows (see `key_bytes` in the JSON).

Resulting byte-proven fact: each of the five contested sites loads four stack (or register-held) pointers into rdi/rsi/rdx/rcx and calls through slot 0x5773aa8 — the same four-argument shape RE-017 pins at 0x3273920.

## Implementation and comparison

Not yet implemented. No Rust re-implementation and no differential run; this is a static, bytes-only packet.

## Results and limitations

- Pinned counts: 6/6 ff15 sites on 0x5773aa8; 5/5 owned sites; 5/5 window hashes; 38/38 key instructions; 5/5 call targets = 0x5773aa8; 6/6 FDE starts. independent_verify.py re-derives all of them without tools/.
- Inferred, not proven: that the four pointers play the same roles as RE-017's (out, 0x1fc8-block, 0x20-byte, 0x30-byte); what the post-call flag bytes mean; which source function each FDE implements.
- Not claimed: the behaviour of 0x3751e80 (RE-016); the body of 0x3273920 (RE-017); whole-FDE hashes or transport/RocksDB/timeout facts already claimed by #139/#179/#192/#211/#334/#352/RE-009 inside these FDEs.
- Not covered by the caller pass: `jmp [slot]`, `mov reg,[slot]` loads, and code outside the four scanned sections.

Next question: do the four buffers at each site match RE-017's 0x1fc8 / 0x20 / 0x30 layout by size, and which of the five sites is the hottest on the gossip/evm_kvs paths named by RE-009?
