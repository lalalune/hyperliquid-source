# RE-017: does the RE-016 materializer slot 0x5773aa8 have a caller that is bound to an l1/abci/state.rs Location?

- Component ID: RE-017-abci-state-link-94
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Source commit / reference commit: base origin/main 1f8c67c63ca4794c9689235471c60297f8a5c985. No reference source is used.
- Claim status: observation for the relocation, caller sites, FDE extents, the Location record and the fixed instruction bytes listed below. Field meanings, the role of 0x3c155a0, and "tag 2 = Err" are inferences; see limitations.
- Scope included and excluded: included the .rela.dyn entry for GOT slot 0x57755a8 (and every entry whose addend is 0x3273810), the Location record at 0x56dfbf8 and the string it points to, one whole-section caller pass over .text/.init/.fini/.plt, the .eh_frame_hdr FDE lookup for each site found, the whole FDE extent 0x3273810..0x327396c (bytes pinned by sha256, 33 fixed instructions pinned byte for byte) and four instructions around the call site 0x3272785 in 0x32725d0. Excluded: the internals of 0x3c155a0, 0x33f9c60 and 0x3751e80, the rest of 0x32725d0, and the five other `ff15 [0x5773aa8]` functions. RE-009 on main lists 0x3273810 (state.rs:107) and 0x32725d0 (state.rs:66) as Location-bearing functions only; this packet adds the two GOT links and the argument hand-off and does not restate RE-009. The RE-016 chain (0x5773aa8 -> 0x3751e80, open as a separate PR) is cited, not depended on: this packet imports nothing from it or from other tools/.

## Reproduce

```
python3 -I -B research/work-items/RE-017-abci-state-link-94/verify.py
python3 -O -B research/work-items/RE-017-abci-state-link-94/verify.py
python3 -B research/work-items/RE-017-abci-state-link-94/independent_verify.py
python3 -B -m unittest tests.test_abci_state_link
for s in 0 7 99; do PYTHONHASHSEED=$s python3 -B tools/abci_state_link.py | sha256sum; done
python3 -O -B tools/abci_state_link.py | sha256sum
```

Tool: Python 3.13 standard library only (no objdump, no pyelftools). Linux x86-64, working directory = repository root. No network, no execution of the target, no side effects; the tool reads the binary and writes only `--out` (or stdout).

Output: abci-state-link.json, sha256 e8e24678b2e9aa32e93a08f5ab9e469b49b40742d2839affb1c9c2295ace4548. It is byte-identical for seeds 0, 7 and 99 and under -O. The tool emits nothing unless every exact expectation holds. File hashes are in MANIFEST.sha256.

## Evidence

All coordinates are virtual addresses (VAs) mapped through the PT_LOAD program headers. Analysis is complete for the listed ranges; nothing timed out.

1. **Relocation.** `.rela.dyn` (80022 entries) holds exactly one entry at r_offset 0x57755a8: type 8 (R_X86_64_RELATIVE), sym 0, addend 0x3273810. No other entry carries addend 0x3273810. The slot sits 0x28 above 0x5775580, the RE-016 slot for 0x326e460, in the same run of RELATIVE slots.
2. **Caller pass.** Every byte offset of .text, .init, .fini and .plt is tried as `e8` rel32 (target = site+5+disp32) and `ff15` RIP slot (target = site+6+disp32). This is a superset of aligned instructions, so zero counts are upper bounds. Exact pinned results:
   - rel32 sites targeting 0x3273810: **0** (reloc-only).
   - `ff15` sites through 0x57755a8: **1**, at 0x3272785 (`ff 15 1d 2e 50 02`), inside FDE 0x32725d0.
   - `ff15` sites through 0x5773aa8: **6**: 0x226685a (FDE 0x22615b0), 0x2268f61 (FDE 0x22689f0), **0x3273920 (FDE 0x3273810)**, 0x4359d34 (FDE 0x4356c90), 0x4746097 (FDE 0x4744160), 0x4b2c8e2 (FDE 0x4b29760).
3. **FDE.** .eh_frame_hdr (datarel sdata4 table) gives 0x3273810 the extent 0x3273810..0x327396c; its bytes hash to ae961c6ff6f14718032ef8b469845ff4ecd79501528c5902a5f046cc584349f6.
4. **Location.** 0x3273856 `48 8d 0d 9b c3 46 02` = `lea rcx,[rip+0x246c39b]` -> 0x56dfbf8. That record's pointer word is filled by a RELATIVE reloc with addend 0x1dd8eb; length 49, line 107, column 37; the 49 bytes at 0x1dd8eb read `/home/ubuntu/hl/code_Mainnet/l1/src/abci/state.rs`.
5. **0x3273810 body (fixed bytes).**
   - Prologue `41 57 41 56 41 55 41 54 53 48 81 ec 00 10 00 00`; stack probes to a 0x3fb0 frame (`48 81 ec b0 0f 00 00` at 0x3273846; `48 81 c4 b0 3f 00 00` at 0x3273929).
   - Saves r15=r8 (0x327384d `4d 89 c7`), rbx=rcx (0x3273850 `48 89 cb`), r14=rdi (0x3273853 `49 89 fe`).
   - 0x3273862 `e8 39 1d 9a 00` calls 0x3c155a0 with rdi=rsp+0x20 and rcx=Location 0x56dfbf8.
   - 0x3273871 `49 83 fd 02` / 0x3273875 `75 41`: if the first result word r13 == 2, it stores `[r14+8]=r12` (0x3273877) and `[r14]=2` (0x327387b), frees the r15 buffer through 0x576e010 (0x3273890), calls 0x33f9c60 on r15+0x18 (0x327389d), frees the rbx buffer through 0x576e010 (0x32738b0), and returns r14.
   - Otherwise: memcpy through 0x576dfe0 (0x32738ca) of edx=0x1fb8 (0x32738c5) bytes from rsp+0x30 to rsp+0x1ff8; stores r13/r12 to rsp+0x1fe8/0x1ff0 (0x32738d0/0x32738d8), so rsp+0x1fe8 holds a 0x1fc8-byte block; copies 0x20 bytes from [rbx] to rsp and 0x30 bytes from [r15] to rsp+0x20; then 0x3273920 `ff 15 82 01 50 02` = `call [0x5773aa8]` with rdi=r14 (0x327391d), rsi=rsp+0x1fe8 (0x327390d), rdx=rsp (0x3273915), rcx=rsp+0x20 (0x3273918). It returns rax=r14 (0x3273926) and `ret` at 0x3273939.
6. **Outer call site.** In 0x32725d0: 0x327276f `lea rdi,[rsp+0x3b50]`, 0x3272785 `call [0x57755a8]`, then 0x327278b `cmp dword [rsp+0x3b50],2` and 0x3272793 `je 0x3272a13`.

Resulting byte-proven chain: 0x32725d0 (state.rs:66 per RE-009) --`ff15 [0x57755a8]` @0x3272785--> 0x3273810 (state.rs:107 Location) --`ff15 [0x5773aa8]` @0x3273920--> slot 0x5773aa8, which RE-016 shows is filled with 0x3751e80.

## Implementation and comparison

Not yet implemented. No Rust re-implementation and no differential run; this is a static, bytes-only packet.

## Results and limitations

- Pinned counts: 1/1 relocation for slot 0x57755a8; 1/80022 .rela.dyn entries carry addend 0x3273810; 0 rel32 + 1 ff15 callers of 0x3273810; 6 ff15 sites on 0x5773aa8, 1 of them (0x3273920) inside 0x3273810; 33/33 key instructions; 8/8 targets; 1/1 extent hash; 1/1 Location record. independent_verify.py re-derives all of them without tools/.
- Inferred, not proven: that word value 2 at the head of the 0x3c155a0 result and of the outer out buffer is a Rust `Err` discriminant; that 0x3c155a0 builds a path-like value (it tests a byte against `/`); what the 0x1fc8, 0x20 and 0x30-byte blocks mean.
- Not claimed: the behaviour of 0x3751e80 (see RE-016); the other five `ff15 [0x5773aa8]` callers; whether 0x32725d0 runs on any particular node path; other releases.
- Not covered by the caller pass: `jmp [slot]`, `mov reg,[slot]` loads, and code outside the four scanned sections.

Next question: what does 0x32725d0 do on the tag-2 path at 0x3272a13, and which state.rs operation does line 66 name?
