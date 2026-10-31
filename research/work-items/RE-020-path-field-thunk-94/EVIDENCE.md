# RE-020: path-field layout in FDE 0x22ae8a0 + GOT thunk 0x4546ba0

- Component ID: RE-020-path-field-thunk-94
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Source commit / reference commit: base origin/main 1f8c67c63ca4794c9689235471c60297f8a5c985. No reference source is used.
- Claim status: observation for the FDE extents, four ff15 sites, path-pointer load bytes, GOT RELATIVE, thunk body bytes, Location record and call census listed below.
- Scope included and excluded: included FDE 0x22ae8a0..0x22b1080 (sha256-pinned), the four ff15 sites through GOT 0x5773c70 and the path-pointer load immediately feeding each, FDE 0x4546ba0..0x4546c60 (sha256-pinned), the GOT RELATIVE addend, the thunk's rsi/rdx-preserving / rcx-injecting / rdi-redirecting prologue through the e8 to 0x3c155a0, Location 0x56dfc28, and a whole-section ff15+e8 census over .text/.init/.fini/.plt. Excluded: filenames/formats held in the path fields, writers of +0xd0/+0x140/+0x220, loader internals (RE-019), other GOT slots.

## Reproduce

```
python3 -I -B research/work-items/RE-020-path-field-thunk-94/verify.py
python3 -O -B research/work-items/RE-020-path-field-thunk-94/verify.py
python3 -B research/work-items/RE-020-path-field-thunk-94/independent_verify.py
python3 -B -m unittest tests.test_path_field_thunk
for s in 0 7 99; do PYTHONHASHSEED=$s python3 -B tools/path_field_thunk.py | sha256sum; done
python3 -O -B tools/path_field_thunk.py | sha256sum
```

Tool: Python 3 standard library only (no objdump, no pyelftools). Linux x86-64, working directory = repository root. No network, no execution of the target, no side effects; the tool reads the binary and writes only `--out` (or stdout).

Output: path-field-thunk.json (sha256 in MANIFEST). It is byte-identical for seeds 0, 7 and 99 and under -O. The tool emits nothing unless every exact expectation holds.

## Evidence

All coordinates are virtual addresses (VAs) mapped through the PT_LOAD program headers. Analysis is complete for the listed ranges; nothing timed out.

1. **FDE A.** `.eh_frame_hdr` gives 0x22ae8a0 the exclusive end 0x22b1080. Body sha256 = 50478e148269fa470c6dd5aae4856b72c729cf49f0c9f3b38cc755ed62fcb9c4 (10208 bytes).

2. **Four ff15 sites through GOT 0x5773c70** (each slot target re-derived as site+6+disp32):
   - 0x22aec0f `ff 15 5b 50 4c 03`. Path pointer: 0x22aebc6 `48 8b b5 d0 00 00 00` = `mov rsi,[rbp+0xd0]`; length 0x22aebcd `48 8b 95 d8 00 00 00`.
   - 0x22aee86 `ff 15 e4 4d 4c 03`. Path pointer: 0x22aee6e `48 8b b5 40 01 00 00` = `mov rsi,[rbp+0x140]`; length 0x22aee75 `48 8b 95 48 01 00 00`.
   - 0x22aef33 `ff 15 37 4d 4c 03`. Path pointer: 0x22aef22 `48 8b b5 20 02 00 00` = `mov rsi,[rbp+0x220]`.
   - 0x22afc2c `ff 15 3e 40 4c 03`. Path pointer: 0x22afc29 `4c 89 fe` = `mov rsi,r15` (r15 earlier filled from `[rbp+0xd0]` at 0x22afbf5).

3. **GOT.** Exactly one `.rela.dyn` RELATIVE at r_offset 0x5773c70, addend 0x4546ba0.

4. **FDE B (thunk).** `.eh_frame_hdr` gives 0x4546ba0 the exclusive end 0x4546c60. Body sha256 = a70030129ce619628e734791f5c998483c7b9f622bbf973432cf60253351add4 (192 bytes). Fixed bytes through the loader call:
   - 0x4546ba0 `41 57 41 56 53` push r15,r14,rbx
   - 0x4546ba5 `48 81 ec 00 10 00 00` sub rsp,0x1000
   - 0x4546bac `48 c7 04 24 00 00 00 00` mov qword [rsp],0
   - 0x4546bb4 `48 81 ec d0 0f 00 00` sub rsp,0xfd0
   - 0x4546bbb `48 89 fb` mov rbx,rdi (save caller out)
   - 0x4546bbe `48 8d 0d 63 90 19 01` lea rcx,[rip+] -> Location 0x56dfc28
   - 0x4546bc5 `48 8d 7c 24 08` lea rdi,[rsp+8] (local out)
   - 0x4546bca `e8 d1 e9 6c ff` call 0x3c155a0
   Between entry and the e8, no instruction writes rsi or rdx: the thunk preserves the caller's path pointer/length and only injects rcx + redirects rdi.

5. **Location.** 0x56dfc28: RELATIVE addend 0x1dd8eb; length 49; line 86; column 40; path `/home/ubuntu/hl/code_Mainnet/l1/src/abci/state.rs`.

6. **Census.** Every byte offset of .text/.init/.fini/.plt tried as `ff15` (slot = site+6+disp32) and `e8` (target = site+5+disp32):
   - `ff15` through 0x5773c70: **exactly 4** — the sites above, all inside FDE A.
   - `e8` to 0x4546ba0: **exactly 0** (GOT-only entry).

## Overlap

- RE-019 pins 0x4546bca as one of three e8 callers of the loader 0x3c155a0 and notes its FDE start 0x4546ba0; it does not pin the GOT slot, the four ff15 sites, the path-field offsets, or the thunk's rsi/rdx-preserving ABI.
- RE-012 / open #170 inventories FDE ranges including 0x22ae8a0 and 0x4546ba0; it does not pin the four path sources or the thunk census.
- Merged #8 / #23 mention 0x22ae8a0 / 0x4546ba0 as Location-bearing FDEs or an action-field state machine; different claims.
- GOT 0x5773c70 appears in no open or merged PR diff at build time.

## Results and limitations

- Pinned: 4/4 ff15 sites; 26/26 key instructions; 2/2 extent hashes; 1/1 GOT RELATIVE; 1/1 Location; 0 e8-direct; path-pointer sources as above.
- Not claimed: filenames/formats in the path fields; writers of +0xd0/+0x140/+0x220; loader behaviour (RE-019); other releases.
