# RE-016: the GOT-indirect chain [0x5773aa8] -> 0x3751e80 -> 0x3270570 -> [0x5775580] -> 0x326e460 in node #94

- Component ID: RE-016-state-chain-94
- Target release and full SHA-256: artifacts/node/94/hl-node, 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Source commit / reference commit: main 1f8c67c63ca4794c9689235471c60297f8a5c985 (no source; binary-only)
- Claim status: observation for the relocations, call sites, call targets, branch counts and output-buffer copies listed below. The role of 0x3751e80 is not proven by any string or named caller; see limitations.
- Scope included and excluded: included the two .rela.dyn entries for GOT slots 0x5773aa8 and 0x5775580 (plus their +-8 neighbours), one whole-section caller pass over .text/.init/.fini/.plt, and three whole function extents decoded linearly to their ret: 0x3751e80..0x37529b5 (448 instructions), 0x3270570..0x32707b3 (112) and 0x326e460..0x326e50d (44). Excluded: the internals of every callee (0x37d08a0, 0x332d440, 0x37d4e30, 0x3269ae0), the field meaning of any copied block, and the behaviour of the six indirect call sites that load slot 0x5773aa8 (their locations are proven, their roles are not). #316 (LtHash writer, which already reports 0x326e460 as reachable only through the relocation at 0x5775580), #262 (LtHash top function 0x3269ae0) and #271 (lists 0x3751e80 as a lead for exchange +0x3a00) are cited. This packet does not claim their ground and imports nothing from them or from other tools/.

## Reproduce

Working directory: repo root. Python 3.13.5, stdlib only. The tool does not need objdump. GNU objdump 2.44 (Debian) was used only to produce the quotes below.

```
python3 -B tools/state_chain.py --out research/work-items/RE-016-state-chain-94/state-chain.json
python3 -I -B research/work-items/RE-016-state-chain-94/verify.py
python3 -O -B research/work-items/RE-016-state-chain-94/verify.py
python3 -B research/work-items/RE-016-state-chain-94/independent_verify.py
python3 -B -m unittest tests.test_state_chain
for s in 0 7 99; do PYTHONHASHSEED=$s python3 -B tools/state_chain.py | sha256sum; done
```

Output: state-chain.json, sha256 6e063821c3de3ad62dc45b0af1bc28ff7cdedaf048da0fbdd3cc5e51cabead75. It is byte-identical for seeds 0, 7 and 99 and under -O. The tool reads only the binary and writes only --out (or stdout). It emits nothing unless every exact expectation in EXPECT holds. File hashes are in MANIFEST.sha256.

## Evidence

All coordinates are VAs. Text maps file offset 0x1342c80 to VA 0x1343c80. .rela.dyn is at file offset 0x6bc0, size 0x1d4e10 (80022 entries of 24 bytes). .got spans 0x576df80..0x5778d88, and both slots lie inside it.

**Relocations** (bounded .rela.dyn parse):

| r_offset | type | sym | addend | other entries with this addend |
|---|---|---|---|---|
| 0x5773aa8 | 8 (R_X86_64_RELATIVE) | 0 | 0x3751e80 | none |
| 0x5775580 | 8 (R_X86_64_RELATIVE) | 0 | 0x326e460 | none |

Neighbours: 0x5773aa0 -> 0x4f94140, 0x5773ab0 -> 0x4743490, 0x5775578 -> 0x4f93d90, 0x5775588 -> 0x4e35e80.

**0x3751e80** (0 branches to its ret at 0x37529b5; r14 = entry rdi):

```
3751eb8:  4989fe              mov    r14,rdi
375220d:  488dbc2450050000    lea    rdi,[rsp+0x550]
3752215:  488b742408          mov    rsi,QWORD PTR [rsp+0x8]
375221a:  4889ea              mov    rdx,rbp
375221d:  4c89e9              mov    rcx,r13
3752220:  e84be3b1ff          call   3270570
3752287:  4c8b3d52bd0102      mov    r15,QWORD PTR [rip+0x201bd52]   # 576dfe0
375285e:  498dbec00b0000      lea    rdi,[r14+0xbc0]
3752865:  488db42450050000    lea    rsi,[rsp+0x550]
375286d:  bae8250000          mov    edx,0x25e8
3752872:  41ffd7              call   r15
37529a1:  4c89f0              mov    rax,r14
37529b5:  c3                  ret
```

Its only rel32 call is 0x3752220 -> 0x3270570. Its other calls all go through the memcpy slot 0x576dfe0: one direct call at 0x3751fb7 and six through r15. Their lengths are 0x298, 0xf0, 0x148, 0x298, 0x90, 0x8f8 and 0x25e8. After the call, the 0x25e8-byte block that 0x3270570 wrote at rsp+0x550 is copied to out+0xbc0.

**0x3270570** (0 branches to its ret at 0x32707b3; rbx = entry rdi):

```
32705ac:  4889fb              mov    rbx,rdi
327066d:  488dbc24700a0000    lea    rdi,[rsp+0xa70]
3270675:  4889ee              mov    rsi,rbp
3270678:  488b542430          mov    rdx,QWORD PTR [rsp+0x30]
327067d:  488b4c2438          mov    rcx,QWORD PTR [rsp+0x38]
3270682:  ff15f84e5002       call   QWORD PTR [rip+0x2504ef8]       # 5775580
327074e:  488db424700a0000    lea    rsi,[rsp+0xa70]
3270756:  ba381b0000          mov    edx,0x1b38
327075b:  4889df              mov    rdi,rbx
327075e:  ffd5                call   rbp                              # rbp = [0x576dfe0] at 32706a5
327079f:  4889d8              mov    rax,rbx
```

The call at 0x3270682 is RIP-relative with no index register, so it always goes through slot 0x5775580. It is the function's only non-register call. Its out buffer (rsp+0xa70) is copied 0x1b38 bytes into the entry rdi object.

**0x326e460** (one branch, the `je 0x326e4fe` at 0x326e4f0 that skips the free; no branch before the copy):

```
326e47b:  4889d3              mov    rbx,rdx
326e47e:  4989f7              mov    r15,rsi
326e481:  4989fe              mov    r14,rdi
326e48a:  e811245600          call   37d08a0
326e49f:  e89cef0b00          call   332d440
326e4ab:  e880695600          call   37d4e30
326e4b0:  488d7c2460          lea    rdi,[rsp+0x60]
326e4bb:  e820b6ffff          call   3269ae0                          # top LtHash fn (#262/#316)
326e4c0:  498b4710            mov    rax,QWORD PTR [r15+0x10]
326e4c4:  498986301b0000      mov    QWORD PTR [r14+0x1b30],rax
326e4cb:  410f1007            movups xmm0,XMMWORD PTR [r15]
326e4cf:  410f1186201b0000    movups XMMWORD PTR [r14+0x1b20],xmm0
326e4d7:  488d742460          lea    rsi,[rsp+0x60]
326e4dc:  ba201b0000          mov    edx,0x1b20
326e4e1:  4c89f7              mov    rdi,r14
326e4e4:  ff15f6fa4f02        call   QWORD PTR [rip+0x24ffaf6]        # 576dfe0 (memcpy)
326e4f0:  740c                je     326e4fe
326e4f8:  ff1512fb4f02        call   QWORD PTR [rip+0x24ffb12]        # 576e010 (free)
326e4fe:  4c89f0              mov    rax,r14
```

The 0x3269ae0 result buffer (rsp+0x60) is copied 0x1b20 bytes to out+0. Then 0x18 bytes from rsi are copied to out+0x1b20..0x1b38. So 0x326e460 writes 0x1b38 bytes, which is exactly the length 0x3270570 copies out of the buffer it passes. That is an observation about lengths; it says nothing about layout meaning.

**Strings:** none of the three extents contains a RIP-relative lea (the JSON pins `rip_lea_targets` as empty for each). The chain therefore references no .rodata literal.

## Implementation and comparison

Not yet implemented. There is no Rust path and nothing is compared.

## Results and limitations

- Proven, from bytes: 2 of 2 relocations (type 8, sym 0, unique addend in 80022 entries); 5 of 5 chain edges; 3 of 3 output-buffer copies (0x1b20, 0x1b38, 0x25e8); branch counts 0/0/1 over 448/112/44 instructions; 4 of 4 rel32 calls in 0x326e460.
- Proven by this packet's caller pass (`caller_scan` in state-chain.json, re-derived by independent_verify.py): every byte offset of .text, .init, .fini and .plt is tried as `e8` rel32 (target = site+5+disp32) and as `ff15` RIP slot (target = site+6+disp32). Because this is a superset of the aligned instructions, the zero counts are upper bounds. Exact pinned counts: rel32 sites targeting 0x3751e80 = 0, targeting 0x326e460 = 0, targeting 0x3270570 = 1 (0x3752220, inside 0x3751e80); `ff15` sites through slot 0x5773aa8 = 6 (0x226685a, 0x2268f61, 0x3273920, 0x4359d34, 0x4746097, 0x4b2c8e2); through slot 0x5775580 = 1 (0x3270682). All counts match the earlier scan; none differed. The caller of 0x3751e80 is therefore not unique. Not covered: `jmp`/`mov reg,[slot]` loads of either slot, and calls from code outside these four sections.
- Inferred, not proven: that 0x3751e80 is a state materializer / exporter. No string literal and no named caller supports "snapshot" or "export".
- Not claimed: what 0x37d08a0, 0x332d440, 0x37d4e30 or 0x3269ae0 compute; what any copied field means; what the six indirect callers do; other releases.

Next question: which of the six `ff15 [0x5773aa8]` sites runs on a snapshot or export path, and does any of them sit next to a string that names it?
