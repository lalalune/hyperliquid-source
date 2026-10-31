# RE-009-D: what 0x37e2610 computes over the three lattices, and where it sits relative to the lt_hashes writer

- Component ID: RE-009-D-lattice-digest-94
- Target release and full SHA-256: artifacts/node/94/hl-node, 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Source commit / reference commit: main 1f8c67c63ca4794c9689235471c60297f8a5c985 (no source; binary-only)
- Claim status: observation for the byte-level facts (lane inputs, lengths, IV bytes, output layout, call order); inference for "BLAKE3-256" (structure, not symbols) and for reading the 16-byte trailers as two u64 counters.
- Scope included and excluded: included 0x37e2610 (whole function, 147 instructions to ret 0x37e2957), its two callers 0x326aec0 and 0x32fc190 (lattice copies through the writer call), the writer prefix 0x32699c0..0x3269a7b, the IV at 0x20c020 and four anchor instructions in the hasher bodies. Excluded: the hasher bodies beyond the anchors, the once-init routine, and the writer past its save call. Post-digest windows after 0x326af55 and 0x32fc224 are now in scope (bounded dead-digest negative: no consumer observed). Related packets #158, #262, #285 and #316 are cited; nothing is imported from them or from other tools/.

## Reproduce

Working directory: repo root. Python 3.13.5, stdlib only (no objdump needed by the tool). GNU objdump 2.44 (Debian) was used only to produce the quotes below.

```
python3 -B tools/lattice_digest.py --out research/work-items/RE-009-D-lattice-digest-94/lattice-digest.json
python3 -I -B research/work-items/RE-009-D-lattice-digest-94/verify.py
python3 -O -B research/work-items/RE-009-D-lattice-digest-94/verify.py
python3 -B research/work-items/RE-009-D-lattice-digest-94/independent_verify.py
python3 -B -m unittest tests.test_lattice_digest
for s in 0 7 99; do PYTHONHASHSEED=$s python3 -B tools/lattice_digest.py | sha256sum; done
```

Output: lattice-digest.json, sha256 53d36b84f3f5cca3821964e1670abdf38ff389d2b62a5b4e75d6f993f74860a0 (identical for seeds 0, 7, 99 and under -O). The tool reads only the binary, writes only --out (or stdout), and refuses to emit output unless every exact expectation in EXPECT holds.

## Evidence

All coordinates are VAs. Text maps file offset 0x1342c80 to VA 0x1343c80; low rodata VA equals file offset.

**Digest function 0x37e2610** (rdi = output struct, rsi = input; straight-line, 0 branches, 3 platform calls):

```
37e2621 mov r15,rsi              ; input
37e2624 mov rbx,rdi              ; output struct
37e2627 lea rax,[rsi+0x810]      ; lane1 base
37e2633 lea rax,[rsi+0x1020]     ; lane2 base
37e265f movups xmm1,[rip..]      ; IV[0:16] from 0x20c020 -> hasher cv (rsp+0x120)
37e266b movups xmm2,[rip..]      ; IV[16:32] from 0x20c030 -> rsp+0x130
37e26e0 movups xmm0,[r15+0x800]  ; lane0 trailer, kept aside, never passed to update
37e26f0 mov rbp,[0x57700c8]      ; update slot
37e26ff mov edx,0x800            ; length 0x800
37e2707 mov rsi,r15
37e270a call rbp                 ; update(hasher, lane0, 0x800)
37e270c mov r12,[0x57700d0]      ; finalize slot
37e2713 mov rdi,rsp
37e2719 call r12                 ; finalize -> 32 bytes at rsp
   ... lane1: 37e27e7 mov edx,0x800 / 37e27f4 call rbp / 37e27fc call r12, trailer 37e27cf [r15+0x1010]
   ... lane2: 37e28c7 mov edx,0x800 / 37e28d4 call rbp / 37e28dc call r12, trailer 37e28b2 [r15+0x1820]
37e2943 mov rax,rbx              ; returns the output struct
37e2957 ret
```

Output struct (0x90 bytes, every byte written exactly once, checked by the tool):

| Offset | Value | Store |
|---|---|---|
| +0x00, +0x10 | lane0 digest (32 bytes) | 37e2904, 37e2900 |
| +0x20 | lane0 input[0x800:0x810], copied, not hashed | 37e290f |
| +0x30, +0x40 | lane1 digest | 37e2923, 37e2927 |
| +0x50 | lane1 input[0x800:0x810], copied, not hashed | 37e2933 |
| +0x60, +0x70 | lane2 digest | 37e28ec, 37e28e8 |
| +0x80 | lane2 input[0x800:0x810], copied, not hashed | 37e293c |

Hashed input ranges are [0x0,0x800), [0x810,0x1010) and [0x1020,0x1820). The 16 bytes at +0x800 and +0x808 of each 0x810 lane are not hashed.

**Why BLAKE3 (structure, not symbols).** Names are stripped. The 32-byte IV at 0x20c020 is 67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b. Those are the SHA-256 initial words, which BLAKE3 reuses as its IV; the tool recomputes them from the square roots of the first eight primes. The update target compares the length against 0x401 (14f940d `cmp rax,0x401`) and uses a 0x400 chunk (14f9419 `mov r14d,0x400`). Finalize ORs in flag 8 (14fa048 `or al,0x8`), which is BLAKE3's ROOT flag. A 32-byte output from a 32-byte chaining value fits BLAKE3-256. SHA-256 uses 64-byte blocks and has no chunk or ROOT flags, so it does not fit this structure.

**Callers compute the digest before the writer.** Both test once flag 0x577ab98, copy 3 × 0x810 bytes from state+0xf8, +0xa00 and +0x1308 into contiguous stack buffers (stride 0x810), and call 0x37e2610 with rsi set to the first copy:

| Caller | State | Copies to | Digest out | Digest call | Writer call (rdi = state) |
|---|---|---|---|---|---|
| A 0x326aec0 | r15 | rsp+0x98/0x8a8/0x10b8 | rsp+0x8 | 326af55 | 326aff3 (326afea mov rdi,r15) |
| B 0x32fc190 | r12 | rsp+0x110/0x920/0x1130 | rsp+0x20 | 32fc224 | 32fc267 (32fc261 mov rdi,r12) |

Neither caller passes the digest struct to the writer.

**Negative: the digest is computed and discarded in both callers (no downstream consumer observed).**

Caller A (after 0x326af55): the tool's length scan of 0x326af5a..0x326b018 (50 instructions) finds zero accesses to rsp+0x8..0x97. The frame is freed at 0x326b006 (`add rsp,0x18c8`) and the function returns at 0x326b017. No read of the digest bytes is observed in this window.

Caller B (after 0x32fc224): the scan of 0x32fc229..0x32fc44e (125 instructions) finds three overwrite stores of a cap/ptr/len record into the first 32 bytes of the digest slot:
- 0x32fc33a `mov [rsp+0x38],rax`
- 0x32fc345 `movups [rsp+0x28],xmm0`
- 0x32fc34a `mov [rsp+0x20],r12`
Then 0x32fc3f1 `lea rsi,[rsp+0x20]` / 0x32fc414 `lea rdx,[rsp+0x20]` pass that record pointer into 0x332d440 and 0x3269ae0. The only subsequent read of the slot is 0x32fc429 `mov rdi,[rsp+0x28]` (the overwritten pointer, freed via [0x576e010]). No read of digest content at struct offsets >= 0x20 is observed in this window (see caveat). The frame is freed at 0x32fc43c (`add rsp,0x1948`).

Caveat: a later read of rsp+0x40..0xaf after 0x332d440 / 0x3269ae0 receive the record pointer is only possible, not observed. 0x3269ae0's opening uses only `[rdx+0x8]` / `[rdx+0x10]`, and only its first 0x180 bytes were read for this packet.

**The writer 0x32699c0 is caller-invariant.** It reads exactly rdi, rsi and rdx (rdi->rbx, rsi->[rsp+0x20], rdx->[rsp+0x28]). It hard-codes the path template 0x201e63 (`c00f` + "/lt_hashes.json"), copies state+0xf8, +0xa00 and +0x1308 with length 0x810, formats through slot 0x576e040 and saves through 0x3c16810 with record 0x56dfb28. No argument selects a format, and the same three state regions are written whichever caller runs it.

Analysis is complete over the ranges named in scope. It was not time-limited.

## Implementation and comparison

Not yet implemented. There is no independent Rust reimplementation, and no digest was compared against a reference BLAKE3 on live lattice data.

## Results and limitations

- Key VAs pinned: 101/101 PASS in independent_verify.py (95 prior + 6 post-digest pins: A frame free, B three overwrite stores, B header-free load, B frame free); packet-claim checks 0 errors.
- verify.py: errors=0 under -I -B and -O -B (lanes 3/3, fields 9/9, struct 0x90 written once, unhashed trailers 3/3, callers 2/2).
- Tamper tests: 101/101 single-byte flips at key VAs FAIL in independent_verify. The tool rejects key-VA flips plus 9/9 semantic tampers (including two no-consumer pins). 5/5 packet-claim edits are rejected (including two no-consumer claim edits).
- Limits:
  - The once-init routine is reached indirectly via 0x576e8b8 and was not traced.
  - The relocations for GOT slots 0x5770818 and 0x576dfe0 (memcpy-like) are not resolved.
  - The `c0 0f` prefix of the template is not decoded (probably the Rust fmt piece encoding).
  - Platform slot 0x57700c0 is called but not characterised.
  - The hasher bodies were checked only at the four anchors, so BLAKE3 is inferred, not proven by test vectors.
  - Reading the trailers as two u64 counters is inference.
  - The 0x3269ae0 caveat above: only the first 0x180 bytes of that function were read.

Next question: no consumer observed in the two callers' post-digest windows (bounded; see the 0x3269ae0 caveat). A remaining open is whether any other path materialises the same 0x90 layout, and the unchecked caveat on 0x3269ae0 beyond its first 0x180 bytes.

## Verifier transcript (this revision)

```
$ python3 -I -B research/work-items/RE-009-D-lattice-digest-94/verify.py
verify: lanes=3 update_len=0x800x3 fields=9 struct=0x90 unhashed_trailers=3 callers=2 writer_args=3 errors=0
$ python3 -I -B research/work-items/RE-009-D-lattice-digest-94/independent_verify.py
independent_verify: 101 key VAs: PASS=101 FAIL=0 INCONCLUSIVE=0; packet checks errors=0
$ python3 -B -m unittest tests.test_lattice_digest
Ran 8 tests in 0.791s
OK
```

- Tamper control: flipping `0x37e26ff` update-len bytes fails independent_verify (PASS=100 FAIL=1).
- Module tamper tests: 101/101 key-VA flips FAIL independent_verify and are rejected by the tool; 9/9 semantic tampers (including two no-consumer pins) rejected; 5/5 packet-claim edits (including two no-consumer claim edits) rejected.

## MANIFEST.sha256

Authoritative hashes are in `MANIFEST.sha256` beside this file (7 paths). Re-check with `sha256sum -c MANIFEST.sha256` from this directory.
