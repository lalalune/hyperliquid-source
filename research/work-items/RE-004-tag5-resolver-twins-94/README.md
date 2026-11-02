# RE-004: tag-5 resolver twins (node #94)

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94,
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Worktree baseline: HEAD 2993e46 (upstream sync forbidden for this run)
- Source commit / reference commit: n/a — no reference-tree claim is made
- Claim status: observation for the twin FDE bounds, decode sites,
  tag/header compares, vector-compare idiom and constants, transform
  call sites, copy/tail bytes, and window digests; inference for the
  routing model (faithful translation of the twin instruction streams)
  and for the untouched-range claim (full manual read of both twin
  disassemblies, pinned by the full-FDE digests); unresolved items are
  listed under Results and limitations
- Scope included: the two tag-5 resolver functions (twin-A `0x2788350`,
  twin-B `0x2788500`), their shared decode → tag → header → vector
  skeleton, the twin-difference (twin-B's post-transform tag check and
  second transform), the decoder-caller census, and the 9-case routing
  model
- Scope excluded: the decoder bodies (`0x2787460`, `0x2786dd0`), the
  transform callees (`0x1e6af40`, `0x37d13c0`, `0x324a070`), the
  cleanup callees (`0x2781760`, `0x26b0730`), the unwind landing pads
  after each twin's main `ret`, the 16 decoder-call sites in 6 larger
  functions (census only), the wider purpose of the tagged-value
  family, and node #115

## Reproduce

Platform: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (`-d -M intel`).
Run from the repository root. The binary is read and disassembled, never executed.

```
python3 tools/artifacts.py verify
python3 tools/tag5_resolver_twins94.py --out research/work-items/RE-004-tag5-resolver-twins-94
python3 -m unittest discover -s tests -p 'test_tag5_resolver_twins94.py'
(cd research/work-items/RE-004-tag5-resolver-twins-94 && sha256sum -c MANIFEST.sha256)
objdump -d -M intel --start-address=0x2788350 --stop-address=0x2788499 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x2788500 --stop-address=0x27886b3 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x2788350 --stop-address=0x2788499 artifacts/node/94/hl-node | grep -oE 'r14\+0x[0-9a-f]+' | sort | uniq -c
objdump -d -M intel --start-address=0x2788500 --stop-address=0x27886b3 artifacts/node/94/hl-node | grep -oE 'r14\+0x[0-9a-f]+' | sort | uniq -c
```

The tool checks the input SHA-256 first and fails on a mismatch. It takes
about 20 seconds (the E8/E9 census scans walk .text).
Outputs: `evidence.json`, `sites.tsv`, `cases.tsv` and `windows.txt`.

## Evidence

Coordinates are ELF virtual addresses. The #162 packet mapped twelve
tag-dispatch wrappers that call the mul256 difference writers only when
a decoded tag byte is 5. These two functions are the other small direct
consumers of the same two decoders: instead of dispatching on the tag,
they resolve a tag-5 decoded value in place.

**Boundaries.** The FDE bounds come from the binary's own unwind index
(via the repository shared ELF parser); the twin bodies are hashed in
`evidence.json` and `windows.txt`. FDE bounds are unwind-described
ranges, not validated function boundaries. Each twin's FDE contains
unwind landing pads after its main `ret` (twin-A `0x278849a..0x27884f5`,
twin-B `0x27886b4..0x278870f`, cleanup plus `_Unwind_Resume`); behavior
claims cover the main bodies only (`0x2788350..0x2788499`,
`0x2788500..0x27886b3`).

| Twin | FDE | Length | Main body | Decoder | Decode site | SHA-256 (FDE window) |
| --- | --- | --- | --- | --- | --- | --- |
| twin-A | 0x2788350..0x27884f5 | 421 | 0x2788350..0x2788499 | 0x2787460 | 0x2788366 | 95e6e17834b24e0394a2f1395986d2660ed44c97a25c8233358527f362e124f4 |
| twin-B | 0x2788500..0x278870f | 527 | 0x2788500..0x27886b3 | 0x2786dd0 | 0x2788516 | adfa83aad4c417e53d2573ec2a034c3aac90b5c1f256b319e8503c9e88d7c519 |

**Decoder-caller census (observation, re-derived by the tool from an
E8 rel32 scan of `.text`, with an E9 scan confirming no tail-jump
caller for either decoder).** The two decoders have exactly 30 direct
callers: 15 each. Twelve are the #162 wrappers (6 per decoder), two are
these twins, and sixteen sit in six larger functions (0x2788710,
0x2789db0, 0x278b410, 0x278bdb0, 0x278c750, 0x278d520) — census only, no
behavior claimed for them.

**The shared skeleton (observation, byte-anchored in both twins).**
Each twin decodes a value into `[rsp]` (tag byte at `[rsp]`, object
pointer at `[rsp+0x8]`, byte at `[rsp+0x10]`), then:

```
movzx eax, BYTE PTR [rsp]        ; tag
cmp   al, 0x5
jne   copy-path                  ; tag != 5: verbatim copy to [rbx]
mov   r14, QWORD PTR [rsp+0x8]   ; object
movzx ebp, BYTE PTR [rsp+0x10]
cmp   DWORD PTR [r14], 0x4       ; header gate
jne   tail                       ; header != 4: return tag-5 as-is
movdqu xmm0, [r14+0x68]
movdqu xmm1, [r14+0x78]
pcmpeqb xmm1, [0x204be0]         ; high constant
pcmpeqb xmm0, [0x206160]         ; low constant
pand   xmm0, xmm1
pmovmskb eax, xmm0
cmp   eax, 0xffff
je    match-path                 ; all 32 bytes equal
; non-match path: transform callee rewrites [r14+0x0..0x40]
tail:
mov   QWORD PTR [rbx+0x8], r14
mov   BYTE PTR [rbx+0x10], bpl
mov   BYTE PTR [rbx], 0x5
```

The tag != 5 copy block (51 bytes) is byte-identical between the
twins, as is the match-path copy block; the vector-compare blocks are
identical modulo rip-relative displacement bytes (same instruction
sequence, same constant targets); the tails are identical modulo the
stack-restore immediate (`add rsp,0x78` vs `add rsp,0xa8`, matching
the frame sizes). The generator asserts all of these identities.

**Vector constants (observation).** The high constant at `0x204be0`
is `e500b653ca82273b7bfad8045d85a470` and the low constant at
`0x206160` is `c5d2460186f7233c927e7db2dcc703c0`. They are arbitrary
16-byte patterns (not zeros, not ones): the match test is an exact
32-byte equality test, not a zero/one check.

**Match path (observation).** On a full match, the twin calls
`0x26b0730` with the decoded buffer, then writes `1` as a QWORD at
`[r14]` and copies the decoded `[rsp+0x0..0x30]` to
`[r14+0x8..0x38]`. A `0x2781760` cleanup call sits on the
header != 4 sub-branch before the overwrite; under the entry-gate
invariant it does not fire on this path (see Limitations).

**Non-match path, twin difference (observation).** Twin-A copies the
object vectors to `[rsp+0x0..0x20]` and calls `0x1e6af40`
(`rdi` = `[rsp+0x38]` output, `rsi` = the twin's `rcx` input,
`rdx` = `[rsp]` vectors), then copies `[rsp+0x38..0x78]` to
`[r14+0x0..0x40]`. Twin-B copies the vectors to `[rsp+0x80..0xa0]`
and calls `0x37d13c0` (`rdi` = `[rsp]` output, `rsi` = `rcx+0x928`,
`rdx` = `[rsp+0x80]` vectors), then checks the transform output's
first DWORD: if it equals 4 it calls `0x324a070`
(`rdi` = `[rsp+0x48]`) and writes `1` at `[rsp+0x40]`, and the
`[rsp+0x40..0x80]` block goes to `[r14+0x0..0x40]`; otherwise the
transform output block `[rsp+0x0..0x40]` is first copied to
`[rsp+0x40..0x80]` and then to `[r14+0x0..0x40]`. Twin-A has no
post-transform tag check.

**Untouched ranges (observation, full manual read of both twin
disassemblies).** Across all paths in both twins, the object
(`r14`) is touched only at `[r14]` (header), `[r14+0x8..0x38]`
(match copy), `[r14+0x0..0x40]` (transform overwrite),
`[r14+0x68]` and `[r14+0x78]` (vector reads). In particular neither
twin reads or writes the #161 difference field `[obj+0x40..0x58]`,
the counter `[obj+0x60]`, or the flag `[obj+0xb0]`. The two `grep`
commands under Reproduce re-derive the touched-offset set from the
disassembly. The full-FDE digests pin the bodies byte for byte, so any
additional object access would break regeneration.

## Inferences

- **The twins resolve tag-5 values; they do not consume the #161
  difference output.** Because neither twin touches `[obj+0x40..0x58]`,
  the collapsed-0-vs-genuine-0 question (#162's open question) is not
  answered here: no twin output varies with the difference value.
  That question remains open, and these twins are not its answer.
- **The match test is a sentinel-equality gate, not a value check.**
  The object vectors must equal two fixed constants exactly; any
  single differing byte routes to the transform path. The match path
  then marks the object (`[r14] = 1`) and installs the decoded value,
  which reads as "already in canonical form, adopt it".
- **Twin-B's extra check makes its transform two-stage.** Only twin-B
  inspects its transform output's tag (4 vs other) and routes to a
  second transform; twin-A applies its single transform
  unconditionally. The twins are therefore not interchangeable: same
  skeleton, different non-match semantics.
- **Transform outputs are opaque to this packet.** The transform
  callees' bodies are out of scope, so cases R7–R9 assert routing and
  overwrite extents (`[obj+0x0..0x40]`, plus `[obj+0x0] = 1` on the
  twin-B tag-4 sub-path) with the transform result as an
  uninterpreted value — not what the transform computes.

## Results and limitations

- The routing model is a faithful translation of the twin instruction
  streams, verified anchor by anchor; it is not an execution of the
  node binary, which this task forbids.
- The model conditions on the entry-gate invariant: once the header
  gate passes (`[r14] == 4`), the header is assumed unchanged by the
  intervening callees, so the later cleanup sub-branches (which fire
  only when `[r14] != 4`) do not fire on the claimed paths. The
  callee bodies are out of scope, so a callee that rewrote the header
  would break this; nothing in the claimed twin stream does.
- The untouched-range claim rests on a full manual read of both twin
  disassemblies (reproducible with the `grep` commands above) plus
  byte-exact FDE digests; the generator itself checks anchors and
  digests, not a decoded instruction stream.
- Out of scope, by precondition, not by oversight: the decoder bodies,
  the transform and cleanup callee bodies, the 16 big-function decoder
  call sites (census only), the wider purpose of the tagged-value
  family, whether the sentinel vectors ever occur in real executions,
  and node #115.

## Next question

- Do the sentinel vectors (`0x204be0`/`0x206160` patterns) ever occur
  in the objects these twins process in practice — i.e. is the match
  path live or only reachable? And who writes the `[obj+0x68..0x88]`
  vectors in the first place (the producers behind the match test)?
