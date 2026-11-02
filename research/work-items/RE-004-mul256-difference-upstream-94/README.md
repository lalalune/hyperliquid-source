# RE-004: direct upstream callers of the mul256 difference writers (node #94)

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94,
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Worktree baseline: HEAD 2993e46 (upstream sync forbidden for this run)
- Source commit / reference commit: n/a — no reference-tree claim is made
- Claim status: observation for the call sites, wrapper FDE bounds,
  tag compare, branch, argument setup, call, post-call jump and
  tag-store/return tail bytes, window digests, and the decoder split;
  inference for the wrapper outcome model; unresolved items are listed
  under Results and limitations
- Scope included: the twelve direct E8 call sites of caller-A
  (`0x279d0c0`) and caller-B (`0x279d3e0`) from the #161 packet, their
  enclosing wrapper FDEs, the tag-5 dispatch idiom, the post-call
  observable behavior, and the 11-case wrapper outcome model
- Scope excluded: the #160 mul256 helper inner loops, the #161
  caller-A/B sentinel chains themselves (reused only as the difference
  input), the decoder bodies (`0x2787460`, `0x2786dd0`), the wider
  purpose and operand provenance of the wrapper objects, indirect
  callers (none found by direct-call scan; see limitations), later
  readers of the mutated object, and node #115

## Reproduce

Platform: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (`-d -M intel`).
Run from the repository root. The binary is read and disassembled, never executed.

```
python3 tools/artifacts.py verify
python3 tools/mul256_difference_upstream94.py --out research/work-items/RE-004-mul256-difference-upstream-94
python3 -m unittest discover -s tests -p 'test_mul256_difference_upstream94.py'
(cd research/work-items/RE-004-mul256-difference-upstream-94 && sha256sum -c MANIFEST.sha256)
objdump -d -M intel --start-address=0x276e340 --stop-address=0x276e3e0 artifacts/node/94/hl-node
```

The tool checks the input SHA-256 first and fails on a mismatch. It takes
about 20 seconds (the E8/E9 census scans walk .text).
Outputs: `evidence.json`, `sites.tsv`, `cases.tsv` and `windows.txt`.

## Evidence

Coordinates are ELF virtual addresses. The #161 packet proved that a
helper-1 false positive collapses caller-A/B results to exactly 0 and
left open whether any upstream caller distinguishes that collapsed 0
from a genuine 0 difference. This packet answers that question for the
direct callers: none of them does — none of them even looks.

**Boundaries.** The FDE bounds come from the binary's own unwind index
(via the repository shared ELF parser); the wrapper bodies are hashed in
`evidence.json` and `windows.txt`. FDE bounds are unwind-described
ranges, not validated function boundaries. All twelve wrappers are
exactly 160 bytes long.

| Call site | Wrapper FDE | Callee | Decoder |
| --- | --- | --- | --- |
| 0x276e398 | 0x276e340..0x276e3e0 | caller-A | 0x2787460 |
| 0x276e508 | 0x276e4b0..0x276e550 | caller-A | 0x2786dd0 |
| 0x2771b58 | 0x2771b00..0x2771ba0 | caller-A | 0x2787460 |
| 0x2772838 | 0x27727e0..0x2772880 | caller-A | 0x2786dd0 |
| 0x2777878 | 0x2777820..0x27778c0 | caller-A | 0x2786dd0 |
| 0x2778768 | 0x2778710..0x27787b0 | caller-A | 0x2787460 |
| 0x276d638 | 0x276d5e0..0x276d680 | caller-B | 0x2786dd0 |
| 0x276da58 | 0x276da00..0x276daa0 | caller-B | 0x2787460 |
| 0x2770ce8 | 0x2770c90..0x2770d30 | caller-B | 0x2786dd0 |
| 0x2770dd8 | 0x2770d80..0x2770e20 | caller-B | 0x2787460 |
| 0x2776908 | 0x27768b0..0x2776950 | caller-B | 0x2787460 |
| 0x2776e78 | 0x2776e20..0x2776ec0 | caller-B | 0x2786dd0 |

**Census (observation, re-derived by the tool from an E8 rel32 scan of
`.text`).** Exactly six direct calls target caller-A and exactly six
target caller-B; the scan finds no others, and an E9 rel32 scan finds
no tail-jump caller for either target. The twelve wrappers split
evenly across the two decoders (six sites each); decoder identity does
not change the wrapper idiom.

**The wrapper idiom (observation, byte-anchored at all twelve sites).**
Each wrapper decodes a value into `[rsp]` (tag byte at `[rsp]`,
object pointer at `[rsp+0x8]`), then:

```
movzx ebp, BYTE PTR [rsp]        ; tag
cmp   bpl, 0x5
jne   copy-path                  ; tag != 5: copy decoded fields to [rbx+...]
mov   rdi, QWORD PTR [rsp+0x8]   ; mutated object
mov   rsi, QWORD PTR [r14+0xd8]  ; context sub-object
call  caller-A / caller-B
jmp   tag-store                  ; eb 31, identical at all twelve sites
copy-path:
  ... copy [rsp+0x1..0x18] fields to [rbx+0x1..0x18] ...
tag-store:
mov   BYTE PTR [rbx], bpl
mov   rax, rbx
add   rsp, 0x40
pop   rbx / r14 / rbp
ret
```

The post-call path is exactly `jmp tag-store; mov [rbx],bpl; mov
rax,rbx; add rsp,0x40; pops; ret`. It contains no load from the
mutated object (`[rdi+0x40..0x58]`), no read of its counter
(`[rdi+0x60]`), and no read of its flag byte (`[rdi+0xb0]`), and no
comparison of the mutated-object pointer against `rbx`. The wrapper's
return value is `rbx` unconditionally; the mutated object is a
different object reached through the decoded value, and the wrapper
never re-reads it.

**Caller-A/B side effects (observation, from #161).** On the tag-5
path, caller-A/B overwrite the mutated object's stored field with the
difference (or 0 on collapse), bump its counter at `[rbx+0x60]`
(increment, -1 on wrap) only when the state byte at `[r14+0x294]` is
1, and set bit 0x4 at `[rbx+0xb0]` unconditionally. None of these
three side effects depends on whether the stored 0 came from a
collapse or from a genuine 0 difference.

## Inferences

- **At all twelve direct upstream sites, collapsed 0 and genuine 0
  are indistinguishable.** Case W5 (caller-A, genuine difference 0)
  and case W6 (caller-A, collapsed 0 from #161's A2 shape) produce
  byte-identical wrapper-observable outputs: return object `tag-only`,
  mutated stored field 0, same counter, same flag. The same identity
  holds at caller-B (W8 vs W9). The wrapper cannot tell them apart
  because it never inspects the result it just caused to be written.
- **The collapse is latent at this layer, not visible.** The
  wrapper's own return object is `tag-only` on every tag-5 path
  regardless of the difference value, so no wrapper output varies
  with the collapse. The collapsed 0 survives only inside the
  mutated object, for whatever later reader touches that object.
- **The counter and flag channels do not leak the collapse either.**
  The counter bump depends only on the state byte (case W10 wraps
  to -1 identically for genuine and collapsed paths), and the flag
  bit is set unconditionally on the tag-5 path.
- **Tag boundaries are exact.** Tags 4 and 6 (cases W2, W3) take the
  copy path and never touch the mutated object; only tag 5 selects
  the difference path. A mis-tagged value cannot accidentally
  trigger the collapse path, and a tag-5 value cannot accidentally
  take the copy path.

## Results and limitations

- The wrapper outcome model takes the caller-A/B difference as an
  input; it does not re-derive the helper behavior or the sentinel
  chains (#160/#161 establish those). The model is a faithful
  translation of the wrapper instruction stream, not an execution of
  the node binary, which this task forbids.
- The census covers direct E8 calls and E9 tail jumps in `.text`.
  Indirect callers (function pointers, vtables, PLT) would not appear
  in either scan; no evidence of such a caller was found, but the
  scan alone cannot exclude one.
- Whether the mutated-object pointer (`[rsp+0x8]`) can alias the
  wrapper's own return object (`rbx`) is a property of the wrappers'
  own callers, not of the wrapper code, which contains no such
  comparison; it is out of scope here.
- Out of scope, by precondition, not by oversight: the decoder
  bodies, the wrapper objects' wider purpose, the provenance of the
  helper inputs (whether multi-limb values can actually reach the
  helper-1 sites — #161's second open question, still open), and
  node #115.

## Next question

- Who reads the mutated object after these wrappers return, and does
  any later reader treat a stored 0 as "no change" (which would make
  the #161 collapse user-visible) versus as an ordinary value? That
  decides whether the collapse is live or permanently latent. The
  second half of #161's question — whether multi-limb helper inputs
  can reach the helper-1 sites at all — remains open alongside it.
