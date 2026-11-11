# RE-006 node 115: who calls the gate family's third inner body and the mirror triple

PR #2608 pinned the gate callee behind slot `0x64e71b8` and the
six inner bodies that carry its six-site pattern — two clone
triples — but could name callers only for the first triple's
first two bodies, the ones PR #2605 packeted: `0x2bbbba0`
(inner_ca) is called three times by the sub-lookup `0x2bb7270`
and `0x2bbd0b0` (inner_s3) three times by the helper `0x2c62820`
(the caller map PR #2598 also recorded). This packet answers
#2608's open edge 2: the caller census of the third body
`0x2bbc750` (inner_c750) and of the whole `0x549xxxx` mirror
triple (`0x5493080` / `0x5493c30` / `0x5494720`), with the two
known bodies censused as controls. It also pins, for every call
site, where the callee's table argument (`rcx`, the argument
each inner body frame-saves and forwards as the gate's `r8`)
comes from — the first fixed rung of #2608's open edge 1, the
producer of the gate's table.

Headline answers:

- **The mirror pair members behave exactly like the first
  triple's packeted bodies.** `0x5493080` (inner_fam_b1) has
  exactly one caller, the mirror sub-lookup `0x55defd0`, three
  sites; `0x5493c30` (inner_fam_b2) has exactly one caller, the
  mirror helper `0x55e16d0` (the helper clone of #2598), three
  sites. At all six sites the table argument is reloaded from a
  single frame slot of the caller (`[rsp+0x68]` / `[rsp+0x60]`),
  the same shape as the controls (`[rsp+0x88]` in `0x2bb7270`,
  `[rsp+0x60]` in `0x2c62820`).
- **The two `rbx`-element bodies are called from much wider
  sets.** inner_c750: 9 sites in 6 FDEs. inner_fam_b3: 14 sites
  in 9 FDEs. Their caller sets are mirror-shaped but not
  identical — the same-size pair `0x2bba100` / `0x548f430`
  (3,191 B each, two sites each, first site forwarding the
  caller's `r8` as the table argument, second reloading
  `[rsp]`-frame state), two 86-byte shims (`0x2bbbb40` /
  `0x5493020`) that shuffle the argument registers
  (`rdi→rsi`, `rsi→rdx`, `rdx→rcx`, `rsp→rdi`, `r8=0`) and call
  once, and a set of small wrappers and large bodies the other
  family members never see.
- **Six sites pass the table as a context-embedded pointer**:
  `rcx = lea [ctx+0x90]` (the caller's `r14` or `rbx` context),
  the same embedded-table form #2608 found at the branchless
  gate sites. The repeat sites inside the three large caller
  FDEs (`0x2bdf8f0`, `0x54a9c70`, `0x54b66b0`) reload a
  frame-saved table pointer instead (`[rsp+0x58]` /
  `[rsp+0x40]` / `[rsp+0x48]`).
- **Exact negatives**: no E9 jump, no rip-relative `lea` or
  load, no GOT-slot reference and no `R_X86_64_RELATIVE`
  addend names any of the six bodies anywhere in the binary.
  Every one of the 35 validated sites is a direct E8 call, and
  every raw E8 candidate validated — the raw superset scan
  produced zero false positives and zero references of any
  other kind.

Target artifact: HL node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(105,896,032 bytes). Every address below is a virtual address in
that artifact; every body is pinned by FDE extent and SHA-256
digest (the six family bodies' digests agree with #2608's frozen
pins, recomputed independently here), and every file offset is
resolved through the section table (`.rodata` identity-mapped,
`.text` delta `0x1000`, `.data.rel.ro` delta `0x2000`).

## The caller map

inner_c750 (`0x2bbc750..0x2bbd0a3`, 2,387 B) — 9 sites, 6 caller
FDEs:

| caller FDE | size | sites | table argument (`rcx`) |
| --- | --- | --- | --- |
| `0x2a8a000` | 851 B | `0x2a8a054` | `lea 0x90(%r14)` — context-embedded |
| `0x2a8a360` | 658 B | `0x2a8a483` | caller's `r15` |
| `0x2bb98a0` | 2,133 B | `0x2bb9f7f` | caller's `r12` |
| `0x2bba100` | 3,191 B | `0x2bba400`, `0x2bba847` | caller's `r8`, then `r12` |
| `0x2bbbb40` | 86 B | `0x2bbbb53` | shim: caller's `rdx` |
| `0x2bdf8f0` | 45,233 B | `0x2be7e17`, `0x2be8b84`, `0x2be9991` | `lea 0x90(%rbx)`, then `[rsp+0x58]` twice |

inner_fam_b1 (`0x5493080..0x5493c2d`, 2,989 B) — 3 sites, 1
caller FDE: `0x55defd0` (6,906 B) at `0x55dfb48`, `0x55dff4d`,
`0x55e10b9`; table argument `[rsp+0x68]` at all three.

inner_fam_b2 (`0x5493c30..0x549471a`, 2,794 B) — 3 sites, 1
caller FDE: `0x55e16d0` (8,338 B, the #2598 helper clone) at
`0x55e1eb8`, `0x55e2446`, `0x55e33d2`; table argument
`[rsp+0x60]` at all three.

inner_fam_b3 (`0x5494720..0x5495073`, 2,387 B) — 14 sites, 9
caller FDEs:

| caller FDE | size | sites | table argument (`rcx`) |
| --- | --- | --- | --- |
| `0x548ebd0` | 1,620 B | `0x548f278` | caller's `r14` |
| `0x548f430` | 3,191 B | `0x548f730`, `0x548fb77` | caller's `r8`, then `r12` |
| `0x5493020` | 86 B | `0x5493033` | shim: caller's `rdx` |
| `0x54a9c70` | 50,226 B | `0x54b3288`, `0x54b4304`, `0x54b4f9d` | `lea 0x90(%rbx)`, then `[rsp+0x40]` twice |
| `0x54b66b0` | 50,232 B | `0x54bf8a9`, `0x54c0884`, `0x54c150d` | `lea 0x90(%rbx)`, then `[rsp+0x48]` twice |
| `0x55a1de0` | 612 B | `0x55a1e32` | `lea 0x90(%r14)` — context-embedded |
| `0x55a2050` | 612 B | `0x55a20a2` | `lea 0x90(%r14)` — context-embedded |
| `0x55a22c0` | 655 B | `0x55a23e3` | caller's `r15` |
| `0x55a2550` | 655 B | `0x55a2673` | caller's `r15` |

Controls (must, and do, reproduce #2598): inner_ca — 3 sites,
all in `0x2bb7270`, table argument `[rsp+0x88]`; inner_s3 — 3
sites, all in `0x2c62820`, table argument `[rsp+0x60]`.

Reading of the shapes (mechanical, from the pinned bindings in
`records.json`, which record the last writer of each of
`rdi`/`rsi`/`rdx`/`rcx`/`r8`/`r9` in the 16 rows before every
site):

- The shims are pure adapters: each takes its own incoming
  `(rdi, rsi, rdx)`, rotates them into the inner body's
  `(rsi, rdx, rcx)`, passes its own stack as the result pointer
  (`rdi = rsp`) and `r8 = 0`, calls once, and then interprets
  the result struct (the `0x2bbbb40` export shows the
  byte-0-equals-1 test and the field fallbacks after the call).
  Who calls the shims is the next level up and is not pinned
  here.
- In the three large caller FDEs the first site of each body
  uses the context-embedded table (`lea 0x90(%rbx)`) and binds
  `rdx = lea 0x6c8(%rbx)`; the later sites reload the table
  pointer from the frame. The small context-embedded callers
  (`0x2a8a000`, `0x55a1de0`, `0x55a2050`) show the same
  `rcx = lea 0x90(%ctx)`, `rdx = lea 0x6c8(%ctx)` pairing.
- The sub-lookup-shaped pair (`0x2bba100` / `0x548f430`) binds
  identically at both sites (`rdi = lea [rsp+0x60]`,
  `rsi = r13`): site 1 forwards the caller's own `r8` as the
  table argument, site 2 passes `r12`. These two FDEs are the
  only callers that invoke their body twice.

## Boundaries (precise negatives)

- The census covers references to the six bodies only. Who
  calls the 19 caller FDEs — in particular the shims, the small
  wrappers (`0x2a8a000`, `0x2a8a360`, `0x55a1de0`…`0x55a2550`)
  and the three large FDEs — is not pinned by this packet; it
  is the same one-level-up question #2598 answered for its
  bodies and left open for the next level.
- Table-argument provenance stops at each call site's last
  writer. Where the context at `+0x90`, the frame slots, and
  the forwarded registers themselves are filled — the table's
  producer, #2608's open edge 1 — remains open; this packet
  only fixes which bodies hand the pointer down, and in which
  of the three shapes (context-embedded, frame-saved,
  register-forwarded).
- Caller FDEs larger than 4 KB are digest-pinned with their
  call-site rows pinned individually, not exported in full;
  their internal semantics are not classified here beyond the
  site bindings.

## Open edges

1. The callers of the callers: the shims' and small wrappers'
   own call sites, and the inputs of the three large caller
   FDEs — the level above this packet.
2. The table behind the gate (#2608 edge 1, unchanged): who
   writes the `0x158`-stride records and the `+0x20`/`+0x28`
   header of the structure whose pointer this packet traces
   one level down.
3. #2608's remaining edges (unchanged): the branchless-select
   callers' conditionally replaced values, the one
   register-supplied gate flag site (`0x3698891`), and the
   panic-formatting callee `0x1680e60`.

## Files

- `records.json` — the machine-readable evidence: artifact and
  body pins (6 family bodies exported, 19 caller FDEs, the
  ≤4 KB ones exported), the per-target censuses with every
  site's call row and argument bindings, the raw-candidate
  counts, counters and the verdict.
- `frames.txt` — the `readelf --debug-dump=frames` FDE lines of
  all 25 bodies.
- `*_objdump.txt` — full-body disassembly exports of the 18
  bodies ≤ ~4 KB (the 6 family bodies and 12 caller FDEs). The
  7 larger caller FDEs are pinned by digest + their pinned
  call-site rows in `records.json`.
- `tools/family_callers_static.py` — the extractor; regenerates
  every file here from the authenticated artifact and fails
  closed on any drift.
- `tests/test_family_callers_static.py` — byte-for-byte
  regeneration, counters and verdict shape, and digest/pin
  drift failures.

## Verification

- `python3 tools/family_callers_static.py verify` prints
  `{"matches": true, "packet": "RE-006-node115-family-callers"}`.
- `tests/test_family_callers_static.py`: 6 tests — byte-for-byte
  regeneration, counters and verdict, wrong-artifact rejection,
  and three mutation tests (a family body, a validated call
  site, a digest-only caller FDE).
- MANIFEST.sha256 covers 21 entries; the isolated-root packet
  verifier reports "Verified 1 evidence-packet manifests and
  21 entries".
