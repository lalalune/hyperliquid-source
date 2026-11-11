# RE-001-node115-lu-bintableinit-caller-2sites-walk-18rsp: lu bin_table_init 18rsp walk caller, 2 sites

- Component ID: RE-001-node115-lu-bintableinit-caller-2sites-walk-18rsp
- Target release and full SHA-256: node #115,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
  (105,896,032 bytes, artifacts/node/115/hl-node)
- Source commit / reference commit: upstream main
  05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly + .eh_frame bounds + byte
  census); the two helper callees' internals are unresolved, not
  inferred.
- Scope included and excluded: the single FDE
  0x63d4171..0x63d4289 only. Helper bodies, bin_table_init body
  (#262), lu-miss handler (#215), tail-jump target bodies, and
  neighboring FDEs are cited, not claimed.

## Reproduce

Worktree ~/workspace/hl-wt-calls293-115 at upstream main
05bc2de303c05525b71e7e257426e741bc66a390. Static analysis only;
the binary was never executed.

- `objdump -d --start-address=0x63d4171 --stop-address=0x63d4289
  artifacts/node/115/hl-node` (exhibit
  bintableinit_caller_walk_18rsp_2sites.objdump.txt).
- Raw window bytes: `.text` file offset = VA - 0x1000, so
  0x63d4171 -> file offset 0x63d3171, 280 bytes (exhibit
  bintableinit_caller_walk_18rsp_2sites.hex, raw binary).
- Verifier: `python3
  tools/node115_lu_bintableinit_caller_walk_18rsp_2sites.py`
  (exit 0).
- Own tests: `python3
  tests/test_node115_lu_bintableinit_caller_walk_18rsp_2sites.py`
  (exit 0).
- `make verify` exit 0 (559 manifests, 7159 entries).
  `make catalogue-check` exit 2, pre-existing `Stale catalogue:
  README.md` on a pristine checkout.
- Full `make test` not run (584 files on the new base); deviation
  declared in README and in the PR body.

## Evidence

Coordinate system: virtual addresses as shown by objdump; `.text`
file offset = VA - 0x1000. FDE bounds from an own `.eh_frame`
parser (PC-relative sdata4, fixed 4-byte range fields, CIE pointer
relative to the CIE_id field; three CIEs, two zPLR; FDE list sorted
before bisect): 135,313 FDEs total; this FDE 0x63d4171..0x63d4289
(280 bytes); previous FDE 0x63d4048..0x63d4171 (padding 0); next
FDE 0x63d4289..0x63d4425 (padding 0).

Raw disassembly is the objdump exhibit. Strict mnemonic lines
(`^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`): 70. Calls: 5 —
0x63d41a9 and 0x63d4244 to bin_table_init 0x63d9880 (rel32
verified: 0x63d41ae + 0x56d2, 0x63d4249 + 0x5637), 0x63d41b7 to
0x63d3f0e, 0x63d4255 to 0x63d4048, 0x63d4271 to __stack_chk_fail
0x63f0d70. Ret: 0. Bsr: 0. Lock: 0 either sign. Lu-miss calls
(to 0x63d9700): 0. Raw `e8` byte scan for rel32 target 0x63d9880
over the window: exactly the two objdump sites.

Site blocks: 0x63d41a1 and 0x63d423c, each `lea 0x18(%rsp),%r12;
mov %r12,%rdi`, each entered only by fall-through of a null-context
test (`jne` away on nonzero at 0x63d419f / 0x63d423a); no other jump
in the window targets either block (verified by program over all
direct jump targets). Rejoins: `mov %r12,%rsi` (site 1, into the
phase-1 helper call) and `mov %r12,%rdx` (site 2, into the phase-2
helper call).

Exits: `jmp 0x63637f0` at 0x63d41f6, `jmp 0x6363260` at
0x63d422b, `jmp 0x63bd6c0` at 0x63d4284 — each after a full epilogue
and canary check; exit-ness verified per FDE (this trio were
ordinary calls in #287's FDE). Canary failure path calls
__stack_chk_fail at 0x63d4271. All other direct jump targets lie
inside the window.

Relocations (readelf -W): `.rela.dyn` 60,723 total, 59,534
RELATIVE; `.rela.plt` 278 entries, counted separately.

## Implementation and comparison

No Rust implementation in this packet; it is an evidence packet
only (README, EVIDENCE.md, records.json, exhibits, MANIFEST, static
verifier, unit tests). The static verifier re-derives every census
figure from the exhibits and the binary and checks disjointness
against all prior packet records. Not yet implemented/measured:
helper internals (flag-byte/`eax` contract of 0x63d3f0e,
out-parameter of 0x63d4048), and any source mapping.

## Results and limitations

Passed: verifier (exit 0), own unit tests including tamper
controls against a temp copy's verifier (exit 0), `make verify`
(exit 0, 7159 entries), MANIFEST 5/5, disjointness NONE over
53,357 ranges scanned (self-excluded by exact match, 0
range-like-but-unparseable entries). Known limitation: `make
catalogue-check` fails pre-existing on the new base (see above);
full `make test` not run (declared deviation). Unknown: helper
semantics; no claim is made about them.

Next question: packet #294 decodes 0x63d4289..0x63d4425 (412
bytes, 2 bin_table_init sites, 0 lu-miss sites, 1 ret, 0 bsr —
the next surviving 2-raw candidate, verified by program against
all prior exhibits; fall-through order 0x63d4497..0x63d463e,
0x63d61a0..0x63d6575, 0x63ed8b0..0x63edf05).
