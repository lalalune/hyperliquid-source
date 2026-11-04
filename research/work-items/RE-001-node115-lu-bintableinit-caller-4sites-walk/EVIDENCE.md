# RE-001-node115-lu-bintableinit-caller-4sites-walk: evidence

- Component ID: RE-001-node115-lu-bintableinit-caller-4sites-walk
- Target release and full SHA-256: node #115,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
  (105,896,032 bytes, artifacts/node/115/hl-node)
- Source commit / reference commit:
  05bc2de303c05525b71e7e257426e741bc66a390 (upstream main, fetch-confirmed)
- Claim status: observation for the decoded FDE; inference for register-use
  names (symbols are stripped); unresolved for callee internals and runtime
  .bss values
- Scope included and excluded: the caller FDE 0x63cb150..0x63cba04 only.
  bin_table_init body (#262), lu-miss handler (#215), previous/next FDEs,
  and all callees are cited, not claimed.

## Reproduce

Worktree ~/workspace/hl-wt-calls280-115, branch codex/re-004-calls280-115,
at upstream main 05bc2de30. Targeted disassembly only:

    objdump -d --start-address=0x63cb150 --stop-address=0x63cba04 \
      artifacts/node/115/hl-node

Static verifier (byte reads only; never executes the binary):

    python3 tools/node115_lu_bintableinit_caller_walk_4sites.py

Own unit tests (tamper controls first, then clean-copy pass):

    python3 tests/test_node115_lu_bintableinit_caller_walk_4sites.py

No full-node execution, no network, no paid sync. Tool versions: system
objdump/readelf as installed in the VM; python3 standard library only.

## Evidence

Coordinate system: `.text` file offset = VA - 0x1000; `.rodata` = VA
as-is; `.data` = VA - 0x3000. `.hex` exhibits contain raw binary bytes,
not hex text.

Validated boundaries (from `.eh_frame`, PC-relative sdata4, fixed 4-byte
range fields, not ULEB): window 0x63cb150..0x63cba04, 2228 bytes
(0x8b4); previous FDE 0x63c9c80..0x63cb146, gap before 10 bytes of
0xcc; next FDE 0x63cba10..0x63ccd22, padding after 12 bytes of 0xcc.
Frame 0x1a8, canary at 0x198(%rsp).

Raw disassembly: bintableinit_caller_walk_4sites.objdump.txt (469
strict lines: address + bytes field + tab + mnemonic starting with a
lowercase letter; byte-continuation lines excluded). Call census: 23
calls total, 4 bin_table_init (0x63cb548, 0x63cb5ad, 0x63cb610,
0x63cb79f; all rdi = lea 0x10(%rsp), all reached from test %rbp,%rbp
followed by je), 4 lu-miss (0x63cb82f, 0x63cb8ca, 0x63cb95a,
0x63cb9fa; all rdi = rbp, rsi = lea 0x6511a00, rcx = rbx, r8 = 1,
r9 = 0), 0 ret. Raw-e8 census for target 0x63d9880 grouped by
enclosing `.eh_frame` FDE: 10 (#275), 8 (#276), 6 (#277), 6 (#278),
5 (#279), 4 (this FDE and seven others). This FDE's raw count (4)
equals its objdump-verified site count (4).

`.rela.dyn` census: 60,723 entries total, 59,534 RELATIVE, stated
distinctly (`.rela.plt` adds 278 entries and is excluded).

Disjointness: the verifier's range-only collector scans the merged
tree plus prior worktree records and gathers string range fields,
[start, end] lists, and start/end pairs inside exhibits/windows lists
or dicts or a dict literally named "window". It never collects
enclosing-fde annotation fields, census/cited-only metadata subtrees,
next-caller pointers, scan descriptors, or control-flow edges. The
window is disjoint from every prior claimed range (37,405 prior ranges
scanned at build time, NONE overlapping).

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed here;
this packet is evidence only. No Cargo graph, no build comparison.

## Results and limitations

Machine-readable metrics with explicit denominators: verifier checks
(all must pass for exit 0); own unit tests 9/9 (4 tamper controls that
must fail the verifier, 1 clean-copy pass, 4 recount/regeneration
checks); `make verify` exit 0 (559 evidence-packet manifests, 7161
entries = base 7154 + this packet's 7 MANIFEST entries); `make
catalogue-check` exit 2, pre-existing `Stale
catalogue: README.md` on the new base — not a packet regression, and
not claimed as passing; full `make test` NOT attempted (584 test files
on the new base take hours and risk a VM-restart kill mid-run; no
full-suite tally is claimed); MANIFEST.sha256 all 7 entries verified
with `sha256sum -c`.

What remains unknown: callee FDE internals beyond call-site argument
patterns; runtime `.bss` values; whether the four walk paths are four
distinct callers or one caller inlined four times; the next caller
FDE 0x63c8d60..0x63c94fc.

Next question: decode the next bin_table_init caller FDE
0x63c8d60..0x63c94fc (4 raw candidates, 1948 bytes).
