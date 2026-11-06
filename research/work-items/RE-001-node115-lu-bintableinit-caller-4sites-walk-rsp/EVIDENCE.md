# RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp: evidence

- Component ID: RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp
- Target release and full SHA-256: node #115,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
  (105,896,032 bytes, artifacts/node/115/hl-node)
- Source commit / reference commit:
  05bc2de303c05525b71e7e257426e741bc66a390 (upstream main, fetch-confirmed)
- Claim status: observation for the decoded FDE; inference for register-use
  names (symbols are stripped); unresolved for callee internals and runtime
  .bss values
- Scope included and excluded: the caller FDE 0x63c8d60..0x63c94fc only.
  bin_table_init body (#262), lu-miss handler (#215), previous/next FDEs,
  and all callees are cited, not claimed.

## Reproduce

Worktree ~/workspace/hl-wt-calls281-115, branch codex/re-004-calls281-115,
at upstream main 05bc2de30. Targeted disassembly only:

    objdump -d --start-address=0x63c8d60 --stop-address=0x63c94fc \
      artifacts/node/115/hl-node

Static verifier (byte reads only; never executes the binary):

    python3 tools/node115_lu_bintableinit_caller_walk_rsp_4sites.py

Own unit tests (tamper controls first, then clean-copy pass):

    python3 tests/test_node115_lu_bintableinit_caller_walk_rsp_4sites.py

No full-node execution, no network, no paid sync. Tool versions: system
objdump/readelf as installed in the VM; python3 standard library only.

## Evidence

Coordinate system: `.text` file offset = VA - 0x1000; `.rodata` = VA
as-is; `.data` = VA - 0x3000. `.hex` exhibits contain raw binary bytes,
not hex text.

Validated boundaries (from `.eh_frame`, PC-relative sdata4, fixed 4-byte
range fields, not ULEB): window 0x63c8d60..0x63c94fc, 1948 bytes
(0x79c); previous FDE 0x63c89c0..0x63c8d5a, gap before 6 bytes of
0xcc; next FDE 0x63c9500..0x63c964d, padding after 4 bytes of 0xcc.
Frame 0x198, canary at 0x188(%rsp).

Raw disassembly: bintableinit_caller_walk_rsp_4sites.objdump.txt (411
strict lines: address + bytes field + tab + mnemonic starting with a
lowercase letter; byte-continuation lines excluded). Call census: 14
calls total, 4 bin_table_init (0x63c8fc6, 0x63c9026, 0x63c908e,
0x63c9296; all rdi = rsp, all reached from test %rbx,%rbx
followed by je, each block the target of exactly one je),
4 lu-miss (0x63c9329, 0x63c93b9, 0x63c9449, 0x63c94f2; all
rdi = rbx, rsi = lea 0x6511a00, rcx = rbp, r8 = 1, r9 = 0),
0 ret, 0 bsr. Raw-e8 census for target 0x63d9880 grouped by
enclosing `.eh_frame` FDE: 10 (#275), 8 (#276), 6 (#277), 6 (#278),
5 (#279), 4 (#280), 4 (this FDE), 4 (six others). This FDE's raw
count (4) equals its objdump-verified site count (4).

`.rela.dyn` census: 60,723 entries total, 59,534 RELATIVE, stated
distinctly (`.rela.plt` adds 278 entries and is excluded).

Disjointness: the verifier's range-only collector scans the merged
tree plus prior worktree records and gathers string range fields,
[start, end] lists, and start/end pairs inside exhibits/windows lists
or dicts or a dict literally named "window". It never collects
enclosing-fde annotation fields, census/cited-only metadata subtrees,
next-caller pointers, scan descriptors, or control-flow edges. The
window is disjoint from every prior claimed range (prior ranges
scanned at build time, NONE overlapping).

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed here;
this packet is evidence only. No Cargo graph, no build comparison.

## Results and limitations

Machine-readable metrics with explicit denominators: verifier checks
(all must pass for exit 0); own unit tests 11/11 (4 tamper controls
that must fail the verifier, 1 clean-copy pass, 6 recount/regeneration
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
FDE 0x636bd90..0x636c49c.

Next question: decode the next bin_table_init caller FDE
0x636bd90..0x636c49c (4 raw candidates, 1804 bytes).
