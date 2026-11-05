# RE-001-node115-lu-miss-caller-1site-dispatch: lu-miss caller with a dispatch body

- Component ID: RE-001-node115-lu-miss-caller-1site-dispatch
- Target release and full SHA-256: node #115,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
  (105,896,032 bytes, artifacts/node/115/hl-node)
- Source commit / reference commit: upstream main
  05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (static disassembly only; no node execution)
- Scope included and excluded: included — the single FDE
  0x6353a70..0x635582b (7611 bytes) and its walk/scan/miss structure
  plus its dispatcher callees by address only. Excluded — the lu-miss
  handler, the bin_table_init body, the second miss handler, the
  lock-wait helper, every dispatcher callee's body, the neighboring
  FDEs, and all runtime table contents.

## Reproduce

Working directory: a worktree of lalalune/hyperliquid-source at
upstream main 05bc2de303c05525b71e7e257426e741bc66a390.

```
objdump -d --start-address=0x6353a70 --stop-address=0x635582b \
  artifacts/node/115/hl-node
python3 tools/node115_lu_miss_caller_1site_dispatch.py
python3 tests/test_node115_lu_miss_caller_1site_dispatch.py
make verify
make catalogue-check
```

Tool versions: GNU objdump (binutils, as installed in the VM),
Python 3. Static analysis only; the node binary is never executed.
No side effects beyond reading the binary and the worktree.

## Evidence

Addresses are virtual addresses (VA); file offset in .text is VA -
0x1000. FDE bounds come from an own .eh_frame parse (CIE zR
encoding 0x1b, FDE range field fixed 4 bytes, FDE list sorted before
bisect): window 0x6353a70..0x635582b (7611 bytes); previous FDE
0x6353a20..0x6353a61 (gap 15, all 0xcc); next FDE 0x6355830..0x63558f2
(padding 5, all 0xcc). Strict mnemonic-line count uses
`^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]` (the bytes column in this objdump
output is space-padded): 1691 lines. Call sites are counted by
objdump mnemonic (105 calls, 33 distinct targets); raw-0xe8 byte
scan is an upper bound only and is used solely for the census.

Raw exhibits beside this record:
`lumiss_caller_1site_dispatch.hex` (raw binary slice, 7611 bytes),
`lumiss_caller_1site_dispatch.objdump.txt` (targeted objdump),
`records.json` (machine-readable decode).

Callers/callees: this FDE calls the lu-miss handler 0x63d9700 once
(0x63557eb), the second miss handler 0x634ebb0 six times, #314's
window 0x63495b0 once (0x6354682), #313's window 0x63c2f00 twice
(0x6353caa, 0x6355415), #298's window 0x6362f90 twice, and 27 further
direct callees plus one indirect call through GOT slot 0x64ffb38.
It calls bin_table_init 0 times and the lock-wait helper 0 times.
Indirect-call target is runtime-filled (R_X86_64_RELATIVE) and is
not established.

ABI/layout observations: frame sub $0x98, canary at 0x88(%rsp);
entry rdi is a size input (byte-table index (rbp+7)>>3 into
0x67277c0, size table 0x6727a00); rbx is a TLS-derived context base;
the walk key r12 is loaded at 0x6354094; the scan key r10 is the
key's high bits; exit rax = r12 (not 0). The scan is a single 8-slot
move-to-front scan with slot 0 compared separately and slots 1-7
sharing one loop compare; exhaustion at slot count 8 falls to the
lu-miss block. No size-table read of 0x6727a00's sibling 0x6727a00
beyond the entry block; no node-resolution tables are read.

Analysis is complete for this FDE (all 1691 strict lines parsed and
censused); the dispatch arms' selection semantics and the callees'
bodies are not decoded here.

## Implementation and comparison

No Rust implementation is claimed in this packet; the deliverable is
the evidence record plus the static verifier below. The verifier
re-checks every figure in records.json from the binary and the
exhibits (FDE bounds, strict/call census, walk/scan/lu-miss block
instructions, r12 write-set on the walk->miss path, second-handler
sites, dispatcher call census, jump closure, rela counts, raw-e8
censuses, disjointness over all prior exhibit ranges, slug
uniqueness, MANIFEST). Corruption controls: the unit tests flip one
hex byte, change the strict count, change a call site, and inject an
overlap with #314's window — each must make the temp-copy verifier
fail; the clean temp copy passes.

## Results and limitations

- Static verifier: exit 0, 188 checks, 0 failures.
- Own unit tests: exit 0, 12 checks, 0 failures.
- `make verify`: exit 0 (559 evidence-packet manifests, 7159 entries).
- `make catalogue-check`: exit 2, pre-existing `Stale catalogue:
  README.md` failure, also present on a pristine checkout; not a
  packet regression.
- Full `make test` is not run (584 files on the new base; hours of
  runtime and VM-restart risk). This deviation is declared in the
  README and the PR body rather than hidden.
- Remaining unknowns: entry size input's caller-side meaning, dispatch
  arm selection semantics, extract helper outputs, indirect-call
  target, runtime table contents. Next question: packet #316 decodes
  0x6355900..0x63577e2 (next surviving lu-miss caller, verified by
  targeted objdump census).
