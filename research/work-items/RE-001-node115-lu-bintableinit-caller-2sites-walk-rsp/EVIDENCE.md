# RE-001-node115-lu-bintableinit-caller-2sites-walk-rsp: lu bin_table_init rsp walk caller, 2 sites

- Component ID: RE-001-node115-lu-bintableinit-caller-2sites-walk-rsp
- Target release and full SHA-256: node #115, a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301, 105,896,032 bytes
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly-backed; no execution, no values claimed for .bss or file-absent regions)
- Scope included and excluded: FDE 0x6349780..0x6349bd9 only. bin_table_init body, lu-miss handler, tail-jump target bodies, gate byte, threshold table, and lu-miss argument table are cited or read, not claimed. Neighboring FDEs excluded.

## Reproduce

Exact commands, run from the worktree root, static analysis only (the binary
is never executed):

- `objdump -d --start-address=0x6349780 --stop-address=0x6349bd9 artifacts/node/115/hl-node` -> exhibit `bintableinit_caller_walk_rsp_2sites.objdump.txt`
- Raw bytes: file slice at offset VA - 0x1000 for the window -> exhibit `bintableinit_caller_walk_rsp_2sites.hex` (raw binary bytes, not hex text)
- `python3 tools/node115_lu_bintableinit_caller_walk_rsp_2sites.py` (exit 0 required)
- `python3 tests/test_node115_lu_bintableinit_caller_walk_rsp_2sites.py` (exit 0 required)
- `make verify` (exit 0), `make catalogue-check` (pre-existing `Stale catalogue: README.md` failure, also on pristine checkout)
- Tool versions: system objdump, python3 (stdlib only). No Ghidra/IDA/REA output is used as evidence here.

## Evidence

Original addresses and coordinate system: virtual addresses as shown by
objdump; `.text` file offset = VA - 0x1000; `.rodata` VA as-is;
`.data` VA - 0x3000. Boundaries validated against `.eh_frame` by an own
parser (CIE pointer relative to the CIE_id field, rec + 4; fixed 4-byte FDE
range fields; code/data alignment and return-address register read before
`z` augmentation data; version-1 CIE return-address register as a single
byte; CIE offsets hex; FDE list sorted before bisect): 135,313 FDEs,
window FDE present, previous FDE 0x63495b0..0x6349775 (gap 11 bytes, all
0xcc), next FDE 0x6349be0..0x634eb7c (padding 7 bytes, all 0xcc).

Raw disassembly is kept beside this record (objdump exhibit, 230 strict
mnemonic lines). Callers/callees: entry `rdi` context, `rsi` key, `rdx`
size argument (gate path only). Callees: bin_table_init `0x63d9880` x2,
lu-miss handler `0x63d9700` x2, `__stack_chk_fail` `0x63f0d70` x1.
Tail-jump exits: `0x63637f0`, `0x63bd6c0`, `0x6363260`. Indirect calls:
none. ABI/layout observations: frame `sub $0x190,%rsp`, canary at
`0x188(%rsp)`, three canary checks all jumping to the fail call at
`0x6349ba3`. Analysis is complete for the window; no range was timed out
or truncated.

## Implementation and comparison

Not yet implemented/measured: no independent Rust reconstruction is claimed
by this packet. The packet is an evidence record plus a static verifier;
it does not assert binary equivalence or a rebuilt implementation.

## Results and limitations

Machine-readable metrics with explicit denominators: strict 230 lines;
calls 5 of 5 classified (2 bin_table_init, 2 lu-miss, 1 stack-chk-fail);
ret 0; bsr 1; lock sub 0; bin_table_init sites 2 of 2 with plain `%rsp`
arguments; lu-miss sites 2 of 2 with the shared argument shape; exits 3
of 3 tail jumps, each canary-checked. Raw-e8 census: 108 total across
135,313 parsed FDEs; this FDE holds 2. Disjointness: 0 overlaps over
44,192 prior ranges (range-only collector, decimal-integer start/end
forms included).

What remains unknown: the semantic meaning of the gate byte at `0x6713606`
(beyond its branch effect), the contents of the threshold table at
`0x67277c0` and the lu-miss argument table at `0x6511a00` (reads only),
and the bodies of the three tail-jump targets. The low-bit branch in
phase 1's second level and the `(value >> 0x30)` vs `0x23` gate are
described as control flow only, without a semantic label.

Next question: build packet #289 on `0x6361320..0x63620da`, the next
surviving 2-raw candidate, after re-verifying its site count and claim
status.
