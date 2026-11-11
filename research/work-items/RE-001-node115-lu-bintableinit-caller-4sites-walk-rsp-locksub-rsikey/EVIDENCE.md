# RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp-locksub-rsikey: bin_table_init caller FDE 0x63d5940..0x63d605c

- Component ID: RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp-locksub-rsikey
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390 (fetch-confirmed at build time)
- Claim status: observation (static disassembly only; the target binary is never executed)
- Scope included and excluded: the single FDE window 0x63d5940..0x63d605c and its call sites, scan shapes, and exits. Excluded: callee FDE internals beyond call-site patterns, runtime values of .bss addresses, the remaining 4-raw caller FDE 0x63ec900, static leaves, and named-only callee families.

## Reproduce

Working directory: the worktree root. Binary: artifacts/node/115/hl-node.
Targeted disassembly (no full-.text dump):

    objdump -d --start-address=0x63d5940 --stop-address=0x63d605c artifacts/node/115/hl-node

Exhibit bytes: file offset = VA - 0x1000 for .text; the .hex exhibit is the
raw 1820-byte slice, not hex text. FDE bounds were parsed from .eh_frame
(PC-relative sdata4, fixed 4-byte range fields; CIE pointer relative to the
CIE_id field, rec+4, not rec). Verifier:
tools/node115_lu_bintableinit_caller_walk_rsp_locksub_rsikey_4sites.py
(byte reads only). Unit tests:
tests/test_node115_lu_bintableinit_caller_walk_rsp_locksub_rsikey_4sites.py.
No execution of the target binary, no network access, no side effects beyond
reading the binary and writing this packet.

## Evidence

Original addresses and coordinate system (VA; .text file offset = VA - 0x1000,
.rodata VA as-is, .data VA - 0x3000). Validated boundaries: window
0x63d5940..0x63d605c (1820 bytes) from .eh_frame; previous FDE
0x63d5850..0x63d5940 (gap 0); next FDE 0x63d6060..0x63d6199 (padding 4 bytes
0xcc). Raw disassembly: bintableinit_caller_walk_rsp_locksub_rsikey_4sites.objdump.txt
(378 strict lines: address + bytes field + tab + mnemonic starting with a
lowercase letter; byte-continuation lines excluded). Call census: 9 calls
(4 bin_table_init at 0x63d5a96, 0x63d5af6, 0x63d5b5e, 0x63d5de6; 4 lu-miss
at 0x63d5e81, 0x63d5f19, 0x63d5fa9, 0x63d6052; 1 __stack_chk_fail at
0x63d602a), 0 ret, 0 bsr, 1 lock sub at 0x63d5a17
(lock sub %r14,0x38(%r8)). Entry: rdi = context (rbx), rsi = key (rbp,
direct — unlike #285, which read the key from 0x28(%rsi)); table pointer
lea 0x1b0(%rdi) into rsi. Walk: top index (key >> 0x1a) & 0xf0 into
context + 0x1b0; high bits key & 0xffffffffc0000000 compared; second level
(key >> 0x9) & 0x1ffff8 + table + 0x8; node resolved via 0x6727a00 indexed
by (value >> 0x30); (value >> 0x30) vs 0x23 gate at 0x63d5bc0..0x63d5bc8;
0x65096c0 read by index at 0x63d59f7..0x63d5a13 followed by the lock sub.
Scan: array at walk-table + 0x100, 16-byte entries; slot-0 head compares
at 0x63d5aa8, 0x63d5b10, 0x63d5b78, 0x63d5d9e; slot-1 compares at 0x63d5c86,
0x63d5ced, 0x63d5d55; unrolled slots 2..7 at 0x63d5df6..0x63d5e56 (r14),
0x63d5e90..0x63d5eec (r15), 0x63d5f28..0x63d5f84 (rsi); indexed loop at
0x63d5fb3..0x63d6037 (base r15, index r10 from 1 while != 8). Exits: three
canary-checked tail-jumps (0x63d5a85 -> 0x63637f0, 0x63d5c35 -> 0x63bd6c0,
0x63d5c75 -> 0x6363260); no other jump leaves the window. Analysis was
complete over the window; no timeout, no range limit.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed for this
window. The verifier and unit tests are static byte/census checks only, not
a reimplementation. Helper/data/relocation closure: .rela.dyn 60,723 entries
total, 59,534 RELATIVE (stated distinctly); .rela.plt 278 entries counted
separately. Fixture identities: the .hex exhibit (1820 raw bytes) and the
objdump exhibit; both are reproduced by the verifier and the unit tests.
Boundary/error cases and corruption controls: tamper controls (hex flip,
strict-count change, call-site change, injected overlap) each fail the
verifier; the clean temp copy passes.

## Results and limitations

Machine-readable metrics with explicit denominators: verifier 53/53 checks
pass; unit tests 13/13 checks pass; MANIFEST.sha256 7/7 entries verified;
make verify exit 0 (559 manifests, 7161 entries = base 7154 + 7);
make catalogue-check exit 2 (pre-existing Stale catalogue: README.md on the
new base, not a packet regression). Disjointness: NONE over prior ranges,
0 overlaps (range-only collector; census/cited-only subtrees, next-caller
pointers, and scan descriptors excluded; self excluded by exact window
equality). What remains unknown: runtime values of .bss addresses; whether
the four walk paths correspond to four distinct callers or one caller
inlined four times; per-scan mapping of all four lu-miss sites to distinct
walk variants beyond the arguments/rejoins listed. This packet requests no
full-suite gate: full make test (584 files) is not run by design (hours +
VM-restart risk), and that deviation is stated in the body rather than
claimed as a pass. Next question: packet #287 decodes 0x63ec900..0x63ed06d
(1901 bytes, 4 raw candidates), the last remaining 4-raw caller FDE.
