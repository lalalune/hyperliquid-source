# RE-001-node115-lu-bintableinit-caller: bin_table_init caller FDE 0x63cba10 (10 sites)

- Component ID: lu bin_table_init caller
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation for the FDE bounds, bytes, strict count, call census, mutex gate, radix walk shape, and splice/scan shapes; inference for the entry contract roles (register use only, no symbols) and the size-class block's purpose; unresolved for the callee internals and all runtime .bss values
- Scope included and excluded: included — the single FDE 0x63cba10..0x63ccd22 in full, its 49 calls, its mutex gate, its radix walk, its 10 bin_table_init sites, its 10 lu-miss sites, its 7-slot scans and splice blocks. Excluded — the callee FDEs' internals, the next-largest caller 0x63c9c80, the next leaf family outside opt children, and the 107 remaining static leaves.

## Reproduce

Worktree ~/workspace/hl-wt-calls275-115 at upstream main 05bc2de30.
Binary verified by size and SHA-256 (see verifier). FDE bounds from
`.eh_frame` (PC-relative sdata4, fixed 4-byte range fields).
Exhibit bytes extracted as binary[VA - 0x1000]. Objdump exhibit
regenerated with `objdump -d --start-address=0x63cba10
--stop-address=0x63ccd22 artifacts/node/115/hl-node` (header
lines stripped for comparison, per the #266 lesson). Static
analysis only; the binary was never executed. No declared
execution or side effects.

## Evidence

Coordinate system: VA as printed by objdump and `.eh_frame`;
`.text` file offset = VA - 0x1000 (verified by prologue bytes
41 57 41 56 41 55 41 54 at the slice start). `.bss`-region
addresses (0x65096c0, 0x6511a00, 0x67144c0, 0x67144f8,
0x6714500, 0x6714620, 0x6714648, 0x6714650, 0x6714658,
0x6714660, 0x6714688, 0x67277c0, 0x6727a00) are runtime-only:
they lie past the file-backed ranges, so no file values are
claimed for them. `.data.rel.ro` address 0x64da4b0 is passed
by address to 0x634ebb0; its file qword reads 0x0 (relocated
at load, not claimed as a value).

Raw files beside this record: bintableinit_caller.hex (raw
binary bytes, not hex text), bintableinit_caller.objdump.txt
(full objdump output for the FDE range). Callers: none claimed
— this FDE's own callers are not part of the packet.
Callees (call-site granularity only): bin_table_init 0x63d9880
x10, lu-miss handler 0x63d9700 x10, 0x63d3aa0 x2, 0x63d39a0
x1, 0x6364880 x1, 0x63637f0 x2, 0x6363260 x2, 0x63bd6c0 x2,
0x63bf680 x3, 0x63c3730 x3, 0x63c3990 x3, 0x634ebb0 x1,
memcpy x1, pthread_mutex_trylock x3, pthread_mutex_unlock x4,
`__stack_chk_fail` x1. Analysis was complete over the FDE
range (all 1015 strict lines read); no timeout or range limit.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is
attempted in this packet. The verifier is an independent
byte-level check, not an implementation: it re-derives the
FDE bounds from `.eh_frame`, the exhibit bytes from the
binary slice, the strict count, the call census from the
objdump text, the stack-temp pattern, and disjointness
against all prior claimed ranges. No normalization masks
beyond the strict-line definition (address + bytes field +
tab + lowercase-start mnemonic) are used.

## Results and limitations

Metrics: 1 window, 4882 bytes, 1015 strict lines, 49 calls,
1 ret, 10 bin_table_init sites, 10 lu-miss sites, 3 trylock
sites, 4 unlock sites, 5 unrolled scans, 5 indexed loops, 5
shared splice blocks. Verifier exit 0; unit tests 7/7 with
tamper controls run first; `make verify` exit 0; `make
catalogue-check` exit 2 (pre-existing stale catalogue, not
a regression); full `make test` NOT attempted (584 files,
hours, VM-restart risk — stated honestly, not claimed).
What remains unknown: callee internals, runtime .bss values,
the named structure (if any) behind rbx+0x1b0, and the 107
remaining leaves. This packet requests no gate beyond the
stated checks. Next question: decode the next-largest
bin_table_init caller FDE 0x63c9c80 (8 sites); or open the
next leaf family outside opt children — pick one, not both.
