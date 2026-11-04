# RE-001-node115-lu-central-flush: decode the node #115 lu central-flush helpers 0x63ead50 / 0x63eb870

- Component ID: RE-001-node115-lu-central-flush
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 (105896032 bytes)
- Source commit / reference commit: upstream main 8fd8db680ec4bfef40996e5616bce3d5156d0b86
- Claim status: observation for all FDE bounds, excerpt bytes, census sites, and cited instruction bytes; inference for field meanings derived from load/store patterns (flagged in README); unresolved for the items listed under "Results and limitations"
- Scope included and excluded: included — flush helpers 0x63ead50 / 0x63eb870, push helpers 0x63612b0 / 0x63bd640, record C layout, segment fields, locking order, move loop, thread-list aftermath, whole-.text census. Excluded — drain helper 0x51e8720, field-drop callees 0x5a50a10 / 0x5a4d200, #200 delegates 0x51f3e20 / 0x57ec1b0, unwind callee 0x1680cab, and full decodes of 0x63e9cd0 / 0x63e94a0 / 0x6363660 / 0x6363560 / 0x63bd5a0 / 0x63c0340 (characterised only where the flush path touches them).

## Reproduce

Working directory: repository root of worktree hl-wt-calls204-115. Tools: GNU objdump 2.42, GNU readelf 2.42, python3 (stdlib only). No binary executed at any point; all reads are byte reads.

- FDE bounds: `readelf --debug-dump=frames artifacts/node/115/hl-node` (grep for 63ead50 / 63eb870 / 63612b0 / 63bd640).
- Excerpts: `objdump -d --start-address=<start> --stop-address=<end> artifacts/node/115/hl-node`, keeping only lines matching `^\s*[0-9a-f]+:`; hex files are the raw bytes at file offset VA − 0x1000 for `.text`.
- Census: whole-`.text` byte scan for E8/E9 rel32 resolving to each target (section bounds from ELF section headers: `.text` file offset 0x1418300, size 0x4fd7700, VA 0x1419300), plus a REX LEA scan (REX 0x40–0x4f + 0x8d + modrm mod=00 rm=101) and a `.rela.dyn` scan for RELATIVE (type 8) addends. RELATIVE `.got` slots are zero-filled in the file, so the `.rela.dyn` scan is the only valid GOT census. Every census site was re-checked by disassembling one instruction at the site.
- Coordinates: `.text` file offset = VA − 0x1000; `.data.rel.ro`/`.got` = VA − 0x2000; `.rodata` = VA as-is. `.bss` VAs (0x64ffe40..0x6728924) have no file content; only their addresses and indexing formulas are claimed.
- Strict mnemonic count: objdump lines of form address + byte field + tab + mnemonic; byte-continuation lines excluded. Each shipped objdump file contains exactly one continuation line (small_lock 34 lines / 33 strict; large_gate 26 / 25; push_large 17 / 16; large_tail 19 / 18).

## Evidence

Original addresses and coordinate system as above. Validated boundaries: small-flush FDE 0x63ead50..0x63eb79f (2639B, main ret 0x63eb586), large-flush FDE 0x63eb870..0x63ec1d8 (2408B, main ret 0x63ec0ae), push-small FDE 0x63612b0..0x636131a (106B, ret 0x6361303), push-large FDE 0x63bd640..0x63bd6ba (122B, ret 0x63bd6a4). Neighbour FDEs 0x63eb7a0..0x63eb865 and 0x63ec1e0..0x63ec349 are separate functions, not parts of the flush helpers; their calls into 0x63ead50 (0x63eb83b) and 0x63eb870 (0x63ec337) are census sites only.

Raw disassembly/data: shipped beside this record as small_lock.hex / small_lock.objdump.txt (0x63eaef0..0x63eaf7e, 142B, 33 strict: segment-table + class-table + sub*224 C computation, mutex arg C+0x40, trylock, +0x38/+0x28/+0x30 updates), large_gate.hex / large_gate.objdump.txt (0x63eb9d0..0x63eba48, 120B, 25 strict: segment resolution, seg+0x13450 vs *(0x650969c) threshold gate, lock add 0x63eba30, lock addq 0x63eba3b, slot zero 0x63eba40), push_large.hex / push_large.objdump.txt (0x63bd640..0x63bd687, 71B, 16 strict: in-wrapper segment resolution, seg+0x2998, call 0x63c0340 at 0x63bd682), large_tail.hex / large_tail.objdump.txt (0x63ec019..0x63ec068, 79B, 18 strict: memmove at 0x63ec055, head advance, u16 clamp). Claims not covered by a shipped excerpt (small unlock at 0x63eb24f, large lock at 0x63ebeba, push-small core, seg-drain call at 0x6363435) are covered by exact key-byte checks in tools/node115_lu_central_flush.py and tests/test_node115_lu_central_flush.py.

Callers/callees/indirect calls: census in README and records.json; no LEA/GOT references to any of the four targets; no E9 tail jumps to them. PLT targets: pthread_mutex_trylock@plt 0x63f17b0, pthread_mutex_unlock@plt 0x63f0b70, pthread_mutex_lock@plt 0x63f0b60 (inside 0x63bf680 only), memmove@plt 0x63f0a70.

Source mapping evidence: none claimed — no source files are cited; all claims are binary addresses and byte patterns.

ABI/layout/rounding/overflow observations: 5-argument shape (rdi, rsi, rdx, rcx, r8d); entry count (total u16 >> 3) − r8d; per-class atomic stride 48 with −760/−744 bias; small C stride 224 (sub*7 << 5); per-class array stride 40; slot+0x18 u16 clamp vs #203's slot+0x1a bound left unresolved.

Analysis was complete for the four target FDEs' lock/move/push structure within the stated scope; the helpers they call (0x63e9cd0, 0x63e94a0, 0x63c0340, 0x63bd5a0, 0x6363660, 0x6363560, 0x63bf680) were decoded only along the paths the flush helpers exercise.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is included in this packet; no build comparison is claimed. The packet is evidence only.

## Results and limitations

Machine-readable metrics with explicit denominators: verifier exit 0; unit tests 8/8; MANIFEST 13/13 entries match (11 packet-dir files + tools + tests; MANIFEST itself excluded from its own listing per prior-packet convention); whole-.text census denominators are the full .text section (0x4fd7700 bytes), not a sampled window; .rela.dyn scan covers all 59534 RELATIVE relocs.

What passed/failed: all packet checks pass; the full-suite `make test` result is reported separately (one pre-existing catalogue failure, unrelated to this packet, if present).

What remains unknown, and why: see README "Explicitly unresolved" — every item there is unknown because the evidence is either runtime-populated `.bss` (no file bytes), an undecoded callee, or a semantic question (e.g. unlock-skip invariant, slot+0x18 vs +0x1a) that static bytes alone cannot settle.

Gate coverage: this packet's gates (verifier, unit, MANIFEST, make verify, make catalogue-check, make test) cover the packet's own files and claims only; they do not gate the wider RE-001 reconstruction.

Finish with a concrete next question: Decode the actual central push 0x63c0340: what is the seg+0x2998 push-list object, what are its two virtual methods (obj+0x18 vs obj+0xf338, selected by block-header bit 0x4000), and what does the &flag out-parameter mean?
