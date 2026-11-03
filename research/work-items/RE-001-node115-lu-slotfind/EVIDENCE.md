# RE-001-node115-lu-slotfind: the node #115 lu slot-find helper

- Component ID: RE-001-node115-lu-slotfind
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes), artifact `artifacts/node/115/hl-node`
- Source commit / reference commit: upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis)
- Claim status: observation for all decoded mechanics; inference
  only where marked (argument roles, threshold rationale, smallest-key
  selection rationale); unresolved items listed in README
- Scope included and excluded: included — the finder FDE
  `0x63b0980..0x63b15e9` in full, its 8 internal calls by target
  address, its 1 caller by address, the record bitmap/slot reads,
  the `.bss` table address. Excluded — the internals of the size
  helper `0x63e8c80`, the empty test `0x63abcf0` beyond its 12
  bytes, the slot-head helper `0x63abd00` beyond #225, the caller
  FDE's purpose, the `.bss` table contents (not in the file).

## Reproduce

Working directory: a worktree of lalalune/hyperliquid-source at
upstream main `8fd8db6`, node binary at
`artifacts/node/115/hl-node`. Static analysis only; the node
binary was never executed.

- Full FDE disassembly:
  `objdump -d --start-address=0x63b0980 --stop-address=0x63b15e9
  artifacts/node/115/hl-node` (812 lines, kept as scratch
  `fde_full.txt`; not part of the packet).
- Exhibit extraction: `.text` file offset = VA − 0x1000;
  `objdump -d --start-address=<start> --stop-address=<end>` per
  exhibit; `.hex` files hold the raw bytes.
- Census: whole-`.text` byte scan for `E8` with rel32 target
  `0x63b0980` (1 site), `E9` with rel32 target (0 sites), and
  `.rela.dyn` addend scan (60,723 entries, 0 hits).
- Verifier: `python3 tools/node115_lu_slotfind.py` (exit 0).
- Unit tests: `python3 -m unittest
  tests.test_node115_lu_slotfind` (10/10).
- Suite: `make verify` (exit 0), `make catalogue-check`
  (exit 0), `make test` (77 files; 1 pre-existing catalogue
  Errno 18 failure only).

## Evidence

Coordinate system: VA as shown by objdump; `.text` file offset =
VA − 0x1000; `.rela.dyn` addends are absolute VAs.

Validated boundaries: finder FDE `0x63b0980..0x63b15e9`
(3177 bytes); next bytes belong to the following function.
Single `ret` at `0x63b132b` (`c3`). Entry `endbr64`
(`f3 0f 1e fa`) at `0x63b0980`.

Raw disassembly: per-exhibit `.objdump.txt` files beside this
record (5 excerpts, 327 bytes, 91 strict mnemonic lines).
Strict count = lines matching address + bytes field + tab +
mnemonic; objdump byte-continuation lines excluded.

Callers/callees (all rel32-verified):

- Inside the FDE (8 calls): `0x63b09cb`, `0x63b0f62`,
  `0x63b0fbc` → `0x63e8c80` (size helper);
  `0x63b0bbb` → `0x63abcf0` (empty test);
  `0x63b0bc7`, `0x63b1131`, `0x63b1490`, `0x63b14ed` →
  `0x63abd00` (slot-head helper, #225).
- Callers of the finder (1 direct E8): `0x63b49a3` (FDE
  starting `0x63b4630`). No E9, no LEA, no GOT (`.rela.dyn`
  addend scan, 60,723 entries).

Key addresses: entry `0x63b0980`; page-align `0x63b098d`;
entry guard `0x63b09b2`; first size call `0x63b09cb`; huge
path `0x63b15c4` (index 199); index idiom `0x63b09ea`;
flag test `0x63b0a22`; exact-slot block `0x63b0bac`;
empty-test call `0x63b0bbb`; exact slot-head call
`0x63b0bc7`; bitmap scan `0x63b0a2b`–`0x63b0bdb`;
loop head 1 `0x63b0c15`; loop head 2 `0x63b0d41`;
replace path 1 `0x63b14d8`; replace path 2 `0x63b1480`;
advance blocks `0x63b0c6e`, `0x63b0d9a`;
loop-head routing test `0x63b0d31`; convergence
`0x63b0f40`/`0x63b0f47`; phase-2 index recompute
`0x63b0f5f`–`0x63b100f`; phase-2 loop `0x63b1120`;
range check `0x63b1136`–`0x63b116c`; phase-2 slot-head
call `0x63b1131`; single exit `0x63b1318`/`0x63b131a`
→ `ret 0x63b132b`.

ABI/layout observations: arguments (record, length, align,
flag byte, shift) per register use; `A` page-rounded from
`rdx`; threshold `r13 = A + L - 0x1000`; record bitmap
`P+0x00..0x20`, slots `P+(i+1)*32`, cached key
`[T+0x10]`/`[T+0x18]`; node `+0x8` base, `+0x10` size,
`+0x20`/`+0x8` sort key; table `.bss 0x6728180`,
qword per class, shifted by 63 (default) or `r8d`.

Analysis was complete over the FDE: every instruction from
`0x63b0980` to `0x63b15e9` was read; every jump target was
checked to lie inside the FDE; no instruction was skipped.
The unrolled bitmap scans (word-by-word, 8-at-a-time blocks)
were read as instances of one scan pattern, not traced
word by word.

## Implementation and comparison

Not yet implemented/measured: no independent Rust path for this
helper exists in this packet; the verifier checks bytes,
counts, calls, census, and MANIFEST only. No Cargo graph, no
build comparison, no normalization masks are claimed.

## Results and limitations

Metrics: verifier exit 0 (5 excerpts, 327 bytes, 91 strict
mnemonics, 8 internal calls, census 1 E8 site, MANIFEST
15/15); unit tests 10/10; `make verify` exit 0 (29 manifests,
471 entries); `make catalogue-check` exit 0; `make test`
77 files attempted, 1 failed — the pre-existing
test_node115_catalogue Errno 18 cross-device-link error,
identical on pristine checkouts, not a packet regression;
this packet's file [36/77] passes 10/10.

What remains unknown: table contents and units, size-helper
contract, `+0x20` and `[slot+8]` identities, smallest-key
rationale, caller purpose, record-chain vs pool-chain node
sharing. No progress gate is requested; this packet is an
evidence record only.

Next question: decode the size helper `0x63e8c80` end to end:
what representative value it returns for its input, and how it
uses the `.bss` table at `0x6728180`.
