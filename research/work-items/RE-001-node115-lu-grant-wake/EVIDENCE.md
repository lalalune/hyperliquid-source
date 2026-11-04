# RE-001-node115-lu-grant-wake: the writer of waiter node +0x10 = 1

- Component ID: RE-001-node115-lu-grant-wake
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  105,896,032 bytes,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main
  `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (node-115-only migration)
- Claim status: observation (grant mechanism, slot-word rewrite, wake loop,
  census, panic provenance); inference (reader-count reading for uniform
  `0x10`-valued nodes; deadline-expiry grant interpretation); unresolved
  (caller-side `esi = 1` role; bit-2/bit-3 gate semantics; spill-time
  SmallVec field migration; mixed-shape slot-word sums)
- Scope included and excluded: see README.md (Scope section). In short:
  the full FDE `0x5bb35f0..0x5bb3c94` end to end; callees referenced by
  address/GOT slot only; no execution; no caller-role claims beyond the
  3-site `esi = 0` sample.

## Reproduce

Exact commands, tool versions, options, input and output hashes, working
directory, platform, environment requirements, and any declared
execution/side effects:

- Working directory: the repository worktree at upstream main
  `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. Fork main HEAD
  `1f8c67c63ca4794c9689235471c60297f8a5c985` is an ancestor; no branch
  state is required for this evidence.
- Input: `artifacts/node/115/hl-node` (105,896,032 bytes, SHA-256 above).
- Tools: GNU objdump (disassembly), readelf (relocations, sections),
  Python 3.12 (verifier, census scans, hash checks). No Ghidra/IDA/REA
  output is used for any claim in this packet.
- Commands:
  - `objdump -d --start-address=0x5bb35f0 --stop-address=0x5bb3c94
    artifacts/node/115/hl-node` → `fde35f0.objdump.txt` (446
    instruction lines).
  - `python3 tools/node115_lu_grant_wake.py` → exit 0; checks digest,
    FDE bytes, opcodes, relocations, panic Locations, packet hex,
    packet records, and census.
  - `python3 -m pytest tests/test_node115_lu_grant_wake.py -q` → 7
    tests, all passing (the packet's own file; the full suite's one
    pre-existing catalogue failure is unrelated).
- Coordinate system: `.text` file offset = VA − 0x1000;
  `.data.rel.ro`/`.got` file offset = VA − 0x2000; `.rodata` file
  offset = VA. All addresses in this packet are virtual addresses
  unless marked as file offsets.
- Execution/side effects: none. The node binary was never executed. All
  reads are static (file bytes, ELF headers, relocations, disassembly).

## Evidence

Original addresses and coordinate system (above), validated boundaries,
raw disassembly/data, callers/callees/indirect calls, source mapping
evidence, ABI/layout/rounding/overflow observations. Raw files beside
this record: `fde35f0.hex` (1700 bytes), `fde35f0.objdump.txt` (446
instruction lines), `records.json` (all counts, sites, and provenance).

Analysis was complete for the FDE range: every instruction in
`0x5bb35f0..0x5bb3c94` was read from the objdump dump, and every count
in README.md was computed from the dump or the binary bytes (FDE bytes
1700 = 1497 body + 203 tail; instructions 446 = 402 body + 44 tail;
5 nop paddings; 1 ret at `0x5bb3bc8`; 5 grant stores; 1 futex wake
site; 0 E8 callers; 66 GOT sites across 26 FDEs).

Key raw facts (all verified against objdump/readelf output):

- Golden-ratio hash: `49 be 15 7c 4a 7f b9 79 37 9e` at `0x5bb3605`
  (`movabs r14,0x9e3779b97f4a7c15`).
- Bucket claim: `lock cmpxchg entry,1` (`f0 48 0f b1 2c 39`) at
  `0x5bb3681`; release `lock xadd [rbx],-1` (`f0 48 0f c1 03`) at
  `0x5bb3a5e`.
- Walk gates: `test al,0x8` (`a8 08`) at `0x5bb376a`; `test al,0x4`
  (`a8 04`) at `0x5bb3777`; accumulator add `49 01 c5` at `0x5bb3790`.
- Grant computation: `or bpl,cl` (`40 08 cd`) at `0x5bb38fd`;
  `and bpl,al` (`40 20 c5`) at `0x5bb3902`; `movzx edi,bpl`
  (`40 0f b6 fd`) at `0x5bb393e`; slot-word store `48 89 08` at
  `0x5bb3915`.
- Grant stores: `49 89 79 10` at `0x5bb3983`; `48 89 79 10` at
  `0x5bb39c3`, `0x5bb39e5`, `0x5bb3a08`, `0x5bb3a2b`.
- Wake: `cmp [rbx-0x8],0x2` (`48 83 7b f8 02`) at `0x5bb3b1b`;
  `mov edi,0xca` (`bf ca 00 00 00`) at `0x5bb3b25`;
  `mov edx,0x81` (`ba 81 00 00 00`) at `0x5bb3b2a`;
  `mov ecx,1` (`b9 01 00 00 00`) at `0x5bb3b2f`.
- Xorshift: `c1 e6 0d` (13), `c1 ef 11` (17), `c1 e1 05` (5);
  magic `48 69 f1 83 de 1b 43` (`0x431bde83`); shift 50
  (`48 c1 ee 32`); mod `10^6` (`69 f6 40 42 0f 00`); compare `10^9`
  (`81 f9 00 ca 9a 3b`); carry `81 c1 00 36 65 c4` (−10^9).
- GOT slots (rip-relative targets verified from instruction bytes;
  addends verified from R_X86_64_RELATIVE relocations): table
  `0x64ec148` → `0x64fff28`; table-create `0x64ec158` →
  `0x5bb6400`; cleanup `0x64ec150` → `0x5bb66b0`; helper `0x64ec160`
  → `0x5bb6790`; self `0x64e1000` → `0x5bb35f0`; syscall `0x64e06b8`,
  memcpy `0x64df508`, free `0x64df4a0` (GLOB_DAT externals).
- Panic Locations (`.data.rel.ro`, VA − 0x2000; file/line/col from
  struct bytes): parking_lot.rs 352:45 (`0x64bd260`), 363:23
  (`0x64bd290`), 352:5 (`0x64bd278`); raw_rwlock.rs 963:31
  (`0x64bd248`); smallvec lib.rs 1124:13 (`0x64bd2c0`), 2243:17
  (`0x64bd478`); deadline message `overflow when adding duration to
  instant` (40 bytes, `.rodata` `0x94a2c1`).
- Callers: 0 direct E8 (every-position scan over all `.text`); 66
  GOT-indirect sites (65 call + 1 jmp) via slot `0x64e1000` across 26
  FDEs (list in records.json); 3 sampled sites pass `esi = 0`
  (`0x5ce74e3`, `0x15471e3`, `0x4fca510`).
- Layouts: waiter node `+0x0` key, `+0x8` link, `+0x10` status
  (0 = retry, 1 = proceed), `+0x18` weight (0, 8, or `0x10` by waiter
  kind), `+0x20` futex word, `+0x24` has-deadline byte (from #190/#192,
  consistent with this FDE's uses); bucket entry 64 bytes with
  `+0x8` head, `+0x10` tail, `+0x18` deadline seconds, `+0x20`
  deadline nanoseconds, `+0x28` xorshift seed (from #188, consistent
  here); SmallVec entries 24 bytes `{node, flag, futex-ptr}`.
- Rounding/overflow: jitter is `(seed * 0x431bde83 >> 50) mod 10^6`
  (not a clamp); deadline carry normalizes on reaching `10^9` with a
  signed-overflow panic on the seconds increment; the `+0x18` sum add
  has its own overflow panic (raw_rwlock.rs:963:31); the vector count
  increment has a capacity-overflow panic (smallvec:1124:13).

## Implementation and comparison

Independent Rust path, Cargo.lock, compiler/linker/build flags,
two-build result, raw and normalized comparisons and masks,
helper/data/relocation closure, fixture identities, boundary/error
cases and corruption controls: not yet implemented/measured. This
packet is a static-evidence packet only; no Rust reconstruction of
this FDE is claimed. Corruption controls exist at the verifier/test
level (not at a Rust-implementation level): the packet's unit tests
reject a flipped grant-store byte, a flipped futex-number byte, a
flipped golden-ratio byte, a tampered records FDE end, and a tampered
hex reference byte.

## Results and limitations

Machine-readable metrics with explicit denominators: see README.md
(Results and limitations) and `records.json`. What passed: the
verifier (digest, FDE bytes, opcodes, relocations, panic Locations,
packet hex, packet records, census) and the packet's 7 unit tests.
What remains unknown: caller-side `esi = 1` role; bit-2/bit-3 gate
semantics; spill-time SmallVec field migration; mixed-shape slot-word
sums; caller consumption of the return value; uniqueness of the
`+0x10 = 1` writer beyond the stated scan evidence (register-source
stores are outside the immediate-store scan; the positive claim does
not depend on it). No gate is requested beyond the standard packet
checks (verifier, unit tests, doctor, verify, catalogue-check, full
test suite with only the pre-existing catalogue failure).

Next question: which caller path grants explicitly (`esi = 1`), and
what unlock or timeout operation does it belong to — complete the
caller-side role of the 66 GOT sites, starting from the 26 caller FDEs
in records.json.
