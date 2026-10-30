# foundation-unwrap-guard-94: what does the signed-value guard window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call
  edges; its source-level name and types remain unproven.
- Included: the 51-byte FDE window, its thirteen int3 padding bytes, the sign
  test and its two static paths, the panic arm with its readable message and
  argument slots, and the tail call through its relocated slot.
- Excluded: the tail-call target's body, the panic helper's body, the caller
  and any incoming calls, other sign or unwrap guards, all #115 addresses,
  target execution, Rust reconstruction, and complete caller behavior.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library
code from private helpers. A reference label or a matching string cannot
establish that mapping. This packet binds one small, previously unclaimed
window: a sign test on a 64-bit input, a panic path on the negative case
carrying a readable message, and a tail call on the non-negative case. It
establishes a concrete small entrypoint for further reconstruction without
declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or
test in the tree mentions `0x1510260`, and no open pull request title
mentions it or unwrap guards. Its bytes overlap nothing in the hour packet
(`0x14509f0`), the days-to-date packet (`0x1450810`), or any other
foundation packet. The panic helper slot `0x576e048` is shared with the hour
packet's panic arm (same relocated target `0x157aa10`); sharing one helper
slot is not a packet overlap, because the claimed window, message, and
argument slots differ.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python
3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use
Python's standard library only. No llvm-objdump, Ghidra, or Java was used;
GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in
CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_unwrap_guard.py --check research/work-items/foundation-unwrap-guard-94/evidence.json
python3 -m unittest tests.test_foundation_unwrap_guard -v
```

`make doctor` reported `analysis_ready: true` (git-lfs 3.4.1 present; the
target artifacts are materialized and are authenticated by exact size
and SHA-256 in the checker below). No target binary, captured service,
networked node, chain operation, or model-backed program was executed.
All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x1510260 --stop-address=0x15102a0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `unwrap.objdump.txt` file retains complete disassembly of the window
including its padding. The `unwrap.frames.txt` file retains excerpts
selecting the shared CIE at offset `0`, the FDE at `.eh_frame` section
offset `0x13ca4` (this window), and the FDE at offset `0x2bff84` (the
tail-call target). The checker locks these raw FDE records and their shared
CIE, and reads their PC/range fields. It does not add a second general FDE
decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra
rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`;
the retained `.eh_frame` has equal file offsets and VAs. The tools resolve
sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and the index-stride correction

- `.eh_frame+0x13ca4` describes `[0x1510260, 0x1510293)`, 51 bytes. GNU's
  independent frame dump agrees. Complete linear decoding from that start
  gives the instruction sequence below, ending exactly at the FDE endpoint.
- The unwind index stride to the next entry is 64 bytes, ending at
  `0x15102a0`, only because thirteen `int3` bytes (`0xcc`) pad the window
  after the FDE end. The stride is **not** the FDE extent; any description
  of this window as "64-byte FDE-bounded" would overstate the frame by
  those thirteen padding bytes, and the checker locks the 51-byte body and
  the padding separately.
- A `R_X86_64_RELATIVE` relocation maps slot `0x576e010` to `0x54c8cb0`
  and slot `0x576e048` to `0x157aa10`. Both slots sit in `.got`.

### Body behavior: one sign test, one panic path, one tail call

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x1510260` | `test rsi,rsi` | Sign test on the 64-bit input |
| `0x1510263` | `js 0x151026d` | Negative input goes to the panic arm |
| `0x1510265` | `xor edx,edx` | Non-negative path clears edx |
| `0x1510267` | `jmp *slot 0x576e010` | Tail call to `0x54c8cb0` |
| `0x151026d` | `push rax` | Panic arm stack slot |
| `0x151026e` | `lea rdi,0x21da2e` | Panic message pointer |
| `0x1510275` | `lea rcx,0x56709e8` | First pointer argument |
| `0x151027c` | `lea r8,0x5670b58` | Second pointer argument |
| `0x1510283` | `lea rdx,[rsp+7]` | Stack-slot argument |
| `0x1510288` | `mov esi,0x2b` | Message length, 43 |
| `0x151028d` | `call *slot 0x576e048` | Panic helper at `0x157aa10` |
| `0x1510293` | `int3` padding (13 bytes) | Noreturn tail, then stride end |

The tail-call target `0x54c8cb0` sits inside `.text` and inside the R E
LOAD segment (`[0x1343c80, 0x5661250)`), and has its own FDE
(`[0x54c8cb0, 0x54c8d55)`, 165 bytes, same shared CIE). It is left unnamed
and undecoded here.

### The panic arm and its argument slots

The panic arm loads `rdi = 0x21da2e`, `esi = 0x2b` (43), and
`rdx = rsp+7`, plus `rcx = 0x56709e8` and `r8 = 0x5670b58`, then calls
through slot `0x576e048` (relocated to `0x157aa10`), after which only
`int3` padding follows, consistent with a noreturn path. The data is
connected through actual PC-relative instructions and
`R_X86_64_RELATIVE` relocations, not just substring presence:

| Item | VA | Value |
| --- | --- | --- |
| Message | `0x21da2e`, 43 bytes | `` called `Result::unwrap()` on an `Err` value `` |
| Panic helper slot | `0x576e048` | Target `0x157aa10` (unnamed here) |
| rcx slot | `0x56709e8` | File qwords `[0, 0, 1, 0]`, no relocation entry |
| r8 slot | `0x5670b58` | Relocated first field `0x2005f6`, second field 91, third field `0x4900000548` |
| Path string | `0x2005f6`, 91 bytes | `/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/bytes-1.11.1/src/bytes.rs` |

The r8 slot's second field (91) equals the path string's length, and its
first field relocates to that string. The rcx slot's fields and the r8
slot's third field are retained raw and uninterpreted: no line, column, or
record layout is claimed for them.

## Inferences and unknowns

- **Inferred, weakly:** this is a guard that rejects negative inputs with
  an unwrap-style panic message and otherwise forwards to another routine.
  That label rests only on the sign test, the message text, and the tail
  call. The binary has no recovered symbol name here.
- The message text is a standard-library-style unwrap message, but that
  resemblance alone does not prove which library routine owns this window,
  what type the input is, or what the tail-call target does with the
  non-negative value (including the cleared `edx`).
- The bytes.rs path string is decoded evidence for one argument slot only.
  It does not prove the caller's source file, and no line or column is
  decoded from either argument slot.
- The tail-call target and the panic helper are left unnamed: their
  library ownership, transitive callees, unwind behavior, and
  non-returning behavior are not closed.
- No incoming-call census is claimed: no `.text` scan for callers of this
  window was used, and none is needed for the three observed behaviors.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence
comparison, normalization mask, behavioral execution, or whole-ELF match is
claimed. All are **not yet implemented/measured**. The raw instruction bytes
in the checker are static evidence locks, not executable reconstruction or
transplanted code. New checker/test/documentation code is independently
authored; imported bytes and disassembly retain the artifact's original
rights.

The repository's required verification, catalogue, and test recipes are run
for this change below. After the change, the new checker and the new unit
test pass. The added controls use the authenticated
real target (explicitly skip if LFS is absent), not fabricated behavior
fixtures. They reject:

- wrong identity and truncation;
- changed sign-test, branch, xor, jump, or call bytes;
- changed FDE extent, source message, relocated slot bytes, and FDE padding bytes;
- changed panic message, argument path string, and argument slot fields;
- changed tail-call or panic-helper relocation targets;
- changed tail-call target FDE extent.

Structural mutations deliberately bypass only the digest gate in the test
helper, so they exercise downstream checks instead of all failing at
SHA-256. The command-line tool always authenticates the complete target
first.

**No progress gate requested.** Foundation's gates and generated
progress files stay unchanged. The denominator here is one bounded window,
not all guards. Next question: attribute the tail-call target at
`0x54c8cb0` far enough to state what the non-negative path forwards to,
before reconstructing Rust.
