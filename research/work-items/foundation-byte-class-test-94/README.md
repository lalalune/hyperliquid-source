# foundation-byte-class-test-94: what does the 69-byte window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 69-byte FDE window, its eleven int3 padding bytes, the byte-class rule, the bit-test mask, the single confirmed caller and its argument setup, the no-naming-relocation scan, and the one-direct-caller scan.
- Excluded: the meaning of the accepted byte set, the meaning of the input byte, the caller's behavior beyond its argument setup, other byte-class helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: nineteen instructions, no calls inside, forward branches plus one bit-test path, and a rule fully determined by signed byte compares and one 64-bit mask. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5430860`, no open pull request title mentions it or byte-class-test, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, or later foundation packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_byte_class_test.py --check research/work-items/foundation-byte-class-test-94/evidence.json
python3 -m unittest tests.test_foundation_byte_class_test -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5430860 --stop-address=0x54308b0 artifacts/node/94/hl-node
objdump -d --start-address=0x5430900 --stop-address=0x5430a5e artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete disassembly of the single confirmed caller FDE. The `frames.txt` file retains excerpts selecting the window FDE at `.eh_frame` section offset `0x2badd4`, the next FDE at `0x2bade8`, and the caller FDE at `0x65d378`. The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000` (segment VA base `0x1343c80`, file offset base `0x1342c80`); the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2badd4` describes `[0x5430860, 0x54308a5)`, 69 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x54308a4` is inside the FDE).
- The unwind index stride to the next entry is 80 bytes, ending at `0x54308b0`, only because eleven `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "80-byte FDE-bounded" would overstate the frame by those eleven padding bytes, and the checker locks the 69-byte body and the padding separately.
- The next FDE starts exactly at `0x54308b0` (`[0x54308b0, 0x54308cc)`, 0x1c bytes); the checker locks its PC/range, and its full record is retained in `frames.txt`.
- The window opens with `endbr64` (an observation, not a scout deviation).

### Body behavior: signed compares, one bit-test path, no calls

Decoded from the FDE start, the window takes a byte in `dil`:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x5430860` | `endbr64` | Entry marker |
| `0x5430864` | `xor %eax,%eax` | Clear the return register first (so the `sete`/`setb` paths leave full-register 0/1) |
| `0x5430866` | `cmp $0x5c,%dil` | Signed-byte compare against 0x5c |
| `0x543086a` | `jg 0x5430885` | Signed dil > 0x5c → fall to the `ret` at `0x5430885` with eax = 0 |
| `0x543086c` | `cmp $0x22,%dil` | Signed-byte compare against 0x22 |
| `0x5430870` | `jg 0x5430890` | Signed dil > 0x22 → bit-test path |
| `0x5430872` | `cmp $0xa,%dil` | Compare against newline |
| `0x5430876` | `je 0x5430880` | Equal → `mov $0x1,%eax; ret` |
| `0x5430878` | `cmp $0xd,%dil` | Compare against carriage return |
| `0x543087c` | `sete %al` | 1 iff equal, else 0 (eax was cleared) |
| `0x543087f` | `ret` | |
| `0x5430880` | `mov $0x1,%eax` | The 0x0a path's return value |
| `0x5430885` | `ret` | Shared by the > 0x5c path (eax = 0) |
| `0x5430886` | 10-byte `cs nopw` | Unreachable alignment padding: it follows a `ret`, is targeted by no branch (the `jg` at `0x5430870` lands directly on `0x5430890`), and is locked as body bytes, not an executed instruction |
| `0x5430890` | `movabs $0x200000000800001,%rax` | Bit-test mask |
| `0x543089a` | `sub $0x23,%edi` | Bit-test index base |
| `0x543089d` | `bt %rdi,%rax` | Test bit (edi - 0x23) mod 64 of the mask |
| `0x54308a1` | `setb %al` | 1 iff the bit is set (eax was cleared) |
| `0x54308a4` | `ret` | |

Rule, with `signed` the signed 8-bit reading of `dil`:

- `signed(dil) > 0x5c` → 0. As byte values this is `0x5d..0x7f`; bytes `0x80..0xff` read as negative and do not take this path.
- `signed(dil) > 0x22` → bit `(edi - 0x23) mod 64` of mask `0x200000000800001`. As byte values this path covers `0x23..0x5c`.
- `dil == 0x0a` → 1; `dil == 0x0d` → 1; else 0.

The mask `0x200000000800001` has exactly bits 0, 23, and 57 set (2^57 + 2^23 + 2^0). For a zero-extended byte input in `0x23..0x5c` the bit-test index is byte − 0x23, so the accepted bytes on that path are `0x23` (`"`), `0x3a` (`:`), and `0x5c` (`\`). Combined with the two single-byte paths, the full accepted set is exactly five bytes: `0x0a`, `0x0d`, `0x23`, `0x3a`, `0x5c`.

### The mod-64 caveat, stated exactly

The bit-test path uses the full `edi`, not just `dil`: the index is `(edi - 0x23) mod 64` because `bt` masks its index to six bits. The window's comparisons read only `dil`, so a caller passing an `edi` whose upper bits are nonzero would take the bit-test path based on the low byte but test a bit indexed by the full value. The confirmed caller does not do this: it sign-extends the byte into `edi` (`movsbl`, see below), so for that caller the index is exactly byte − 0x23. No other caller behavior is claimed, and the general mod-64 behavior is part of the rule, not an edge case to smooth over.

### Scout correction, stated prominently

The round-10 scout note listed the bit-test set as offsets 0, 15, 49, i.e. chars `0x23`, `0x32`, `0x54`. That is wrong. The retained mask immediate `0x200000000800001` decodes to bits 0, 23, 57, i.e. chars `0x23`, `0x3a`, `0x5c` — verified by direct bit extraction from the immediate, and locked in the checker (mask immediate bytes plus the bit list). The scout's set is replaced by the verified set everywhere in this packet. All other scouted elements verified exactly: FDE range, 69-byte body, 11 padding bytes, one caller, no naming relocation.

### Incoming calls: one direct caller, boundary-confirmed

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly one direct `e8` site — `0x54309be` (bytes `e8 9d fe ff ff`), confirmed as an instruction start by linear disassembly from its caller FDE start (`0x5430900..0x5430a5e`). This is explicitly not a complete xref census. The caller's setup immediately before the call is `movsbl 0x0(%rbp),%r15d; mov %r15d,%edi; mov %r15d,%r14d` — the byte is sign-extended into `edi`. Caller purpose beyond that setup is not claimed.

### Data edge: no naming relocation

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan of `.rela.dyn` and `.rela.plt`, counts locked in the checker). The absence of a naming relocation does not identify the window's provenance.

### Symbol hint, explicitly disclaimed

objdump annotates the address with a nearest preceding `ctype` `do_widen` symbol `0x488a60` bytes below; at that distance it proves nothing, and no stdlib or private provenance is claimed either way.

### Nearest claimed window

Dual-zero test `0x5341920` (packet #36), `0xeef40` away; nothing in `0x54308xx` claimed.

## Inferences

- The "byte-class test" label is an inference from the observed rule (a byte in, a 0/1 out, with a small accepted set). It is kept separate from the rule itself.
- The accepted set is reported literally and is not assigned to a category: it is newline, carriage return, double quote, colon, and backslash. Any reading of it as an escape set, a delimiter set, or anything else would go beyond the bytes.

## Unknowns

- What the input byte represents, what the caller does with the 0/1 result, and why these five bytes are the accepted set.
- Whether other callers reach the window indirectly (the scan covers direct `e8` sites only).
- The window's source-level name, type, and component ownership.

## Limits

- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- The rule is stated for the window's own bytes; the general mod-64 bit-test behavior applies only when `edi` is not a clean zero- or sign-extended byte, and only the confirmed caller is known to sign-extend.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
