# foundation-hlu-validator-keys-94: what does the `base/src/hlu.rs` validator-key loader compute?

- Component: `foundation` (owner of `base/hlu.rs` in `research/components.json`), one
  bounded loader plus its collector.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference pin: can1357/hl `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  `base/hlu.rs` was used as a list of claims to test. No inferred implementation was copied.
- Claim: observations about three complete FDE windows and their data/relocation edges.
  Source-level names and types remain inferences.
- Included: the 418-byte loader `[0x13d2620, 0x13d27c2)`, the 403-byte collector
  `[0x13e0720, 0x13e08b3)`, the 20-byte Display shim `[0x13da090, 0x13da0a4)`,
  four source-location records, two messages, one format template, eleven
  `R_X86_64_RELATIVE` slots and two code sites that load the lazy storage's GOT slot.
- Excluded: the reader body `0x144e250`, the per-key constructor `0x13d1960`, the
  path-prefix static's initializer `0x164ff00`, both consumers beyond the validated
  slot load, all #115 addresses, target execution and Rust reconstruction.

## Why this packet

The component map asks for foundation helpers to be mapped and private code to be
separated from library code. The `assertion failed: keys.len() >= N_HLP_REQUIRED_VALIDATORS`
string is a private `base` message with no PR or packet yet. The reference tree has a
detailed narrative for it (`references/can1357-hl/base/hlu.rs`), but a narrative is not
evidence. This packet binds every claim it can test to bytes, relocations and decoded
operands, and records one claim the binary contradicts.

## Reproduce

Working directory: repository root. Platform used: Ubuntu 24.04.5 LTS on WSL2
(kernel 6.6.87.2), x86-64, Python 3.12.3, LLVM 18.1.3 (`llvm-objdump`,
`llvm-dwarfdump`), GnuPG 2.4.4. The checker and tests use Python's standard library
and the repository's `tools/elf_index.py` only. Exploratory queries used pyelftools 0.32
and Capstone 5.0.6 outside the repository; neither is needed to reproduce.

Submodules and LFS inputs were materialized as CONTRIBUTING describes. No input or
submodule pin changed.

```sh
make doctor
make verify test catalogue-check
make reproduce
python3 tools/foundation_hlu_keys.py --check research/work-items/foundation-hlu-validator-keys-94/evidence.json
python3 research/work-items/foundation-hlu-validator-keys-94/crosscheck.py > work/hlu-retained.json
python3 research/work-items/foundation-hlu-validator-keys-94/crosscheck.py --objdump llvm-objdump > work/hlu-fresh.json
cmp work/hlu-retained.json research/work-items/foundation-hlu-validator-keys-94/boundaries.json
cmp work/hlu-fresh.json research/work-items/foundation-hlu-validator-keys-94/boundaries.json
python3 -m unittest tests.test_foundation_hlu_keys -v
```

`make doctor` reported `analysis_ready: true`, `exact_rebuild_ready: false`. No target
binary, captured service, networked node, chain operation, key file or model-backed
program was executed or read.

Raw exports were generated with:

```sh
llvm-objdump -d --start-address=0x13d2620 --stop-address=0x13d27c2 artifacts/node/94/hl-node  # loader
llvm-objdump -d --start-address=0x13e0720 --stop-address=0x13e08b3 artifacts/node/94/hl-node  # collector
llvm-objdump -d --start-address=0x13da090 --stop-address=0x13da0a4 artifacts/node/94/hl-node  # shim
llvm-objdump -d --start-address=0x13cd040 --stop-address=0x13cd257 artifacts/node/94/hl-node  # consumer-a
llvm-objdump -d --start-address=0x14b14c0 --stop-address=0x14b1612 artifacts/node/94/hl-node  # consumer-b
llvm-dwarfdump --eh-frame artifacts/node/94/hl-node   # FDE extents, see below
```

The `*.objdump.txt` files retain complete disassembly of those windows. `crosscheck.py`
requires each one to decode contiguously from its FDE start to its FDE end and to match
the authenticated bytes, and requires every locked instruction to be an instruction start.
`MANIFEST.sha256` covers every packet file.

## Observations

All addresses are **ELF VAs**, with no loader or Ghidra rebase. The checker resolves
sections rather than assuming one VA/file-offset relationship.

### Windows, unwind records and how the loader is reached

| Window | FDE record VA | CIE VA | Extent | Instructions |
| --- | --- | --- | --- | --- |
| loader | `0xfc65ec` | `0xfbdc2c` | `[0x13d2620, 0x13d27c2)`, 418 bytes | 102 |
| collector | `0xfc70e0` | `0xfbdc2c` | `[0x13e0720, 0x13e08b3)`, 403 bytes | 107 |
| shim | `0xce6cd4` | `0xce1518` | `[0x13da090, 0x13da0a4)`, 20 bytes | 5 |

LLVM's independent `--eh-frame` dump reports the same three PC ranges. The checker reads
each FDE's CIE pointer, pcrel/sdata4 initial PC and range from the record bytes.

- There is **no** `e8 disp32` call to the loader anywhere in `.text` (70 MB scanned).
- Exactly one `R_X86_64_RELATIVE` addend equals the loader start: `.data` slot
  `0x577ab08`, whose pre-relocation bytes are zero. Exactly one RELATIVE addend equals
  `0x577ab08`: GOT slot `0x576ea08`.
- A REX.W `8b`/`8d` rip-relative byte scan finds two loads of `0x576ea08`: `0x13cd07d`
  (in FDE `[0x13cd040, 0x13cd257)`) and `0x14b1501` (in FDE `[0x14b14c0, 0x14b1612)`).
  Both are validated as instruction starts by decoding their windows from the FDE start.
  At `0x13cd084` the first consumer tests a dword at storage+0x18 and then reads a
  length at storage+0x10. This is not a complete xref census.

### Loader dataflow

1. **Lazy prefix static.** `r14` = `[0x576e928]` = `0x577b288` (RELATIVE). If the dword at
   `0x577b288+0x50` is nonzero, it calls `0x4ee3b20` (slot `0x576e8b8`) with `esi = 1`
   and the location `/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/std/src/sync/once.rs:219:20`,
   then continues. The storage at `0x577b288` itself holds RELATIVE `0x164ff00`.
2. **Path format.** The single format argument is `{value: 0x577b288+0x18, fmt: 0x13da090}`.
   The shim loads `(ptr, len)` from `+0x8`/`+0x10` of its argument and tail-calls
   `[0x576e000]` = `0x1573450`. The template at `0x1f881c` is the byte `0xc0`, the byte
   `0x2a` (42), then the 42-byte literal **`/hyperliquid_data/main_validator_keys.json`**.
   The formatter is `[0x576e040]` = `0x1344760`.
3. **Read.** It calls `0x144e250` with `(out, path_ptr, path_len, &loc)` where `loc` is
   `base/src/hlu.rs:57:13`.
4. **Err test.** `neg rax; jo` on the returned first word: the unwrap arm is taken iff that
   word is `i64::MIN`. That arm passes the 43-byte message
   ``called `Result::unwrap()` on an `Err` value`` (`0x216f9d`) and location
   `base/src/hlu.rs:58:18` to `[0x576e048]` = `0x157aa10`, the same target as the
   unwrap arm in `foundation-hour-94`.
5. **Path buffer freed** through `[0x576e010]` = `0x54c8cb0` when its capacity is nonzero.
6. **Assertion.** `cmp r13, 1; jbe` on the returned length: a length of **0 or 1** takes the
   arm with the 57-byte message `assertion failed: keys.len() >= N_HLP_REQUIRED_VALIDATORS`
   (`0x216e5d`), location `base/src/hlu.rs:61:13`, and `[0x576e108]` = `0x157b7f0`, the
   same target as the assertion arm in `foundation-hour-94`.
7. **Collect.** `shl r13, 5` forms `end = ptr + len * 32`. An into-iterator
   `{buf, ptr, cap, end}` and the caller's return slot go to `0x13e0720`.

The three `hlu.rs` records share one relocated path (`0x1ecb91`, length 44). The text
immediately after the assertion message in `.rodata` is an unrelated
`base/src/ren.rs` path. Adjacency is not attribution; the relocated records are.

### Collector

- `shr rbx, 5` on `end - ptr`, then `imul r12, rbx, 0x98`: **32-byte input elements**
  and **152-byte output elements**.
- The capacity guard immediate `0x1af286bca1af2860` equals exactly
  `(isize::MAX // 152) * 32`. The output stride therefore also follows from the
  allocation limit, not only from the `imul`.
- Loop `0x13e07c0..0x13e07ff`: copy 32 bytes to the stack, call `[0x576e848]` =
  `0x13d1960` with `(out, &key)`, copy `0x98` bytes into the output buffer, advance
  input by `0x20` and output by `0x98`. It then frees the input buffer (`cap << 5` bytes)
  and stores `{cap, ptr, len}` to the return slot.

## Reference comparison (`references/can1357-hl` `999556f`, claims only)

| Reference claim | Binary result |
| --- | --- |
| `N_HLP_REQUIRED_VALIDATORS = 2` and `assert!(keys.len() >= …)` | Consistent: unsigned `len <= 1` panics, so the minimum is 2. |
| Keys are `[u8; 32]` | Consistent: 32-byte stride in the loader and the collector. |
| `LazyLock::new(load_hlp_validator_wallets)` | Consistent: the loader is the RELATIVE initializer stored in `.data` storage `0x577ab08`. That storage's `Once` wiring is not traced. |
| `.expect("called `Result::unwrap()`…")` | Consistent with an unwrap at `hlu.rs:58:18`. `.unwrap()` and `.expect` with that text reach the same helper and are not distinguished here. |
| One wallet per key via a private-key constructor | Consistent: one call to `0x13d1960` per 32-byte key, 152-byte results. The constructor's name and the output type are not validated. |
| `Path::new("/hyperliquid_data").join("main_validator_keys.json")` | **Contradicted.** The binary formats a runtime String (`0x577b288+0x18`) followed by the single 42-byte literal `/hyperliquid_data/main_validator_keys.json`. A constant `DATA_DIR` join has no prefix argument and no format template. |
| Reader branches on a case-insensitive `.rmp` extension | Not validated. The reader contains a `..` comparison (`0x144e34a`), a last-`.` byte test (`0x144e371`) and a `0x72` (`r`) comparison (`0x144e3a8`); these are leads only. |

## Inferences and unknowns

- **Inferred:** this is the lazy initializer of a process-wide `Vec` of HLP validator
  wallets loaded from an operator key file, with a private `base/src/hlu.rs` origin. The
  binary has no recovered symbol here.
- **Path prefix:** what the String at `0x577b288+0x18` contains (for example a home or data
  directory) is **not established**. Its initializer `0x164ff00` is not decoded.
- The `0xc0`/length/literal template layout is described by its bytes only; the
  formatter's template grammar is not decoded.
- `esi = 1` to the Once slow path, plus the `once.rs:219:20` location, fits a force/ignore-poison
  call such as `LazyLock` uses. The Once implementation is not decoded.
- Library ownership of `0x1344760`, `0x157aa10`, `0x157b7f0`, `0x4ee3b20`, `0x54c8cb0` and
  `0x1573450` is not closed. A private location argument does not make a generic helper private.
- Reader `0x144e250` (1,761 bytes), its error type and file-format handling are out of scope.

## Implementation, controls and results

No independent Rust implementation, lockfile, equivalence comparison, normalization mask,
behavioral execution or whole-ELF match is claimed. All are **not yet implemented/measured**.
Instruction bytes in the checker are static evidence locks, not executable reconstruction or
transplanted code. New checker/test/documentation code is independently authored; imported
bytes and disassembly keep the artifact's original rights.

Baseline `1f8c67c`: `make verify`, `make test` (**431 tests, OK**) and `make catalogue-check`
pass. With this change: `make verify`, `make test` (**443 tests, OK**), `make catalogue-check`
and `make reproduce` pass. The 12 added tests use the authenticated real target (they skip
only if LFS is absent) and reject:

- wrong identity and truncation;
- a changed byte in each window, including both loader ends;
- changed threshold, key stride, input stride, output stride, capacity guard and Once flag operands;
- a changed loader FDE range and a changed `hlu.rs` line;
- a changed template literal, template length byte and assertion message;
- changed RELATIVE targets for the lazy storage, its GOT slot, the prefix-static slot and the
  per-key constructor slot;
- an extra RELATIVE reference to the loader, an extra `e8` call and an extra storage-slot load
  (inserted only into `int3` padding outside every claimed window);
- a shifted address, changed bytes and truncated retained disassembly.

Structural mutations bypass only the digest gate in the test helper, so they reach downstream
checks. The command-line tool always authenticates the complete target first. Identity cases
pass for both retained and freshly regenerated LLVM output. Hosted CI was not observed during
local validation.

**No progress gate requested.** Foundation's gates and generated progress files are unchanged.
The denominator is one loader, one collector and one shim, not all `base` helpers.

Next question: decode the prefix static's initializer `0x164ff00` to establish what the runtime
String contains, then validate the reader `0x144e250`'s file-format branches before attempting
a Rust reconstruction of `hlu.rs`.
