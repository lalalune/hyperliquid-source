# RE-001: pin node #115 RegisterEncryptionBuiltins

## Task and bounded question

Task **RE-001** (the node #115 function map). Which factory entries does
`rocksdb::_GLOBAL__N_1::RegisterEncryptionBuiltins()` register, what
`PatternEntry` does each carry, and what does each creator lambda build
when it is invoked?

## Answer

The host lambda `0x5ff88c0..0x5ff9c50` (catalogue identity
`_ZZN7rocksdb12_GLOBAL__N_1L26RegisterEncryptionBuiltinsEvENKUlvE_clEv.isra.0`,
4,550/5,008 published-crate rebuild match) creates the `encryption`
`ObjectLibrary` and registers three `FactoryEntry` records:

| # | map name | creator (`_M_invoke` / manager) | pattern | elements | flag |
|---|----------|----------------------------------|---------|----------|------|
| 1 | `EncryptionProvider` | E_ `0x5ff6d60` / `0x5fefa50` | `CTR` | `://test`, mode 2 | 1 |
| 2 | `EncryptionProvider` | E0 `0x5ff6a00` / `0x5fefa80` | `1://test` | — | 1 |
| 3 | `BlockCipher` | E_ `0x5ff7120` / `0x5fefab0` | `ROT13` | `:`, mode 3 | 1 |

- Block 1 calls the registry getter `0x61f92b0` (PR #4015), builds the
  0x90-byte `make_shared` library block (control-block vtable
  `0x64d00f0`, counts `0x100000001`, version float 1.0, SSO name
  `encryption`) and appends it to the registry libraries vector under
  the registry mutex.
- Blocks 2–4 each build one `FactoryEntry` (operator new `0x30`) with
  its `PatternEntry` (operator new `0x70`) and register it through the
  helper `0x5ff8260` (find-or-insert `0x5fd1da0`, append one qword,
  unlock; PR #3983 pins the map helpers).
- Entry 1's element is inserted through the vector grow helper
  `0x5ff7420`; entry 3's element is inserted inline when the vector
  has room, else through the same helper; entry 2's `PatternEntry` is
  built in place with both sub-pattern vectors empty (exact match
  only).
- The host runs once, on first use: its only direct referrer is the
  9-byte tail-call thunk `0x5ff9c50`, whose address is taken as the
  `pthread_once` callable at `0x5ffa77f` and `0x5ffba7f`.

## Creators

- **E0** `0x5ff6a00` builds a `CTREncryptionProvider` via C1 `0x5ff6880`
  from a `BlockCipher` looked up in the registry, then registers
  options via `Configurable::RegisterOptions` `0x6099ce0`.
- **E_** `0x5ff6d60` checks `EndsWith(name, "://test")` (`0x61d1390`);
  on the true branch it resolves `ROT13BlockCipherOptions` (literal
  `0x443890`) and then builds the provider; on the false branch it
  builds the provider directly.
- **BlockCipher E_** `0x5ff7120` finds `:` in the name, builds
  `ROT13BlockCipherOptions`, and creates the ROT13 cipher; a bad
  substring throws `out_of_range` (`basic_string::substr`).

## Layouts

- `PatternEntry` (0x70 bytes, vtable `0x64d8ed0`, pinned by PR #3983):
  +0x08 pattern string, +0x28 pattern-length copy, +0x30 vector of
  plain strings, +0x48 flag byte, +0x50 pointer, +0x58 vector of
  0x28-byte `{string, mode u32}` elements. The host's scratch struct
  at `rsp+0x130` confirms it field for field.
- `FactoryEntry` (0x30 bytes): +0x00 vtable, +0x08 `PatternEntry*`,
  +0x10..+0x20 `std::function` functor storage (16 zero bytes for
  these stateless lambdas), +0x20 manager, +0x28 invoker. D2 destroys
  the function via `manager(this+0x10, this+0x10, op 3)` and deletes
  the `PatternEntry` through its vtable slot 1.
- `std::function` managers `0x5fefa50` / `0x5fefa80` / `0x5fefab0`:
  op 0 stores the typeinfo address, op 1 clones the functor, op 2
  and op 3 are no-ops here (the effective clone is the bitwise
  `movdqa` copy of the `{manager, functor}` pair).
- Matching follows the pinned str-match `0x61f8430` + elem-match
  `0x61f8280` semantics (PR #3983): empty element vector means exact
  match only; otherwise the query must start with the pattern, every
  element must match in sequence, and the tail is decided by the last
  element's mode. So entry 1 matches `CTR` and `CTR://test`, entry 2
  matches only `1://test`, and entry 3 matches `ROT13` and
  `ROT13:<digits>`.

## Evidence

- `records.json` — semantic records only. Instruction-level detail
  lives in the verbatim objdump excerpts; mnemonics such as
  `endbr64` are genuine instructions present in the target binary,
  not placeholders.
- `excerpts/` — 26 whole-function verbatim objdump files, produced by
  `export_excerpts.py` with
  `objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin`
  run from the repository root.
- `frames.txt` — the 26 FDE ranges, checked against a fresh frame dump.
- `callers.tsv` — every pinned routine's direct calls, tail jumps,
  lea references and RELATIVE addends, with the enclosing FDE.
- `relocations.txt` — the RELATIVE records for the four vtables, their
  typeinfos, and the manager typeinfos, plus the typeinfo names.
- `census.py`, `export_excerpts.py`, `gen_records.py`, `verify.py` —
  the scripts that produced and check this packet.
- `MANIFEST.sha256` — SHA-256 of every packet file except itself.

## Verification

```
python3 research/work-items/RE-001-register-encryption-builtins-115/verify.py
```

Checks: binary digest vs provenance, manifest, excerpt regeneration
byte-for-byte, every excerpt instruction byte-for-byte vs the raw
binary, three seeded random gate spots (`0x5ff82ff`, `0x5ff73c7`,
`0x5ffbd79`) byte-for-byte vs a fresh objdump run and the raw binary,
frames, relocations, typeinfo names, literals, census reproduction,
records regeneration, the vtable map, the caller needles, and the
model tests (`tests/test_register_encryption_builtins_115.py`,
143 checks). Prints `ALL CHECKS PASSED` on success.

## Model

`tools/register_encryption_builtins_115.py` + `tests/test_register_encryption_builtins_115.py`
(143 checks): the registry with its libraries vector and
name-to-entries map, the three entries in registration order,
`PatternEntry.matches` per the pinned matcher, creator dispatch
(E0 / E_ / BlockCipher), the manager ops, and vector growth.

## Environment limits

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java, so the
repository gates (`make verify`, `make test`, `make catalogue-check`)
cannot be run here; the packet's own `verify.py` is the check that
was run. The registry getter, the map helpers and the `PatternEntry`
slots are cited from PRs #4015 and #3983, not re-derived here.

## Open unknowns

- ObjectRegistry +0x70..0x98 region (from PR #4015, still open).
- The two `pthread_once` host FDEs (`0x5ffa710..0x5ffaad9`,
  `0x5ffba10..0x5ffbdd9`) are unnamed in the catalogue; only their
  once-callable role is pinned.
- The E0 creator's cipher-lookup name (the virtual call at
  `0x5ff6c33`) is not pinned; the model resolves it through the
  registered `BlockCipher` entries.
- The E_ creator's fallback path (`0x5ff6f70`) builds the provider
  directly; which cipher it uses by default is not pinned.
- The BlockCipher creator's jump target `0x61d1540` is not pinned.
- The LibCB slots `0x5fefc70` / `0x5fefd00` / `0x5fefd50` /
  `0x5feff70` are cited from RELATIVE records, not individually
  disassembled.
- The `.init_array` entry `0x5ffbe80` (`endbr64; jmp 0x5ff7c90`) is the
  static-initialization chain entry in the encryption area; the full
  chain from `0x5ff7c90` to the once hosts is not traced.
- The fourth manager typeinfo (`0x64cf7e8`,
  `OptionTypeInfo::AsCustomSharedPtr<EncryptionProvider>`) is NOT
  used by the host; it is recorded only so it is not mistaken for a
  fourth creator.
