# RE-002: compact-string LSDA ownership on node94

- Component: `foundation`; one bounded static provenance question. No gate change.
- Target: Linux x86-64 node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Pinned inferred reference: `999556f6e0a474b8312db96ec3149e1c44e97c23`;
  no inferred reference implementation was read or copied for this packet.
- Question: which exception call-site intervals, landing pads and actions are
  actually attached to the previously mapped compact-string constructor?
- Claim status: observed metadata and decoded edges; source/cleanup interpretation
  is qualified, and helper/runtime behavior remains unresolved.

The existing [FDE packet](../RE-001-fde-extents/README.md) explicitly excludes
language-specific data area (LSDA) contents. The [build-provenance
packet](../RE-002-build-provenance/README.md) infers unwind support from table
size, warns that C++ contributes to it, and asks for owners. The
[compact-string packet](../RE-001-short-string-94/README.md) associates this
constructor with a Rust source path but leaves unwind behavior opaque.

This packet binds that **one constructor's** actual LSDA, decoded calls,
landing-pad entries, personality slot and external resume binding. It supplies
concrete Rust-path-associated cleanup metadata beyond the whole-section-size
inference. It does not establish the selected panic handler, all crate flags,
runtime cleanup correctness or an independently implemented constructor.

## Reproduce

From the repository root with authenticated LFS inputs and unchanged references:

```sh
make doctor
make verify test catalogue-check reproduce
python3 tools/compact_string_unwind.py --output work/compact-string-unwind-94
diff -ru research/work-items/RE-002-compact-string-unwind-94/observed work/compact-string-unwind-94
python3 -m unittest discover -s tests -p test_compact_string_unwind.py -v
shasum -a 256 -c research/work-items/RE-002-compact-string-unwind-94/MANIFEST.sha256
```

Required tools are Python 3.10+, GNU `readelf`/`objdump`, LLVM `llvm-objdump`
and the repository verification tools. The recorded host was macOS 15.7.7
arm64, Python 3.12.10, GNU binutils 2.47.20260726 and Apple LLVM 17.0.0:

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/private/tmp/slop-git-lfs/bin:$PATH
export LLVM_OBJDUMP=/Library/Developer/CommandLineTools/usr/bin/llvm-objdump
```

Core LSDA regressions use GNU tools. The separate LLVM comparison test reports
an explicit skip if that optional provider is absent; packet generation always
requires both decoders. This host ran all nine focused tests with no skips.

No package installation, Rust/Java/Ghidra startup, captured executable launch,
emulator, node service, model call or chain action is involved. The collector
hashes the bytes it reads, then gives those same bytes to native tools through
an owned temporary **non-executable** snapshot. It does not reopen a changing
original path for native analysis. Only the snapshot filename in native
disassembly headers is replaced; original addresses, bytes and operands remain.

## Exact bindings and native corroboration

All addresses below are original ELF virtual addresses; ends are exclusive.

| Item | Address or range |
| --- | --- |
| Constructor FDE | `0x1449a80..0x144a009`, 1,417 bytes |
| Constructor file range | `0x1448a80..0x1449009` |
| FDE record / CIE record | `0xfcf5e0` / `0xfbdc2c` |
| CIE augmentation | `zPLR`; FDE/LSDA pointers `0x1b`, personality `0x9b` |
| LSDA | `0x926238`, in `.gcc_except_table` |
| Next LSDA pointer | `0x926290`; an **upper bound**, not a proved object size |
| Personality slot / local RELA target | `0x577a668` → `0x4f14ca0` |
| Opaque personality FDE | `0x4f14ca0..0x4f1524f` |
| Source Location slot / RELA target | `0x566a990` → `0x1ea56a` |
| Resume call / PLT / JUMP_SLOT | `0x1449fed` → `0x5660110` → `0x5778db0` |

The source Location points to the exact bytes
`/home/ubuntu/hl/code_Mainnet/base/src/short_string.rs`. The constructor's
RIP-relative `lea` at `0x1449f8f` reaches that Location. This independently
retains the earlier source-path association; it does not recover a Rust type
or original function signature. Native nearest-export labels in the listing
are not treated as the constructor's original name.

The resume call's rel32 destination contains a RIP-relative PLT jump. Its slot
has one `R_X86_64_JUMP_SLOT` relocation to dynamic symbol `_Unwind_Resume`;
native `readelf -rW` also records `GCC_3.0`. The personality slot instead has a
local `R_X86_64_RELATIVE` relocation. Its target is FDE-bounded but opaque here:
no original symbol name or personality implementation is assigned to it.

`observed/frames.txt` retains native readelf's selected CIE/FDE records;
`relocations.txt` retains the three selected relocation rows. The Python FDE
reader independently decodes their addresses. Both native disassemblers cover
all **315 logical instructions** in the 1,417-byte constructor.

Apple LLVM 17 prints eight `LOCK` prefix bytes as separate display records.
The collector joins each adjacent `f0` record only with the observed REX.W
`CMPXCHG` or `XADD` form. After these explicit joins, GNU and LLVM logical
boundaries and bytes agree completely. **No byte or operand is masked.** The
unjoined raw LLVM listing and `decoder-formatting.json` retain the eight joined
addresses separately from the portable semantic record. Unknown
or orphan standalone prefix records fail rather than being silently ignored.

## LSDA intervals and call association

The observed header uses omitted LPStart (the function start), indirect
PC-relative signed-32 type pointers, and ULEB128 call-site fields. Its call-site
table is **75 bytes**. The action table begins at `0x926288`, and the declared
type-table base is `0x92628c`. The signed action fields are decoded, but type
entries, exception specifications and personality decisions remain unclosed.

| Row | Protected VA interval | Landing pad | Action index |
| ---: | --- | --- | ---: |
| 0 | `0x1449a80..0x1449c73` | none | 0 |
| 1 | `0x1449c73..0x1449cb7` | `0x1449fa8` | 0 |
| 2 | `0x1449cd4..0x1449d21` | `0x1449fbc` | 0 |
| 3 | `0x1449d21..0x1449dc7` | none | 0 |
| 4 | `0x1449dc7..0x1449dd0` | `0x1449fc1` | 0 |
| 5 | `0x1449dd0..0x1449e15` | none | 0 |
| 6 | `0x1449e15..0x1449e31` | `0x1449fc1` | 0 |
| 7 | `0x1449e31..0x1449edb` | none | 0 |
| 8 | `0x1449edb..0x1449f7d` | `0x1449fbc` | 0 |
| 9 | `0x1449f7d..0x1449f8f` | none | 0 |
| 10 | `0x1449f8f..0x1449f9c` | `0x1449fbc` | 0 |
| 11 | `0x1449f9c..0x1449ff2` | none | 0 |
| 12 | `0x1449ff2..0x144a001` | `0x144a003` | 1 |

The collector checks ordering, nonoverlap, FDE bounds and logical instruction
boundaries. It maps **25 of 26 decoded calls** using the return PC minus one,
retaining the one call without a table entry. This is a static call census
inside one FDE, not an execution trace or whole-target denominator.

For example, the alias-producer call at `0x1449cb2` returns to `0x1449cb7`,
exactly a protected interval's exclusive end. Lookup at `0x1449cb6` correctly
assigns row 1 and landing pad `0x1449fa8`; lookup at the return address would
miss that row. Conversely, the final call at `0x144a003` has **no** table entry.
It must not be presented as another covered call or assumed safe to unwind.

Six rows have no landing pad; six have a nonzero pad with action index zero
(cleanup-only in the conventional LSDA interpretation). The final row selects
the two bytes `7f 00`: signed filter **−1**, next displacement **0**. That
negative filter is retained as data; this packet does not turn it into a
typed catch, recoverability guarantee or implemented exception policy.

## What the landing-pad instructions show

- `0x1449fa8` saves `rax` in `rbx`, tests a stack value, optionally loads a
  pointer, and joins the call through slot `0x576e010` before resume.
- `0x1449fbc` saves `rax` in `rbx` and joins another stack-value/null-test
  route to the same slot and resume.
- `0x1449fc1` saves `rax` in `rbx`, performs a locked compare-exchange, and
  either joins that route or calls through slot `0x576f608` before joining it.
- `0x144a003` calls through slot `0x576e128`. That callee is opaque; its call
  is the one outside all listed call-site intervals.

The shared resume sequence moves saved `rbx` to `rdi` and calls the validated
`_Unwind_Resume` PLT entry. These are decoded edges and argument movements,
not a proof that opaque helpers return, free the intended resources, release
a lock correctly or execute for a particular thrown value.

The format interpretation is supported by the primary
[GCC LSDA reader](https://github.com/gcc-mirror/gcc/blob/releases/gcc-13.3.0/libstdc%2B%2B-v3/libsupc%2B%2B/eh_personality.cc)
and [pointer encodings](https://github.com/gcc-mirror/gcc/blob/releases/gcc-13.3.0/libgcc/unwind-pe.h).
They are format references, not evidence that this target's local personality
is GCC's C++ personality. The Python collector is independently authored;
no GCC implementation is copied into the project.

The [Rust Reference](https://doc.rust-lang.org/reference/panic.html#panic-strategy)
distinguishes a crate's supported panic strategy from its final panic handler;
unwind-capable code can use an aborting handler. Thus these owned cleanup
records strengthen the earlier provenance inference without identifying the
complete build flags or promising that a captured panic is recoverable.

## Validation and limits

See `validation.txt` and the SHA-256 manifest for exact commands and outcomes.
Nine focused tests check the real target and retained record, source and
resume bindings, the interval-end case, raw signed actions and prefix display.
Below the whole-input identity gate, **ten actual target-data mutations** are
rejected: seven LSDA structure/boundary changes, two RELA retargets and a PLT
slot retarget. Another valid action mutation changes filter −1 to 0 and changes
the parsed action record while leaving the census counts unchanged. It is
detected semantically rather than by a changed whole-file digest alone.

All original packets, imports, pins and generated progress/catalogue files
remain unchanged. **No gate is requested.** No native execution, Rust build,
allocator/unwinder recovery, dynamic reachability, complete panic flags,
whole-node equivalence, #115/visor transfer or hosted-CI success is claimed.
The next concrete question is the shared cleanup/helper contract and the
local personality's action interpretation; those need their own evidence
before a compatible compact-string implementation can be asserted.
