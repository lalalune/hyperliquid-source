# evm: reconstruct the node #115 BLAKE2 F compression precompile (run body, provider dispatcher, portable compression body)

This packet makes it possible to reimplement the HyperEVM BLAKE2 `F` precompile of node #115 from evidence: the exact input layout and error precedence of the run body at `0x5c16650` (length, then gas, then final-flag), the gas rule (`gas_used == rounds`), the 64-byte output value it builds, the three-way routing of the provider dispatcher at `0x5bebac0`, and a Python model of the portable compression body at `0x5c38870` that reproduces the recorded x86-64 code on 11,469 byte-level comparisons and reproduces the standard library BLAKE2b digest for every single-block message length 0..128.

- Component ID: `evm` (HyperEVM execution, precompile at address 9; the address lookup itself is covered by the merged RE-021 packets and is outside this one).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No reference source was copied; the model is written from the instruction bytes and the public BLAKE2b definition (RFC 7693 round function), and checked against the standard library `hashlib.blake2b`.
- Claim status: observation (instruction bytes, relocations, FDE extents, branch behaviour under emulation); inference (names such as "provider vtable", "Bytes value", `Crypto`-trait-like slot roles); unresolved (vector arm body, provider initialisation closure, allocator and handler identities, live fork selection).
- Scope included and excluded: included are the run body, the dispatcher reached through provider vtable slot `+0x58`, the portable compression body, the lazily initialised provider cell and the feature-word cell as seen by those bodies. Excluded are the vector-instruction arm at `0x5c37750` (3,226 bytes, not decodable by the shared interpreter; replaced by a hook that pins its arguments), the other 17 provider slots, the `Once` initialiser closure, the allocator, and any gate request.

## Reproduce

From the repository root with Python 3.12 and the authenticated node #115 artifact present:

```sh
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
python3 tools/evm_blake2f_compress115.py --out research/work-items/evm-blake2f-compress-115
python3 -m unittest tests.test_evm_blake2f_compress115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

Repeatability check, replacing `<tmp-dir>` with an existing writable directory:

```sh
PYTHONHASHSEED=0 TZ=UTC python3 tools/evm_blake2f_compress115.py --out <tmp-dir>/one
PYTHONHASHSEED=937 TZ=Pacific/Honolulu python3 tools/evm_blake2f_compress115.py --out <tmp-dir>/two
diff -r <tmp-dir>/one <tmp-dir>/two
```

The tool verifies the input digest before reading anything else (`load_image` raises on a mismatch), reads ELF sections, relocations and unwind records through the repository parsers `tools/elf_index.py` and `tools/fde_extents.py`, launches no external program and never executes the node. SHT_NOBITS sections have no file bytes and are excluded from address resolution. One regeneration takes about 90 seconds and 0.4 GB; the 35 tests take about 15 seconds. Python 3.12.3 was used. GNU objdump was used by hand only to read the instruction listings quoted below; no generated file depends on it.

## Evidence

All addresses are virtual addresses of the PIE image (section address minus section offset is the file mapping). Function extents are the `.eh_frame` FDE ranges (`constants.tsv`, rows `fde-*`). Instruction listings below are a human aid; the evidence files carry only values the tool read from bytes.

### Call shape

```
run(out, input, input_len, gas_limit)          0x5c16650 .. 0x5c16863
  cell = *(0x64ec358)  -> 0x64fe3d8             (RELATIVE slot, constants.tsv provider-cell-slot)
  if cell.state(+0x10) != 0: call 0x5bee2d3     (Once-style initialiser, hooked here)
  (cell.vtable)[+0x58](cell.data, rounds, &h, &m, &t, f)   -> 0x5bebac0
dispatcher 0x5bebac0 .. 0x5bebb28
  feature = **(0x64dfa60 -> 0x6500098); if 0: call *(0x64dfa68 -> 0x5cadd50)   (feature initialiser, hooked here)
  if (feature & 0xffff) is negative as i16: tail jump 0x5c37750        (vector arm, hooked here)
  else tail jump 0x5c38870                                             (portable body, executed for real)
compress 0x5c38870 .. 0x5c38d51: (rounds edi, h rsi, m rdx, t rcx, final r8d)
```

The vtable that the run body indexes is the 21-slot table at `0x64bff60` (`provider-vtable.tsv`): three header words (drop 0, size 0, align 1) and 18 RELATIVE method slots from `+0x18` to `+0xa0` with FDE sizes between 15 and 4,802 bytes. Slot `+0x58` is the only one whose relocation addend is the dispatcher `0x5bebac0`. The other 17 methods are listed but not analysed here; the slot roles (hash, curve and signature operations of a `Crypto`-trait-like provider) are an inference from their sizes and from the error strings that the node carries, not an observation.

### Run body (`0x5c16650`), observed branch by branch

| step | bytes | behaviour |
| --- | --- | --- |
| 1 | `48 81 fa d5 00 00 00` (`cmp rdx,0xd5`) | input length must be exactly 213 (`0xd5`); otherwise result is `Err` with code `0x8000000000000002` |
| 2 | `0f cb` (`bswap ebx`) | rounds is the first four input bytes read big-endian (`bswap`) |
| 3 | `cmp rcx,rbx` / `73 35` (`jae`) | if `gas_limit < rounds` the result is `Err` code `0x8000000000000001`; the comparison is unsigned on 64-bit `gas_limit` against zero-extended `rounds` |
| 4 | `0f b6 ae d4 00 00 00` / `40 80 fd 02` (`cmp bpl,2`) | final flag is byte 212; a value of 2 or more gives `Err` code `0x8000000000000003` (`0x8000000000000001 \| 2`) |
| 5 | `0f 10 46 04` and the following 16-byte copies | h = bytes 4..68 and m = bytes 68..196 are copied unchanged (no byte swap), t = bytes 196..212 |
| 6 | `mov r15,[0x64ec358]`, `mov eax,[r15+0x10]`, `test`, `jne` | provider cell state word zero takes the fast path, any other value calls the initialiser first |
| 7 | `ff 50 58` (`call [rax+0x58]`) | provider slot `+0x58`, arguments (data, rounds, &h, &m, &t, f) |
| 8 | `mov edi,0x40`, `call [0x64df480]`, `test rax,rax`, `je` | allocate 64 bytes; a null result jumps to the failure arm that calls the handler slot `0x64df498` (see below) |
| 9 | stores | `out[0]` vtable word, `out[8]` pointer, `out[0x10] = 0x40`, `out[0x18] = ptr \| 1`, `out[0x20] = rounds` |

The error result is `out[0] = 0` and `out[8] = code`. Error codes are `0x8000000000000000 + 1` (out of gas), `+ 2` (wrong input length) and `+ 3` (wrong final flag); the names follow the order of the three message strings `out of gas`, `wrong input length for blake2`, `wrong final indicator flag for blake2` in the node's read-only data (observation of the strings; the mapping from code to string happens inside a large error-formatting function that this packet does not reconstruct, so the code-to-name pairing is an inference).

The allocation-failure arm loads `edi = 1`, `esi = 0x40` and calls the handler slot (the argument pair is `(1, 0x40)`; reading it as alignment and size is an inference). The harness raises an exception at that call and the model expects the pair (`alloc-failure`, 240 cases).

The success value has the shape of a promotable `Bytes` value: `out[0]` is the word read from `0x64df8c0` when the allocation address is even and from `0x64df8c8` when it is odd (the `cmove` after `test al,1`); both slots are RELATIVE and resolve to `0x64040e8` and `0x64040c0` (`constants.tsv`). `out[0x18]` is the pointer with bit 0 set in both cases (`or rcx,1` followed by a `cmovne` that cannot change an odd pointer).

### Dispatcher (`0x5bebac0`)

The dispatcher shifts its arguments down one register (`edi = esi`, `rsi = rdx`, `rdx = rcx`, `rcx = r8`, `r8d = r9b`), reads a 64-bit feature word through the pointer slot `0x64dfa60`, calls the feature initialiser when the word is zero, and then tests the low 16 bits as a signed value: negative goes to the vector arm, non-negative to the portable body. Both continuations are tail jumps.

### Portable compression body (`0x5c38870`)

The body loads the eight chaining words from `rsi`, builds `v12 = IV4 ^ t0`, `v13 = IV5 ^ t1`, and chooses the constant for `v14` with `test r8d,r8d` / `cmovne`: **any non-zero 32-bit flag word selects the inverted constant** `0xe07c265404be4294`. The round counter is reduced modulo ten with the multiply-by-`0xcccccccccccccccd` idiom, so rounds beyond ten reuse the first message-schedule rows (12 rounds use rows 0..9, 0, 1). A zero round count skips the loop (`je` at `0x5c3892e`), and the loop back-edge at `0x5c38c96` runs once per round. The rotations are 32, 24 (`rol 40`), 16 (`rol 48`) and 63 (`rol 1`). The schedule table at `0x943c33` is stored in a different permutation layout from the RFC text (its first row reads `0f 0e 0a 04 08 09 0f 0d ...`); the packet records its SHA-256 only and relies on emulation, not on a decoded copy, to establish equality with the RFC schedule.

### Branch census

`branches.tsv` lists all nine conditional jumps of the three bodies with taken and not-taken counts over the case sets. Every jump has both arms reached; none is unreachable.

| body | jump | meaning |
| --- | --- | --- |
| run | `0x5c16664` | length differs from 213 |
| run | `0x5c1666d` | gas at least rounds |
| run | `0x5c166af` | final flag at least 2 |
| run | `0x5c1675c` | provider state word non-zero |
| run | `0x5c167c4` | allocation returned null |
| dispatch | `0x5bebada` | feature word zero |
| dispatch | `0x5bebaec` | feature word negative as 16-bit |
| compress | `0x5c3892e` | zero rounds |
| compress | `0x5c38c96` | round loop back-edge |

### Slot census (`constants.tsv`)

| name | slot | RELATIVE addend | note |
| --- | --- | --- | --- |
| alloc-slot | `0x64df480` | `0x6355830` | callee of the 64-byte allocation (identity inferred) |
| feature-pointer-slot | `0x64dfa60` | `0x6500098` | `.bss` cell holding the feature word |
| feature-init-slot | `0x64dfa68` | `0x5cadd50` | called when the word is zero |
| bytes-even-slot / bytes-odd-slot | `0x64df8c0` / `0x64df8c8` | `0x64040e8` / `0x64040c0` | value words of the output |
| provider-cell-slot | `0x64ec358` | `0x64fe3d8` | `.data` cell, 32 file bytes recorded |

The 32 recorded file bytes of the provider cell are zero except for 32-bit values 3 at `+0x10`, `+0x18` and `+0x1c`. Only the word at `+0x10` is read by the run body; its initial file value is 3, which sends the first call through the initialiser. After initialisation the cell is assumed to hold `(1, 0x64bff60)` and state 0; that assumption is the model's, supported by slot `+0x58` being the unique dispatcher entry, not read from an executed initialiser.

## Implementation and comparison

`tools/evm_blake2f_compress115.py` contains (1) a copy of the offline x86-64 interpreter used by the merged packets (decode, memory, machine), with two local changes: reads of 8 bytes at RELATIVE slots return the addend, and a per-address hook table; (2) the Python model: `blake2_f(rounds, h, m, t, f)`, `run_model(data, gas_limit)` and `expected_run(...)`, which also predicts routing, the allocation request and the output value layout; (3) the harness `Rig`, which runs the recorded bytes of the run body, dispatcher and compression body, and replaces exactly four callees by hooks that pin their arguments: allocator, allocation-failure handler, feature initialiser, provider initialiser, plus the vector arm. No Rust crate is built; this packet reconstructs behaviour as an executable Python specification.

Case sets (all generated by SplitMix64 from fixed seeds, so they depend on no library version):

| kind | cases | content |
| --- | --- | --- |
| length | 700 | input lengths 0..212 and 214..413, random gas |
| gas | 700 | valid length, gas below rounds (rounds up to `0xffffffff`, flag byte any value) |
| flag | 700 | flag byte 2..255, gas at least rounds (including `u64::MAX`) |
| accept | 5,800 | rounds 0..32, gas exactly rounds or more, zero and all-ones words, four provider scenarios, both allocation parities |
| alloc-failure | 240 | accepted input, allocator returns null |
| digest | 129 | message lengths 0..128, output compared with `hashlib.blake2b` |
| compress | 3,200 | direct calls of `0x5c38870`, rounds 0..40, flag words `0, 1, 2, 255, 0x100, 0x80000000, 0xffffffff` and random |

Total 11,469 comparisons (`measure.json`); the SHA-256 chains over every result line are in `summary.json`. The provider scenarios are: portable (feature word `0x0001`), feature-init-portable (word 0, initialiser hook writes `0x0001`), vector-arm (word `0x8001`, hook checks `(rounds, flag)` and answers with the model) and provider-init-portable (state word 3, initialiser hook writes state 0).

Negative controls: 67, all detected (`controls.tsv`). 32 are mutations of the model (rotation counts, initial constants, schedule rows, flag handling, byte orders, comparison operators, error precedence and codes, gas, offsets), each detected by at least one generated case; 34 flip one byte of the recorded code (the length constant, the `bswap`, the `jae`, error-code immediates, flag limit and offset, copy offsets, the vtable slot displacement, output length and store offsets, the dispatcher's `js`, argument move and flag zero-extension, all eight initial constants and the flagged constant, and eight rotation instructions); one changes the expected digest handed to the loader. Byte controls end as `result-differs` or, for two, as a halt in the interpreter; none survives. No equivalent mutants are claimed.

### Control list

Model mutations (each is run against every generated case; the table gives the change, `controls.tsv` the first distinguishing case and the number of cases that differ):

| control | change |
| --- | --- |
| `sigma-swap-rows-3-4` | message schedule rows 3 and 4 exchanged |
| `sigma-last-entry` | last entry of schedule row 9 replaced |
| `sigma-index-mod-12` | round index reduced modulo 12 before modulo 10 |
| `sigma-index-mod-9` | schedule row index reduced modulo 9 |
| `rot24-23` | second rotation 24 replaced by 23 |
| `rot16-15` | third rotation 16 replaced by 15 |
| `rot32-31` | first rotation 32 replaced by 31 |
| `rot63-62` | fourth rotation 63 replaced by 62 |
| `iv0-bit` | low bit of IV word 0 flipped |
| `iv7-bit` | high bit of IV word 7 flipped |
| `t0-ignored` | low offset counter word not mixed into v12 |
| `t1-ignored` | high offset counter word not mixed into v13 |
| `flag-ignored` | final flag never inverts v14 |
| `flag-inverts-v15` | final flag inverts v15 instead of v14 |
| `no-upper-half-xor` | output omits the v[i+8] term |
| `rounds-plus-one` | one extra round |
| `gas-le` | gas test uses less-or-equal |
| `gas-minus-one` | gas test compares against rounds minus one |
| `length-212` | length check accepts 212 |
| `length-ge` | length check accepts anything at least 213 |
| `flag-gt-2` | flag limit is above 2 instead of at least 2 |
| `flag-before-gas` | flag check runs before the gas check |
| `rounds-little` | rounds read little-endian |
| `gas-used-plus-one` | gas used is rounds plus one |
| `gas-used-zero` | gas used is zero |
| `output-big-endian` | output words written big-endian |
| `m-big-endian` | message words read big-endian |
| `error-swap-length-gas` | length and out-of-gas codes exchanged |
| `error-flag-2` | flag error code is the length code |
| `h-offset-3` | chaining words read from offset 3 |
| `t-short` | only eight counter bytes read |
| `flag-only-one` | compression treats only the value 1 as final |

Byte corruptions (one code byte XOR-ed; each is run against a fixed 56-call suite covering all scenarios, both allocation parities, every error and flags 0, 1, 2 and 7, then against 300 direct compression calls):

| control | address | byte change |
| --- | --- | --- |
| run: length constant 0xd5 off by one | `0x5c16660` | `d5->d4` (result-differs) |
| run: bswap ebx becomes bswap edx (rounds byte order) | `0x5c16669` | `cb->ca` (result-differs) |
| run: jae gas test becomes jb | `0x5c1666d` | `73->72` (result-differs) |
| run: out-of-gas code 1 becomes 0 | `0x5c16671` | `01->00` (result-differs) |
| run: out-of-gas code 1 becomes 3 | `0x5c16671` | `01->03` (result-differs) |
| run: wrong-length base code 1 becomes 3 | `0x5c1667d` | `01->03` (result-differs) |
| run: flag limit 2 becomes 3 | `0x5c166ae` | `02->03` (result-differs) |
| run: flag byte offset 0xd4 becomes 0xd5 | `0x5c166a7` | `d4->d5` (result-differs) |
| run: h source offset 4 becomes 5 | `0x5c166bb` | `04->05` (result-differs) |
| run: m source offset 0x44 becomes 0x45 | `0x5c166df` | `44->45` (result-differs) |
| run: vtable slot 0x58 becomes 0x59 | `0x5c1678e` | `58->59` (halt:Halt) |
| run: output length 0x40 becomes 0x41 | `0x5c16813` | `40->41` (result-differs) |
| run: gas-used store offset 0x20 becomes 0x21 | `0x5c16821` | `20->21` (result-differs) |
| run: pointer tag or-mask 1 becomes 3 | `0x5c167f2` | `01->03` (result-differs) |
| dispatch: js becomes jns | `0x5bebaec` | `78->79` (result-differs) |
| dispatch: first argument move source | `0x5bebacc` | `f7->f5` (result-differs) |
| dispatch: flag zero-extend byte move | `0x5bebadf` | `c1->c0` (result-differs) |
| compress: iv0 low byte | `0x5c3896d` | `08->09` (result-differs) |
| compress: iv1 low byte | `0x5c38885` | `3b->3a` (result-differs) |
| compress: iv2 low byte | `0x5c3895e` | `2b->2a` (result-differs) |
| compress: iv3 low byte | `0x5c3888f` | `f1->f0` (result-differs) |
| compress: iv4 low byte | `0x5c388ab` | `d1->d0` (result-differs) |
| compress: iv5 low byte | `0x5c388bc` | `1f->1e` (result-differs) |
| compress: iv6 low byte | `0x5c388e0` | `6b->6a` (result-differs) |
| compress: iv7 low byte | `0x5c3889e` | `79->78` (result-differs) |
| compress: flagged iv6 low byte | `0x5c388d6` | `94->95` (result-differs) |
| compress: rotate by 32 at 0x5c38a58, count byte +1 | `0x5c38a5b` | `20->21` (result-differs) |
| compress: rotate by 40 at 0x5c38a6c, count byte +1 | `0x5c38a6f` | `28->29` (result-differs) |
| compress: rotate by 48 at 0x5c38aa8, count byte +1 | `0x5c38aab` | `30->31` (result-differs) |
| compress: rotate by one at 0x5c38acf, register byte +1 | `0x5c38ad1` | `c0->c1` (result-differs) |
| compress: rotate by 40 at 0x5c38a9a, count byte +1 | `0x5c38a9d` | `28->29` (result-differs) |
| compress: rotate by one at 0x5c38b5e, register byte +1 | `0x5c38b60` | `c5->c4` (halt:Halt) |
| compress: rotate by 48 at 0x5c38c15, count byte +1 | `0x5c38c18` | `30->31` (result-differs) |
| compress: rotate by one at 0x5c38c7d, register byte +1 | `0x5c38c7f` | `c6->c7` (result-differs) |

The remaining control hands the loader an altered expected digest and requires `load_image` to refuse.

### Error and scenario tables

| code | meaning | raised when |
| --- | --- | --- |
| `0x8000000000000001` | out of gas | `gas_limit < rounds` (checked second) |
| `0x8000000000000002` | wrong input length | input length is not 213 (checked first) |
| `0x8000000000000003` | wrong final flag | flag byte at least 2 (checked third) |

| scenario | provider state word | feature word | route recorded |
| --- | --- | --- | --- |
| portable | 0 | `0x0001` | none |
| feature-init-portable | 0 | 0 | `feature-init` |
| vector-arm | 0 | `0x8001` | `avx2(rounds,flag)` |
| provider-init-portable | 3 | `0x0001` | `provider-init` |

## Results and limitations

- 11,469 / 11,469 comparisons agree with the model (run body 8,269, compression body 3,200); 129 outputs equal the standard library digest; 67 / 67 negative controls detected, 0 equivalent; 9 / 9 conditional jumps reached on both arms.
- The packet requests no component gate. It covers one precompile path of the `evm` component, not the component.
- Limits: the vector arm (`0x5c37750`) is not executed, so equality of the vector implementation with the portable one is unresolved; the dispatcher is pinned only for its argument forwarding on that arm. The provider initialiser, the allocator, the allocation-failure handler and the feature initialiser are hooks; their identities and effects are not established. The feature word's runtime value on a given machine is outside static analysis. The code-to-message pairing for the three error codes and the gas charge applied by the caller before and after this body are not reconstructed.
- Next question: the EVM-side caller that converts this `Result` into a call outcome (how the 64-byte value and `gas_used` become return data and gas accounting), and the vector arm at `0x5c37750` with a VEX-capable decoder.

The sampled result digests in `cases.tsv` and `compress-cases.tsv` are every fourth or second case; the full set is regenerated by the tool.
