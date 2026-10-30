# RE-004: how does node #94 turn a spot order's wire price and size into raw quantities?

- Component ID: RE-004 (quantities/rounding)
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c`; `references/can1357-hl` used for leads only, no code copied
- Claim status: observation for bytes, tables and the whole-domain proof; inference where marked; unresolved items are
  listed
- Scope included and excluded: included are the price helper in 2 copies (`0x4ca6940`, `0x230af90`) and the size helper
  in 1 copy (`0x4ca6a90`), for all 64-bit inputs and all token decimal bytes. Excluded are the copy `0x230b0e0`, which
  RE-010 names as an anchor, and the inline size copy in `0x42f57e0`, which `census.tsv` lists unread. What the callers
  do with the result is not read.

## Reproduce

Run from the repository root. Python 3 standard library only; no objdump, no execution of the binary.

```sh
python3 tools/spot_wire_scale.py --out research/work-items/RE-004-spot-wire-scale-94
python3 -m unittest tests.test_spot_wire_scale
```

The tool checks the binary digest first and takes about 30 s. FDE records come from `tools/fde_extents.py` and sections
from `tools/elf_index.py`, so `.bss` and other NOBITS sections are never address-resolved. Files: `evidence.json`,
`scale-table.tsv`, `bounds.tsv`, `census.tsv`, `call-sites.tsv`, `mutation-controls.tsv`.

## Evidence

Addresses are ELF virtual addresses of node #94. All numbers below are in `evidence.json` or the TSV files. The excerpts
are objdump text for reading only and no generated file holds them.

### Finding the helpers

The error Display table at `0x59a8d0` gives tag `0x65` the text `Order has invalid price.` and tag `0x66` the text
`Order has invalid size.`, read from the bytes of each arm. `census.tsv` lists every `mov $tag,%cx` (`66 b9`) of the two
tags in `.text`, 6 byte hits: 3 analysed, 1 left out, 1 inline and not read, and 1 inside a `call` in C++ code, which the
instruction sweep shows is not an instruction start.

### The price helper

`rdi` is the output record, `rsi` the spot table, `rdx` the input x, `rcx` the asset index.

```
 4ca6966:  mov    0x8(%r9,%rcx,1),%rax     # quote token index
 4ca6974:  mov    (%r9,%rcx,1),%rcx        # base token index
 4ca698f:  movzbl 0x49(%rdx,%rax,1),%eax   # q
 4ca699b:  movzbl 0x48(%rdx,%rcx,1),%edx   # b
 4ca69a3:  sub    %dl,%r10b                # k = q - b
 4ca69a6:  jb     4ca6a75                  # panic
 4ca69ac:  mov    $0x65,%cx
 4ca69b3:  sub    $0x8,%r9b
 4ca69b7:  ja     4ca69f9                  # k > 8: error
 ...
 4ca6a2d:  cmp    %r8,%rsi
 4ca6a30:  jbe    4ca6a40
 4ca6a32:  jmp    4ca69f9                  # s > x: error
 4ca6a40:  test   %rdx,%rdx
 4ca6a43:  jne    4ca69f9                  # remainder: error
 4ca6a45:  mov    %rax,0x8(%rdi)
 4ca6a49:  mov    $0x186,%cx
```

Between the two, a ladder builds `s = 10^(8-k)` from the bits of `8-k` (10, 100, 10000, 1e8), and the divide takes a
32-bit form when `(x | s) < 2^32`.

### The closed form

`scale-table.tsv` holds one row per case. With `q` the quote token byte `+0x49`, `b` the base token byte `+0x48`, and
`k = q - b`:

| helper | bytes | every u64 x |
| --- | --- | --- |
| price | `q < b` (32640 pairs) | panic, Location `l1/src/spot_meta.rs:984:9` |
| price | `k > 8` (30628 pairs) | error tag `0x65` |
| price | `0 <= k <= 8` (2268 pairs) | `s = 10^(8-k)`; `x < s` or `x % s != 0` gives tag `0x65`; otherwise `Ok(x / s)` |
| size | `b > 8` (247 values) | error tag `0x66` |
| size | `b <= 8` (9 values) | `s = 10^(8-b)`; `x % s != 0` gives tag `0x66`; otherwise `Ok(x / s)` |

The helpers never round: a value that is not an exact multiple is refused. They differ at zero: `x = 0` is an error for
the price helper because `s > 0`, and `Ok(0)` for the size helper, which has no such compare. The status word `0x186` is
the same ok word the other order helpers use.

### How it is proved

The walker in the tool reads the real instruction bytes. q and b are concrete, and all 65536 pairs are run for each price
copy, and all 256 values of b for the size helper. x is symbolic. The walk can only ask three things about x:
`(x | s) < 2^32`, `s > x`, and `x % s == 0`. Each one forks the walk, so a leaf covers every x that gives those answers,
and every leaf is held against the closed form. A price case with a divisor has 6 leaves and a size case 4. A case with no
divisor has one leaf and asks nothing about x. Both divide forms are walked, so the two give the same quotient and
remainder by the condition that selects the 32-bit form.

The table is modelled as a fake memory holding only the slots the rule needs: `+0x168` pair table with 32-byte entries,
`+0x170` its length, `+0x180` token table with `0xe8`-byte entries, `+0x188` its length, and the two decimal bytes. Any
other read stops the tool, so the walk also proves that these are the only fields read. Each token's other decimal byte
holds a different value, so reading the wrong one shows. A write outside the output record stops it too.

196 concrete vectors per helper run through the same machine as a second check: the multiples and neighbours of each `s`
around 0, `2^32` and `2^64`.

`evidence.json` records that all 86 instructions of each price copy and all 72 of the size helper were walked, counting
the index panics in `bounds.tsv`. Branch sides never taken are also listed. In each price copy these are the fallthrough
of `cmp %dl,%al; je` at `0x4ca69f7` and of the third ladder test at `0x4ca6a10`. In the size helper they are the matching
two at `0x4ca6b32` and `0x4ca6b5e`. The compiler kept the checks, and with `8-k` in `0..=8` they cannot go the other way.

### Index checks

`bounds.tsv` runs each index one past its table. The asset index reaches `l1/src/spot_meta.rs:565:25` and a token index
reaches `l1/src/spot_meta.rs:113:33`. The price helper checks the quote index before the base index. The size helper
reads the base token only.

### Callers

`call-sites.tsv` has 10 direct calls: 4 of `0x4ca6940`, 1 of `0x230af90`, 5 of `0x4ca6a90`, each an instruction start
in its caller, and each followed within 16 bytes by a read of the ok word. No RELATIVE relocation points at any of the 4
helper copies.

### Comparison with the reference (leads only)

- `l1/qtys/mod.rs` `Px::wire_decimals` picks a fixed 8 for spot and subtracts size decimals, and `parse_wire` takes a
  string. These helpers take a u64 and use the quote token's own byte, so the two agree only when `q = 8`.
- `l1/exchange/impl_spot_deploy.rs` `parse_nonzero_start_px` has the same exponent, quote wei minus base size decimals,
  for the deploy start price, with an error where the helper here panics. That is a different path.
- A case-insensitive search of the `l1` tree finds neither error text, and no equivalent of these helpers in
  `spot_meta.rs`.

### Inferences (not proved)

- `q` and `b` are `weiDecimals` of the quote token and `szDecimals` of the base token. The merged packet
  `RE-004-spot-wei-scale-family-94` makes the same reading of `+0x49` and `+0x48`, and the serde keys are not re-read here.
- The input is a fixed-point value with 8 decimals, and the helpers drop the digits the asset cannot hold. The constant 8
  in both helpers and the reference's `FP_DECIMALS` point this way. The code that fills the u64 is not read here.
- Raw price then has `k` decimals and raw size `b` decimals, so their product has `q` decimals.
- The rounding rule is a refusal: a client must send a value that is already a multiple of `s`.

## Implementation and comparison

not yet implemented

## Results and limitations

| metric | value |
| --- | --- |
| byte cases proved per price copy | 65536 of 65536 |
| byte cases proved, size helper | 256 of 256 |
| mismatches | 0 |
| instructions walked | 86/86, 86/86, 72/72 |
| concrete vectors per helper | 196 |
| direct calls | 10 |
| negative controls detected | 20 of 20 |

The 20 controls in `mutation-controls.tsv` patch one constant, branch, field offset or tag in a copy of the bytes, then
rerun the proof, and each stops it at the row shown. Unit tests also refuse a wrong digest, addresses with no file bytes
(`.bss`, outside all sections), an unmodelled instruction, and a table read outside the fake memory.

Limits:

- A leaf is checked whether or not it can happen. For example the leaf with `s > x` and `(x | s) >= 2^32` is impossible.
  That makes the check stricter, and no count here depends on it.
- The proof takes the x86 meaning of the modelled instructions from the tool's own short table, and a mistake there would
  be shared by the walk and the vectors. The tests pin edge values by hand.
- The instruction sweep behind the census resynchronises after a misaligned start, so an exact FDE-end stop does not by
  itself prove alignment.
- `0x230b0e0` is outside the proof, and so are its callers. `0x42f57e0` holds an inline size conversion with a different
  table layout, which is not read.
- `0x21f8520` calls `0x230af90` once while `0x4c17b10` calls `0x4ca6940` twice. The reason is not traced, and indirect
  calls are not scanned.
- The token table's contents are not read, so this packet says nothing about which `(q, b)` pairs exist.
- No gate in `research/progress.json` is requested.

Next question: what fills the u64 at order record `+0x10` and `+0x18` before these helpers run, and does it round?
