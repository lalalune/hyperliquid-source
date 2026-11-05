# RE-002 · Node #115 blst 384-bit scalar Montgomery helpers

Component: foundation utilities, native dependency provenance. Target is Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Repository baseline is `05bc2de303c05525b71e7e257426e741bc66a390`.

## Question and result

Which complete function bodies from the upstream assembly for 384-bit scalar Montgomery helpers are present in #115? The exact matches include `__mulq_384`, `__mulq_by_1_mont_384`, `__mulq_mont_384`, `__sqrq_384`. The labels come from the reference object's symbol table. The stripped target supplies addresses and unwind records.

The [window table](windows.tsv) records **4 complete bodies and 4,008 raw-equal bytes**. Each reference window is one ELF function symbol, has no overlapping relocation in `.rela.text`, and occurs exactly once in the target `.text`. Its target bounds coincide with one `.eh_frame` FDE. The listed ranges were absent from the baseline byte-window registry. The equality applies to these bodies. Calls and references outside the listed ranges, version exclusivity, and the full linked library remain unproved. No acceptance gate or coverage accounting changes.

## Inputs

The public reference is [blst v0.3.16, Apache-2.0](https://github.com/supranational/blst/tree/e7f90de551e8df682f3cc99067d204d8b90d27ad). This revision is a reproducible candidate. Other revisions may produce the same bodies. Build only the following files, with Zig 0.15.2's integrated assembler, ELF x86-64 and `__BLST_PORTABLE__`.

- [`mulq_mont_384-x86_64.s`](https://github.com/supranational/blst/blob/e7f90de551e8df682f3cc99067d204d8b90d27ad/build/elf/mulq_mont_384-x86_64.s) (SHA-256 `171292798aea6392ac8858a3354955a264d58ad3f95cd187e3600e944c8e6a8c`).

## Reproduce

From a scratch directory containing the pinned sources and the authenticated node binary as `hl-node`, run the build. Confirm the input hashes above before assembling. The assembly is read and compiled to an object. Neither binary is executed.

```sh
zig cc -target x86_64-linux-gnu -D__BLST_PORTABLE__ -x assembler-with-cpp -c mulq_mont_384-x86_64.s -o ref.o
objcopy --dump-section .text=ref.text ref.o
objcopy --dump-section .text=node.text hl-node
readelf -sW ref.o
readelf -rW ref.o
readelf --debug-dump=frames-interp hl-node
```

The target `.text` VA is `0x1419300`. For each table row, compare `length` bytes at `source_text_offset` in `ref.text` and at `target_va - 0x1419300` in `node.text`. Check the reference symbol's size, its relocation exclusion, and the target frame interval. For example, set the following values for the first row:

```sh
dd if=ref.text of=ref.window bs=1 skip=$((0x7c0)) count=853 status=none
dd if=node.text of=node.window bs=1 skip=$((0x5d292c0 - 0x1419300)) count=853 status=none
cmp ref.window node.window
sha256sum ref.window node.window
```

Observed result: all 4 pairs are byte-identical and match the recorded SHA-256. No bytes were masked. In the local Python 3.12.14 and pyelftools 0.33 check, toggling the first bit of each target window caused exact equality and the recorded digest to fail.
