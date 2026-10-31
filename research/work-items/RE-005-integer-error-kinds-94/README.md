# RE-005: diagnostic fields and observed integer-name slices

- Component: serialization; bounded static research, no gate requested.
- Target: Linux x86-64 node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Pinned reference revision: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  No unlicensed inferred Rust implementation was read or copied.
- Question: which diagnostic labels and name slices are associated with the
  raw tag/byte fields produced by `0x466dac0`?

The accepted [varint packet](../RE-005-bincode-varint/README.md) leaves integer
error codes inferred. Open [#253](https://github.com/lalalune/hyperliquid-source/pull/253)
pins the shared builder and reader codes while keeping source-level names
inferred; [#371](https://github.com/lalalune/hyperliquid-source/pull/371) keeps
kind byte 5 opaque. This packet adds the distinct diagnostic consumer,
descriptors, two name thunks and actual literal slices. It does not implement
or modify the Rust codec held by [#48](https://github.com/lalalune/hyperliquid-source/pull/48),
the slow readers, or the kind-5 component.

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/bincode_integer_error_static.py \
  --output work/integer-error-kinds-94
diff -ru research/work-items/RE-005-integer-error-kinds-94/observed \
  work/integer-error-kinds-94
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest \
  tests.test_bincode_integer_error_static -v
make doctor verify test catalogue-check reproduce
cd research/work-items/RE-005-integer-error-kinds-94
sha256sum -c MANIFEST.sha256
```

Use a new output directory. Existing evidence is refused before reading the
input. Wrong identity creates no output. The producer authenticates one full
input `bytes` object and derives every metadata and native-span input from it.
GNU objdump receives only owned mode-0600 raw copies of the four bounded spans,
using `-D -b binary -m i386:x86-64 -M intel --insn-width=16` and their explicit
ELF VA as `--adjust-vma`. It never receives or reopens the original ELF path.
No captured code is executed.

`INPUTS-AND-TOOLS.json` binds source/test hashes, versions and validation scope.
The retained GNU tool is binutils 2.44. Two actual current exports match all six
observed files byte for byte on that tool. Only the owned input pathname in
native text is replaced with `<node94-raw-NAME>`; instruction bytes, VAs and
operands are unchanged. Tool-version text differences must remain visible.

## Byte and metadata scope

All addresses below are ELF VAs. File coordinates and complete raw FDE/CIE
records are in `observed/records.json`. Each selected FDE references CIE
`0xce1518`, augmentation `zR` with the retained raw encoding bytes.

| Scope | Half-open range | Bytes | Native instruction rows | Interpretation |
| --- | --- | ---: | ---: | --- |
| Parent diagnostic consumer | `0x14f68e0..0x14f722d` | 2,381 | 533 | Entry dispatch and tag-3 arm only |
| Name through a pointer | `0x14f7310..0x14f733f` | 47 | 12 | Complete thunk |
| Name from a byte address | `0x14f7910..0x14f793c` | 44 | 11 | Complete thunk |
| Shared raw constructor | `0x466dac0..0x466dace` | 14 | 5 | Context already identified by #253 |

The parent is byte-bound in full, but its other variants are not interpreted.
Linear native rows are not CFG coverage, a function-equivalence denominator,
or a recovered Rust component. The 121,299-entry unwind index is metadata,
not a validated-function count.

## Constructor to selected diagnostic fields

The 14-byte constructor returns the supplied pointer and stores:

| Offset | Stored byte |
| ---: | --- |
| 0 | `3` |
| 1 | Low byte of `rsi` (`sil`) |
| 2 | Low byte of `rdx` (`dl`) |

At `0x14f68f0`, the consumer loads a record pointer through its first argument,
then reads that record's byte 0. The relative jump-table entry at
`0x21d2d8 +3*4` resolves to `0x14f6bfa`. This selected arm passes the actual
18-byte slice `InvalidIntegerType` at `0x21d356` to the destination's slot
`+0x18`. It then makes these two calls through slot `0x576e2c8`, whose unique
RELATIVE relocation binds it to `0x1571f50`:

| Call VA | Name slice | Data association | Descriptor |
| --- | --- | --- | --- |
| `0x14f6c51` | `expected`, 8 bytes at `0x20ae58` | Address of record byte 1 | `0x566fa20` |
| `0x14f6c6f` | `found`, 5 bytes at `0x21d368` | Address of a stack-held pointer to record byte 2 | `0x566fa40` |

The first descriptor's raw words are `(0,1,1,0)`; its `+0x18` RELATIVE entry
points to `0x14f7910`. The second has `(0,8,8,0)` and its corresponding entry
points to `0x14f7310`. The thunk with the extra pointer load agrees with the
second call's extra indirection. These are observed words and accesses, not
a recovered Rust object layout, trait identity, or function ABI.

The constructor and this consumer therefore share a **conditional raw-record
interpretation**: if that record is presented through this consumer's input
protocol, its two byte fields are associated with those literal field labels.
No application call path or actual formatting of a particular reader return
is established. Helper `0x1571f50` and destination slot `+0x18` remain opaque;
the packet does not prove a complete rendered runtime message.

## Observed name lookups

Both complete thunks zero-extend a byte, multiply it by 8, load a length from
`0x21d4a0 +8*index`, and load a pointer from `0x566fb80 +8*index`. They pass
that pointer and length to the destination's slot `+0x18`. The reference thunk
first dereferences its input pointer; the value thunk reads the byte directly.

The **inspected** pointer window is `[0x566fb80,0x566fbe8)` and the length
window is `[0x21d4a0,0x21d508)`. All 13 selected pointer slots have unique
`R_X86_64_RELATIVE` records with symbol index zero and zero original file words.
The analyzer checks each actual addend, length, UTF-8 slice and literal hash.

| Raw index | Literal slice | Bytes |
| ---: | --- | ---: |
| 0 | `U8` | 2 |
| 1 | `U16` | 3 |
| 2 | `U32` | 3 |
| 3 | `U64` | 3 |
| 4 | `U128` | 4 |
| 5 | `Usize` | 5 |
| 6 | `I8` | 2 |
| 7 | `I16` | 3 |
| 8 | `I32` | 3 |
| 9 | `I64` | 3 |
| 10 | `I128` | 4 |
| 11 | `Isize` | 5 |
| 12 | `Reserved` | 8 |

In particular, the previously opaque 5 and 12 select `Usize` and `Reserved`
in this lookup. The thunks have **no local index guard**. Thirteen inspected
rows do not prove a complete valid byte domain or rejection of indices
13..255; those inputs remain uncharacterized. A diagnostic literal `U128`
does not establish a u128 wire decoder. These names do not recover an
original nominal `IntegerType` enum.

## Validation and remaining scope

Thirteen focused methods pass, including 30 copied-real-target byte/metadata
corruption cases below the production identity gate, two native-listing
corruption cases, whole-input identity/truncation rejection, existing-output
preservation and actual CLI regeneration. Controls alter constructor/field
offsets, pointer indirection, tag-3 dispatch, descriptor and helper RELA
bindings, name pointers/lengths/UTF-8, FDE extents/lengths/CIE references, and
retained native bytes/coverage. Native comparisons check exact byte tiling
and selected instruction boundaries; they do not independently decode
arbitrary hostile mnemonic text.

Focused commands and their raw log are retained here. Required full repository
checks must run on the frozen candidate; their exact final commit/result is
recorded in the PR validation receipt, not invented in this pre-freeze packet.
Original artifacts, imports, reference revisions and progress records remain
unchanged. No Rust crate, dependency, gate, source equivalence, runtime replay,
node #115 or visor claim is made.

Next: establish application producer-to-formatter reachability and helper
`0x1571f50`'s actual behavior before assigning a complete runtime error API.
