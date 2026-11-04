# RE-001: node #115 system-transaction RPC address projection

- Component: EVM RPC projection; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses, interval ends exclusive.
- Full evidence extents: projection `0x232dff0..0x232e7c5` (2,005 bytes) and constructor context `0x16ef450..0x16ef624` (468 bytes), 2,473 bytes total. Constructor fee arithmetic is context, not a new claim. All component gates remain false.

## Finding

The function associated with the exact 19-byte context `system_txs_by_block` projects stored system-transaction rows into 0x230-byte RPC records. This packet closes how it chooses one 20-byte address field, including when it consults a callback and when it uses a literal fallback. The field's original source name and authority meaning are not needed for the raw contract.

Input row stride is `0x120`. The first 16 bytes are compared with the pair of little-endian qwords `(5, 0)` before the row is projected. Exact equality ends the loop, returning the preceding prefix; a first qword of 5 with a nonzero second qword is not that sentinel. Empty vectors produce no rows. For valid rows the loop starts index zero and increments once per emitted record. The numeric index, block scalar and block hash are separately staged as constructor metadata.

The row's byte at `+0x108` and 20 bytes at `+0x109` supply an optional address. A helper at `0x176d6c0` produces a decoded descriptor with raw kinds 0 through 4; its transaction decoding and signature semantics remain opaque. The descriptor's kind-specific address layout is observed directly:

| Raw kind | Presence test | Address bytes |
| --- | --- | --- |
| 0 | byte +0x80 equals 1 | +0x81..+0x95 |
| 1 | byte +0x90 equals 1 | +0x91..+0xa5 |
| 2 | byte +0xa0 equals 1 | +0xa1..+0xb5 |
| 3 | unconditional | +0xc8..+0xdc |
| 4 | unconditional | +0xb8..+0xcc |

This address availability does **not** override an explicitly supplied row address. The chosen output follows the same precedence on every raw kind:

1. When the low bit of row byte `+0x108` is set, copy row bytes `+0x109..+0x11d`.
2. Otherwise, if the decoded descriptor has no address, use twenty zero bytes.
3. Otherwise, select a qword at decoded `+0x30` when kind and qword `+8` are both zero, or at `+0x40` in every other case. If it is zero, use twenty `0x22` bytes.
4. Otherwise, invoke `0x29ba3d0` with the decoded 20-byte address and the exact `system_txs_by_block` context, using its returned 20 bytes. Its lock/callback implementation and returned-address meaning are outside this claim.

The mask is one, not an equality test against byte one. Thus raw flag 3 selects the supplied bytes and raw flag 2 does not; these cases describe instruction behavior, not valid serialized booleans. The zero-field fallback combines a verified 16-byte literal with a four-byte immediate. The callback has no opportunity to replace any earlier branch's choice.

The selected 20 bytes are staged at the temporary transaction's `+0x190`. After type-specific packing, the constructor copies `0x1b0` bytes to output `+0x50`, retaining the address at output `+0x1e0..+0x1f4`. The surrounding projection appends one `0x230`-byte result. This placement is bounded evidence for the address field; the constructor's other fields and fee rules are not reconstructed here.

The relations cover 61,440 combinations of five raw kinds, selector qwords, presence bytes, all 256 supplied-flag values and zero/nonzero selected fields, plus 36 exact-sentinel pairs. Three mutations of actual operands alter the flag mask, the repeated-byte suffix and the selected-field offset. No native code is executed or emulated.

## Preconditions and unresolved behavior

The question starts after any enclosing owner initialization and assumes valid row/vector extents and decoded kinds 0..4. The native jump table has no local general-purpose range check; the packet does not claim acceptance of arbitrary kinds or malformed pointers. It does not infer transaction type names, public API promises, sender authority, cryptographic recovery, callback contents, archive format, system-transaction construction/execution, full output schema or full RPC equivalence. Cleanup of the remaining owned rows is supporting context; this is not an end-to-end resource-lifecycle proof.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Three changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-system-rpc-address-projection/export_disassembly.py
python3 research/work-items/RE-001-node115-system-rpc-address-projection/verify.py --controls
python3 research/work-items/RE-001-node115-system-rpc-address-projection/relations.py
python3 -m unittest discover -s tests -p 'test_node115_system_rpc_address_projection.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-system-rpc-address-projection/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

The all-state overlap audit is retained in `scope-audit.json` and the PR census. [PR #1269](https://github.com/lalalune/hyperliquid-source/pull/1269) covers node #94 system-transaction construction and execution, including repeated-byte sender input. [PR #1553](https://github.com/lalalune/hyperliquid-source/pull/1553) covers stored system-transaction/receipt serialization. [PR #2104](https://github.com/lalalune/hyperliquid-source/pull/2104) uses a repeated-byte address in a different address-set policy. Those are related evidence, not newly claimed findings. This packet's question is the stored-row RPC projection's ordered supplied/absent/zero-field/callback selection and the placement of the selected 20 bytes.

Open and closed PR metadata and available file evidence were inspected by GPT-6.1 Terra, including older-release semantic analogues. Missing patches, GitHub's capped historical file list and unavailable historical PRs limit the audit; this is not an absolute guarantee about unpublished or future work.

New analysis and relations are independently authored under the repository MIT license. ELF parsing, export and corruption-check scaffolding adapt existing MIT registry-row-labels and later evidence packets. No unlicensed inferred source is copied. Captured binary and imported-reference rights remain unchanged. There is no hosted-CI success, completed component gate or source-to-target equivalence claim.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
