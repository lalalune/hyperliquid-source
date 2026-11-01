# RE-004: schema asset cap display conversion in node #94

This packet shows that the non-Main dex schema's per-asset map is displayed by resolving each asset to a name and converting its unsigned 64-bit value to binary64 before division by one million, including an empty-name fallback for an invalid asset lookup.

- Component ID: RE-004 (quantities and rounding).
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23` used only as a lead, with no code copied.
- Claim status: observation for pinned bytes, calls and FDE ranges; the names of the dex, schema and map are inferences, as explained below. The unit of the map value and the final serialized field name remain unresolved.
- Scope included and excluded: the response path through three listed FDE ranges, with the asset lookup, value conversion, empty and allocation branches. Tree navigation, the sort and map-building callees, the external dex lookup, allocator internals, serialization, other callers and runtime execution are excluded.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3 and its standard library. The tool reads ELF bytes using the repository's `elf_index` and `fde_extents` parsers; it checks the full input digest before parsing and never executes the node or invokes binutils. Generated evidence is `evidence.json` and `model-cases.json`; the manifest also covers this README. The model cases assume ordinary IEEE-754 binary64 round-to-nearest, ties-to-even; they do not execute the target instructions.

```sh
python3 tools/artifacts.py verify
python3 tools/schema_cap_view94.py --out <tmp-dir>
python3 -m unittest tests.test_schema_cap_view94
python3 tools/catalogue.py --check
```

Compare the generated files with the retained files. Repeating the tool with different `PYTHONHASHSEED` and `TZ` values must produce identical bytes. For a human-readable disassembly only:

```sh
objdump -d -M intel --start-address=0x26b3890 --stop-address=0x26b3c17 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x27ed840 --stop-address=0x27eda58 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x27d6710 --stop-address=0x27d6c68 artifacts/node/94/hl-node
```

## Evidence

Addresses are ELF virtual addresses. `evidence.json` includes each entire FDE range as bytes and SHA-256, the FDE record address, fixed landmarks, and the conversion constant bytes. An FDE is an unwind-described range; it is not by itself proof of a complete source function.

| Range | Observed role |
| --- | --- |
| `0x27d6710..0x27d6c68` | obtains a dex row; for tag other than 3, prepares the map at pointer `row+0x208` and calls the view builder |
| `0x27ed840..0x27eda58` | allocates 32-byte temporary rows, invokes the conversion loop, dispatches by resulting length, and builds the returned collection |
| `0x26b3890..0x26b3c17` | iterates the input tree, resolves each key to a name, converts the value and appends one temporary row |

The mode test at `0x27d6834` follows a successful tagged lookup. A returned tag different from `0x186` takes the outer error path; a row with byte `+0x230 == 3` takes the path without this map conversion. On the other path, the pointer at `row+0x208` supplies a root at `+0x30`; if that root is zero, the caller supplies an empty iterator, otherwise it also loads the two words at `+0x38` and `+0x40`. The context passed to the converter is the row itself. A prior packet identifies the row variant as `MainOrHip3` and the pointer as `schema`; another associates the map with an open-interest cap. Those are cross-packet inferences, not independently established names in this packet.

For each yielded tree entry, the key comes from `node+8+8*i` and its value from `node+0x60+8*i`. The loop at `0x26b3af7` computes quotient and remainder of the key by 10000. It checks the quotient against `context+0x30`, and the remainder against the length at `context+0x10`. On success it loads a name pointer and length at offsets `+8` and `+0x10` of the 48-byte row at `context+8 + 48*remainder`, allocates and copies the name if nonempty. On either failed lookup it emits an empty string representation with length 0 and pointer 1. In both cases it converts the same original value and appends a row with name capacity, pointer and length at offsets `0`, `8` and `0x10`, and the binary64 result at `0x18`. Thus invalid asset metadata does not itself discard that value.

The reciprocal is read from the instruction bytes. Let `m = 0x346dc5d63886594b`. The `mul` high word followed by `shr 11` gives `(key*m)>>75`. The generated proof records `10000*m - 2^75 = 432` and `(2^64-1)*432 < 2^75`. Since the largest remainder is 9999, the positive approximation error cannot carry the quotient to the next integer. This proves the quotient and remainder for every u64 key, independently of sample vectors.

The loop uses the two packed constants at `0x203e80` and `0x202ea0` for the unsigned-u64-to-binary64 conversion idiom, then divides by the binary64 word at `0x20ae60`, exactly 1,000,000. The integer conversion happens first, so this is not an exact rational conversion. Under the stated rounding mode, raw values `2^53` and `2^53+1` produce the same result; both and the maximum u64 are retained in `model-cases.json`. The cases are predictions from an independent expression, not differential execution.

The wrapper checks multiplication of the input length by 32 and the allocation size limit. A zero length yields an empty result. Length 1 bypasses both sort calls; lengths 2 through 20 call the short-sort helper, while lengths at least 21 call an indirect helper. The collection builder receives the resulting rows. Allocation failure calls the allocation-failure path; invalid tree navigation reaches panic paths. The comparator, duplicate-name handling, all ordering guarantees and the allocator bodies were not established.

## Implementation and comparison

Rust implementation: not yet implemented. No Cargo build, target execution, compiler comparison, normalization mask, relocation closure or byte-equivalence claim is made. The Python tool fixes complete function hashes, checks 12 semantic landmarks and validates both direct call displacements, the FDE extents and three floating-point constant records. Its 72 model rows cover asset quotient/remainder boundaries, lookup success and failure, floating-point integer precision boundaries and the u64 maximum. They are model examples rather than proof that target instructions ran.

The focused unittest includes bad input digest, altered code, altered divisor, changed FDE end, invalid and NOBITS addresses, lookup boundaries and an altered reciprocal. These controls test the static checks and the model, not the omitted callees.

## Results and limitations

Three FDE ranges and 12 byte landmarks pass the digest-bound checker. Nine focused tests pass with no skips. Two independent output directories, generated with different hash seeds and time zones, compare byte for byte. The reciprocal argument covers all 2^64 keys; floating-point cases are sampled. The exact floating-point environment at every production call site is not established here. The input tree is assumed structurally valid on the normal path; its iterator and panic reachability are not exhaustively evaluated. A missing or duplicate name may affect the subsequent collection, whose builder is outside the scope. The original map's units, user-visible field name and upstream writers remain open. No component progress gate is requested.

Next question: bind this schema map to its serializer key and writers, then test how duplicate or missing names behave in the returned collection.
