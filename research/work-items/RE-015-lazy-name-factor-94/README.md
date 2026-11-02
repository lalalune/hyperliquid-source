# RE-015: lazy configuration publication and name-indexed binary64 selection

The #94 reconstruction can now preserve the configuration cell's 80-byte callback copy and its name-indexed output: the previously established `NvTestnet` fallback byte selects `5.0`, while the adjacent `NvMainnet` entries select `1.0` under the prior inventory's descriptor-index correspondence.

- Component ID: `constants`, task `RE-015`; this follows the existing configuration-cell and name inventory evidence.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; can1357 reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was used as a lead, not copied or treated as authoritative.
- Claim status: observations of authenticated ELF data, relocation records and selected machine-code bytes; a connection to the previously researched Once dispatcher is an inference from those observations and prior evidence. No execution or reconstruction claim.
- Scope included and excluded: the selector at `0x1402750`, callback bodies at `0x164c560` and `0x164c5d0`, their cell and descriptor records, the new binary64 value table on the previously established valid name domain, and selected failure branches. Existing Once and static-config initializer bodies are external boundaries. The original name inventory is not reproduced. #115, visor, runtime behavior, complete helper closure and the full component gate are excluded.

## Reproduce

From the repository root on Linux x86-64 with the pinned artifacts present, Python 3.12.3 and the standard library are sufficient for the collector and tests. GNU objdump 2.42 was used separately to inspect instruction starts; neither the collector nor the tests invokes it or any subprocess. Static reads only.

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/config_lazy_name_factor94.py --out work/lazy-name-factor-a
PYTHONHASHSEED=983 TZ=Pacific/Honolulu python3 tools/config_lazy_name_factor94.py --out work/lazy-name-factor-b
diff -r work/lazy-name-factor-a work/lazy-name-factor-b
for f in functions.tsv instructions.tsv branches.tsv rip-references.tsv relocations.tsv factor-runs.tsv failure-returns.tsv name-context.tsv summary.json; do
  cmp "work/lazy-name-factor-a/$f" "research/work-items/RE-015-lazy-name-factor-94/$f"
done
python3 -m unittest tests.test_config_lazy_name_factor94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
(cd research/work-items/RE-015-lazy-name-factor-94 && sha256sum -c MANIFEST.sha256)
```

The collector verifies the complete input size and SHA-256 before parsing. It imports `tools/elf_index.py` and `tools/fde_extents.py`; address reads reject NOBITS, ambiguous mappings and spans outside a file-backed section. Evidence files contain no disassembler output. The two generation runs above were also made with a Python-only `PATH` and matched byte for byte.

## Evidence

All addresses are linked ELF virtual addresses, before rebasing. The output files contain original file offsets, complete selected body bytes, decoded fixed-form targets and relocation record offsets. FDE extents are unwind-described ranges, not a full function census.

| Selected body | Half-open FDE range | File offset | Bytes | Observed role |
| --- | --- | --- | ---: | --- |
| Selector | `0x1402750..0x14027a9` | `0x1401750` | 89 | Guard the cell, load byte `+0x48`, index binary64 data |
| Callback at vtable `+0x20` | `0x164c560..0x164c5c6` | `0x164b560` | 102 | Consume a closure slot, call its cell initializer, copy the result |
| Callback at vtable `+0x18` | `0x164c5d0..0x164c636` | `0x164b5d0` | 102 | Same selected byte-level operations with separate RIP displacements |

### Cell and callback handoff

`0x1402755` addresses slot `0x576e928`; its `R_X86_64_RELATIVE` addend is cell `0x577b288`. The selector reads the dword at cell `+0x50`. A nonzero value branches to the existing Once target via slot `0x576e8b8`, passing `1` in `esi`, a pointer-to-pointer context and vtable `0x567b210`; normal return resumes at the byte load. Zero takes the byte load directly. The captured file contains dword `3` at `0x577b2d8`; this is an initial file value, not a claim about a running process.

The vtable's first three qwords are `0, 8, 8`. Its `+0x18` and `+0x20` relocation addends are the two callback bodies above. The existing `RE-001-once-state-94` packet reports dispatch through vtable `+0x20`; combining that prior finding with the selector's setup identifies `0x164c560` as the relevant callback when the external dispatcher takes that call. The `+0x18` body is retained as the sibling vtable entry, without asserting that this reader invokes it.

Both callbacks load a cell pointer through the supplied context and clear that **context slot** before testing the pointer. With a non-null pointer and state byte at argument `+0x04` unequal to `1`, they call the function pointer at the cell, using an 80-byte stack result. On normal return they store five 16-byte chunks into cell offsets `0x40`, `0x30`, `0x20`, `0x10` and `0x00`, in that order. The copied interval ends before the once word at `+0x50`; these writes are not claimed to be atomic. The cell's original pointer is supplied by a RELATIVE relocation to the already studied initializer `0x164ff00`. The prior initializer evidence accounts for 73 meaningful output bytes, so the remaining seven copied bytes are not assigned a value or field here.

| Condition | Observed local branch | Boundary |
| --- | --- | --- |
| Context yields null | `0x164c575` to `0x164c5b3`; sibling `0x164c5e5` to `0x164c623` | Call through slot `0x576e470` with Location `0x567b250` |
| Non-null and byte `+0x04` equals `1` | `0x164c57b` to `0x164c5c0`; sibling `0x164c5eb` to `0x164c630` | Call through slot `0x576e868` |
| Non-null and byte differs from `1` | Indirect call at `0x164c580` or `0x164c5f0` | Copy occurs only after the initializer returns normally |

The failure slots resolve to `0x157a9f0` and `0x4eeb4c0` respectively. Their implementations, unwind effects and return behavior are not reconstructed here. No inference about all concurrent executions follows from the local copies alone.

The local fallthroughs can nevertheless be fixed from the bytes. If the null-branch helper returns normally, control reaches the second helper call at `0x164c5c0` or `0x164c630` respectively; it does not rejoin the copy. If that second call returns normally, its next byte is `cc` at `0x164c5c6` or `0x164c636`, outside the selected FDE, an x86 breakpoint instruction. This describes the conditional instruction sequence only; it does not assert that either helper returns, how a breakpoint is handled, or the functions' boundaries beyond their FDEs. `failure-returns.tsv` records both pairs of call and continuation coordinates.

### Name-indexed values

`0x1402763` zero-extends the cell byte at `+0x48`; `0x1402767` selects `0x218640`, and `0x140276e` reads eight bytes at `table + 8 * byte` into `xmm0`. The local body performs **no bounds check**. The valid `0..75` name domain comes from the earlier RE-015 name inventory, not from this selector. For that domain the 608 bytes consist of 16 instances of binary64 `1.0` and 60 instances of binary64 `5.0`; `factor-runs.tsv` gives the complete run boundaries of these new values, not a copy of the old name table.

Four adjacent relocated name descriptors give a contextual boundary check. Associating their positions with variant bytes follows the prior inventory; these descriptor records alone do not independently prove the name parser's complete mapping:

| Index | Name | Selected value |
| ---: | --- | ---: |
| 32 | `NvTestnet` | `5.0` |
| 33 | `NvTestnet2` | `5.0` |
| 34 | `NvMainnet` | `1.0` |
| 35 | `NvMainnet2` | `1.0` |

The earlier constants packet established the `/cham` and `/static_config` template entries and the fallback byte `32`. This packet links that already documented result to the new selector; it does not assert the runtime directory, rederive the templates, or establish the source-level purpose or unit of the selected number. The tool's rejection of index `76` is a research-domain check, not an observed target rejection.

## Implementation and comparison

Not yet implemented or measured: no Rust component, build, target execution, raw/normalized comparison, operand masks, full relocation/helper closure or behavioral equivalence. The table values and callback consequences are static interpretations under valid-memory and normal-return assumptions.

## Results and limitations

The collector retains 3 FDE ranges, 47 checked instruction windows, 6 short-branch targets, 4 conditional failure-helper return sites, 11 RIP-relative targets, 12 selected RELATIVE relocations, 17 value runs and 4 contextual name descriptors. Twenty-two focused unittest methods passed with no skips, including changed digest, instruction, branch, post-helper breakpoint byte, FDE, relocation and table controls, duplicate-relocation, descriptor-prefix and cell-state corruption rejection, NOBITS/range checks and the invalid research-domain boundary. Independent outputs under different hash seeds and time zones were identical.

These results are a bounded RE-015 extension, not a complete constants reconstruction or a large/full-scope gate. All four component gates remain false. In particular, Once internals and the original initializer are prior-work boundaries, not newly recovered functions; the selected value's consuming application and behavior for invalid cell bytes remain unresolved. Next question: independently reconstruct the selector and its validated caller contract while preserving the existing Once and initializer boundaries.
