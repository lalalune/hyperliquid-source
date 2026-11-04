# RE-017: post-block action keys and result cleanup

This packet shows how a selected node #115 post-block path constructs a 20-byte key, conditionally updates state, carries a 304-byte result row back through the block engine, and hands that row to cleanup; an independent reconstruction can therefore preserve both the key encoding and the row's distinct lifetime.

- Component ID: `abci`; this RE-017 loader-linked question also advances RE-009 state-root research.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; the unlicensed navigation reference is `999556f6e0a474b8312db96ec3149e1c44e97c23`. No reference source is copied.
- Claim status: selected ELF bytes, relative operands, locations, relocations and unwind records are observations; the key interpretation and cross-call value flow are conditional inferences. Execution, scheduling, alias stability and helper effects remain unresolved.
- Scope included and excluded: six previously unselected FDEs, the selected expanded and compact post-block arms, one bounded key-to-state route, result-row layout, returned descriptor and selected cleanup/failure paths. Prior loader, block engine, root selector, GOT slots, their call sites and nested dispatcher are contextual dependencies, not newly owned bodies. This does not close every begin/action/end branch or any component gate.

## Reproduce

Run from the repository root, with the authenticated #115 artifact and the repository's `tools/elf_index.py` and `tools/fde_extents.py` present. Replace the placeholders with empty writable directories and a PATH that contains Python but no binutils:

```sh
python3 tools/abci_postblock_keys115.py --out research/work-items/RE-017-abci-postblock-keys-115
python3 -m unittest tests.test_abci_postblock_keys115
python3 tools/artifacts.py verify
python3 tools/verify_imports.py
python3 tools/verify_packets.py
python3 tools/catalogue.py --check
python3 tools/reproduce.py
PYTHONHASHSEED=1 TZ=Etc/UTC PATH="<python-only-path>" python3 tools/abci_postblock_keys115.py --out "<tmp-dir>/one"
PYTHONHASHSEED=937 TZ=Pacific/Honolulu PATH="<python-only-path>" python3 tools/abci_postblock_keys115.py --out "<tmp-dir>/two"
diff -r "<tmp-dir>/one" "<tmp-dir>/two"
diff -r -x README.md -x MANIFEST.sha256 "<tmp-dir>/one" research/work-items/RE-017-abci-postblock-keys-115
(cd research/work-items/RE-017-abci-postblock-keys-115 && sha256sum -c MANIFEST.sha256)
```

The optional historical check authenticates the separate #94 input and must leave the #115 output unchanged:

```sh
git show d3bc12bdf4cb324ee659a2c79fdcf4e2f8eba1b0:research/work-items/RE-017-abci-state-link-94/README.md
python3 tools/abci_postblock_keys115.py --historical references/can1357-hl/bin/hl-node-mainnet-new --out "<tmp-dir>/historical"
diff -r "<tmp-dir>/one" "<tmp-dir>/historical"
```

Python 3.12.3 on Linux x86-64 was used. The producer checks the complete #115 digest before creating output, uses the repository ELF/FDE/CIE/LEB readers and reads RELA and selected fixed instruction patterns directly. File-backed mapping excludes `SHT_NOBITS` and rejects missing or ambiguous mappings. It invokes no external program and does not run a captured binary. GNU objdump 2.42 was used only for separate human inspection; none of its output is parsed or emitted. The manifest covers this README and every generated evidence file.

## Evidence

Coordinates are linked ELF virtual addresses before load bias; generated tables include file offsets and raw bytes. `functions.tsv` contains the complete bytes, hashes and exclusive ends of the six FDE ranges. Each range is reconciled with the unwind header; an FDE is an unwind-described range, not proof of a complete source-function boundary or a function census. `windows.tsv` distinguishes `new` and `context` selections; `edges.tsv` decodes only the listed pinned relative forms; `fields.tsv`, `relocations.tsv`, `location.json`, `exceptions.tsv` and `unwind-links.tsv` retain byte-backed operands, RELA and LSDA records. `summary.json` contains counts and arithmetic joins, not coverage percentages.

### Selected route and boundaries

Earlier proposals #2047, #2107 and #2243 describe a conditional route from the #115 `state.rs:123:37` loader, through a captured owner and block wrapper, to the expanded block engine. Their loader, slot and call-site observations are context. On the prior selected route, `0x4fcb590` supplies an output buffer to adapter `0x56186c0`, which forwards that buffer to engine `0x5a06600`. The engine forms a pointer to its context's state-pointer cell at `+0x450`, calls the prior begin boundary and later passes that cell to `0x5486720`. The caller dereferences it and conditionally calls the newly examined expanded post-block body. An earlier proposal also records a separate compact engine path through `0x54897e0`. The two layouts are examined independently; they are not assumed to be the same live allocation.

| New FDE start | Selected observation |
| --- | --- |
| `0x5601e50` | Expanded post-block body: assembles state-derived pointers, calls two existing relative-slot boundaries, appends a returned range, detaches one of two state descriptors, builds keys and result rows, and returns a three-word row descriptor. |
| `0x5605ee0` | Compact counterpart with separately checked offsets and instructions; it calls the same append boundary and its own row wrapper. |
| `0x57c3090` | Appends a selected range in `0xc0`-byte units to a ring-like destination, with addition-carry, capacity, growth, copy and cleanup boundaries. |
| `0x5601970` / `0x5601be0` | Expanded / compact row wrappers: pass a zero-initialized flag pointer to already studied dispatchers, branch on the returned result byte, update a leading state counter and assemble a `0x130`-byte result row. |
| `0x4f33990` | On the selected upper return, consumes three adjacent descriptors: it iterates the first in `0x130`-byte steps, then processes two `0x68`-stride collections and their allocation-release boundaries. |

The expanded caller's selected zero- and one-mode call sites are `0x5486d62` and `0x548726d`; the compact equivalents are `0x5489ea6` and `0x548a3ad`. The caller's quotient-versus-saved-word checks precede these calls; reaching division with a zero divisor is not ruled out by this packet. The functions and call sites above the six new extents remain context. The upstream loader-to-owner connection, ordinary copy binding, normal returns and preservation of the state-pointer cell across all intervening aliases are conditions, not observed runtime facts.

### Descriptor choice and append

The expanded body obtains the ring destination at state `+0x42d0`; the compact body uses `+0x3760`. Before detaching either of two 40-byte descriptors, both call `0x57c3090` with a returned range whose selected end calculation uses `0xc0 * count`. The append body reads destination words at `+0`, `+8`, `+0x10` and `+0x18`; under a valid ring representation these behave as capacity, storage pointer, head and length. For a nonwrapping byte span that is a multiple of `0xc0`, its shift and modular inverse yield the number of rows. The body does not itself establish that an arbitrary corrupt byte span is aligned. Addition carry reaches the recorded failure call and `ud2` if it returns; insufficient space reaches a growth boundary. The growth and dynamically bound copy implementations are not reconstructed.

| Mode byte passed to post-block body | Expanded descriptor | Compact descriptor | Selected stores after saving 40 bytes |
| --- | --- | --- | --- |
| zero | state `+0x3eb8` | state `+0x3348` | Five qwords become `0`, `8`, `0`, `0`, `0`. |
| nonzero | state `+0x4268` | state `+0x36f8` | The same replacement is applied to that selected descriptor. |

The listed pairs, the root-group offset and the mode-byte offsets differ by `0xb70`; this is only a comparison of the selected operands, not proof that the entire objects have the same layout. Calls before and after the stores can affect the state through aliases. If append or an earlier helper unwinds, the later reset is not reached on that direct instruction sequence; no rollback of earlier helper writes is established.

### Key construction and action decision

For a selected `0x48`-byte input row, let `x` be its qword at `+0x20`. The following table describes the exact selected instructions in both post-block bodies. The comparison at state `+0x80` is **32 bits**, while the comparison with state `+0x88` is 64 bits.

| Condition | Resulting 20 bytes passed as the selected key |
| --- | --- |
| Low 32 bits at state `+0x80` equal 1 and state `+0x88 == x` | Twenty bytes of `0x22`. |
| Either comparison fails | `0x20`, then eleven zero bytes, then `x` in eight-byte big-endian order. |

The first byte and the two overlapping writes that fill the next eleven bytes are distinct instructions. The normal arm uses `bswap` before the final little-endian qword store. The equal case replaces the last qword with the repeated `0x22` value. These are bytes, not a claimed address type or proof of reachable input. The focused tests exercise each of the 64 comparison bits and distinguish byte order and noncanonical upper tag bits.

After constructing a separate object with first qword `0xbf`, the expanded body tests byte state `+0x434b`; the compact body tests `+0x37db`.

| Selected condition | Observed local continuation |
| --- | --- |
| Gate byte is nonzero | The expanded or compact wrapper receives the state pointer, 20-byte key, a copied `0xf0`-byte object and a 32-byte row prefix. |
| Gate byte is zero | The post-block body saturating-increments state `+0x50`, sets state byte `+0x78` to 1, calls the existing dispatcher, and clears that byte on normal return. It later performs the leading-word update described below. |
| A row in the separate `0x128`-stride input begins with qword `0xe2` | The second loop branches to its cleanup boundary before calling the wrapper for that row; it does not visit later rows in that loop. Earlier rows and the separate first loop are unaffected by this local test. |
| Wrapper dispatcher returns first byte `0x0f` | The selected path passes its payload to the pre-existing conversion boundary and builds a 40-byte local result containing byte `0x0f`. |
| Wrapper dispatcher returns another first byte | The selected path uses the existing relative-slot conversion boundary instead. |

The expanded wrapper initializes a byte to zero at its stack `+0x50` and passes its address in caller stack argument `+8`. The prior expanded dispatcher saves six registers and reserves `0x268` bytes; after accounting for the call's return address, it reads that pointer at callee stack `+0x2a8`. On its previously documented internal `0x0f` arm, a flag byte other than 1 selects a saturating increment of state `+0x50`, sets byte `+0x78`, calls the existing dispatcher and clears the byte on normal return. Thus this wrapper supplies a zero flag on entry, unlike the earlier caller's initially-one flag. That consequence still requires the indicated internal result, normal calls and no intervening write through an alias.

After either wrapper conversion returns normally, a **32-bit** comparison of state `+0` with 1 determines the next write. A match preserves the entire qword at `+0` and writes `min(old + 1, 2^64 - 1)` to state `+8`; any other low dword writes qword 1 to `+0` and qword 1 to `+8`. This rule also applies to noncanonical high dword bits and is not a Rust type claim.

### Row lifetime and conditional root connection

On the selected wrapper return, the call through the copy slot is supplied `0xf0` bytes from the object. Under its ordinary copy behavior, the row layout is:

| Row offsets | Selected producer |
| --- | --- |
| `+0x000..+0x0ef` | The supplied object. |
| `+0x0f0..+0x117` | The 40-byte locally prepared result. |
| `+0x118..+0x12b` | The 20-byte key; the final four bytes are a separate store. |
| `+0x12c..+0x12f` | No store is established by this selected wrapper sequence. |

The post-block body appends rows with stride `0x130` and returns a three-word descriptor at the caller's stack `+0x30`. On the selected expanded mode-zero path, a nonzero returned count reaches the growth boundary and a call through the copy slot, supplying `0x130 * count` bytes from the returned pointer to the caller's accumulator; zero count bypasses that copy. The caller later saves the accumulator descriptor from stack `+0xf0` into `+0x1f0` at `0x5487625..0x5487647`; `0x5488f03..0x5488f1d` prepares its return, and `0x5489103..0x5489140` writes it at the start of the caller's result. After its later root-selector call, the engine copies that returned descriptor to engine result `+0x30`. These joins require ordinary copy behavior and no relevant intervening mutations.

The upper adapter uses the same output pointer. The upper caller's engine result begins at stack `+0xb0`; its separate leading descriptor is processed first with a `0x168` element stride. The call at `0x4fcb820` then passes stack `+0xe0`, corresponding to the distinct engine result `+0x30`, to `0x4f33990`. Thus the selected accumulator descriptor is handed to the cleanup routine if earlier calls return normally and do not replace the relevant stack slots or storage. The earlier `0x168`-stride cleanup is context, not a claim that those elements have the new row's `0x130` layout.

The cleanup routine handles three adjacent descriptor triples on its normal path, with offsets relative to the pointer passed by the upper caller:

| Allocation word | Pointer / count | Element stride | Selected per-element boundary |
| --- | --- | --- | --- |
| `+0x00` | `+0x08` / `+0x10` | `0x130` | Calls `0x5b1d0f0` on the row start and `0x5b232a0` on row `+0xf0`. |
| `+0x18` | `+0x20` / `+0x28` | `0x68` | Calls `0x5b0d830` with element `+8`. |
| `+0x30` | `+0x38` / `+0x40` | `0x68` | Calls the same boundary with element `+8`. |

After each loop, a nonzero allocation word selects slot `0x64df4a0` with the pointer and the low 64 bits of allocation word multiplied by element stride. The last such transfer is a tail jump. Zero count and zero allocation are distinct decisions. The indirect binding and full helper effects are not proved. This selected returned row descriptor is cleaned up on this upper route; that observation does not rule out other publications, aliases or consumers.

The previously examined expanded dispatcher uses the original 20-byte input key on its selected internal `0x10/0xd0` arm, calls the existing account-entry boundary with state `+0x14d8`, and saturating-adds to the returned value at `+8`. This keyed-update arm and the internal `0x0f` arm described above are alternatives for the same intermediate result; the latter arm's zero-flag decision does not imply the former update. The earlier root packet independently captures state `+0x14d8` as group input 4; the existing group visitor pairs the stored key and value with child descriptors. The new wrapper-to-dispatch call and key copy make a conditional connection from this packet's key to that already studied root input. It requires the internal result, normal helper returns, the same state object, no relevant alias changes, and the root selector choosing its hashing arm followed by that group visit. It does not establish the final root digest, a callback schedule, or the behavior of other action tags.

### Failure and historical controls

`unwind-links.tsv` associates selected calls with encoded LSDA call-site rows. For example, an unwind across the expanded wrapper-to-dispatch call at `0x5601a06` has landing `0x5601bc6`, whose local sequence calls a cleanup boundary and then the unwind-resume boundary. The direct expanded dispatcher call at `0x56052ea` has landing `0x5605c7a`; the normal flag-clear store lies after the call, while that landing enters cleanup. The compact direct call has its own landing at `0x5609ba6`.

| Cleanup call that unwinds | Encoded landing | Selected continuation, if its helpers return normally |
| --- | --- | --- |
| Row-start helper at `0x4f339bf` | `0x4f33b27` | Calls the current row's `+0xf0` helper, processes remaining rows, conditionally releases the row allocation, invokes boundaries for both following descriptors, then reaches unwind resume. |
| Row `+0xf0` helper at `0x4f339d4` | `0x4f33b3f` | Joins the remaining-row and subsequent-descriptor cleanup sequence without re-calling that current helper. |
| First or second `0x68`-stride helper at `0x4f33a1d` / `0x4f33a5d` | `0x4f33ae1` / `0x4f33a9c` | Processes remaining elements in that collection, conditionally releases its allocation, and continues with any later descriptor before unwind resume. |

These are encoded static paths: helper side effects, rollback and the final flag on an actual unwind are unresolved. Further unwinds during cleanup have separate encoded rows. The cleanup release call at `0x4f339ef` has no matching selected LSDA row; that is not proof that it cannot unwind.

The retired RE-017 clue is preserved in Git revision `d3bc12bdf4cb324ee659a2c79fdcf4e2f8eba1b0` and belongs to node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`: caller `0x32725d0`, call `0x3272785`, wrapper `0x3273810`, and Location `0x56dfbf8` for `state.rs:107:37`, with a comparison against 2. The optional command checks that old digest, FDE/header records, relocation, call, reference and Location against #94 bytes. Separately, #115 bytes establish `0x3c13520`, reference `0x3c1352f`, Location `0x64767a8` at `state.rs:123:37`, and a comparison against 1. Similar topology is a navigation clue, not release equivalence; no #94 layout, address or tag is transferred to #115.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, compiler/linker options, two-build result, raw or normalized implementation comparisons, masks, helper/call-target closure, full relocation/vtable/data closure and whole-ELF comparison are **not yet implemented or measured**. Target bytes are evidence rather than transplanted implementation. No captured node or visor was executed.

## Results and limitations

The generated summary reports six selected FDEs totaling 35,016 bytes, 40 new and 35 contextual windows, 65 new and 22 contextual edges, 135 operand fields, eight relocation records and 287 LSDA rows. Of 38 selected new calls, 35 match a call-site row. These are bounded selections, not a denominator for node coverage. The focused suite passes 17 tests with zero skips, including bad digest before output, corruption of every selected byte window and operand, every listed transfer displacement, ambiguous/NOBITS/out-of-range mappings, FDE/header disagreement, malformed and duplicate relocations, changed LSDA headers, stack and row-offset joins, key byte order and equality boundaries, tag-width and saturation cases, and aligned versus unaligned ring-span controls. The models are synthetic and do not execute target instructions.

No `abci` gate is requested. The process entry, complete loader-to-owner identity, all block actions and alternate arms, helper/alias effects, real scheduling, complete unwind cleanup, allocator semantics, snapshot compatibility, final state-root digest and Rust equivalence remain open. The available PR snapshot contains titles and file lists rather than every independent contributor's full diff; a submitting reviewer should recheck the selected six FDEs against current PR bodies. Next question: establish whether the returned row key and its state-map update survive intervening helpers to a particular root visit, and close the additional direct-dispatch and unwind effects without re-owning prior bodies.
