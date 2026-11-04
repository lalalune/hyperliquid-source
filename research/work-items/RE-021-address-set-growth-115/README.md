# RE-021: address-09 companion-set insertion and rehash on node 115

The address-09 record's key can now be followed into the registry's companion set through the four-record preflight, collision handling, and both table-rehash paths, making the source-set membership needed by the previously mapped projection a conditional reconstruction result rather than an assumption.

- Component ID: `evm`; RE-021 is a bounded extension of RE-011, not a new official task row.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; historical node #94 packets are retained at `c5ce58bdc9f346394d5e8ce12e8bd095acaedc6e` and `2fff9c5e02c5ecd6cb5062f1b23442b5ba712104`. No unlicensed reference source was copied.
- Claim status: instruction bytes, FDEs, relative transfers, relocations and record contents are observations; set, growth, key, allocator and callback names are inferences. Live seeds, selected fork and runtime membership remain unresolved.
- Scope included and excluded: one normal mode-2 record handoff, the 20-byte set insertion, its hash, reserve, two rehash routes, selected failure and unwind landings. Earlier registry builder, lookup, callback and context projection bodies are boundaries, not selected functions in this packet. Complete transaction execution, all allocator and synchronization internals, reth/revm fork closure, every exception action and all EVM state-transition inputs are excluded.

## Reproduce

From the repository root, with the authenticated node #115 artifact present:

```sh
python3 tools/re21_address_set115.py --out research/work-items/RE-021-address-set-growth-115
python3 -m unittest tests.test_re21_address_set115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

Replace the two placeholders below with distinct empty writable relative directories:

```sh
PYTHONHASHSEED=0 TZ=UTC python3 tools/re21_address_set115.py --out <tmp-dir-one>
PYTHONHASHSEED=937 TZ=Pacific/Honolulu python3 tools/re21_address_set115.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

If the independently authenticated historical capture is available, the following optional check compares the two record keys, callback relocations and historical FDE extents. It prints the comparison and leaves the generated #115 files unchanged:

```sh
python3 tools/re21_address_set115.py --legacy references/can1357-hl/bin/hl-node-mainnet-new --out <tmp-dir-one>
```

The collector authenticates the complete input before parsing it, imports the repository ELF and CIE/FDE readers, reads file-backed sections only, and invokes no external program. It produces the ten evidence files; it does not modify this README or the manifest. Python 3.12.3 and GNU objdump 2.42 were used for analysis; objdump served only for human interpretation and is not an input to the collector or tests. No captured node code was executed. `MANIFEST.sha256` covers every other file in this directory.

## Evidence

All addresses are linked ELF virtual addresses before load bias. The generated records also contain section-derived file offsets, unmasked bytes, FDE/CIE records and relocation addends. An FDE is an unwind-described interval, not a complete function census. The selected branches and slices are not a complete x86 CFG.

| Selected role, inferred | Start | Exclusive FDE end |
| --- | --- | --- |
| 20-byte set insertion | `0x5c06630` | `0x5c06829` |
| Key hash state update | `0x5c394a0` | `0x5c3954b` |
| Reserve and new-table rehash | `0x5c06b20` | `0x5c06f4a` |
| In-place rehash | `0x5c05e70` | `0x5c060fe` |
| In-place hash callback | `0x5c07440` | `0x5c074bc` |
| Element swap | `0x5c06100` | `0x5c061bf` |
| Rehash landing cleanup | `0x5c063b0` | `0x5c06466` |
| New-table landing cleanup | `0x5c06470` | `0x5c064c1` |

### Handoff from the prior registry work

Open PR 2049 separately records the mode-dependent registry, the address-09 record, its callback and the direct lookup. This packet does not reclaim those bodies. `handoff.json` checks only the small boundary slices needed to join that prior work to new callees. The source record at `0x64c0730` has 56 file bytes, a 20-byte key at +`0x20` ending in `09`, tag `0x8000000000000009`, and a callback relocation at +`0x18` with addend `0x5c165b0`. Relocation is not applied to the saved raw bytes. Four RIP-relative loads and their stack stores reconstruct all 56 source bytes in the fourth 56-byte element of a 224-byte argument; the tag differs from the skipped sentinel `0x8000000000000013`.

At the previously studied extension boundary, the key bytes are copied to the stack and the call at `0x5c1894b` passes them to `0x5c06630`, with the first argument derived from registry +`0x28`. Before the four-element loop, a growth word at registry +`0x38` is compared to 3. A value at most 3 takes a call through relocation slot `0x64ec338` to `0x5c06b20`, with additional count 4 and seed pointer registry +`0x48`. Larger values skip that call. The same slot is used by the insertion routine for an additional count of 1. These preflight and call-site slices are context for the newly analyzed callees; the earlier FDE bodies are not included in `functions.json`.

Assuming a valid set header, successful preflight and ordinary returns with no alias mutation, the four calls cannot exhaust an initial growth budget of at least four before the final call: each new empty-bucket insertion consumes one, while a duplicate or reuse of a deleted bucket consumes none. Under those conditions the source record's key is present after its call, whether it was already present or was inserted. Open PR 2120 separately copies this registry +`0x28` set during refresh and projects short keys. If that copy preserves its members, later helpers return normally, and the destination bound exceeds 9, the previously recorded projection can set logical bit 9. This is a conditional join across packets, not a live-memory observation.

### Set hash, probes, and writes

The selected instructions access a set header as follows: control pointer +`0x00`, mask +`0x08`, growth budget +`0x10`, element count +`0x18`, seed +`0x20`. For bucket index `i`, the 20-byte payload begins at `controls - 20 * (i + 1)`. The key comparison includes the first 16 bytes and the remaining 4 bytes; a matching control fingerprint alone is insufficient.

For a fresh hash state and a 20-byte key, let `a`, `b`, and `c` be little-endian loads of 8, 8, and 4 bytes, and `fold(x,y)` the XOR of the low and high 64-bit halves of the unsigned 128-bit product. The selected state-update and finish bytes give:

```text
h = fold(fold(a XOR set_seed, b XOR secret) XOR c, secret)
```

The address-09 key has `a = b = 0` and `c = 0x09000000`. The relocation at `0x64dfa78` points into `.bss`; neither its runtime value nor the set seed is file-backed evidence. The previously analyzed general map has a separate seed field: the common expression does not imply equal hashes, equal bucket positions, or shared allocation.

The high seven bits of `h` select a control fingerprint. A 16-byte group tests all matching fingerprints and full keys before a `0xff` empty control ends a miss. The first available negative control is remembered across groups, whose masked advances are +16, +32, +48 and so on. For a small table, a padding-derived candidate that aliases an occupied real bucket triggers a first-group fallback. `windows.tsv` and `edges.tsv` contain the exact selected instruction slices and transfers.

| Selected condition | Observed write or return |
| --- | --- |
| Growth budget is zero on entry | Call the reserve helper before probing, even if the key would be a duplicate. |
| Full 20-byte key already matches | Return low byte 1 without an insertion write; an earlier reserve may already have changed table layout. |
| Miss uses an empty `0xff` control | Store fingerprint and mirrored control, write 20 key bytes, decrease growth by 1, increase count by 1, return low byte 0. |
| Miss reuses a deleted `0x80` control | Perform the same key/control writes and increase count, without decreasing growth. |

The growth-zero case is a general property of this insertion routine, not a claim that a valid mode-2 fourth call must take it after the four-item preflight. Those conclusions require normal helper returns and the stated table invariants.

### Reservation, state changes, and failure boundaries

The reserve routine checks `count + additional` for carry. For a valid power-of-two bucket count, its observed capacity is the mask when the mask is below 8, otherwise `(mask + 1) - ((mask + 1) >> 3)`. If the requested total is at most half of that capacity, it selects the in-place path; otherwise it chooses a new allocation. Small requests round to 4, 8, or 16 buckets, and the larger path uses checked arithmetic and power-of-two rounding. The allocation layout has 20 bytes per bucket, alignment padding, and the control region. The synthetic tests independently compare the recorded bucket rounding with a capacity-based oracle over 65,536 requests.

The in-place route first changes occupied controls to `0x80` and negative controls to `0xff`, then hashes pending keys through `0x5c07440`. A key already in the same probe group keeps its payload and gets a fresh fingerprint; otherwise the selected path moves it to an empty bucket or swaps with another pending bucket via `0x5c06100`, continuing with the displaced key. On ordinary completion it recomputes growth as capacity minus count. The allocation route initializes a new control region to `0xff`, rehashes and copies each selected old 20-byte payload, then writes the new control pointer, mask, growth and count into the header before the conditional old-buffer release. The seed field is not among those four stores.

Overflow reaches a distinct failure-helper call when the selected caller's flag is nonzero; a null allocation reaches another failure-helper call. The helper internals and their effects are boundaries. The two LSDA tables identify an in-place hash-callback landing at `0x5c060e3` and a new-table hash-call landing at `0x5c06f35`. They call the selected cleanup routines before the unwind-resume boundary. The in-place caller supplies a zero per-element drop callback; its cleanup has a corresponding skip branch. `exception-sites.tsv` records call-site ranges and raw action offsets, not a decoded proof of all exception actions or recovery after a partially completed rehash.

### Historical cross-release check

The prior #94 packet identifies a callback slot at `0x574f0b0`, address bytes at `0x574f0c0`, wrapper `0x4e9d2a0`, and compression candidate `0x4e9a8a0` for node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. A later #94 record places the enclosing 48-byte record at `0x574f0a8`; the #94 maintainer review left its captured-execution receipt pending. The optional static comparison was run on that independently authenticated capture and confirmed the 20 key bytes, callback relocation, and the selected wrapper and compression FDE extents. It is not required for #115 evidence regeneration.

The independently authenticated #115 record above has a different 56-byte layout, key offset, callback offset and coordinates. Its 20 key bytes independently agree with the historical address-09 clue; its callback relocation agrees with the separately analyzed #115 adapter. This limited cross-check does not transfer #94 addresses, hash arithmetic, runtime behavior or execution receipts to #115.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo dependency closure, compiler/linker settings, native and normalized byte comparisons, relocation masks, executable behavior and whole-ELF equivalence: **not yet implemented or measured**.

The focused tests use synthetic keys, seeds, controls and budgets, including an independent 32-bit-limb multiplication oracle, all 160 individual key bits, empty/deleted controls, small-table padding, the 16-byte group transition, duplicate-before-empty ordering, four-element preflight budget and overflow boundaries. Corrupt digest, instruction, branch displacement, record, relocation, symbol, section and unwind controls must fail. These models are checks of the stated interpretation, not target execution or a captured behavioral oracle.

## Results and limitations

`summary.json` records 8 selected FDEs totaling 2,974 bytes, 40 selected windows, 51 selected transfers, 15 RIP references, 11 relocations, 9 prior-boundary slices and 8 call-site entries from 2 LSDA tables. These counts describe only this selection. The focused suite passed 39 tests with zero skips and with binutils absent from `PATH`. Two regenerations under different hash seeds and time zones matched all ten packaged evidence files byte for byte with binutils absent from `PATH`. Artifact digest/signature verification and the catalogue check passed.

Actual fork selection, publication, mutable seed values, the separately owned copy helper, external allocator effects, concurrency, all failure actions, the complete projection and all state-transition inputs remain open. No `evm` component gate advances. Next, validate the source-set copy and its owning provider's lifetime without reselecting functions covered by the existing refresh packet.
