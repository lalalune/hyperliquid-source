# RE-011: node 115 storage-read input to state lookup

This packet identifies the selected node #115 storage-read adapter's field checks, two slot representations, database key construction and lookup-result paths, enabling a reconstruction to preserve their distinct inputs and return tags.

- Component ID: `RE-011` (`evm`, with an `evm-rpc` entry and a storage adapter).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; public sync reference `d0945c699d9d4774417f4355b10744e7cd420df8`; separate unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is used only to locate questions, not as implementation source.
- Claim status: selected byte, relocation, literal and FDE observations; role names and the method association are inferences; unresolved boundaries are listed below.
- Scope included and excluded: from a name-parameterized registration descriptor and its callback through selected parameter, slot and guarded storage-read paths to the response handoff. This is a read path, not an EVM transaction or persistent state transition. It does not establish all request grammar, original Rust types, live RPC behavior, the complete dispatcher, the block-selector effect, persistence, or reconstruction equivalence.

The existing #115 build provenance matrix is in `research/work-items/RE-002-build-provenance/provenance-115.json`. Its reth and revm fork-directory indicators establish source-path observations, not exact linked dependency versions or full private fork boundaries. The pinned public sync project's `Cargo.toml` declares reth tag `v1.1.5` and revm `=19.2.0`; those declarations describe that separate project, not the #115 binary. Earlier node #94 EVM storage-key work exists, including PR #730, but its artifact digest `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` and coordinates are not used as #115 evidence here; no cross-release equivalence is claimed.

## Reproduce

Run from the repository root with the authenticated target at `artifacts/node/115/hl-node` and the existing shared `tools/elf_index.py` and `tools/fde_extents.py`. The collector verifies the full SHA-256 before interpreting the image. It uses Python's standard library and those shared modules, reads ELF bytes directly, excludes fileless `SHT_NOBITS` sections from virtual-address mapping, and neither executes the target nor invokes another program. The analysis used Python 3.12.3 on Linux x86-64. GNU objdump 2.42 was used only for the human reading below; no generated record or test parses its output. There are no network operations.

```sh
python3 tools/re011_storage_read115.py --out research/work-items/RE-011-storage-read-115
python3 -m unittest tests.test_re011_storage_read115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

`MANIFEST.sha256` records output hashes, including this README; from the packet directory run `sha256sum -c MANIFEST.sha256`. To compare clean outputs with changed hash seed and timezone, substitute a writable directory for `<tmp-dir>`:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/re011_storage_read115.py --out <tmp-dir>/storage-read-a
PYTHONHASHSEED=987 TZ=Pacific/Honolulu python3 tools/re011_storage_read115.py --out <tmp-dir>/storage-read-b
diff -r <tmp-dir>/storage-read-a <tmp-dir>/storage-read-b
```

## Evidence

Coordinates are linked ELF virtual addresses, not rebased process addresses; file offsets are zero based, and FDE ends are exclusive. `functions.tsv` supplies the associated CIE/FDE and unwind-header bytes, offsets and body hashes for 22 selected unwind-described ranges. An FDE is not proof of an original source-function boundary or a complete function census. `windows.tsv`, `edges.tsv`, `relocations.tsv`, `data-refs.tsv`, `dispatch.tsv` and `literals.tsv` preserve selected raw bytes, direct and indirect transfer targets, referenced data and exact RIP-relative destinations. The collection is bounded to the listed witnesses; it is not full CFG or call-target closure.

### Selected path and boundaries

| Observed site or FDE start | Selected observations and direct consequences |
| --- | --- |
| `0x2cff6a0` | A constructor takes a supplied name, increments a reference count, builds descriptor `0x6450728`, and passes it to an insertion helper. ELF relative relocations at `0x6450748` and `0x6450750` both name `0x2d018b0`; allocation and reference-count failure exits are recorded. |
| `0x2d018b0` | The callback distinguishes object-shaped from positional input. Its object path calls `0x1d75220`, then the visitor at `0x1f4f020`. On a positional missing second argument, selected bytes construct `No more params` and pass code `-32602` with the `Invalid params` literal. Separate annotation sites use `address`, `index`, and `block_id`. The shared positional address/block parsers remain opaque boundaries. |
| `0x1f4f020` | Length and immediate-byte tests recognize `address`, `index`, `blockId`, and `block_id`. The two block names share a duplicate guard. Under the documented successful-value-parsing precondition, duplicate recognized fields are rejected; missing `address` is checked before missing `index`; an absent block field takes a default branch. Unrecognized names go to a value-skipping helper, whose complete grammar is outside this packet. |
| `0x2666d20` | Slot conversion first tries `0x21cf920`, then `0x21cfe10`; failure of both builds the recorded `JsonStorageKey` untagged-variant error. Successful first and second representations carry tags 0 and 1 respectively. |
| `0x21cf920`, `0x167a9c0` | Selected fixed-byte variants require 32 bytes. A selected string arm calls a fixed hex decoder: parity is checked before a lowercase `0x` prefix is stripped; the remaining length must decode to 32 bytes. The scalar table and selected SIMD classifier accept the same 22 ASCII hex characters. This is one attempted variant, so its failure does not alone establish RPC rejection. |
| `0x21cfe10`, `0x29fe3b0`, `0x29fd610`, `0x29fdb60` | Selected numeric arms produce four words or route a string to numeric parsing. The dispatcher recognizes binary, octal and hexadecimal prefixes in either letter case and otherwise chooses decimal. The power-of-two path walks from the end; the decimal path walks from the start in 19-digit chunks. Both selected helpers skip underscores and have explicit invalid-digit and 256-bit overflow exits. Their empty digit sequence reaches the zero result. Outer JSON and variant admission remain separate questions. |
| `0x2a1f3b0` | The tuple includes the literal `eth_getStorageAt` and the input pointers passed in `rdx` and `rcx`; the callback supplies a block-related pointer in `r8`. The selected tuple construction does not copy that `r8` pointer. The direct and another selected branch call `0x2a39b80`. |
| `0x2a39b80` | Selected instructions load a state pointer at context offset `0xb00`, copy 20 address bytes and convert the two slot representations to four words. A fast guard increments the word at offset `0x6a8` using `lock cmpxchg`; release uses `lock xadd` with `-0x10`. Both selected read arms call through relocation slot `0x64e7060`, whose relative addend is `0x43c89a0`. Returned words are reordered and byte-swapped. Slow guard and timing branches exist. The fast path is selected only when bit 3 is clear and the unsigned word is below `2^64 - 16`; a failed comparison-exchange enters the slow helper. Release calls its selected slow helper when the old word masked by `0xfffffffffffffff2` equals `0x12`. These are local synchronization updates, not a persistent state write. |
| `0x43c89a0` | A call goes to the separately owned account-read boundary `0x3d48970`. The selected account tag 1 path uses a storage descriptor at offset `0x1230` and calls `0x3d48700`; selected tags 0 and 2 reach zero-fill after their applicable cleanup. For a storage return, tag 1 selects the 32-byte payload; tags 0 and 2 reach zero-fill after applicable cleanup. This describes the observed normal-return branches, not behavior if cleanup or an external callee fails. |
| `0x3d48700`, `0x3d47d20`, `0x3d9e820` | The key builder copies a dynamic prefix, allocates a 52-byte suffix, copies the 20-byte address and emits the four 64-bit slot words in reverse order with each word byte-swapped. A two-slice concatenator has carry and allocation failure paths. An `Es` literal is present in the ELF, but the selected path has not proven that the runtime prefix equals it; the example keys in `key-vectors.tsv` are conditional examples. |
| `0x3d5e960`, `0x3d48180`, `0x3151e90` | The backend opens read options, handles an options-creation failure, invokes the read helper and distinguishes error pointer, absent value and present value. The storage wrapper maps absence to tag 0, decoded success to tag 1, and selected backend/decode errors to tag 2. If a present value is supplied with length zero, the selected parser state takes an empty-input error, the wrapper takes the kind-zero cleanup arm and returns error tag 1 with payload 4, and the storage wrapper increments the tag to 2. Whether the external backend can actually return such a value is unresolved; the complete value format remains unproved. |
| `0x2d01fe6` | The selected result tag 3 arm copies 32 bytes and passes a result structure to `0x22d5210`; the complete response serializer is an external boundary. |

The method association is an inference from the method literal carried by `0x2a1f3b0`, the callback-to-adapter call and the descriptor relocations. The name supplied to the constructor comes from a shared router-builder region already covered by other work; its method-to-constructor registration edge is not reproduced here. This packet therefore does not establish the full public dispatch chain on its own. Similarly, seeing a parsed block value and its incoming pointer does not prove that every block selector is ignored: unexamined indirect paths and ambient state may matter.

Selected human-readable instruction excerpts, transcribed from the authenticated image, illustrate the key join and lookup branches. The authoritative raw bytes and destinations are in the generated tables.

```text
0x3d47d95  mov edi, 0x34          ; allocate 52 bytes
0x3d47dac  bswap rbp             ; four words are individually byte-swapped
0x3d47dbc  mov [r12+0x10], eax   ; last four address bytes
0x3d47dcb  mov [r12+0x14], r15   ; first emitted slot word
0x43c8a5e  call 0x3d48700         ; storage read after account selection
0x43c8a67  cmp rax, 2            ; selected storage error tag
0x43c8ab3  test al, 1            ; distinguish present from absent on normal arm
0x2a39e67  lock xadd [rdi], rax  ; selected guard release
```

### Conditional models and controls

`parameter-error.tsv` assembles the missing-argument detail from the two overlapping immediate stores and decodes the signed code directly from their instructions. `empty-value.tsv` records the conditional empty-input error chain and models its normal-return result after cleanup. The `*-vectors.tsv` files are deterministic synthetic consequences of the selected instructions, not captures from an executing node. `field-vectors.tsv` classifies four exact names and all their one-byte mutations; `field-flows.tsv` explores field sequences only when each value parses normally. `key-vectors.tsv` models zero, maximum and each single-bit slot; `lookup-vectors.tsv` models the selected account/storage tags with zero and nonzero in-memory payloads and the selected outer byte reorder. `guard-vectors.tsv` models selected fast-gate and release arithmetic for hypothetical words, without asserting those words are reachable or modeling the slow helpers or races. `dispatch.tsv` records 22 selected entries in each conversion jump table and seven decoder error-kind entries, without claiming that these are complete enum definitions. `hex-classes.tsv` compares all 256 byte classes; other vector files cover selected fixed-hex, prefix, digit, overflow and ordering cases. The separate AVX decoder reached by a dynamic branch is a previously covered helper and is not independently analyzed here.

The byte-level evidence supports the 52-byte suffix observation; treating it as an address and 256-bit slot is an inference from its callers and conversions. The observed cleanup-to-zero branches do not establish when the account boundary can return each tag. The ordering and contents of `field-flows.tsv` are a model under successful parsing, not proof for malformed JSON or for every order-dependent error.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No Cargo graph, compiler flags, two-build test, target execution, byte-for-byte executable comparison, normalization mask or equivalence claim is supplied. The evidence collector is a static analysis aid, not a production implementation. Its table and arithmetic models have independent Python-oracle tests and malformed-input controls; those tests do not measure target execution. Helper, relocation, vtable, data and whole-ELF closure remain open beyond the selected records.

## Results and limitations

`summary.json` is the machine-readable scope: 22 selected FDE ranges, 122 byte windows, 149 transfers, 18 selected relocations, 13 selected data references, 14 literal witnesses and one selected parameter error; 51 selected jump entries; 6,889 field-name cases, 781 conditional field flows, 258 key vectors, 24 guard vectors, 18 lookup vectors and one conditional empty-value case. The focused suite has 35 tests and no skips; each selected window, transfer, data reference and literal has an in-memory corruption control. Hash, FDE, address-range, NOBITS, duplicate-relocation, symbol, endian, length, digit and overflow controls also reject selected invalid inputs. These are scoped checks, not denominators for node function coverage. No component gate is requested or advanced.

Next question: independently close the shared registration-to-method edge and trace whether every accepted block selector reaches the same state snapshot, then identify a non-overlapping write path and its persistent error behavior.
