# RE-011: Trace node 115 EVM checkpoint hash loading, rebuild and output

Node #115 ties checkpoint selection to three specific EVM key spaces, reuses a successfully decoded hash cache, and otherwise rebuilds and attempts to write three named hash records, making their key widths, accumulation rules, JSON fields and failure handling concrete for a future independent implementation.

- Component ID: `evm` (RE-011, with `storage` as a dependency).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; `upstream/hyper-evm-sync` is pinned at `d0945c699d9d4774417f4355b10744e7cd420df8`. The unlicensed inferred reference at revision `999556f6e0a474b8312db96ec3149e1c44e97c23` was used for search leads only; no source code was copied. The historical RE-011 packet concerns node #94 and none of its code coordinates or layouts are transferred here.
- Claim status: static observations from authenticated #115 bytes, with inferences and unresolved behavior identified separately; no execution or equivalence claim.
- Scope included and excluded: one checkpoint-select/save/load path, three cache/rebuild branches, selected JSON serialization and parsing/error branches, state projection and fork path observations. This is not a complete reth/revm fork comparison, all EVM execution, transaction processing, an RPC method, filesystem durability, or a component gate.

## Reproduce

From the repository root on Linux x86-64 with Python 3.12.3, the authenticated node artifact and the existing shared `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/artifacts.py verify
python3 tools/re011_evm_checkpoint115.py --out research/work-items/RE-011-evm-db-checkpoint-hashes-115
python3 -m unittest tests.test_re011_evm_checkpoint115 -v
python3 tools/catalogue.py --check
(cd research/work-items/RE-011-evm-db-checkpoint-hashes-115 && sha256sum -c MANIFEST.sha256)
```

For the following commands, replace `<tmp-dir>` with a writable directory. Both generated directories contain only the 18 evidence files; the README and manifest are not generator outputs.

```sh
mkdir -p <tmp-dir>/python-only
ln -s "$(command -v python3)" <tmp-dir>/python-only/python3
PATH="<tmp-dir>/python-only" PYTHONHASHSEED=1 TZ=UTC python3 tools/re011_evm_checkpoint115.py --out <tmp-dir>/first
PATH="<tmp-dir>/python-only" PYTHONHASHSEED=297 TZ=Pacific/Honolulu python3 tools/re011_evm_checkpoint115.py --out <tmp-dir>/second
diff -r <tmp-dir>/first <tmp-dir>/second
diff -r --exclude=README.md --exclude=MANIFEST.sha256 research/work-items/RE-011-evm-db-checkpoint-hashes-115 <tmp-dir>/first
PATH="<tmp-dir>/python-only" python3 -m unittest tests.test_re011_evm_checkpoint115 -v
```

The collector checks the complete binary digest before making an output directory, reads the ELF section, unwind and FDE records through the shared parsers, rejects ambiguous file mappings and excludes `SHT_NOBITS`. Its outputs contain raw unmasked instruction windows, raw FDE/CIE and relocation records, and byte-derived addresses. It does not invoke an external program, execute a captured binary or require access to the reference tree. GNU objdump 2.42 was used only to inspect selected human-readable instructions during analysis; its text is not a generator input or generated evidence. All addresses below are linked ELF virtual addresses, before load bias; `functions.tsv` and the other tables provide file offsets. FDE ends are exclusive and describe unwind intervals, not proven source-function boundaries.

## Evidence

### Checkpoint and hash state path

| Selected role | FDE start | Evidence and continuation |
| --- | --- | --- |
| Outer wrapper | `0x518d140` | Relocated call at `0x518d164` reaches `0x3915d30`. On its normal continuation, the wrapper copies `0x1b20` result bytes and constructs a separate four-word trailing region using sentinel tests and clone helpers on the original object. |
| Select checkpoint | `0x3915d30` | Saves the current three records through relocated slot `0x64e61d0`, then invokes a previously researched list helper as a boundary. The selected loop advances by `0x20` bytes and compares the entry word at `+0x18` to the incoming `rdx` value. A matching entry with first word `0x8000000000000000` is not selected. After three preparation boundaries, one previously researched elsewhere and left outside this packet, relocated slot `0x64e9528` calls the selected loader. |
| Save current records | `0x38c2e00` | Copies `0x810` bytes from object offsets `0xf8`, `0xa00` and `0x1308`; each selected payload contributes `0x800` bytes to a separate digest-shaped helper. The selected wrapper passes a null fourth argument, taking the call through slot `0x64e2080` to `0x1692ff0`; the normal path calls `0x38c2580`. The previously researched directory helper reached from this branch is a boundary, and its internals are not selected here. The digest algorithm and all directory effects are not established here. |
| Load and reconstruct | `0x38c2690` | Calls `0x422e730` with the formatted `lt_hashes.json` path and Location `evm_db.rs:189:67`. Result tag `1` is handled by dropping the returned object and setting all three option headers to zero. The other selected result path supplies three `0x810` payloads under tag `1`. Three separate constructors then either copy the supplied record or call their scan fallback; normal completion passes all three records to `0x38c2580` and copies the resulting `0x1b20` aggregate to the caller. |
| Output helper | `0x38c2580` | Copies the same three `0x810` records, forwards the path and `hash.rs:68:27` Location to `0x422f030`, tests its returned pointer, and calls the pointer's first virtual slot if nonzero. It returns no checked writer status to its caller. This is not proof of a successful or durable write. |

For the wrapper's trailing region, the comparison at `0x518d16c` distinguishes the original object's `+0x1b20` word equal to `0x8000000000000000` from other values. In the latter case it passes the trailing region to a helper. In the sentinel case it tests `+0x1b38`; zero enters a construction path that zeroes two temporary words, while nonzero requires a nonzero word at `+0x1b28`. A zero `+0x1b28` reaches a failure call followed by `ud2`; otherwise a separate helper receives the `+0x1b28` and `+0x1b30` words. The exact meaning of the trailing region and both helpers remains unresolved.

The two relevant #115 Locations at `0x646ec68` and `0x646ec80` identify `evm_db.rs:91:14` and `:94:14` respectively. The former is passed on the list result's error-sentinel path to an unwrap-related formatter. An empty or exhausted list reaches the latter failure call. Their presence does not identify every failure in the list helper. The output helper and loader also have recorded unwind continuations; `functions.tsv` records LSDA addresses, but exception tables and all landing-pad effects are not decoded.

On paths where calls return normally, the save/output attempt precedes list enumeration even if enumeration later fails or finds no usable entry. After either a cache result or a rebuild, the loader invokes the output helper again before returning the reconstructed aggregate. These call sequences do not establish a successful or durable write.

| Decision and selected site | Condition | Selected continuation |
| --- | --- | --- |
| Wrapper `0x518d173`, `0x518d17d`, `0x518d189` | Trailing-region sentinel; empty associated word; or required word is zero. | Separate helper or temporary construction paths; the last condition reaches a failure call and `ud2`. |
| List result `0x3915d7d` | Negating its first word sets signed overflow. | Location-backed unwrap-related failure; no selection. |
| List scan `0x3915dbe`, `0x3915dfc`, `0x3915de3`, `0x3915dec` | Empty; or matching identifier with sentinel first word; or no remaining rows. | Empty/exhausted reaches the separate failure Location; a sentinel row is skipped. A matching non-sentinel row proceeds to preparation and load. |
| Cache result `0x38c2756` | Result tag is `1`, versus the other selected arm. | Drop the error and pass three absent options, versus pass three present cached payloads. |
| Constructors `0x3c27f5f`, `0x3c2851f`, `0x3c2823f` | Option tag is `1`, versus another tag. | Copy that record, versus zero it and invoke the corresponding scan. |
| Example account scan `0x3d4aee0`, `0x3d4aef5`, `0x3d4af5f` | Prefix mismatch; wrong suffix width; or value-decoder tag `1`. | Stop scanning; skip the row; or take the error arm with conditional cleanup before continuing, respectively. |
| Cache parser `0x411fe8a`, `0x411fb4f`, `0x3fd2a27`, `0x3fd2af9` | Selected missing/duplicate outer field, short byte array, or wrong decoded string length. | Selected parse-error branch, which becomes the absent-option path on a normal loader return. Earlier syntax and value errors may take other branches. |
| Output result `0x38c2643` | Writer return is zero versus nonzero. | Return after cleanup, versus invoke the returned pointer's first virtual slot and then return; the caller receives no checked writer status. |

### Three key spaces and rebuilding

The selector immediates, indexed relative-relocation slots, pointed-to two-byte keys, construction calls, selected FDEs and key-width checks are in `prefixes.tsv` and `transfers.tsv`.

| Output field on the selected JSON branch | Selector | Key prefix | Required bytes after prefix | Constructor and fallback |
| --- | ---: | --- | ---: | --- |
| `accounts_hash` | 26 | `Ea` | 20 | `0x3c27f30` → `0x3d4acf0` |
| `contracts_hash` | 27 | `Ec` | 32 | `0x3c284f0` → `0x3d4b410` |
| `storage_hash` | 28 | `Es` | 52 | `0x3c28210` → `0x3d4a640` |

Each constructor tests its option discriminant. For tag `1` it copies the `0xf8`-byte descriptor and the supplied `0x810`-byte record. Otherwise it zeroes a record, passes the descriptor to its fallback and supplies batch capacity `1,000,000`. The three loops terminate when the key is shorter than the prefix or the prefix comparison differs; a matching prefix with a nonmatching total width advances to the next candidate. For `Es`, the selected body takes the first 20 bytes following the prefix unchanged and reverses the following 32 bytes through four reversed, byte-swapped words before putting them into its 88-byte intermediate row. This establishes the byte transformation; interpreting those pieces as an address and storage slot is an inference.

The `Ea` and `Es` value decoders have a tag-`1` failure/cleanup arm. The `Ec` path admits its selected row-building arm on tag `5`, while other tags enter separate cleanup/continue arms. Exact formats and all decoder errors are outside the selected windows. A valid row is buffered; a full batch is folded at the stated capacity, and a nonempty final tail is folded at loop exit. Capacity is a batch threshold, not a claimed limit on the total number of database keys. The selected `Ea` iterator has a separate null-result failure call and `ud2`; allocation, iteration and unwinding internals remain boundaries.

Each batch fold first calls an unanalysed helper with a three-word output area. The selected continuation reads its words, tests one as a count, and advances through records by `0x810` bytes before merging them. The raw call-site and record-step windows are retained for all three key spaces. These observations do not establish how a buffered database row is turned into a record or identify the digest algorithm.

Each record has a `0x800`-byte payload followed by two little-endian 64-bit words. In the three selected batch and tail accumulation bodies, the two words use unsigned saturating addition. The SSE loops swap each 16-bit lane's byte order, add with `paddw`, swap back, and cover the `0x800` payload bytes. Thus the selected model adds 1,024 independent big-endian 16-bit lanes modulo 65,536. No carry propagates between lanes. `vectors.json` contains a synthetic carry, wrap and saturation example; those vectors are a model checked against the instruction windows, not captured-node execution.

### Cache encoding, decoding and errors

On the selected writer branch where a helper's comparison with the three bytes `rmp` returns false, `0x422f030` calls `0x38c2230`. Its three field-name arguments are exactly `accounts_hash`, `contracts_hash` and `storage_hash`; the calls to `0x36c5cf0` use record offsets `0`, `0x810` and `0x1020`, respectively. The inner writer passes `n_elements` at record `+0x800`, `n_bytes` at `+0x808` and `hash` at `+0`. The `hash` helper passes `0x800` bytes to `0x4670ae0`, whose selected path writes brackets, iterates over zero-extended bytes and writes their unsigned decimal values separated as an array. This is the selected writer's representation, not a claim about every accepted input or serialization mode. `schema.tsv`, `data.tsv`, `decimal-vectors.tsv` and the windows bind these observations to bytes and offsets. The table-backed decimal model was checked for every value from 0 through 255.

The read path calls `0x3ef1790` and then `0x411f770`; the latter has distinct object and sequence entry branches. Its inner `0x40833f0` calls `0x3fd2880` for `hash`. On the selected object branches, missing-field checks occur in the following order, after earlier parsing has succeeded:

| Object | First missing field checked | Second | Third |
| --- | --- | --- | --- |
| Outer | `accounts_hash` | `contracts_hash` | `storage_hash` |
| Inner | `n_elements` | `n_bytes` | `hash` |

The six fields also have separate duplicate-field branches when their already-present guards are met. `parse-errors.tsv` gives both branch sites, targets and binary-resident field-name coordinates. The format descriptors for missing and duplicate fields are distinct. These are selected parser paths, not a universal precedence over malformed earlier fields.

For the array-shaped `hash` input, the parser loops for `0x800` decoded elements. Its selected numeric helper accepts post-parser tags `1` or `2` only when the associated unsigned word is below `0x100`. A missing next element, numeric error, extra element or invalid closing sequence reaches an error path. A separate quoted-string branch invokes the relocation-backed decoder `0x5c56f10`; a non-error result must have decoded length `0x800`. The complete string/escape language and every numeric syntax are not established. After an otherwise successful outer parse, `0x3ef1790` permits only bytes `09`, `0a`, `0d` and `20` in the remaining tail. Any other remaining byte selects its error result, which the loader handles through the tag-`1` rebuild path on normal return. The 256-byte tail classification, array-length boundaries and numeric/string gates have synthetic positive and negative vectors.

### Dependency and fork observations

The selected diagnostic Location paths anchor this work in `l1/src/evm/evm_db.rs` and `l1/src/evm/hash.rs`; they do not by themselves establish crate ownership. The #115 `.rodata` contains the following selected path fragments, with every occurrence and file offset in `fork-markers.tsv`:

| Fragment | Occurrences |
| --- | ---: |
| `z_forks/reth-chainspec/` | 1 |
| `z_forks/reth-ethereum-forks/` | 1 |
| `z_forks/reth-rpc-eth-types/` | 2 |
| `z_forks/reth-rpc-server-types/` | 1 |
| `z_forks/revm-precompile/` | 12 |
| `z_vendor/revm-context/` | 3 |
| `z_vendor/revm-interpreter/` | 9 |

These bytes establish path-string occurrences, not a call edge from this checkpoint path to those dependencies, the fork revisions, patches or a complete dependency graph. The separately pinned `upstream/hyper-evm-sync/Cargo.toml` is public comparison material; its dependency versions are not evidence for the captured node's versions.

### Inferences and unresolved

The named serializer fields and key widths support calling the three records account, contract-code and storage hash state. The exact contents represented by every key and value, the relationship between these records and the EVM state root, and the complete reth/revm boundary remain unproven. The selected save-before-select ordering assumes normal returns, ordinary dynamic relocation and no intervening mutation through aliases. Cached values are copied on the success arm; no cache-to-database equality check is established within the selected constructor windows. Error-pointer disposal is an observation at this caller, not proof that every possible output failure is represented by that pointer.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo graph and build flags: not yet established. Target execution, runtime differential tests, two-build comparison, raw/normalized binary comparisons, masks, complete helper/call-target/relocation/vtable/data closure and whole-ELF comparison: not yet implemented or measured. The executable was only read. The small Python arithmetic and branch models are evidence controls, not recovered code or a behavioral execution harness.

## Results and limitations

The collector retains 31 selected indexed FDE intervals totaling 29,429 bytes, 122 validated byte windows, 144 selected transfers, 12 relative relocation records, four diagnostic Locations, three prefixes, six named serializer fields and six missing/duplicate field pairs. It also emits 256 decimal-byte vectors and 256 trailing-byte classifications. These are scoped evidence counts, not function coverage, a matched-window denominator or proof of equivalence.

The focused suite passed 35 tests with zero skips. Controls mutate every selected window and transfer, reject changed digest/opcodes/displacements/frame lengths/relocations/schema data and invalid mappings, test the wrapper sentinel/null failure, key-width boundaries and the composite-key reversal, exercise all 256 decimal and tail-byte values, and check array length, value range, field-presence, batching, lane-wrap and saturation boundaries. Two binutils-free generations under different hash seeds and time zones matched byte for byte. Artifact/signature verification and catalogue check passed; no full repository suite, hosted CI or container result is claimed.

No progress gate changes. The selected cache and state path does not prove the complete EVM component, complete private forks, transaction execution, runtime reachability or persistence durability. Next question: trace the typed `Ea`, `Ec` and `Es` row encoders and their database writes into the same hash-record update functions, then establish whether the resulting three records are inputs to the independently validated node #115 state-root path.
