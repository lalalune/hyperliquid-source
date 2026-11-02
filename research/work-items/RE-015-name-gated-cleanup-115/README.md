# RE-015: name-gated periodic snapshot cleanup on node 115

Node 115 uses release-specific name tags for cleanup: in mode 2, `NvTestnet` bypasses the directory predicate while `NvTestnet2` reaches it and can proceed to removal only when that predicate succeeds.

- Component ID: `constants`, task `RE-015`, with the directory and stream routines treated as shared dependency boundaries rather than component ownership claims.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; unlicensed inferred reference `can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` supplied search leads only. No reference implementation was copied.
- Claim status: selected instruction bytes, unwind extents, data, relocations, imported symbols and branch targets are observations; formatted-path and metadata roles are inferences from those records; actual runtime inputs, complete helper behavior and concurrency are unresolved.
- Scope included and excluded: one periodic caller's selected path through a configuration-byte gate, directory check, removal retry, root and recursive removal, and selected close/error branches. Other caller paths, the name initializer and classifiers already covered by configuration work, full synchronization and formatting contracts, the whole operating-system interface, and component equivalence are excluded.

## Reproduce

From the repository root on Linux x86-64, with Python 3.12.3 or compatible Python 3 and the authenticated node #115 capture:

```sh
python3 tools/re015_config_cleanup_115.py --out research/work-items/RE-015-name-gated-cleanup-115
python3 -m unittest tests.test_re015_config_cleanup_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
PYTHONHASHSEED=7 TZ=UTC python3 tools/re015_config_cleanup_115.py --out work/re015-cleanup-a
PYTHONHASHSEED=91 TZ=Pacific/Honolulu python3 tools/re015_config_cleanup_115.py --out work/re015-cleanup-b
diff -r work/re015-cleanup-a work/re015-cleanup-b
```

The producer verifies the complete input digest before parsing or creating output. It imports the repository's ELF/FDE/ULEB readers, uses bounded `struct` reads and selected fixed x86 instruction forms, and excludes `SHT_NOBITS` from byte mappings. It does not call a disassembler or another process. The evidence was also generated twice and the focused tests run with a Python-only `PATH`, without binutils. GNU objdump 2.42 was used separately for human instruction inspection; its text is not parsed by the producer or retained as generated evidence. No captured executable or filesystem operation from the target was run.

An optional cross-release comparison reads a separately available historical capture, authenticates it with its own digest, and prints a comparison without changing the default generated files:

```sh
python3 tools/re015_config_cleanup_115.py --out work/re015-cleanup-compare --compare-94 references/can1357-hl/bin/hl-node-mainnet-new
```

The #94 input is not needed for default generation or any focused test. The older capture, when present, is node #94 with SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`; its coordinates remain explicitly historical.

Before the target migration, repository commit `1f8c67c63ca4794c9689235471c60297f8a5c985` pinned this #94 digest in `provenance/artifacts.json`. Later commit `c3b77a8e84c3f2b10db7a2a69b6b66bfddea93d4` retains the historical `RE-015-format-prefix-correction-94` and `RE-015-xref-instruction-starts` records with the template and corrected instruction-start leads. The `RE-015-rip-xref-tail` record is named `EVIDENCE.md`. Those records supplied leads only.

## Evidence

All code coordinates below are linked ELF virtual addresses (VAs). The tables include section-derived file offsets; the selected text coordinates have file offset VA minus `0x1000`, whereas the selected read-only data entries have the same VA and file offset. The producer checks each selected FDE against the unwind index and saves the full raw byte range and hash. FDE ranges are unwind-described extents, not a complete function census or a proof that every byte is reachable. The branch and transfer lists are deliberately selected witnesses rather than a complete instruction partition.

| Record | Contents |
| --- | --- |
| `functions.tsv`, `body-bytes.tsv` | Fourteen selected FDE extents, raw bodies, FDE/CIE/LSDA coordinates, indices and hashes. |
| `branches.tsv`, `calls.tsv`, `register-calls.tsv` | 84 selected branch encodings and destinations, 45 direct or relocated transfers, and two register calls joined to `clock_nanosleep`. |
| `exception-sites.tsv` | 58 ULEB call-site records in the selected LSDAs, including landing addresses and raw action offsets. Action and type tables are not interpreted. |
| `pool-entries.tsv`, `pool-references.tsv`, `selected-names.tsv` | Four complete format entries, nine selected LEAs and ten relevant name descriptors. |
| `global-loads.tsv` | Two code loads, the common GOT slot, its relocation and the resolved configuration cell. |
| `operands.tsv`, `state-writes.tsv`, `summary.json` | Fixed operation/mode witnesses, nine selected writes and aggregate target-derived facts. |
| `name-cases.tsv`, `clock-cases.tsv`, `retry-cases.tsv`, `zero-cases.tsv` | Finite synthetic inputs to the selected byte, quotient, retry and zero-check relations. |
| `directory-cases.tsv`, `root-cases.tsv`, `open-error-cases.tsv`, `entry-cases.tsv`, `child-result-cases.tsv`, `close-cases.tsv` | Conditional models with externally supplied metadata, syscall outcomes, entry bytes and errors; these are not observed filesystem behavior. |

### Selected function map

Each row is one or more selected unwind extents. The continuation column describes only the witnessed route; external helpers and unwinding can leave it.

| FDE start VA | Role | Selected continuation or failure boundary |
| --- | --- | --- |
| `0x5a07ec0` | Periodic caller | Obtain the selector result; when it is at least 2, format arguments and call the name gate. Formatting and later caller behavior remain boundaries. |
| `0x1567ad0` | Quotient selector | Return the checked quotient below the range bound; larger inputs enter one of two diagnostics. |
| `0x37be6f0`, `0x46dd7f0`, `0x59dbfb0` | Formatting callbacks | Extract pointer/length fields and tail-call the common formatter, whose output is unresolved. |
| `0x1563fc0` | Mode and name gate | Release on a mode or name bypass; otherwise call the directory predicate and, if true, the retry wrapper. |
| `0x1500a60` | Directory predicate | Two metadata results lead to false on selected tag-2 cases; otherwise the second mode selects true or false. |
| `0x1561530` | Removal wrapper | Check a short path or invoke the long adapter, make an initial removal attempt and conditionally retry up to three times. |
| `0x167e030`, `0x5cad7a0` | Short checker and long callback | Distinguish terminal and interior zero cases; the long callback tail-jumps to root removal. |
| `0x5ca0ef0` | Root removal | Propagate a metadata or `lstat64` error, unlink a selected symlink case, or enter recursive removal. |
| `0x5ca0ff0` | Recursive removal | Open, enumerate and process entries; selected open, child and enumeration errors leave the normal loop. Final unlink classification is a boundary. |
| `0x5c98ca0`, `0x5caaaa0` | Stream release and close | Conditionally release and close the stream; selected non-interruption close errors reach a diagnostic. |

### Caller, full entries and selected path

The caller's FDE begins at `0x5a07ec0`. On one selected route it invokes the selector at `0x1567ad0`; the call at `0x5a080ca` is bound by a RELATIVE relocation. The selector reads an unsigned word, uses multiplier `0x91a2b3c5` and shift 43, and for the entire checked input domain 0 through 89999 this computes the same quotient as division by 3600. Inputs at or above 90000 enter a diagnostic route, with a separate earlier overflow route at 921600. The caller's branch at `0x5a080d2` bypasses this cleanup construction when the returned byte is below 2. This is a finite arithmetic observation; the upstream clock representation and which inputs occur are not established.

On the selected continuing route, `0x5a08117` points to the **full** entry `c0 06 /data/ c0 00` at `0x448b77`, not to its interior text. A second full entry `c0 01 / c0 00` at `0x43aa84` is referenced at `0x5a08192`. The caller also references the relocated pointer/length descriptor at `0x646e9f0`; it resolves to the 20 bytes `periodic_abci_states` at `0x7a1572`. The selected formatting callbacks read pointer/length fields and feed an external formatter. These observations support a formatted path involving the selected configuration root, `/data/`, this descriptor and a later separator; they do not reveal the runtime root or the complete second formatted argument.

Calling these byte sequences complete formatting entries and treating `c0` as an argument placeholder follows the earlier #94 compiler-stamped Rust formatting contract as an inference. The #115 byte sequences, LEA destinations and callback bindings are independently observed here; the current formatter token semantics are not closed by this packet.

At `0x5a081c7`, the caller loads a byte from a structure at offset `0xb9a`, passes it as the gate's low argument byte and passes the formatted object to the call through slot `0x64e1220` at `0x5a081da`. That RELATIVE slot resolves to the new selected gate `0x1563fc0`. On a normal return, the caller resumes at `0x5a081e0` and later calls an unclosed continuation. Separately, one caller branch stores the high-bit sentinel as its output word and returns. The selected witness does not establish the complete caller state machine or actual path, clock or mode values.

### Name decision and release-specific comparison

The gate first tests mode byte 2. Other modes reach the shared object-release path without testing the name. The caller load at `0x5a080d8` and gate load at `0x1563fcf` both address slot `0x64e0918`, which relocates to configuration cell `0x64f06c0`; for mode 2, a nonzero word at cell offset `0x50` reaches a shared initialization boundary. Conditional on its normal return, the gate reads byte `+0x48`. It checks an upper bound of 33 **before** testing the bit in mask `0x2000800a1`.

| Mode and name byte | Selected local consequence |
| --- | --- |
| Mode other than 2 | Skip the directory predicate and release the incoming object. |
| Mode 2, byte 0, 5, 7, 19 or 33 | Skip the directory predicate and release the incoming object. |
| Mode 2, any other byte through 255 | Call the directory predicate. |
| Predicate returns zero | Do not enter the `remove_dir` retry wrapper. |
| Predicate returns nonzero | Call the wrapper; a nonzero returned object is passed to its first vtable entry, then the local path continues through a separate initialization guard and object release. |

The five selected #115 descriptors identify the indexed strings as `Ec`, `NodeTestnet`, `NodeTestnet3`, `SoloTestnet`, and `NvTestnet`. Treating the descriptor index as the runtime name byte also relies on the prior #115 renderer and classifier evidence; this packet independently re-reads the selected descriptors but does not reanalyze those owned bodies. The neighboring `NvTestnet2` is 34 and reaches the predicate under mode 2. The prior #115 initialization work identifies 33 as the normally returned fallback name; this packet does not reanalyze its functions or establish that a particular process used the fallback. The upper-bound branch also ensures bytes such as 64 and 96 are not treated as wrapped bit indices. The focused tests compare the selected predicate against an independently written set for all 65,536 combinations of two input bytes.

The optional authenticated #94 comparison finds the corresponding old gate at `0x13cbb80`, bound 32 and mask `0x1000400a1`. Its bypass indices 0, 5, 7, 18 and 32 resolve to the same five names; in #115 the last two are 19 and 33. The old `NvTestnet2` tag 33 becomes 34. In particular, transplanting the old mask would incorrectly bypass current byte 32 (`SoloSandbox`) and send current byte 33 (`NvTestnet`) to the predicate. The earlier #94 `RE-015-config-snapshot-cleanup-94` record supplied a historical lead, not a #115 conclusion.

The earlier full-entry leads remain bound to #94: `/cham` entry `0x1fc0ec` is referenced by instruction `0x164f840`, and `/static_config` entry `0x1ef5f5` by `0x164fbae`. The optional comparison verifies those old instructions and bytes against the #94 digest and separately checks #115 entries `0x44ab69` and `0x4401ef`. Existing #115 configuration packets own the corresponding initializer and name-classifier bodies; they are not selected in this packet. The historical 76-name table is not reproduced.

### Predicate, retry and removal branches

The selected directory predicate calls a shared metadata boundary twice on its normal non-error route. A tag-2 result on either call returns zero locally; otherwise the second result yields true only when `(mode & 0xf000) == 0x4000`. This is an observation about two supplied results, not a promise that the filesystem cannot change between them.

At the gate's retry call the explicit delay-slice pointer is zero. After an initial nonzero removal result, the wrapper therefore uses three binary64 values from `0x467738`: 0.001, 0.05 and 1.0. Conditional on normally returning sleep and conversion helpers, it makes at most one initial attempt and three further attempts, stopping on a zero result. The exact conversion and effective elapsed duration are not closed here. After `clock_nanosleep` returns code 4, the selected paths inspect the remaining duration and may repeat; other nonzero codes reach a diagnostic boundary. For a nonzero object returned after exhausted attempts, the gate calls its first vtable entry; no selected instruction explicitly forwards that object as a result, and the return-value ABI remains unresolved.

For a path length at most 383, the wrapper copies the bytes, appends a zero and calls the selected zero checker. A zero only in the last position is the success case; an earlier zero and the absence of any zero have distinct error fields. At length 384 and above it passes a callback to a separate long-input adapter; the callback tail-jumps to the same root removal. The adapter's full allocation and validation behavior remains a boundary.

The root's metadata tag 2 propagates an error word. Tag 3 reaches imported `lstat64`; a failure captures an error number. A successful mode with `(mode & 0xf000) == 0xa000` reaches imported `unlink`; other modes enter the selected recursive routine. The mode names are a Linux ABI interpretation supported by the operations, not an observed runtime file type.

The recursive routine calls `openat64` with flag value `0xb0000`. An error number 4 retries the open; errors 20 or 40 in the child case take an `unlinkat` fallback with flags 0, while the root case returns the error. Following a successful open, `fdopendir` failure closes the descriptor and returns an error. With a stream, the selected `readdir64` loop skips exactly `.` and `..`; entry type bytes 0 and 4 recurse and other bytes use `unlinkat` with flags 0. A child result of zero continues; a nonzero result also continues when its low two bits are 2 and its upper 32 bits equal 2. A null enumeration with a nonzero error follows an error return. On normal enumeration completion, a conditional stream release precedes `unlinkat` with flags `0x200`; the classification of a final unlink error is an unclosed helper boundary.

Selected reference-count increments/decrements and buffer-clearing stores are retained in `state-writes.tsv`. If the stream's count reaches zero, the selected release calls a closer which invokes `dirfd` and `closedir`. A zero `closedir` result returns; a nonzero result with error number 4 also returns without another close call. Other error numbers reach a diagnostic call followed by `ud2`. These consequences assume the intermediate helper calls return normally. They are static paths; no directory, stream or clock was accessed through the capture.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Compiler flags, Cargo graph, build comparison, whole-component helper closure and binary equivalence are **not yet measured**. The raw selected body bytes and hashes are preserved without normalization; no relocation mask or raw-equal/normalized denominator is claimed. Relocation slots and dynamic symbol bindings are recorded separately from the instruction windows. The checker rejects wrong capture digests, changed body bytes, duplicate or altered relocation slots, bad FDE/index joins, out-of-range and NOBITS mappings, altered branch displacements/opcodes, invalid templates, and truncated or out-of-range exception entries. The finite branch models supply outcomes to these byte-backed conditions; they neither execute the node nor prove that each synthetic input is reachable.

## Results and limitations

The target-derived record contains 14 selected FDEs totaling 6,118 bytes, 84 selected conditional branches, 45 direct or RIP-relative transfers, two register-indirect sleep calls, 58 LSDA call-site entries, nine selected writes and ten name descriptors. The 16 focused unittest methods passed with no skips. Two generations under different hash seeds and time zones, with binutils absent from `PATH`, matched byte for byte. Artifact hash/signature verification, catalogue consistency and inventory reproduction passed. Repository-wide unittest discovery was not run under the memory constraint; hosted CI and a container build were not run.

No component gate is requested or advanced. The complete caller CFG, external formatter, metadata, synchronization, long-path adapter, duration conversion, final unlink-error classifier, allocation/destructor internals, actual operating-system behavior and source reconstruction remain unverified. The precise next question is whether the final unlink-error classifier and stream release preserve the same selected missing-entry behavior on #115 across all external result encodings, without reusing the #94 table.
