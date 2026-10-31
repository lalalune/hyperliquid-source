# RE-001: node #115 cache suffix selection and concrete key consumers

- Component: foundation / data-cache path construction, with two contextual node-runtime callers.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Question: which exact key selects the three-byte suffix, and which suffix do the two measured concrete consumers receive?
- Observation: the complete ten-byte key `abci_state` selects `rmp` / length 3; all other valid keys select `json` / length 4. The two concrete measured keys are `node_metadata` and `node_artifact_2`, so both take the latter selection.
- No serialization-format, actual file I/O, complete caller, #94 compatibility or reconstruction-gate claim.

## Exact scope

| Role | FDE half-open VA range | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| selector/path-argument builder | `0x59429e0..0x5942b3e` | 350 | 85 |
| metadata-key caller | `0x595aff0..0x595b1a0` | 432 | 91 |
| artifact-key contextual caller | `0x4ec71b0..0x4ec79f7` | 2,119 | 377 |
| pointer/length callback | `0x5616320..0x5616333` | 19 | 5 |
| owned-buffer callback | `0x58621b0..0x58621c4` | 20 | 5 |

The measured denominator is **five complete FDEs, 2,940 bytes / 563 native
instructions**. Each complete native export starts at its actual FDE entry and
covers the complete body. Native readelf confirmations, raw FDE/CIE records,
file offsets, body hashes, source Location and pointer relocations are retained.
All bodies are hash-pinned without normalization. This is not a raw-equal or
normalized cross-function/cross-release equivalence claim.

Both contextual callers pass the actual relocated
`base/src/data_cache.rs:97:9` Location `0x64b6778` downstream. This, their direct
calls to the shared builder and the concrete key data establish a bounded
source association. It does not reconstruct the original source function names.
No inferred reference source is copied or used as a correctness oracle.

## Equality and suffix proof

The selector compares input key length at `+8` with **10**. Only that length
reaches the two fixed loads: the first eight bytes are XORed with little-endian
`abci_sta`, and the last two with `te`. OR of those XOR results is zero exactly
when all ten bytes match `abci_state`. These are fixed-width byte equality tests,
not prefix, case folding or NUL-terminated string matching.

The equality flags select the RIP-relative pointer `0x9382b9` (`rmp`) instead of
`0x459f60` (`json`) with CMOVE. SETNE yields 0 for equality / 1 otherwise; adding
3 sets length 3 / 4. The non-ten-byte fallback independently assigns pointer
`json` and length 4. The producer extracts and checks both actual pointers,
lengths, literal immediates and selection opcodes. A potential lazy initializer
can run before this sequence; its effects are not closed. The normal-path
selection assumes valid immutable key bytes and ABI-preserving helper returns.

The algebraic predicate reads the captured equality constants. Changing the
first immediate byte from `a` to `b` makes `bbci_state` satisfy that altered
predicate and makes the real special key fail it; the checker then rejects the
counterfactual. This is a static relation on bytes, not execution/emulation of
the target. Controls cover all 80 one-bit variants of the special key plus
short/long/case/NUL/longer-prefix examples. The unique-key claim follows from
coverage of all ten input bytes by the equality tests, not from those examples
being an exhaustive test of all strings.

## Concrete key and argument bindings

| Context | Key fat-string slot / bytes | LEA / direct call | Selection |
| --- | --- | --- | --- |
| metadata | `0x64b6818` / `node_metadata` (13) | `0x595b000` / `0x595b00f` | `json`, length 4 |
| artifact | `0x649dbf8` / `node_artifact_2` (15) | `0x4ec7244` / `0x4ec7256` | `json`, length 4 |

The artifact caller reaches this path when its incoming low selector byte is
unsigned greater than 1. Its other branches, logs, helper effects and resulting
objects remain unclosed. The metadata caller binds its key unconditionally in
the measured prefix. The shared builder can have other callers; this is not a
complete xref census.

The inner compact descriptor at `0x43d024` has raw bytes `c0 01 2e c0 00`.
The actual two argument records are key then selected suffix. Both reference
callback `0x5616320`, which reads pointer/length at `+0/+8`, preserves the output
context and tail-calls relocated slot `0x64df720`. These are the observed
`key.suffix` format bindings; the generic formatter implementation is outside
this packet.

A second descriptor at `0x44f615` has raw bytes
`c0 12 2f 68 79 70 65 72 6c 69 71 75 69 64 5f 64 61 74 61 2f c0 00`
(two argument markers around `/hyperliquid_data/`). Its arguments are the static
global object plus `0x18`, then the temporary inner output. Both use callback
`0x58621b0`, which reads pointer/length at `+8/+0x10` and tail-calls the same
slot. The global pointer's RELATIVE binding is checked. **No live root directory
or concrete filesystem path is read or guessed.**

The formatter entry slot `0x64df6e8 -> 0x141e3a0`, string-output slot
`0x64df720 -> 0x167fa70`, global slot, lazy-initialization slot and cleanup slot
are separately recorded. The callback field observations do not establish a
complete Rust String/fat-pointer ABI, allocation/unwind closure or actual
rendered-file creation. In particular **a suffix is not proof of a codec**:
`rmp` does not by itself establish MessagePack and `json` does not prove a
complete accepted JSON schema or a read/write direction.

## Reproduce and validation

macOS arm64; Python 3.12.14; GNU readelf/objdump 2.47.20260726. From repository
root with materialized pinned captures and native GNU tools on PATH:

```sh
python3 -B tools/cache_suffix_static.py --output work/cache-suffix-check
# Compare generated files with this packet, excluding README/manifest.
python3 -B -m unittest discover -s tests -p test_cache_suffix_static.py -v
make doctor verify test catalogue-check
make reproduce
(cd research/work-items/RE-001-node115-cache-suffix && shasum -a 256 -c MANIFEST.sha256)
```

The whole capture is authenticated before analysis, output or native calls.
Readelf/objdump receive private byte-identical snapshots; all text is written as
UTF-8/LF bytes. Wrong-release, truncated and same-size modified public inputs
are rejected before output creation.

Focused controls alter the actual key immediates, selected pointer displacement,
lengths, conditional selector, argument/callback operands, caller condition,
key LEAs and calls, suffix/descriptor bytes, all relative/source/key relocations
and each FDE extent. The changed key predicate and pointer projection are
observed before their checker rejection. Below the full public digest gate,
this checks the named obligations, not arbitrary-byte error detection or target
execution equivalence.

An exploratory guess that the artifact caller's key was `abci_state` was
rejected by its actual fat-string relocation: it is `node_artifact_2`. Earlier
exploration of a version-diagnostic caller did not close the helper semantics
and is not used to claim a decoder, read-only cache or hardfork policy here.

No captured executable/emulator, live file access through the target, metadata
update, process launch, network/chain/wallet/signing action is performed.
Captured inputs/imported code/pins and all progress gates are preserved. No
hosted-CI result or whole-component completion is claimed.

Next question: close the selected caller's downstream data-cache helper and
its I/O direction before choosing a serialization fixture or implementing cache
compatibility.

The final six focused tests passed in **38.027s**. An initial six-test run
(36.770s) rejected the corrupted length as intended but failed one test's overly
narrow expected-error regex; its assertion was corrected to allow that earlier
conditional-selector rejection. No corrupted input became accepted.
`make reproduce` passed. Required repository results are retained with the PR.
The required `make doctor verify test catalogue-check` completed successfully:
**437 tests in 179.552s**, pinned capture/import/source/signature verification and
catalogue consistency passed. Manifest and staged whitespace checks passed.
