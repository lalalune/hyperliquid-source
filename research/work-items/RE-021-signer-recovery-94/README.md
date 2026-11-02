# RE-021: signer recovery before the conditional BLAKE2b route

Node #94's previously external transaction-signer recovery boundary can now be partially reconstructed as compact-signature status handling, recovery-context initialization, public-key serialization and a 20-byte digest slice, with distinct failure and cleanup paths.

- Component ID: `evm`; this is a bounded RE-021 continuation, not a new official task-queue row.
- Target release and full SHA-256: node #94, Linux x86-64, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; inferred, unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. Reference code was not copied.
- Claim status: **observed** for ELF bytes, FDE and LSDA records, relocations, selected operands and branch destinations; **inferred** for cryptographic and container names, byte-lane projections and composition with other packets; **unresolved** for native execution, live reachability and external cryptographic helper behavior.
- Scope included and excluded: the 15 FDEs in `functions.tsv` are selected. The earlier BLAKE2b wrapper and compressor, registry lookup, the pending raw-transaction adapter, generic once helper, recovery curve core, Keccak helpers, allocator and digest compression are boundaries, not newly selected bodies. Node #115, visor, target execution, emulation, keys, networking, chain actions and a component-gate change are excluded.

## Reproduce

Run from the repository root with the authenticated node #94 artifact. Python 3.12.3 and GNU objdump 2.42 were used on Linux x86-64. The generator and tests require only Python's standard library and the repository's shared `tools/elf_index.py` and `tools/fde_extents.py`; they invoke no external programs. The restricted instruction-length decoder is adapted from MIT-licensed `tools/evm_kvs_inventory.py` and fails on unrecognized shapes. It never executes or emulates target instructions. Full SHA-256 verification precedes parsing; file-backed address mapping excludes SHT_NOBITS and rejects crossings or ambiguity.

```sh
python3 tools/artifacts.py verify
python3 tools/re21_signer_recovery94.py --out research/work-items/RE-021-signer-recovery-94
python3 -m unittest tests.test_re21_signer_recovery94
python3 tools/catalogue.py --check
(cd research/work-items/RE-021-signer-recovery-94 && sha256sum -c MANIFEST.sha256)
```

Replace the two placeholders below with distinct empty writable directories. Empty `PATH` applies to Python runs; restore the normal shell environment for `diff`.

```sh
PYTHON_BIN=$(command -v python3)
PYTHONHASHSEED=1 TZ=UTC PATH= "$PYTHON_BIN" tools/re21_signer_recovery94.py --out <tmp-dir-a>
PYTHONHASHSEED=937 TZ=Pacific/Honolulu PATH= "$PYTHON_BIN" tools/re21_signer_recovery94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
PATH= "$PYTHON_BIN" -m unittest tests.test_re21_signer_recovery94
```

The generator writes all JSON and TSV evidence files, in a stable order, without a clock, random value, machine path or disassembler text. README and MANIFEST are packaging files; the manifest covers every other file in this folder. Objdump was used only for human interpretation of the authenticated byte windows. No captured binary was run.

## Evidence

### Boundary and selected functions

All addresses are linked ELF virtual addresses before load bias; `functions.tsv` supplies actual file offsets and exclusive FDE ends. `bodies.json` and `unwind.json` retain full selected interval bytes, hashes, FDE/CIE bytes and unwind-index entries. A linear decode and an unwind interval do not by themselves prove reachable control flow, a source-function boundary or whole-module coverage. `instructions.tsv` retains the decoded byte shapes, `control-flow.tsv` the recognized transfers, and `decisions.tsv` the annotated subset. `rip-edges.tsv` and `relocations.json` bind the selected dynamic slots to their original ELF RELA records.

Pending PR #1733 documents a raw typed-transaction path and calls this packet's `0x4e57c90` as an external recovery boundary. Its earlier recipient and input propagation remains owned by that work. The pending RE-021 runtime packet #1373 and the existing BLAKE2b packet separately own the address-09 registry, dispatch and compressor. The 20-byte recovered **signer** here is a different field from the transaction recipient that may equal address `0x09`; this packet does not prove that an admitted transaction reaches that registry or invokes compression.

| Selected FDE start | Bounded role inferred from the selected operations |
| --- | --- |
| `0x4e57c90` | Recovery-byte gate, callback results, output serialization and 20-byte result |
| `0x5640710` | Two helper calls, status-word combination and compact-result copies |
| `0x5640860`, `0x563a5e0` | Digest and parsed signature handoff to recovery, then public-key storage |
| `0x5640530`, `0x5637320`, `0x5632c40` | Public-key storage conversion, form selection and output-byte stores |
| `0x4eb8650`, `0x4eb8530` | Once callback, global-context replacement and allocation handoff |
| `0x5640430`, `0x56403a0`, `0x56403f0`, `0x56404b0` | Context construction, size checks and destruction |
| `0x56402a0`, `0x563efa0` | Context self-test setup, digest comparison and selected finalization body |

The compact converter, recovery core, synchronization primitive and sponge functions are existing boundaries. The compact converter also appears as a call target in prior foundation disassemblies and is not selected here. No bytes from their FDEs are counted here. The supplied PR snapshot and checked-out work items were examined for ownership; a fresh public PR inventory was unavailable because networking was excluded.

### Compact signature, recovered key and returned bytes

`0x4e57c90` reads a recovery byte at input `+0x40` and, when it is below 4, calls the compact parser through a RELATIVE slot. `0x5640710` calls a separate existing converter twice, first on the input start and then at `+0x20`, using the same status-word destination. Assuming ordinary calling conventions and normal returns, it saves the first status and calls the second converter before testing either status. It then ORs the two statuses, zeroes a 65-byte parsed object and returns zero if either is nonzero. Otherwise it copies two helper-written 32-byte temporaries into the result, stores the recovery byte at `+0x40` and returns one. `parser-call-order.tsv` records the eight selected setup, call and test instructions; `compact-copy-lanes.tsv` derives all 64 temporary-to-result lanes. The converter is an external boundary: its status meanings, accepted scalar range and relation of those temporaries to the original input bytes are not claimed here.

The wrapper supplies a 32-byte digest and parsed object to `0x5640860`. That adapter passes the parsed words, converted digest and recovery byte to an external core. A zero core result zeros the 64-byte public-key result and returns zero; a nonzero result passes the core output to `0x563a5e0` and returns one. The point equation, malformed-point handling and core helper closure are not reconstructed here. The assertion literals and relocation-connected input/output sizes are observations; the secp256k1 role is an inference from these combined facts, not a claim of original source identity.

On the inspected normal arm the wrapper asks `0x5640530` for a 65-byte form with flag 2. The serializer emits prefix byte `04` and calls `0x5632c40` once for each normalized coordinate. The latter reads five limbs, four of 52 bits and one of 48 bits; `field-byte-lanes.tsv` derives every one of the 32 destination stores from the actual load, shift and store shapes, including the two bytes straddling limb boundaries. After serialization the wrapper passes the 64 bytes following the prefix to an existing sponge absorb boundary, with a 136-byte rate; it asks the corresponding squeeze boundary for 32 bytes. Earlier `bridge-signed-message-94` work identifies those boundaries as Keccak. Conditional on normal helpers, `result-byte-lanes.tsv` shows digest bytes 12 through 31 copied to output offsets 1 through 20, and output byte zero written as zero. The resulting address is therefore inferred as the low 20 bytes of a Keccak digest of the uncompressed coordinate bytes; neither the earlier Keccak body nor this target is executed here.

The wrapper does not test the serializer's return value before the sponge call. This is an observed call sequence, not a claim that serialization can fail after a successful recovery on valid internal objects. The relationship above assumes the selected nonnull pointers, adequate buffer, correct internal point and normal helper returns.

### Failure ordering and mutation

| Observed condition | Selected local result or operation |
| --- | --- |
| Recovery byte at least 4 | Wrapper writes raw error detail 6 and error tag 1 before parsing. |
| Compact parser returns a value other than 1 | Wrapper writes detail 3 and tag 1. |
| Either of the two converter status words is nonzero | Parser zeroes its 65-byte result and returns 0; the wrapper takes the preceding error branch. |
| Recovery callback returns a value other than 1 | Wrapper writes detail 3 and tag 1; it does not enter the serialization arm. |
| Recovery core returns 0 | Its adapter zeroes the 64-byte public-key result and returns 0. |
| Serializer length pointer is null or input capacity is too small | Serializer invokes the selected context error callback and returns 0 if that callback returns. |
| Serializer output pointer is null | It has already stored zero in the length word before the selected callback. |
| Serializer public-key pointer is null or the low flag byte differs from 2 | It has stored zero in the length word and cleared the caller-supplied output span before the selected callback. |
| Existing once state requires the generic initializer | The descriptor method at `+0x20` resolves to `0x4eb8650`, under the prior `RE-001-once-state-94` once-call contract. |
| Once callback's input byte was not 1 | The callback has already cleared that byte and calls an external error boundary. |
| A self-test digest byte differs | The self-test tail-jumps to an external diagnostic; its return behavior remains external. |
| Context-size helper returns 0 | The constructor returns a null result before writing the context fields, if earlier calls return normally. |

The serializer's capacity check occurs before its length-zeroing store; its output clearing occurs before the public-key and flag checks. The normal caller supplies length 65 and flag 2, but arbitrary caller validity is not assumed. Raw error details are not assigned unverified Rust enum names. Indirect error callbacks and stack-canary failures are external boundaries.

The once descriptor is at `0x5750e40`; its `+0x20` RELATIVE slot resolves to `0x4eb8650`. The callback reads and clears the byte reached through its input pointer. Only if its previous value was 1 does the inspected normal arm create a new context, then conditionally check, destroy and release an existing context before storing the new pointer at `0x5788468`; the other arm calls an external error boundary. This location is in `.bss` and has no file bytes. The separate once state at `0x5786878` is file-backed; its initial bytes do not establish the value seen at runtime. The selected context-size routine returns 208 for the caller's flag `0x301` on the inspected normal arm; the allocator has separate size and null branches. Context construction runs `0x56402a0` before initialization.

`exception-sites.tsv` records three LSDA call-site intervals for the callback. The selected diagnostic interval `0x4eb86d6..0x4eb86fb` has landing `0x4eb86fd`, whose bytes store the new pointer before the external unwind-resume call. Action chains and the effects of the external diagnostic, allocator, destructor and once machinery are not fully decoded; this is not an atomicity claim.

### Context self-test

The selected initializer constructs a 63-byte message from four file-backed chunks, including a checked one-byte overlap, and compares a 32-byte result with the bytes at `0x806880`. A mismatch takes the tail jump at `0x5640367` to an external diagnostic; its behavior is not reconstructed. Its eight initial 32-bit words are the SHA-256 initial values. `self-test.json` records the exact chunks, state words, expected digest and a separate `hashlib.sha256` result; the two digests match. This establishes consistency of the target's embedded self-test input and expected bytes with SHA-256, not execution of the captured digest routine. A changed input or expected digest is rejected by the extractor.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo lockfile, compiler and linker configuration, two-build result, raw or normalized rebuilt comparison, relocation/helper closure, target behavior and whole-ELF identity: **not yet implemented/measured**. No normalization masks are used and no captured machine code is used as an implementation.

The generated 54 recovery/status cases and 108 serializer cases are synthetic projections of selected predicates and write ordering, not captured transactions or curve executions. The focused tests check all 512 bits of the helper-written temporaries across the copied result, all 256 coordinate bits against big-endian integer encoding, and all recovery-byte values. The first test does not assert an input-to-temporary byte mapping. Controls reject altered digest, instruction pins, control displacement, field shift, result destination, relocation type/addend, dynamic symbol, self-test byte and LSDA encoding; they also reject missing/duplicate FDEs, branch targets inside instructions, unsupported instruction shapes and non-file-backed or ambiguous mappings.

## Results and limitations

`summary.json` records 15 selected FDE intervals and 6,517 bytes, 1,550 linearly decoded instructions, 189 transfer records including 75 conditional transfers, 37 annotated decisions, 164 instruction pins, 20 selected relocation entries, 17 selected RIP-relative edges, eight parser-order events, 64 temporary-copy lanes, 32 field stores, 20 result-byte lanes, 108 serializer cases, and three exception intervals with one landing. These numbers describe this chosen corpus, not EVM function coverage or rebuilt-byte equivalence.

The focused suite passed 39 tests with no skips. Artifact verification and catalogue checking passed; two independent PATH-empty generations under different hash seeds and time zones are compared in the submission validation. The repository-wide test suite was not run in the shared-memory environment.

No acceptance gate is requested; `evm` remains 0/4. The existing registry and prior transaction packet still require review, and the raw transaction-to-converter handoff, the converter status meanings, the recovery core's curve operations, live registry selection, arbitrary callback behavior and native execution remain open. The broader HyperEVM first task, all state-transition inputs and private-fork boundaries are not complete. Next question: recover a non-overlapping producer-to-converter handoff and validate the complete conditional transaction path under separately authorized target-grounded execution.
