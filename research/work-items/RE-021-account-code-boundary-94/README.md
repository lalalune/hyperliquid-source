# RE-021: account and code preparation around the address-09 lookup

Before the standard frame can look up the address-09 precompile, it prepares the same 20-byte address as an account and may update its journal; this packet establishes that ordering, the code-value branches, and the conditional ordinary-code fallback needed to reconstruct the call boundary.

- Component ID: `evm`; RE-021 extends the unresolved wiring question in `RE-021-blake2b-compress-94`, not a new row in the official task table.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; can1357 reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. No reference implementation was copied.
- Claim status: observations cover authenticated bytes, selected FDEs, instructions, displacements and relocation records. Account, code, journal and interpreter names, the known empty-code-hash interpretation, and composition with pending work are inferences. Runtime contents and callback effects are unresolved.
- Scope included and excluded: 16 previously unselected FDEs for account preparation, code-value construction and cleanup, journal growth, a reverse-journal lookup, and the conditional ordinary-code handoff. The parent frame, address-09 registry construction and lookup, dispatcher, wrapper, compression body and separately studied preparation callback remain earlier-owned boundaries. Other releases, live state and captured execution are excluded.

## Reproduce

Run from the repository root with Python 3.12.3 or a compatible Python 3, the standard library, the repository's shared `tools/elf_index.py` and `tools/fde_extents.py`, and the authenticated artifact present:

```sh
python3 tools/re21_account_code_boundary94.py --out research/work-items/RE-021-account-code-boundary-94
python3 -m unittest tests.test_re21_account_code_boundary94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-021-account-code-boundary-94 && sha256sum -c MANIFEST.sha256)
```

Replace the placeholders with two distinct empty relative directories when checking determinism:

```sh
PYTHON_BIN=$(command -v python3)
PATH= PYTHONHASHSEED=1 TZ=UTC "$PYTHON_BIN" tools/re21_account_code_boundary94.py --out <tmp-dir-a>
PATH= PYTHONHASHSEED=937 TZ=Pacific/Honolulu "$PYTHON_BIN" tools/re21_account_code_boundary94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
PATH= "$PYTHON_BIN" -m unittest tests.test_re21_account_code_boundary94
```

The generator authenticates the full binary before parsing, rejects NOBITS and ambiguous file reads, and writes the 18 evidence files in this directory. README and MANIFEST are maintained separately; the manifest covers all other files in the directory. The generator and tests do not call external programs or execute captured instructions. GNU objdump 2.42 was used only to inspect instructions by eye; its output is not a generator input. The restricted byte walker validates local branch boundaries but is not a general x86 decoder.

## Evidence

All addresses below are linked ELF virtual addresses before load bias. `functions.tsv` provides section-derived file offsets, FDE and CIE addresses, exclusive FDE ends, body hashes and instruction counts; `function-bytes.json` retains the original bodies. An FDE describes an unwind range, not a full-program coverage denominator. `instructions.tsv` records the byte walk, while `transfers.tsv` records its calls, jumps and terminals. `semantic-windows.tsv`, `byte-predicates.tsv` and `branch-decisions.tsv` are selected interpretations backed by those bytes; `rip-references.tsv` and `relocations.tsv` retain the corresponding slots and raw RELA records.

No selected body is mapped here to a verified source function. The revm and component association is inferred from the previously studied call path, data layout and artifact provenance, not from a trusted reference label.

| Selected entry | Bounded role inferred from the bytes |
| --- | --- |
| `0x4e6f360`, `0x4e6fd50` | Account access, journal decision and subsequent code-value preparation. |
| `0x4e6c8b0`, `0x4e7d270` | Construct the default code-shaped object from a one-byte zero input and a one-bit iterator. |
| `0x4e73680`, `0x4e6ed00`, `0x4e6ec80` | Code-value cloning and selected normal or exceptional cleanup. |
| `0x4e7c4e0`, `0x4e7c550`, `0x4e7c5c0`, `0x4e7c6b0` | Journal-entry, journal-frame and byte-vector growth, plus their checked allocation boundary. |
| `0x4e8cd70` | Full-key account lookup reached from an earlier-owned reverse-journal arm. |
| `0x4e6cab0`, `0x4e6cc70`, `0x4e8fa30`, `0x4e88a90` | Conditional ordinary-code conversion, input assembly, interpreter-shaped initialization and ownership handoff. |

### Account preparation precedes registry selection

The earlier-owned standard frame copies the 16 bytes at call input `+0x60` and the four bytes at `+0x70` into a 20-byte stack key and calls `0x4e6fd50` at `0x4e6ff83`. Later, subject to the transfer and scheme gates, it uses call input `+0x60` as the registry lookup key. `prior-boundaries.tsv` retains the exact instructions, including the prior frame's depth check and the two bypass branches. The earlier BLAKE2b object has key `00...09` in its 48-byte source record; `prior-object.json` preserves those file bytes and the callback relocation to `0x4e9d2a0`. The conditional inference is that, when the input key is that value and the earlier registry construction and selection conditions hold, the account-preparation key and the precompile lookup key are identical. This is not evidence of a live call.

`0x4e6fd50` calls `0x4e6f360`. The latter probes the 208-byte-stride account table at context `+0x30`; on a miss it obtains a default record through the earlier-owned constructor at relocation slot `0x5773268`, tests the 20-byte set at context `+0x80`, publishes the account bucket and updates its controls and count. A hit retrieves the existing account and tests flag bit `0x10` at account `+0xb0`. The separately pending account-preparation study covers a different entry and the shared probe/set helpers; this packet does not claim those helpers as new bodies.

| Account condition | Local ordering, assuming ordinary helper returns |
| --- | --- |
| Hit, flag `0x10` clear | Return tag 5 and journal byte 0. |
| Hit, flag `0x10` set | Clear that bit first; then require a journal frame and append a tag-0/key entry. |
| Miss, address-set hit | Insert the default account, then return tag 5 and journal byte 0. |
| Miss, address-set miss | Insert the default account, then require a journal frame and append a tag-0/key entry. |
| A journal entry is needed and frame count at context `+0x28` is zero | Reach the missing-frame failure slot after the flag clear or account insertion. The external failure helper and its effects are not reconstructed. |
| Last journal entry vector is full | Call the growth helper before writing the tag, 20-byte key and incremented entry count. |

The frame's own new journal-frame count is published only after this first account-preparation call returns. Thus the journal-needed branch depends on an existing frame at that earlier point; the bytes do not say whether that condition holds for a particular invocation. No rollback of earlier writes is inferred from reaching a failure boundary.

Every syntactically reachable local normal return from `0x4e6f360` passes the pinned tag-5 store. `normal-return-proof.json` records the finite control-flow check: both conditional edges are explored, direct and indirect calls are assumed to return normally, traps terminate, and exception/callee effects are excluded. The non-5 copy arm in `0x4e6fd50` is present in the machine code, but this local proof does not find a normal return from its direct callee that supplies it. This does not rule out unwinding or nonlocal failure.

### Code state and the fallback arm

When the low 32 bits of the account code tag are not 4, `0x4e6fd50` preserves that code-shaped field. For low word 4, it compares two 16-byte halves at account `+0x68` and `+0x78` with bytes at `0x206160` and `0x204be0`. Those 32 bytes match the conventional empty-code hash; that algorithmic label is an inference. Both the equal and unequal arms call `0x4e6c8b0` and publish code tag 1 after the constructor returns. Its output includes a pointer to the file byte `00` at `0x1e629b` and length 1. The two arms use different copy sequences, so this packet does not assert equality of every byte in the surrounding account storage. The constructor has distinct one-byte and shared-object allocation failure boundaries.

On a registry miss, the earlier frame returns to account/code handling. Only if its further code and scheme tests reach the ordinary-code path does it call `0x4e6cc70`. The clone helper `0x4e73680` has four byte-derived table entries: tags 0 and 3 call a virtual clone; tag 1 calls a virtual clone and increments a shared count; tag 2 increments a shared count. After the latter increments, `jle` reaches `ud2` when ZF is set or SF differs from OF. For example, incrementing the maximum signed 64-bit value sets both SF and OF, so that branch is not taken; incrementing the all-ones value sets ZF, so it is taken. Table rows and exact targets are in `clone-table.tsv`; invalid tags are not characterized.

`0x4e6cab0` copies a nonzero-tag representation. For tag 0 it checks the input length, allocates length plus 33, copies the original bytes, appends 33 zero bytes, and publishes a converted representation. Unsigned overflow, the signed-size guard, a null allocation, dynamic cleanup and exception landings are distinct boundaries. The following initializer `0x4e8fa30`, reached through the earlier frame's relocated slot, uses the four entries in `fallback-table.tsv`, requests `0x8000` bytes, and stores capacity `0x400` in the resulting object. `0x4e88a90` then conditionally allocates `0x218` bytes, copies its inputs and returns raw tag 3. These are construction observations, not interpreter execution or proof that every registry miss reaches this handoff.

The tagged cleanup table at `0x7c353c` contains four selected entries in `cleanup-table.tsv`. Tag 1 invokes a virtual cleanup before a reference decrement; tag 2 decrements a reference; tags 0 and 3 use the same virtual cleanup arm. At the earlier reverse-journal boundary, `0x4e8cd70` compares the full 20-byte key and returns a value pointer or null; a successful tag-0 journal arm subsequently sets flag bit `0x10`. The pending journal packet owns the caller and other reversal arms.

### Size and failure boundaries

For the two journal vector helpers, the candidate capacity is `max(4, (2 * old_capacity) mod 2^64)`. Their element sizes are 88 and 24 bytes, respectively; the common allocator checks the widened size product and an upper bound of `2^63 - alignment` before selecting allocation or reallocation slots. This arithmetic is a machine-level observation; valid container invariants and external allocation behavior are assumptions. In particular, wrapping the doubling operation is not treated as a valid real capacity state. The code-conversion path separately checks the addition of 33 and the signed-size boundary.

`exception-sites.tsv` and `unwind.json` contain the 43 decoded call-site entries and original FDE/CIE/LSDA bytes. For example, the two old-code cleanup call ranges in `0x4e6fd50` have distinct local landing addresses, and the default-object allocator's shared-object failure call has a cleanup landing. Action chains, catch types, dynamic vtable methods, allocator internals, process seed initialization and final exception ownership remain external. The 12 tag-table entries cover three explicitly bounded four-entry tables, not a whole-program dispatch census.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Build scope, compiler and linker flags, two-build result, compiled-code comparison, masks, native behavior comparison and whole-ELF identity: **not yet implemented/measured**. No target bytes were used as an implementation.

The focused Python suite uses synthetic inputs to test tag precedence, every single-bit change of the 32-byte comparison value, account hit/miss and missing-frame ordering, vector and padding boundaries, and checked allocation limits. Negative controls corrupt the input hash, a branch operand, a jump-table entry, an FDE/index relationship, an LSDA header, and file-range or relocation constraints. A separate control redirects a selected real branch directly to the return past the tag store and checks that the normal-return proof rejects it. These controls validate the evidence extractor and small static projections; they do not execute the target or establish target behavior under arbitrary inputs.

## Results and limitations

The selected corpus contains 16 FDE intervals totaling 4,787 file bytes, 1,185 walked instruction shapes, 211 control-transfer records, 66 annotated windows, 51 exact byte predicates, 48 annotated branches, 37 relocation records and 43 LSDA call-site rows. The 28 earlier-code interface instructions and the address-09 data anchor are dependencies, not newly selected functions. These numbers describe the selected corpus only.

The direct registry lookup and callback still rely on pending earlier work. No runtime registry, process seed, live caller, external database, dynamic callback, complete exception semantics or target behavior was observed. The full HyperEVM first task, reth/revm fork boundaries and all state-transition inputs remain unfinished; no progress gate is requested and `evm` stays 0/4. Node #115 and visor are separate targets. The supplied local main and PR snapshot were screened, but an independent submission must refresh public heads and ownership.

Next question: establish the selected standard frame's concrete descriptor and caller state, then independently reconstruct this account/code boundary and validate the composition with separately authorized target-grounded fixtures.
