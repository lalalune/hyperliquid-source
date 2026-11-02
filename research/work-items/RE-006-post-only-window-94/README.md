# RE-006: order-modify admission during the post-only window

This packet establishes the two node #94 order-check gate bodies, their exact time and height boundary rules, the post-only exception, and the two failure messages, so the previously mapped modify path can preserve the old order when this admission check rejects its replacement.

- Component ID: RE-006, book transitions; the pre-removal order-modify check.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `e5c9b6436876b2a4a39daef813171f9879317699` / `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`; the reference is a search lead, not a source of implemented semantics.
- Claim status: observations are the pinned bytes, FDE ranges, conditional destinations, state offsets and literals below; the connection between the named Context fields, post-only labels and the previously mapped modify path is described separately. No live execution was performed.
- Scope included and excluded: two 104-byte gate FDEs and the 47-byte payload formatter FDE are selected. Four existing order-check caller windows, four existing modify caller windows, a status-dispatch window, serializer windows and prior Context debug-writer windows are contextual evidence only; their containing bodies are not reconstructed here. The first-layout gate is outside the selection because its address already appears in existing evidence. Book removal, insertion, later admission checks, target execution, and any progress gate are outside scope.

## Reproduce

Run from the repository root with Python 3.12.3 and the standard library; the tool imports the repository's `tools/elf_index.py` and `tools/fde_extents.py`. The program authenticates the complete binary before parsing and reads it as data. It invokes no external programs and does not execute the target. It creates or replaces only its three generated output files in the selected output directory.

```sh
python3 tools/post_only_window.py --out research/work-items/RE-006-post-only-window-94
python3 -m unittest tests.test_post_only_window
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
PYTHONHASHSEED=1 TZ=UTC python3 tools/post_only_window.py --out work/post-only-window-a
PYTHONHASHSEED=2 TZ=Pacific/Honolulu python3 tools/post_only_window.py --out work/post-only-window-b
diff -r work/post-only-window-a work/post-only-window-b
```

The generator SHA-256 is `f80bd46dd3d360ece0146430244dec67cd7cf91009476ac72e8f22e2328338ec`; the focused test SHA-256 is `67b9649314d2130e03fc938bceb313d5d065eaee43e44bab909ef6cb858ec330`. `evidence.json`, `cases.tsv` and `admission.tsv` are generated; `MANIFEST.sha256` records their hashes and this README's hash. `cases.tsv` contains synthetic inputs evaluated against the authenticated instruction bytes and a separate formula, not captured node transactions. `admission.tsv` similarly exercises only the pinned caller windows. The tests also exhaust the pair of possible input bytes for one spot and one perp window. No generated result depends on disassembler output.

## Evidence

Addresses are linked ELF virtual addresses, not file offsets or runtime relocated addresses. `evidence.json` records both coordinates and the complete selected FDE bytes. An FDE is an unwind-described extent, not proof of a complete logical Rust function or of all call sites.

| Selected FDE | Exclusive end | File offset | Role |
| --- | --- | --- | --- |
| `0x4d8c270` | `0x4d8c2d8` | `0x4d8b270` | window gate, secondary state layout |
| `0x4d8c2e0` | `0x4d8c348` | `0x4d8b2e0` | window gate, low state layout |
| `0x37ecea0` | `0x37ececf` | `0x37ebea0` | status payload formatter |

The two gate byte sequences differ in four state displacements. Both compare the 32-bit fields at state `+0x60`, `+0x64`, `+0x68` lexicographically to a three-field threshold; the first comparison is signed and the latter two are unsigned. Both read a 64-bit value at `+0x28` and a second 64-bit value at `+0x10`.

| Gate | Three threshold offsets | 64-bit threshold offset | Other shared offsets |
| --- | --- | --- | --- |
| `0x4d8c270` | `+0x4524`, `+0x4528`, `+0x452c` | `+0x4408` | `+0x60`, `+0x64`, `+0x68`, `+0x28`, `+0x10` |
| `0x4d8c2e0` | `+0x3aa4`, `+0x3aa8`, `+0x3aac` | `+0x3988` | same |

Let `T` be the three input fields, `U` the three threshold fields, `H` the unsigned value at `+0x28`, `M` the respective 64-bit threshold, and `S` the unsigned value at `+0x10`. All comparisons include equality as shown:

| Conditions | Return byte | Follow-on when a non-exempt order is checked |
| --- | --- | --- |
| `T >= U` and `H >= M` | `2` | continue validation |
| either condition fails and `H < saturating_add(S, 5000)` | `0` | status `0x74`, payload `0` |
| either condition fails and `H >= saturating_add(S, 5000)` | `1` | status `0x74`, payload `1` |

The `5000` immediate occurs in both add instructions, and overflow chooses `u64::MAX`. The result of `S + 5000` is therefore `u64::MAX` both when it equals the maximum and when the mathematical sum exceeds it. The low-layout serializer context at `0x275b1fa` binds `+0x3aa4` to the key `post_only_until_time`; context at `0x275b222` binds `+0x3988` to `post_only_until_height`. The two code copies support a parallel reading of the other offsets, but their field names are not independently serialized in this packet. The existing `research/work-items/RE-006-order-place-route-94/README.md` maps the Context debug writer to `initial_height` at `+0x10`, `height` at `+0x28`, and `time` at `+0x60`. This packet also extracts its field-name and offset windows as `previous_context_field_evidence`; the association of each name and value uses the prior packet, not just the separated windows.

### Caller and status path

The four caller windows are within the check bodies already named by `research/work-items/RE-006-order-modify-path-94/README.md`. They are included only to connect the new gates to that path. The byte-copy windows additionally bind the checked stack bytes to compact order bytes `+0x09` and `+0x00` in both spot and perp checks.

| Check kind | Call instruction | Gate | Reject status write |
| --- | --- | --- | --- |
| spot | `0x4c1811f` | `0x4d8c2e0` | `0x4c18134` |
| perp | `0x4c18992` | `0x4d8c2e0` | `0x4c18acc` |
| perp | `0x4c19272` | `0x4d8c270` | `0x4c193ac` |
| spot | `0x4c19a2f` | `0x4d8c270` | `0x4c19a44` |

Each window continues if the gate returns `2` **or** if order byte `+0x09` equals `2` and order byte `+0x00` equals `0`. Otherwise it writes 16-bit status `0x74` and the gate's returned byte at status `+0x02`, then jumps straight to the check's return epilogue. The rejection jump and epilogue bytes are also retained in each `callers` row. Continuing means only that this check has passed; later checks may still reject the order.

The known modify callers `0x4d1c2ad`, `0x4d1c499`, `0x4d1e0dd`, and `0x4d1e2c9` call the four respective check bodies and branch away when their status differs from `0x186`; their byte windows and destinations are in `modify_context`. `modify_rejection_paths` pins the full status-copy blocks, their common tails and the return epilogues for both modify copies; those blocks contain no calls. A `0x74` result therefore leaves these modify bodies through the status-copy return before reaching any old-order lookup or removal. The existing modify packet independently documents their later successful path. This does not establish any later insertion or matching outcome.

The status dispatcher at `0x37ffd40` reads the 16-bit status and indexes the signed relative table at `0x59a8d0`. Its `0x74` arm `0x37fffe6` formats a prefix and passes the byte at status `+0x02` to `0x37ecea0`:

| Payload | Prefix plus selected suffix |
| --- | --- |
| `0` | `Only post-only orders allowed immediately after network upgrade` |
| `1` | `Only post-only orders allowed during extreme L1 congestion` |

The formatter actually tests zero versus nonzero; the two gates supply only `0` or `1` on their rejection paths. The messages describe the byte selected by the machine code and do not independently prove the operational cause of either state.

### Inferences and unresolved points

The serialized names and the error text support calling the two threshold groups a post-only time and height window. The prior Context debug-writer analysis supports reading the input triple as `time`, `+0x28` as `height`, and `+0x10` as `initial_height`; applying those names to the gate state uses the established path and calling convention. The first time component is compared as a signed 32-bit value regardless of its higher-level representation. The existing action-admission packet identifies the `2, 0` byte pair as post-only; that name remains an inference here. This packet proves the numeric predicate even if a name changes. It does not identify the units or valid ranges of the time components, the producer of the start value, all callers of either helper, or the first-layout gate's implementation.

## Implementation and comparison

Not yet implemented in Rust. `post_only_window.py` uses an exact byte-pattern guard and a small evaluator for the selected gate instruction sequence; its separate tuple-and-saturating-add formula supplies the comparison. The caller evaluator models only the checked windows and a substituted gate result. No helper, relocation, vtable, full ELF, compiler or binary-equivalence comparison is claimed, and no real node transactions are replayed.

## Results and limitations

- `cases.tsv`: 1,224 synthetic gate evaluations, 612 for each FDE; 1,224 agree with the independent formula. The data include 560 zero, 224 one and 440 two return bytes. Across each FDE the cases visit all 29 instruction offsets in the narrow evaluator; this is not a claim about complete node coverage.
- `admission.tsv`: 180 synthetic caller combinations, with 112 status writes and 68 continuations; all agree with the explicit byte-pair predicate. The focused tests additionally check 131,072 byte pairs across the two caller shapes.
- Focused unittest: 23 tests passed, zero skipped. Controls reject an altered digest, instruction or immediate, malformed field layout, altered caller/modify/status-copy/dispatch/formatter bytes, truncated code, non-executable or non-file-backed mappings, and an out-of-range address.
- Both authenticated artifact verification and the existing catalogue check passed. Two independently seeded and zoned generations are compared byte for byte. No full milestone gate is requested.

Next question: identify when the Context initial height and post-only thresholds are written, and verify how the first-layout gate is reached without overlapping its existing evidence.
