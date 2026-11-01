# RE-009: app-hash header serialization in node #94

The first app-hash input is a 13-field named record, including a two-field `hardfork` record and a nullable `tx_index`; this fixes its field order and scalar encoding and permits a bounded static example and digest for an independent reconstruction of that hash input.

- Component ID: RE-009, storage and state roots.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `3324e50333042b391312515e542279ca21f63dc8` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is an unlicensed lead, not copied source.
- Claim status: observations are byte patterns, literal bytes, FDE extents, calls, and selected branches; the interpretation as MessagePack and field meanings is inferred. There is no target execution.
- Scope included and excluded: the two first-row serializers, selected child writers, unsigned scalar encoding and error exits. Other hash rows, general time formatting, serializer allocations, inputs supplied at runtime, readers, node #115 and the rest of the state root are excluded.

## Reproduce

From the repository root with Python 3.12.3 or a compatible Python 3 and the standard library:

```sh
python3 tools/artifacts.py verify
python3 tools/apphash_header_94.py --out research/work-items/RE-009-apphash-header-94
python3 -m unittest tests.test_apphash_header_94
python3 tools/catalogue.py --check
(cd research/work-items/RE-009-apphash-header-94 && sha256sum -c MANIFEST.sha256)
```

The generator reads the authenticated ELF without running it. It uses the repository ELF and FDE parsers, exact instruction patterns and explicit site selectors; it calls no external program. `records.json` is deterministic. The input digest is checked before parsing. FDE ends below are exclusive. The retained full raw body bytes and hashes are unmasked. The scalar Keccak model uses the binary round table, rate and delimiter pinned below; it is separately checked against two known-answer values and Python SHA3-256 across padding boundaries. FDE coverage is not a complete function census.

## Evidence

All addresses are linked ELF virtual addresses. Existing app-hash evidence identifies the first closure row; here the direct calls at `0x28194d0` and `0x4ae5790` resolve to previously unanalysed serializers `0x2218e60..0x22192c9` and `0x4c633b0..0x4c63754`. Both closure calls set a four-byte writer configuration `00 04 00 01`; its byte at writer offset `+0xb` is 1. The low builder writes the first vtable at output slot 0 and a job count of 41; two row vtable-slot relocations and their thunk calls connect the row-zero table entries to these closures. The selected calls, FDEs and all body bytes are in `records.json`. These call sites are boundary links to the earlier packet, not a new claim about the already documented closure bodies.

The two serializers write the following outer keys in order. Offsets refer to their input object. Each row has separately decoded instruction and literal addresses for both lanes in `records.json`.

| Key | Input offset and observation |
| --- | --- |
| `initial_height` | `+0x10`, 64-bit load, unsigned writer |
| `hardfork` | `+0x18`, nested two-field record |
| `height` | `+0x28`, 64-bit load, unsigned writer |
| `tx_index` | compare 32 bits at `+0x00` with 1; on equality serialize 64 bits at `+0x08`, otherwise call the null writer |
| `round` | `+0x30`, 64-bit load, unsigned writer |
| `time` | address `+0x60`, time helper |
| `prev_time` | address `+0x6c`, time helper |
| `next_oid` | `+0x38`, 64-bit load, unsigned writer |
| `next_lid` | `+0x40`, 64-bit load, unsigned writer |
| `next_twap_id` | `+0x48`, 64-bit load, unsigned writer |
| `system_nonce` | `+0x50`, 64-bit load, unsigned writer; key literal is selected inside the child |
| `use_system_nonce` | `+0x78`, 32-bit load, one-byte writer |
| `mac` | `+0x58`, 64-bit load, unsigned writer |

The low serializer emits the nested `hardfork` keys `version` and `round` from `+0x18` and `+0x20`. The shared serializer passes `+0x18` to an existing two-field child; this packet does not re-analyse that child. Both emit the same outer names and offsets. Do not interpret either `round` as an alias for the other.

At `0x2218e80`, zero mode selects a 13-element sequence header and nonzero mode selects a 13-entry map header. In the selected mode 1, the literal-name calls run. The low inline `hardfork` similarly selects a two-element sequence or two-entry map. On the named map path, the map and short string writers use `0x80 | count` and `0xa0 | length`; therefore the top-level header begins `8d`, and the nested header is `82`. The integer writer at `0x25ac0d0` selects a single-byte value below 128, `cc` plus one byte below 256, `cd` plus two bytes below 65536, `ce` plus four bytes below 2^32, or `cf` plus eight bytes otherwise. The multi-byte helpers swap before stores; payloads are big endian. Ten boundary examples are in the generated record. The null helper writes `c0`; the `use_system_nonce` helper ORs its low input byte with `c2`. The latter gives `c2` and `c3` for input 0 and 1 respectively; this does not prove other values are impossible.

The low-lane time helper selects the ordinary `Time` formatting path, which formats a date, writes byte `T`, then formats a time. ELF relative relocations bind its two formatter slots to `0x151f240` and `0x15204a0`. For the specifically selected input with date word 16138256, the date formatter shifts by 13 for year 1970 and uses index 2 of the table at `0x250675`; the table byte is 64, resulting in month 1 and day 1. Two zero time words select `00:00:00` and the no-fraction return. This bounded path yields the 19-byte string `1970-01-01T00:00:00` and its short-string marker `b3`. We do not claim that the raw input was accepted by any source-level constructor or was observed in a node.

The generated `symbolic_complete_low` is a 194-byte static example covering all 13 fields in named mode, assuming successful writes. It uses those identical raw date/time words for both time fields, `initial_height=0`, nested `version=1` and `round=2`, `height=3`, a `tx_index` tag unequal to 1, outer `round=4`, and zeros for the remaining scalar fields. `symbolic_prefix` gives the first part independently. A second fixture `symbolic_present_low` changes `tx_index` to tag 1 and value 5 and `use_system_nonce` to 1; it retains the other inputs. The closure configures rate 136 and delimiter 1. The generator applies an independent Keccak-256 model, with the 24 round constants from `0x7d04c8`, to the 194 bytes and obtains `a20a6c0b3a9f6d3c34feed28e34e1c4ffa239d91dffb11c17340aa3549a9a3f3`. For the second fixture the model digest is `18d7bd6591c8bf5a8d7d30010326a092b738cae65e80dab972b3f84346741c5b`. The earlier app-hash packet establishes the closure hash core. This packet checks the closure update and finalizer slots, their links to the permutation, and the permutation table reference; the digest here is a model output, not an executed-target result. Neither fixture is a complete app-hash preimage: this is only the first of 41 digest inputs. For a fractional word below 1,000,000,000, the formatter skips the fractional descriptor when the word is zero. For nonzero inputs its multiply/rotate tests select one of three pinned formatting descriptors. The six generated branch examples select the descriptor tagged `0x369` for 1,000,000, `0x669` for 1,000, and `0x969` for 1, 999 and 999,999,999. These are observations about selection, not a complete decoding of the descriptors or rendered fractional text. Extended years, leap-second handling, general formatted output and the shared lane's time formatting remain unresolved.

### Error and branch observations

Both top-level functions test the return of the container opener before writing the first field. On scalar and key writer failure they return an error representation instead of proceeding. Low and shared variants use different child addresses and different internal control-flow layouts, but the eight late child-result checks converge on a common three-word result copy in each. The low variant's null-value call is at `0x22190ba`; a tag unequal to 1 reaches that call through `0x221908a`, while tag 1 reaches the scalar call. The analogous shared branch is `0x4c6351f`. The date formatter branches to its bounds failure for table index at least 733; the time formatter branches to failure when the low byte of its computed hour quotient exceeds 99. These checks are not a general date validity test. All 67 selected conditional edges are recorded with exact bytes, targets and fallthroughs; this is a manually selected set, not a claim of complete CFG coverage. Formatting failure and allocation failures are visible in child bodies but their full cleanup/exception behavior is not reconstructed.

### Inferences

The header/string/scalar markers and byte ordering match MessagePack. The names suggest height and execution metadata, but binary strings alone do not prove higher-level meaning. `time` and `prev_time` appear to be textual time values; apart from the bounded example, no general timestamp grammar, timezone, or representable range is claimed. The outer field list and the selected byte prefix are evidence for one digest input, not a snapshot compatibility claim.

## Implementation and comparison

not yet implemented. No Rust build, compiler identity, two-build comparison, normalized byte comparison or helper/relocation closure is claimed. The target is only read as static input. Tests include incorrect target hash, body byte mutation, key byte mutation, changed closure call displacement, invalid opcode/load patterns, an unmapped address and a NOBITS address. The scalar vectors, complete fixture and digest are model results constrained by pinned target instructions, not differential executions. The hash model passes known empty and `abc` Keccak-256 vectors, and with delimiter 6 agrees with the standard-library SHA3-256 for lengths 0, 135, 136, 137, 194 and 271.

## Results and limitations

The generator checks 24 complete FDE bodies, 2 closure-to-serializer calls, 26 outer field rows, 2 inline nested rows, 67 selected conditional branches, 52 fixed instruction pins, 2 vtable-to-closure links and 4 hash-call links. Ten scalar boundary vectors, a partial prefix and two complete low-lane symbolic fixtures with their model digests are generated. Nineteen focused unit tests passed. The catalogue check passed in an isolated copy with the authenticated node files placed within the repository; it fails in the original linked-artifact workspace because the byte-coverage guard rejects resolved files outside the repository. The 13-field serializer is one of 41 digest inputs; general time formatting, decoding, noncanonical modes and entire app-hash construction remain open. No milestone gate is requested.

Next question: recover the general time string grammar and range, and determine how the row-zero digest joins the other 40 row digests.
