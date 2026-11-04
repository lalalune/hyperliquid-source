# RE-001: node115 DB iterator mode and virtual-slot dispatch

Component: storage. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The DB-associated constructor at `0x2a0da50` creates an options object through `0x5d34c90`, then passes owner+0x30 and those options to `0x5d34520`. A null iterator reaches the bound failure helper. On a non-null iterator, the mode byte controls one of four native adapters.

Mode0 calls `0x5d34820` and stores direction0. Mode1 calls `0x5d34830` and stores direction1. The other valid mode uses the key pointer/length at +8/+0x10: direction byte exactly1 calls `0x5d34890` and stores1, otherwise `0x5d34840` and stores0. The caller does not normalize arbitrary direction bytes to their low bit.

All four adapters are retained in full. They dereference the iterator wrapper to its native object and dispatch through that object's vtable: slots+0x18 and+0x20 for modes0/1; slots+0x28 and+0x30 for the two key-taking paths. The latter construct a two-qword pointer/length slice before the virtual call. These are measured virtual slots; exact original method names and concrete implementations are unresolved. Consequently this packet does not assert key ordering or database seek results.

The returned object initializes qwords+0/+0x18 to the0x8000000000000000 sentinel, retains options at+0x30 and iterator at+0x38, stores direction at+0x40 and zero at+0x41. Relations enumerate modes0/1/2 and all256 supplied direction bytes as machine controls. Real mode, direction and virtual-slot changes alter the result.

Prior #2030/#2035 close lower memtable seek internals and #2129 a fee-history consumer. They do not establish this Rust-to-native constructor's mode selection and output contract. No prior primary-address claim was found. Native callbacks, allocation/lifetime validity and source enum domain remain premises or opaque boundaries.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| constructor | `0x2a0da50..0x2a0db3e` | 238 | 67 |
| mode_zero | `0x5d34820..0x5d3482d` | 13 | 4 |
| mode_one | `0x5d34830..0x5d3483d` | 13 | 4 |
| key_forward | `0x5d34840..0x5d34887` | 71 | 17 |
| key_reverse | `0x5d34890..0x5d348d7` | 71 | 17 |

The denominator is 5 complete FDEs, **406 bytes /109 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **23 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-db-iterator-mode-dispatch/export_disassembly.py
python3 research/work-items/RE-001-node115-db-iterator-mode-dispatch/verify.py --controls
python3 research/work-items/RE-001-node115-db-iterator-mode-dispatch/relations.py
python3 -m unittest discover -s tests -p test_node115_db_iterator_mode_dispatch.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
