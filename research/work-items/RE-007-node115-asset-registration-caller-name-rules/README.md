# RE-007: map the node115 registration caller 0x38b3f90, its pre-registration rule check 0x447d760 and the asset-name scan

- Component ID: RE-007 (per-index state and registry records, `l1/src/dex_registry/*`)
- Target release and full SHA-256: Linux x86-64 node #115, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository base `05bc2de303c05525b71e7e257426e741bc66a390`; no source tree was copied
- Claim status: observations (below), inferences (separate section), unresolved items (separate section)
- Scope included: the four complete FDE extents listed next. Scope excluded: every callee outside them, value semantics, the callers of `0x38b3f90`, and any Rust reconstruction

Independently authored static research; the target was never executed or emulated.

- Complete FDE `[0x38b3f90,0x38b4546)`: 1462 bytes / 300 instructions, LSDA `0x2cfb98` (the caller).
- Complete FDE `[0x447d760,0x447db37)`: 983 bytes / 218 instructions, LSDA `0x33b0fc` (the rule check).
- Complete FDE `[0x3f10940,0x3f109b2)`: 114 bytes / 29 instructions, LSDA `0x310eb8` (a 288-byte element push).
- Complete FDE `[0x44e59d0,0x44e5a9c)`: 204 bytes / 60 instructions, no LSDA (the character scan).

Export denominator: **2763 bytes / 607 instructions**. These are evidence extents, not
recovered or compiled-comparison coverage. No progress gate is requested.

## Question and relation to the entry packet

The registration entry `0x446bf60` has exactly one direct caller, `0x38b3f90` (call at
`0x38b4206`). Where does the entry's state object come from, where do its fifth and
sixth arguments come from, and which rules are checked before the entry runs? The
entry itself is described in the companion packet `RE-007-node115-asset-registration-path`
(open as PR #2757 when this was written). This packet does not rely on that packet for any
claim made here; the entry is treated as a callee with a known address.

Register roles are SysV ABI observations at instruction level. No public ABI, field names or
units are recovered. A "result" is a record whose first 16-bit word is a tag; the word
`0x1a2` is the success tag in every function below.

## Caller `0x38b3f90`

Arguments observed at entry: RDI result, RSI selector, RDX a pointer saved at `[rsp+0xa0]` and
later passed unchanged as the entry's RDX, RCX a parameter block (kept in R15), R8 a byte
kept at `[rsp+0x1c]`, R9 a pointer (kept in RBP) to two bytes.

| Step | Instructions | Observation |
| --- | --- | --- |
| Guard | `0x38b3fb7..0x38b3fc4` | dword `0x64f01d8` is tested; nonzero takes the slow path at `0x38b4366` which calls `[0x64df9f0]` with the Location `0x63fe278` (`std/src/sync/once.rs:219:20`) and rejoins at `0x38b3fde`. The file value of the dword is 3 |
| Selector | `0x38b3fca..0x38b4006` | R12 = `[RSI+0x10]`; `[R12+8]` points to a vector header whose pointer is at +8 and length at +0x10; an empty vector goes to an unwrap-on-Err panic (`0x38b43c0`). R13 = first element pointer of that vector. Selector tag `[RSI]` equal to 1 selects the indexed branch, any other value the direct branch |
| Direct branch | `0x38b403f..0x38b404e` | `[RSI+8]` is a pointer to a boxed object; the state object passed on is that pointer + `0x200` |
| Indexed branch | `0x38b4006..0x38b403d` | index `[RSI+8]` must be below the vector length (else panic, `0x38b43f1`); state object = vector pointer + index * `0x510` |
| Rule check | `0x38b404e..0x38b405f` | `call 0x447d760(result=rsp+0x20, state, params, R9, R13)` |
| Rule-check failure | `0x38b4112..0x38b41a9` | the failing result (word `[rsp+0x20]` plus the following bytes up to `+0x70`) is copied to the output; both parameter strings (`{cap,ptr}` at `R15+0`/`+8` and `R15+0x18`/`+0x20`) are freed through `[0x64df4a0]`; in the direct branch the boxed object is destroyed (below) |
| Rule-check Ok | `0x38b4074..0x38b4083` | R8 = `[rsp+0x28]`, R9 = `[rsp+0x30]`, i.e. the second and third qwords of the rule-check result |
| Front element | `0x38b40c8..0x38b40fa` (indexed) / `0x38b41ae..0x38b41bc` (direct) | R13 = `[[R12]+8] + index*0x200` (a bounds check against the length at `+0x10`, panic `0x38b444d`); in the direct branch R13 = RBX and the state object RBP = RBX + `0x200` |
| Entry call | `0x38b41bc..0x38b4206` | the 56-byte parameter block (`R15+0..0x38`) is copied to `rsp+0xb0`; `call 0x446bf60(result=rsp+0x20, state, saved RDX, copy, R8, R9)` |
| Entry Ok | `0x38b4210..0x38b4235` | the entry's second result qword is stored at `[rsp+0xa8]`; `call 0x3f10940(R13)` |
| Optional insert | `0x38b4235..0x38b42a7` | only when the byte at `[rsp+0x1c]` is nonzero: a key record (byte `0x3` at `rsp+0x42`, word `0x202` at `rsp+0x40`, zeroed qwords at `rsp+0x20/0x30`) and a value built by `call 0x3bcb6c0` from a pointer to `[rsp+0xa8]`, then `call [0x64e6bc8](state+0x1a0, key, value)` |
| Ok output | `0x38b42a7..0x38b42c7` | the 24 bytes at the selector (`[RSI+0..0x18]`) are stored at `[out+8..0x20)` and the word `[out]` is `0x1a2`; the entry's id is not returned |
| Entry failure | `0x38b42c7..0x38b4351` | the failing result is copied to the output; the parameter strings are not freed by the caller on this path; in the direct branch the boxed object is destroyed |
| Direct-branch destroy | `0x38b432d..0x38b4351` | `call 0x38f9d40(RBX)`, `call 0x38fb820(RBX+0x200)`, then `free(RBX, 0x710)` through `[0x64df4a0]` |

Observed sizes: `0x200 + 0x510 = 0x710`, the size passed to the free call, so the direct
branch's boxed object holds one `0x200`-byte part followed by one `0x510`-byte part. The
indexed branch reaches the same two parts through two vectors with strides `0x200` (headers
at `[R12]`) and `0x510` (headers at `[R12+8]`).

Four failure sites (`0x38b43c0`, `0x38b43f1`, `0x38b441f`, `0x38b444d`) write the word `0x156`
to `[rsp+0x20]` and call `[0x64df6a0]` with length `0x2b` and the 43-byte string
`called \`Result::unwrap()\` on an \`Err\` value` (`0x7d3212`, and a second copy at `0x7c95fa`). Their
Locations (each a relocated 24-byte record whose string, line and column the collector
checks):

| Site | Location slot | Source | Line:column |
| --- | --- | --- | --- |
| `0x38b43c0`, `0x38b43f1` | `0x648b990` | `l1/src/dex_registry/clearinghouses.rs` | 11:29 |
| `0x38b441f` | `0x648b9a8` | `l1/src/dex_registry/clearinghouses.rs` | 17:33 |
| `0x38b444d` | `0x6483e20` | `l1/src/dex_registry/perp_dex.rs` | 34:33 |

## Rule check `0x447d760`

Arguments: RDI result, RSI state, RDX the parameter block (first string triple at +0/+8/+0x10,
byte at +0x34), RCX the two bytes `{a, kind}` (`a = [RCX]`, `kind = [RCX+1]`), R8 a context
pointer. `count` is the qword `[state+0x10]`.

| Order | Instructions | Condition | Result |
| --- | --- | --- | --- |
| 1 | `0x447d778..0x447d795` | qword `[state+0x378]` equals `0x8000000000000000` and `count > 9999` | tag `0x155` |
| 1b | `0x447d800..0x447d815` | same niche value and `count <= 9999` | tag `0x1a2`; `[out+8]=0`; `[out+0x10]` is whatever R15 held on entry (not an argument of this function). No later rule runs |
| 2 | `0x447d795..0x447d7a6` | `count >= table[kind]`, table = qwords at `0x4575a0` | tag `0xf0` with the 27-byte heap string `Too many assets in perp dex` |
| 3 | `0x447d7a6..0x447d7be` | `a != 0` and byte `[params+0x34] == 0` | tag `0xf0` with the 26-byte heap string `cross margin not supported` |
| 4 | `0x447d864..0x447d8b2` | name length `[params+0x10] > 100` | tag `0x158`, `[out+8]` = params pointer |
| 5 | `0x447d864..0x447d8d8` | an owned string P is built from a two-piece template at `0x434aac` (bytes `c0 01 3a 00`) and the qword `[state+0x4a0]` handed to the formatting adapter at `0x43cd590`, which loads `[value+8]` and `[value+0x10]` as pointer and length; name length is below P's length, or `bcmp(P, name, len(P)) != 0` | tag `0x156`; P is freed |
| 6 | `0x447d90e..0x447d92b` | suffix length `name_len - len(P)` is 0 or at least 10 | tag `0xf0` with a message built from the template at `0x43e2f6` (`asset name must be between 1 and ` + the value 9 shown through `0x64df6c8` + ` characters`) |
| 7 | `0x447d991..0x447d9ab` | `call 0x44e59d0` on the suffix returns nonzero | tag `0xf0` with the 56-byte heap string `asset name only accepts upper case characters and digits` |
| 8 | `0x447da0f..0x447da2f` | qword `[state+0x408]` equals `0x8000000000000001` | tag `0x1a2`; `[out+8]=0`; `[out+0x10]=` suffix length |
| 9 | `0x447da2f..0x447da5c` | otherwise `call [0x64e69b8](out2, suffix pointer, suffix length, R8)`; a result word other than `0x1a2` is copied to the output | on success tag `0x1a2`; `[out+8]=1`; `[out+0x10]` = qword at `out2+8` |

The table at `0x4575a0` starts with the qwords 15, 100, 100, 150; the bytes after the fourth
entry are string data (the text `authorization list not supported` follows), and this function does not bound-check `kind`. The messages are
built by allocating through `[0x64df480]` and copying from `0x7d24a5` (26 bytes),
`0x7d24bf` (27 bytes) and `0x7d24da` (56 bytes); an allocation failure calls `[0x64df498]`.

Character scan `0x44e59d0` decodes UTF-8 from a `{cursor, end}` pair and returns 1 at the first
code point that is neither in `0x41..0x5a` nor in `0x30..0x39`, and 0 when the end is reached
(range tests `c-0x5b` below `-26` and `c-0x3a` below `-10` as unsigned values, read as "not
A-Z" and "not 0-9"). The anchors pin both compare constants.

Element push `0x3f10940`: builds a default element with `call 0x38cca40(rsp+0x8)`; if the vector's length `[rbx+0x10]`
equals its capacity `[rbx]` it calls `[0x64e6010]`; it copies `0x120` bytes (`memcpy` through the GLOB_DAT slot
`0x64df508`) to `[rbx+8] + length*0x120` and stores `length+1`.

## Inferences (not observations)

- The success value `1` in the rule-check result and the qword that follows it become the entry's R8 and R9 (the caller loads them from `[rsp+0x28]/[rsp+0x30]`). The entry packet describes R8 compared with 1 and R9 passed on to a map update; read together this is consistent with the map update only running for a name that passed all rules and was looked up by the helper at `0x421a8b0`. The lookup's meaning is not decoded.
- Rule 5 plus rule 6 together are consistent with an asset name of the form `<prefix>:<1 to 9 characters from A-Z0-9>` where `<prefix>` is the text at `[state+0x4a0]`. Only the template bytes and the adapter's loads were observed; that the value is a dex name is a guess. A public description of dex-scoped asset names was not consulted for this packet.
- `kind` selecting one of 15/100/100/150 for the maximum number of name records is consistent with a per-category capacity; the meaning of `kind` and of the byte `a` is not recovered. The cross-margin message suggests `a != 0` means a cross-margin request and byte `[params+0x34]` an isolated-margin flag; neither is observed beyond the compare.
- The two parts of the `0x710`-byte object (`0x200` and `0x510`) and the two vectors with the same strides suggest a front record and a state record per index. The entry packet's 96-byte append targets the `0x510` part; the `0x200` part is only touched here (its first 24 bytes are used as a vector header by `0x3f10940`).
- The word `0x156` is both written before two `call 0x44e0810` / `call 0x42320d0` sites and used as the Err value of the unwrap panics. The two calls look like destructors of that temporary, but their bodies (842 bytes each) were not analysed.
- Dword `0x64f01d8` with a call into `std/src/sync/once.rs` is consistent with a lazily initialised global guard; the initial value 3 and the zero test were observed, the protocol was not.

## Unresolved

- Bodies of `0x421a8b0`, `0x3bcb6c0`, `0x38cca40`, `0x38f9d40`, `0x38fb820`, `0x44e0810`, `0x42320d0`, `[0x64e6bc8]` (`0x42096d0`), `[0x64df9f0]` (`0x5c87d50`), the Display adapter targets, and the grow call `0x43bce50`.
- What the `0x120`-byte default element contains, and what key and value the optional insert builds.
- The callers of `0x38b3f90`: it has no direct `E8` caller; its address is stored by a relative relocation in slot `0x64e7c38`. An ad-hoc scan (not retained here) found nine `ff15`/`ff25` references to that slot in nine other extents; they are leads only.
- Which of the many exit paths run the landing pads after `0x38b447b`; they were listed, not traced.
- No Rust implementation, no function-window comparison, no gate.

## Reproduction and negative controls

Linux Python 3.14.4 and GNU binutils 2.46 (recorded in `tool-versions.json`); no target execution or emulation. The target is the Git LFS object `artifacts/node/115/hl-node`.

```sh
python3 research/work-items/RE-007-node115-asset-registration-caller-name-rules/collect.py --output work/caller-replay --check
python3 -m unittest tests.test_asset_registration_caller_static -v
```

The collector authenticates the complete target (size and SHA-256) before any native command, compares its independent ELF/FDE/relocation parse with GNU `readelf -wf` and `readelf -rW`, exports the four extents with `objdump`, and checks 47 byte anchors (40 inside the extents at instruction boundaries, seven in read-only data outside them), four source Locations (string bytes, line, column and a `lea` cross-reference each) and the relocated or imported call slots. `records.json` is the retained machine-readable result and `MANIFEST.sha256` binds every file in this directory.

Negative controls (private `bytearray` copies only): one-bit corruption of the first, middle and last byte of every anchor is refused with `changed native anchor`; 26 claim bytes (the strides `0x510`/`0x200`/`0x710`/`0x120`, the selector tag 1, the tags `0x1a2`, `0x155`, `0x156`, `0x158`, `0xf0`, the limits 9999, 100, 9 and 10, the three message lengths, the map offset `0x1a0` and the four character-range constants) are verified against their documented value and each counterfactual is refused; an altered target identity fails before any native tool or output; and every export regenerates byte for byte.

## Limitations and next step

Static evidence only. Anchors prove that the cited bytes exist at the cited addresses in this exact binary; they do not prove source-level types, names or semantics. Message texts are read from the binary's read-only data and are exact bytes; what the rules mean for the exchange is not claimed.

Next question: what do `0x421a8b0` and `0x3bcb6c0` compute from the validated suffix and the front-record id, and what do the nine other extents that call through slot `0x64e7c38` do with the result?
