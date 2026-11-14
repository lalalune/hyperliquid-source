# RE-004: reconstruct the node #115 BOLE user reply 0x38e5d00 (read address 0x...0811): gas, three ordered lookups, four reply words and two 1e14 products, 12,699 compared cases, 39 wrong readings and 10 structural controls detected, 381 of 400 byte edits killed (11 equivalent, 8 dependent on un-run callees)

The table of address and callback pairs holds 21 read callbacks. No packet on main reconstructs the body `0x38e5d00`. The callback for `0x...0812`, `0x38e64b0`, is covered by an open, unmerged pull request (lalalune/hyperliquid-source #5997). This packet covers its table neighbour `0x38e5d00` (`0x0000000000000000000000000000000000000811`), which uses the same token store. The function charges gas, parses a 20 byte key and a token index, checks the token against a count and a token store, finds a 0x38 byte value for the key in a second ordered store, finds the token in that value's own ordered map, scales two words of the 32 byte entry it finds by two words of the token record, and returns four 32 byte big-endian words. The packet gives the whole body as a rule list, shows the three store layouts, and lists the places where a rule list written from the shape of the code alone would be wrong. A Rust crate for the arithmetic is checked against vectors read from runs of the target bytes.

- Component ID: RE-004 (quantities and rounding), component `assets` (assets and fixed-point quantities in `research/components.json`; `docs/TASKS.md` names RE-004 "Quantities/rounding"); BOLE token arithmetic. Touches `evm` only as the owner of the table.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: base commit `a8616af94` plus the files of this change. No reference-tree text is used here. The merged packet `RE-004-bole-rate-curve-115` is the sibling in the same family. `0x38e64b0` is covered by the open, unmerged pull request lalalune/hyperliquid-source #5997 and is cited only as that. The routing to this callback is in the merged packet `RE-021-scaled-precompile-route-115`.
- Claim status: observation for everything in Evidence (ELF bytes, relocations, and an interpreter that runs the bytes); inference where marked; unresolved where marked.
- Scope included and excluded: included is the body `0x38e5d00..0x38e63dd` (1,757 bytes, 361 instructions) interpreted whole, with the real bytes of `0x46df170` (130 instructions), `0x369a210` (109) and `0x35bf460` (39) under it, and the init function `0x3714110` run once in a structural control. Stubbed at the edge, each checking its arguments: the input parser `0x3897020`, the parse drop `0x38f9750`, the two message builders `0x46de430` and `0x3d4eb60`, the code drop `0x3d57b80`, the three ring searches `0x4556410`, `0x4555250`, `0x455b7b0`, `memcmp`, the once call, the allocator slots, the bytes constructor, the bytes drop and the 128 bit divide. Excluded: what those callees compute, the 207 unwind-cleanup bytes `0x38e63dd..0x38e64ac` (never interpreted), the table dispatcher (covered by `RE-021-scaled-precompile-route-115`, not re-examined here), and who writes the stores. No component gate is requested.

## Reproduce

From the repository root with Python 3 (3.11.5 here, macOS arm64; the tool is pure standard library and only reads the ELF) and Rust 1.95.0. No network, no key, and the binary is never executed.

```sh
python3 tools/bole_user_reply115.py --out research/work-items/RE-004-bole-user-reply-115
python3 -m unittest tests.test_bole_user_reply115
(cd src/node115-bole-user-reply && cargo test)
make verify
```

`make verify` checks `MANIFEST.sha256` through `tools/verify_packets.py`. The manifest is added after this README is final and covers the generated files and this README.

The tool checks the input SHA-256 first, reads the ELF through `tools/x86_115.py` (shared interpreter, not changed by this packet, over `tools/elf_index.py` and `tools/fde_extents.py`), calls no external program and parses no disassembler output. The disassembly used to write the block walk below was read as text and is not evidence; every address the walk names is a row of `function-rows.tsv`.

Regeneration: the full default run (12,000 vectors, 400 byte edits) was repeated independently and every generated file was byte-identical to the committed one, also across two `PYTHONHASHSEED` values; it took about 40 to 50 s on the machine used (approximate). A reduced run, `--vectors 300 --no-mutants`, takes about 5 s. Test results on the authoring machine (macOS arm64): `python3 -m unittest tests.test_bole_user_reply115` runs 24 tests, and `cargo test` in `src/node115-bole-user-reply` runs 6 tests over all 361 vector rows. No Linux or hosted CI result is claimed.

Generated files: `evidence.json`, `measure.json`, `function-rows.tsv`, `table-entries.tsv`, `slots.tsv`, `call-sites.tsv`, `constants.tsv`, `reply-samples.tsv`, `outcomes.tsv`, `vector-outcomes.tsv`, `model-variants.tsv`, `structural-controls.tsv`, `mutations.tsv`, `unreached-rows.tsv`, `rust-vectors.tsv`.

## Evidence

All addresses are virtual addresses of the ELF; in `.text` and `.rodata` they equal file offsets. The function start `0x38e5d00` and end `0x38e64ac` (1,964 bytes) are one FDE (`tools/fde_extents.py`). The decoder lands exactly on `0x38e63dd`, the first byte after the `ud2` at `0x38e63db` and the start of the cleanup code. The ends of the three callees (`0x46df355`, `0x369a3c2`, `0x35bf4f2`) are constants of the tool that the decoder must land on exactly; their FDE extents are not separately checked here.

### Where the body is referred to

`table-entries.tsv`: `.data.rel.ro` holds 32 byte entries of 20 address bytes, 4 zero bytes and a `R_X86_64_RELATIVE` callback pointer.

| Slot | Address bytes | Callback |
| --- | --- | --- |
| `0x646e718` | `...0810` | `0x38e3cf0` |
| `0x646e738` | `...0811` | `0x38e5d00` |
| `0x646e758` | `...0812` | `0x38e64b0` |

The tool refuses the packet if slot `0x646e738` does not hold the body, and two identification controls show that the neighbouring slots do not. The test `test_only_the_table_slot_refers_to_the_body` scans `.text` for direct rel32 `call` and `jmp` (`e8`/`e9`) targets equal to `0x38e5d00` and finds none, and checks that only slot `0x646e738` holds `0x38e5d00` as a relative relocation. RIP-relative `lea` and `mov` references to the body are not scanned. In the merged packet `RE-021-scaled-precompile-route-115`, `private-records.json` has a record (index 18) with key bytes `...0811`, `record_va` `0x646e720`, `callback_slot_va` `0x646e738` and `callback_addend_va` `0x38e5d00`, with the key test at `0x38be1f7` and its branch at `0x38be208`, in the function that packet lists as the private-key dispatcher `0x38be030`. This packet does not re-examine that dispatcher. `slots.tsv` resolves the eight GOT slots the three real bodies call through, each by its relative relocation, plus the `memcmp` slot `0x64dfb50` (`R_X86_64_GLOB_DAT`, symbol `memcmp`) and the lazy static (below).

### Arguments and result

`rdi` = result (5 words), `rsi` = context, `rdx` = input pointer, `rcx` = input length, `r8` = gas limit. The function returns `rdi`.

| Read | What the bytes do with it |
| --- | --- |
| `[[rsi+0x10]+0x38]` | count: a token at or above it is refused |
| `[rsi+0x48]` = S | state that holds both stores |
| `S+0x58..S+0x78` | token store (below) |
| `S+0x88..S+0xa0` | key store (below) |
| `0x64fb8e8`, `0x64fb8b0` | once-state word and lazy static value, read by `0x369a210` |

Result forms (words not named are left as the caller had them):

| Form | Words |
| --- | --- |
| reply | `[bytes word 0, bytes word 1, bytes word 2, bytes word 3, gas charged]` |
| out of gas, or input longer than 2,000 | `[0, 0x8000000000000001]` |
| text | `[0, 13, pointer, 13]`, the 13 bytes `Invalid input` |
| message | `[0, w1, w2, w3]`, the three words the message builder wrote |

### Rule list (each line is checked by the cases below)

```
if len > 2000: out of gas
first = 1000 + 33 * len                      ; if first > limit: out of gas (nothing else is called)
parse(input, len) -> R (0x58 bytes)          ; R[0] != 0x0c: drop R (0x38f9750), text "Invalid input" (allocation of 13)
key = R[8..0x1c] (20 bytes), token = u64 at R+0x20
if token >= count: message(code 0xfa, token), builder 0x46de430, then drop 0x3d57b80
token store (S+0x58): tree walk, or ring: 0x4556410(S+0x58, &token) and the whole answer word must be 0
  not found: message(code 0xf1, 0x00), builder 0x46de430, then drop 0x3d57b80
P = 0x369a210(S, &key)                       ; key store S+0x88: tree (memcmp of 20 bytes) or ring 0x4555250
  if [0x64fb8e8] != 0: once call through slot 0x64df9f0, whether the key was found or not
  key not found: P = 0x64fb8b0 (lazy default, a ring map with length 0)
value = token in map P: tree walk, or ring 0x455b7b0(P, &token): bit 0 clear and index < length
  not found (including every token against the default): message(code 0xf1, 0x00), builder slot 0x64e9570, no drop
(v0, v8, v10, v18) = the four u64 of the 32 byte value
0x46df170(out, value, closure)               ; value: pointer to the 32 byte map value (four u64 words v0, v8, v10, v18); closure: three words {S, &token copy, &token copy}
  half 1: rec = token record in S+0x58 (searched again); p1 = v8 * rec[0x58] (u128)
          divide(p1, 1e14) is always requested; q1 = low 64 bits of floor(p1 / 1e14); tag1 = (p1 >> 64) < 1e14
          record not found (ring only): tag1 = 0 and no divide
  half 2: the same with p2 = v18 * rec[0x78], carrying v10
words = [ tag1 ? v0 : 0,  tag1 ? q1 : 0,  tag2 ? v10 : 0,  tag2 ? q2 : 0 ]
reply = each word as 24 zero bytes then 8 big-endian bytes (0x80 bytes); allocations of 0x80 and 0x20, the 0x20 box holds 0x80 and is freed at once; bytes constructor through slot 0x64df948
total = sat(first + sat(33 * reply length reported by the constructor))
if total > limit: drop the reply through its vtable (+0x20), out of gas ; else reply with total
allocation failure: the allocation-error slot, arguments (1, 13), (1, 0x80) or (8, 0x20)
```

Points a reconstruction would get wrong without the bytes:

- **The divide is requested even when the guard fails.** Both halves call the 128 bit divide whenever the token record is found; the guard `high word < 1e14` only decides the tag. The tag is exactly "the quotient fits in 64 bits" (derived arithmetic), and when it is clear both words of its pair are zero, including the pass-through word (`v0` for the first pair, `v10` for the second). `reply-samples.tsv`, "first guard trips": `v0 = 1`, `v8 = f58 = 2^64-1` gives words `0 0 2 5`.
- **The main-body ring test reads the whole word, the others read bit 0.** After `0x4556410` at `0x38e6031` the body tests `rax` as a whole (`testq` at `0x38e6036`) and takes a hit only on 0. `0x369a210` (`0x369a30b`), the map ring (`0x38e6172`) and both ring searches in `0x46df170` (`0x46df203`, `0x46df2c3`) test bit 0 only, and also compare the index with the length. An answer such as 2 is a miss in the main body and a hit in the others. This state is reached only through injected stub answers.
- **A missing key is not a separate refusal.** `0x369a210` returns the lazy static `0x64fb8b0` instead; the body then looks the token up in it and refuses with the same code as a missing token in an existing map: `{0xf1, 0}` through the second builder, with no drop. A missing token in the token store gives the same code value through the other builder (`0x46de430`) and a drop. The default has capacity 0, so the ring test `index >= length` refuses whatever the ring search answers.
- **The once call also happens on a hit.** `0x369a210` tests the once-state word `0x64fb8e8` on every path: after a ring hit (`0x369a342`), after a tree hit (via `0x369a351`) and after a miss. The file image holds 3 there, so the first call in a fresh image runs the once closure even when the key exists.
- **The third closure word is never read.** The body passes `{S, &token copy, &token copy}`; `0x46df170` reads the first two words (`0x46df19f`, `0x46df1a2`) and not the third. Byte edits that change only that pointer survive (below, equivalent class).
- **The token is searched three times.** Once in the body and once in each half of `0x46df170`; the halves do not reuse the body's result. With a consistent store the answers agree. A ring half can miss after the main search hit only through an injected answer, and then that half's pair is zero and has no divide.
- **The two products use different record words.** Half 1 uses `v8 * rec[0x58]`, half 2 uses `v18 * rec[0x78]`. `v0` and `v10` only pass through, and only when their pair's tag is set.
- **The reply is charged by the length the constructor reports, not by 0x80.** With the real constructor that is 0x80, so a 32 byte input costs 1000 + 1056 + 4224 = 6,280. The product by 33 and the sum both saturate (`mulq`, `jo` at `0x38e6340`, then a carry test).
- **Only the low 32 bits of `memcmp` are used.** `cltq` at `0x369a2a4` sign-extends `eax` and the sign decides; the searched key is the first operand. The case group "memcmp wide" returns garbage in the high half and the bytes still agree with the rule list.
- **Refusals do not charge.** Only the reply form carries a gas word; a refusal leaves out word 4 as it was. Out of gas after the reply is built still allocates the reply, then drops it.

### Block walk (observation; raw rows in `function-rows.tsv`)

Body `0x38e5d00`:

| Range | What the bytes do |
| --- | --- |
| `0x38e5d00..0x38e5d35` | frame `0x168`; `len > 0x7d0` refuses; `r13 = len + (len << 5) + 0x3e8`; `r13 > r8` refuses |
| `0x38e5d37..0x38e5d60` | refusal exit: `[rbx+8] = 0x8000000000000001`, `[rbx] = 0` at `0x38e5d45`, return `rbx` at `0x38e5d4c` |
| `0x38e5d61..0x38e5d74` | `rbp = [rsi+0x10]`, `r15 = [rsi+0x48]`; parser `0x3897020(rsp+0x20, input, len)` |
| `0x38e5d79..0x38e5ef6` | tag byte against `0x0c`; the 0x58 byte block is stored back (unchanged on the refused path; on the accepted path the token goes to `rsp+0x28` and the key to `rsp+0x30..0x43`); second tag test sends a refused parse to `0x38e5fb7` |
| `0x38e5efc..0x38e5f15` | key copied to `rsp+0x130`; `r12 >= [rbp+0x38]` goes to code `0xfa` |
| `0x38e5f1b..0x38e5f3a` | token copied to `rsp+0x128` and `rsp+0x20`; store tag against `0x8000000000000000` |
| `0x38e5f40..0x38e5fb5` | token store, tree form: root null is a miss; node length `+0x7f2`, keys from `+0x798`, edges from `+0x7f8`; compare by `seta`/`sbb`; equal goes to `0x38e6099` |
| `0x38e5fb7..0x38e6004` | refused parse: drop `0x38f9750`, allocate 13 (slot `0x64df480`, null goes to `0x38e63ab`), two overlapping 8 byte stores write `Invalid input`, out words 1 to 3 |
| `0x38e6009..0x38e6026` | code `0xfa` (u16 at `rsp+0x20`, token at `rsp+0x28`) through `0x46de430` |
| `0x38e6028..0x38e6039` | token store, ring form: `0x4556410(S+0x58, rsp+0x20)`, whole `rax` against 0 |
| `0x38e603b..0x38e6094` | code `0xf1` with byte 2 clear through `0x46de430`; message copied; code dropped (`0x3d57b80`); out words 1 to 3; join at `0x38e6058`, copy-out entry at `0x38e607c` |
| `0x38e6099..0x38e60d0` | key copied to `rsp+0x150`; call through slot `0x64e6498` (`0x369a210`) with `rdi = S`; result in `r12` |
| `0x38e60d3..0x38e6160` | map form test (`[P]` against the B-tree tag); tree: root `[P+8]`, height `[P+0x10]`, node length `+0x1c2`, keys from `+0x168`, edges from `+0x1c8`; equal goes to `0x38e61c5` (value `node + 0x20 * index`) |
| `0x38e6162..0x38e619f` | map ring: `0x455b7b0(P, rsp+0x98)`, bit 0, `rdx` against `[P+0x18]`, `+ [P+0x10]`, minus `[P]` when not below it, `* 0x28`, `+ [P+8] + 8` |
| `0x38e61a1..0x38e61c0` | map miss: code `0xf1` with byte 2 clear through slot `0x64e9570` into `rsp+0xa8`, then straight to `0x38e607c` (no drop) |
| `0x38e61cc..0x38e6214` | 32 byte value copied to `rsp+0xe0`; closure `{S, rsp+0x98, rsp+0x128}` at `rsp+8`; `0x46df170(rsp+0x20, rsp+0xe0, rsp+8)` |
| `0x38e6219..0x38e625d` | `bswap` of the four words; words cleared by `cmove` on bit 0 of the tag words at `rsp+0x20` and `rsp+0x38` |
| `0x38e6265..0x38e62f7` | allocate `0x80` and `0x20`; box holds `0x80`; reply words at `+0x18, +0x38, +0x58, +0x78` with zeros between; free the box (slot `0x64df4a0`) |
| `0x38e62fd..0x38e632a` | triple `{0x80, reply, 0x80}`; bytes constructor through slot `0x64df948` into `rsp+0x20` |
| `0x38e6330..0x38e6361` | `[rsp+0x30] * 0x21` with `jo`; add to `r13` with carry saturation (twice, the same test); compare with `r14` |
| `0x38e6363..0x38e6383` | over the limit: out word 1 `0x8000000000000001`, word 0 zero, drop through `[word 0 + 0x20]` with `rdi = rsp+0x38` |
| `0x38e6388..0x38e639d` | else four words copied to out words 0 to 3 and the charge to word 4 |
| `0x38e63a2..0x38e63a9` | product saturation arm |
| `0x38e63ab..0x38e63db` | three allocation-error calls through `0x64df498` and the `ud2` |

`0x46df170` (`0x46df170..0x46df355`): setup and closure loads `0x46df170..0x46df1b3`; half 1 tree arm `0x46df1bf..0x46df1f4` (`0x35bf460`, flag dword at result `+0` against 1, node at `+8`, index at `+0x18`, record `node + 0xb0 * index`) and ring arm `0x46df1f6..0x46df22b` (`* 0xb8 + 8`); product with `mulq 0x58(rcx)`, tag by `setb` against `0x5af3107a4000`, divide through slot `0x64dfaf8` at `0x46df22f..0x46df25e`; miss exit `0x46df260`; half 2 from `0x46df263` (same shape, `mulq 0x78(rcx)`); six result words stored at `0x46df322..0x46df343`: `[tag1, v0, q1, tag2, v10, q2]`.

`0x369a210` (`0x369a210..0x369a3c2`): `neg` test of `[S+0x88]` (only `0x8000000000000000` overflows); ring arm `0x369a2f9..0x369a33e`; tree arm `0x369a237..0x369a2f4` with `memcmp(key, node key, 20)` at `0x369a2a1`; once-state test on every exit (`0x369a342`, `0x369a351`, `0x369a37b`); once call `0x369a385..0x369a3ba`; return `value` or `0x64fb8b0` through `cmovne` at `0x369a365`.

### Store layouts (observation)

| Token store at S+0x58 | Tree form | Ring form |
| --- | --- | --- |
| `S+0x58` | `0x8000000000000000` | capacity |
| `S+0x60` | root (null: empty) | buffer |
| `S+0x68` | height | head |
| `S+0x70` | not read | length |
| entry | record `node + 0xb0 * i`; u64 keys at `node+0x798+8*i`; u16 length at `node+0x7f2`; edges at `node+0x7f8+8*i` | `0xb8` bytes: u64 key at `+0`, record at `+8` |
| fields read | record `+0x58` and `+0x78` | the same |

| Key store at S+0x88 | Tree form | Ring form |
| --- | --- | --- |
| `S+0x88` | `0x8000000000000000` | capacity |
| `S+0x90` | root (null: miss) | buffer |
| `S+0x98` | height | head |
| `S+0xa0` | not read | length |
| entry | value `node + 8 + 0x38 * i`; 20 byte keys at `node+0x270+20*i`; u16 length at `node+0x34e`; edges at `node+0x350+8*i` | `0x50` bytes: 20 byte key at `+0`, value at `+0x18` |
| search | `memcmp`, 20 bytes | `0x4555250(S+0x88, &key)`: bit 0 clear, index < length |

| Map in the 0x38 byte value (P) | Tree form | Ring form |
| --- | --- | --- |
| `P+0x00` | `0x8000000000000000` | capacity |
| `P+0x08` | root (null: miss) | buffer |
| `P+0x10` | height | head |
| `P+0x18` | not read | length |
| entry | 32 byte value `node + 0x20 * i`; u64 keys at `node+0x168+8*i`; u16 length at `node+0x1c2`; edges at `node+0x1c8+8*i` | `0x28` bytes: u64 key at `+0`, 32 byte value at `+8` |

Ring index: `(head + index)`, minus capacity once when not below it. Tree walk: keys compared as unsigned u64 (token) or by `memcmp` sign (key); the walk stops at the first key not below the searched one, takes the value on equality, otherwise descends at that index while height remains. The ring answers are read as `rax` (flag) and `rdx` (index); the convention used by the tool's stub (flag 0 found, 1 absent with the insertion index) is its assumption, since the ring searches are not run. The fixtures build nodes of 11 keys, which the offsets suggest; the bytes do not state a node capacity.

The 32 byte value: `+0` goes to word 0 (`v0`), `+8` is the first multiplicand (`v8`), `+0x10` goes to word 2 (`v10`), `+0x18` is the second multiplicand (`v18`). Of the token record only `+0x58` and `+0x78` are read by this function.

The lazy default at `0x64fb8b0` is `0x38` bytes. Before init its first word holds the init function `0x3714110` (relocation in `slots.tsv`). The tool runs `0x3714110` from its bytes once (structural control) and checks what it writes against the table it uses for the once stub: `+0x00 = 0`, `+0x08 = 8`, `+0x10 = 0`, `+0x18 = 0`, `+0x20 = 0`, `+0x28 = 0xf6401a`, dword `+0x30 = 0`. The body reads only `+0x00..+0x1f`: capacity 0 (so not the tree tag), buffer 8, head 0, length 0. The once call is made with state address `0x64fb8e8`, `esi = 1`, vtable `0x6468ce8` and location `0x6468d10` (`constants.tsv`); the stub checks those arguments and applies the init result. The file image holds 3 in the state word, the stub sets it to 0, and the body calls the once only when the word is nonzero.

### The arithmetic of 0x46df170

For each half, with `m` = `v8` (half 1) or `v18` (half 2) and `f` = `rec[0x58]` or `rec[0x78]`:

| Step | Result |
| --- | --- |
| `p = m * f` | u128 from `mulq`; high word `h`, low word `l` |
| tag | `h < 0x5af3107a4000` (1e14), as `setb` |
| divide | 128 bit `p / 1e14` through slot `0x64dfaf8`, always requested when the record is found; quotient low word kept, high word ignored |
| word | `tag ? q : 0`; the carried word (`v0` or `v10`) is `tag ? v : 0` |

Floor division; there is no rounding up. `reply-samples.tsv`: `v8 = 8e14`, `f58 = 1.25e14` gives `1e15`; `v8 = 3`, `f58 = 33333333333333` gives 0; `v18 = 999`, `f78 = 99999999999999` gives 998.

### Counts (`measure.json`, `evidence.json`)

| Group | Cases |
| --- | --- |
| Named cases (lengths and gas edges, parse refusals, count edges, token, key and map trees of height 0 to 2, rings with wrap, the lazy-state values, product edges, own-divide answers, reported reply lengths) | 699, of which 76 inject stub answers |
| Pseudo-random vectors (seed `0x5eed0811`) | 12,000, of which 985 inject stub answers |
| Total compared | 12,699 |
| Mismatches | 0 |

Injected kinds (`evidence.json`, `injected_case_kinds`): search answers that disagree with the store, divide quotients, a reply length other than 0x80, allocation failure, and a once state other than 0 or 3.

Outcomes of the 699 named cases (`outcomes.tsv`): 448 replies, 134 code `0xf1` through the second builder, 74 code `0xf1` through `0x46de430`, 29 out of gas, 7 invalid input, 4 code `0xfa`, 3 allocation failures. `vector-outcomes.tsv` keeps every tenth vector (1,200 rows).

Controls and edits are reported in separate fields of `measure.json` and are not summed:

| Item | Count | Result |
| --- | --- | --- |
| Wrong readings of the rule list (`model-variants.tsv`; fields `variants`, `variants_detected`) | 39 | 39 detected |
| Structural controls (`structural-controls.tsv`; `structural_controls`, `structural_detected`): 8 of kind identification (digest gate, five wrong function starts, two neighbouring table slots) and 2 of kind target bytes | 10 | 10 detected |
| Comparator self-tests (`comparator_self_tests`, `comparator_self_tests_detected`): a flipped bit in the expected reply, a flipped bit in the expected store, one of two divide requests removed from the expected events, a changed expected once state | 4 | 4 detected |
| Byte edits of reached instructions (`mutations.tsv`; `byte_edits`) | 400 | 381 killed, 11 equivalent, 8 stub-dependent |

Wrong readings: each is detected by a real disagreement between the rule list and the bytes on at least one case of a sample of 1,099 cases (`model-variants.tsv` gives the number of disagreeing cases and the first one). The rule list never raises under a wrong reading; an exception there is a tool error. For one variant, `umap_ring_no_len`, 3 of its 6 disagreeing cases are predicted faults: the wrong reading would address memory outside the fixture (through the lazy default's buffer, the dangling pointer 8), and the rule list predicts a fault at that address. For all others the count of predicted faults is 0.

The structural controls of kind target bytes run the bytes and judge them against a changed rule list. The comparator self-tests change only the expected side of a comparison to show the comparator notices; they say nothing about the target bytes and are not counted as controls on them.

Byte edits by function: body 262, `0x46df170` 72, `0x369a210` 47, `0x35bf460` 19. The family is one condition-bit edit (low bit of the `jcc`, `cmov` or `set` condition), one edit of the low bit of the first immediate byte, and one edit of bit 3 of one displacement byte, per reached instruction. It is not every byte: call and jump targets, RIP-relative displacements, ModRM register fields and instructions that were not reached are outside it. An edit counts as killed when the bytes and the rule list disagree on any heap byte, ordered stub request, the lazy static, the allocation-failure flag, or when the run faults or exceeds 20,000 steps; so some kills are crashes, not differences of result. Of the 381 kills, 14 come only from cases with injected answers.

The 19 survivors fall in two classes (each row of `mutations.tsv` carries the full reason).

Equivalent (11): the edit provably cannot change any compared result, with no assumption about an un-run callee. The changed bytes are identical to the original, never read by code that runs from its real bytes, or overwritten before such a read, and lie outside every object whose pointer reaches a stubbed callee.

| Address | Reason |
| --- | --- |
| `0x38e5e75` | `rsp+0x20` keeps the parser's tag byte that `cl` was loaded from; `rsp+0x28` is overwritten at `0x38e5e87` on every path |
| `0x38e5f25` | store to the third closure word's target; that word is never read by `0x46df170`, and the edited store lands on `rsp+0x120`, rewritten before use |
| `0x38e5fd5` | text byte 5 is written again by the `Invalid ` store |
| `0x38e61f5` | only the third closure word changes, never read |
| `0x38e61fd` | the closure's second word points to another copy of the same token; `0x46df170` copies the key by value |
| `0x38e63a2` | the saturated product `2^64-2` plus a first charge of at least 1000 carries like `2^64-1`; reached only with an injected reply length |
| `0x46df1cc`, `0x46df28c`, `0x35bf4ae`, `0x35bf4c6` | tree height only decides whether `0x35bf460` descends below a leaf, which happens only on a miss, and from here the token is always found |
| `0x35bf4df` | the edited store lands on `+0x18`, which the next store overwrites; `+0x10` of the result is never read by `0x46df170` |

Stub-dependent (8): unresolved. The edit changes bytes or a pointer that reach an un-run callee, and survives only because the stub reads fewer bytes than the edit changes. Settling them means running those callees from their bytes.

| Address | Reason |
| --- | --- |
| `0x38e5e79`, `0x38e5e7e`, `0x38e5e83` | padding bytes of the `0xfa` code struct at `rsp+0x20` keep the parser's bytes instead of 0; the builder `0x46de430` and the drop `0x3d57b80` receive it and the stubs read only `+0..+1` and `+8..+15` |
| `0x38e5ed7`, `0x38e5eea`, `0x38e5eef` | bytes at `rsp+0x44`, `+0x70`, `+0x74` keep parser bytes; a callee receiving `rsp+0x20` before `0x38e6214` (`0x46de430`, `0x3d57b80`, slot `0x64e9570`, `0x4556410`, and `0x38f9750` on the refused path) would have to read offsets `0x24..0x27` or `0x50..0x5f` of it |
| `0x38e602c` | the key pointer of the token-store ring search `0x4556410` moves to `rsp+0x28`, which holds the token, but the bytes after it differ; the stub reads only the 8 byte key |
| `0x46df267` | the second half's key store lands on `rsp+0`; in the ring form this rests on the stubbed `0x4556410` not writing through its key pointer |

Rows not reached (`unreached-rows.tsv`, 4 of the 639 decoded rows): the `ud2` at `0x38e63db` (after the third allocation-error call; that the allocation-error slot `0x141e264`, which is not run, never returns is inference) and the three miss exits of `0x35bf460` at `0x35bf4b4`, `0x35bf4eb` and `0x35bf4f0` (from `0x46df170` it searches the token in the same tree in which the body's inline walk already found it, so it cannot miss). Rows reached only with injected stub answers (13, listed in `unreached-rows.tsv`): `0x38e63a2` and `0x38e63a9` (a reply length whose product with 33 overflows), the allocation-failure rows `0x38e63ab..0x38e63d5` (nine rows, three calls through `0x64df498`), and `0x46df260`, `0x46df31f` (a ring half missing after the main search hit). Every other row is reached with consistent fixtures.

### Inferences (not observations)

- Role names. "User" for the 20 byte key, "token" for the u64, "count" for the number of tokens, "value" for the 32 byte entry, and the idea that `v8`/`v18` are amounts and `rec[0x58]`/`rec[0x78]` are scale or index words, so that words 1 and 3 are scaled amounts, are inference from the shape and the 1e14 scale. The open packet for `0x38e64b0` also multiplies by record words at `+0x58` and `+0x78` and divides by 1e14, which is consistent with a shared meaning but is not shown here. The file name and the words "reply" and "user" come from the work item, not from the binary.
- The three stores look like one ordered-map type with two layouts (a B-tree and a sorted ring buffer). Which layout is live on chain is not established.
- The table is read as a table of read precompiles from the address bytes and the gas shape. The dispatcher that compares the key `...0811` and takes the callback from slot `0x646e738` is covered by `RE-021-scaled-precompile-route-115` (see above) and is not re-examined here.
- The slot targets `0x6355830`, `0x635de30` and `0x141e264` are read as allocate, free and allocation failure from their arguments; `0x161cc70` as a bytes constructor from the four words it must return and the drop at `+0x20` of its first word; `0x5c87d50` as a once call from its five arguments and the state word. None of them is run.
- The text `Invalid input` is the 13 bytes the body stores; that the result at words 1 to 3 is a string is read from its capacity, pointer, length shape.

## Implementation and comparison

**Rule list.** `spec` in `tools/bole_user_reply115.py`, written from the block walk and sharing no code with the interpreter. Each case is compared on: every heap byte after the run (result words, reply bytes, text, and everything that must not change), the ordered stub requests with their arguments (parse, token, key and map searches, `memcmp` right operands, divide numerators and denominators, allocations, free, bytes constructor and drop, once, message builders and drops), the lazy static and its state word, and whether the run ended in the allocation-error call. The interpreter's stack is not compared.

**Interpreter.** `tools/x86_115.py`, used as is. The four real bodies run from the ELF; the stubs answer from the case and fail the run if their arguments are not the ones the rule list expects.

**Stub answers that a consistent store would not give.** A case can inject five kinds (`evidence.json`, `injected_case_kinds`): search answers that disagree with the store (including flag values other than 0 and 1), quotients of the 128 bit divide (including a high word), a reported reply length other than 0x80, allocation failure, and a once state other than 0 or 3. The rows are real runs of the bytes, but the states are not claimed to occur: a ring half missing after the main search hit, reply lengths other than 0x80, injected quotients, ring flags other than 0 and 1 and allocation failures are reachable only this way. The refusal code constants are u16 in the bytes (`movw $0xfa` at `0x38e6009`, `movw $0xf1` at `0x38e603b` and `0x38e61a6`).

**Rust.** `src/node115-bole-user-reply` (`no_std`, no dependencies, `Cargo.lock` committed, edition 2024, Rust 1.95): `first_charge`, `whole_charge`, `pair`, `reply_words`, `reply_bytes` and `evaluate`. It takes the parse result, the two lookup results and the reported reply length as inputs and does not implement them. Its test reads `rust-vectors.tsv` (361 rows, each from a run of the target bytes: 238 replies, 69 code `0xf1`, 38 out of gas, 9 invalid input, 7 code `0xfa`). Rows come from cases with consistent fixtures except the 31 rows of kind `gas_reply_len`, which use an injected reply length other than 0x80 because the gas charge reads that length. No object-code comparison was made: the crate is checked on behaviour, not on bytes, and no byte window is registered.

Tests: `tests/test_bole_user_reply115.py` runs 24 tests and the crate's `cargo test` runs 6 tests over all 361 vector rows (results on the authoring machine, macOS arm64; no Linux or CI result is claimed).

## Results and limitations

- `measure.json`: cases 12699, mismatches 0, variants 39 (39 detected), structural_controls 10 (10 detected), comparator_self_tests 4 (4 detected), byte_edits 400 (381 killed, 11 equivalent, 8 stub_dependent). `evidence.json`: 699 named cases, 12,000 vectors, 14 kills only with injected answers, 361 Rust vectors. There is no combined control total.
- Limits:
  - The parser, the three ring searches, `memcmp`, both message builders, the drops, the allocator, the once call, the bytes constructor and the 128 bit divide are stubs. The packet shows what the body does with their answers and which arguments it gives them, not what they compute. The texts of the `0xfa` and `0xf1` messages, which inputs the parser turns into tag `0x0c` and a token, and how the ring searches order keys, are not established. The 128 bit divide is checked only as floor division by the stub.
  - Injected answers reach states real callees might not (see above). Fixtures for the real tree walks are generated with height 0 to 2 and at most 27 keys; rings have at most 27 entries; unsorted stores are outside the model.
  - Only the first 0x20 bytes of the lazy default are read by the body; the remaining 0x18 bytes are known only as what `0x3714110` writes.
  - The role names are inference. No claim is made about what the four words mean.
  - Byte-edit kills include faults and step-limit stops. The edit family is one condition, one immediate and one displacement edit per reached instruction, not every byte, and has no ModRM register edits, so the survivor lists do not bound other single-byte changes. 8 survivors are stub-dependent and unresolved until the un-run callees (`0x46de430`, `0x3d57b80`, slot `0x64e9570`, `0x4556410`, `0x38f9750`) are run from their bytes. 14 kills come only from cases with injected answers.
  - Unreached rows (4) and rows reached only with injected answers (13) are those of `unreached-rows.tsv`; the unreached `ud2` reason rests on the allocation-error slot not returning, which is inference.
  - The 207 cleanup bytes are not interpreted and not claimed. RIP-relative references to the body were not scanned; only direct rel32 calls and jumps and the relative relocation were.
  - The Rust crate is checked on behaviour only; there is no object-code comparison, no byte window and no helper, data or relocation closure for it.
  - Interpreted on macOS arm64 only. The tool has no platform-dependent step, but Linux and hosted CI results are not claimed.
  - No gate change: `research/components.json` is not edited, so the crate is not listed under a component, and no completion number changes.

Next question: the parser `0x3897020` (which input bytes become tag `0x0c`, a 20 byte key and a token index), the two message builders `0x46de430` and `0x3d4eb60` (so the refusal texts can be written), and the three ring searches `0x4556410`, `0x4555250` and `0x455b7b0` (so the index and flag conventions the stubs assume can be checked); then the once closure behind `0x5c87d50` and the neighbour callback `0x38e3cf0` (`0x...0810`).
