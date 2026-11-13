# RE-005: node #115 TWAP cancel signing input (`0x36aa9a0`, `twapCancel` path)

- Component ID: `serialization` (RE-005, Serialization/signing).
- Target release and full SHA-256: node #115, Linux x86-64, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Reference commit: `a8616af9432b8d8517b2af677880e117b7c28ef3`. No submodule commit
  is changed; no existing file is modified.
- Claim status: **observation** for every byte-level fact listed below (each is a
  pinned, re-checkable item in `pins.json`); **inference** where marked; **unresolved**
  for everything under "Not covered".
- Scope included: from a valid `twapCancel { a: u32, t: u64 }`, the suffix record
  (nonce, optional vault, optional expiry) and the chain selector to the object
  `0x36aa9a0` returns: 32-byte digest, one-byte tag, constant `0x539`.
  Excluded: signing, the outer EIP-712 hash, wire decoding, who builds the action
  and suffix, native allocation/unwind/ABI.
- Rust crate: [`src/node115-twap-cancel-signing-input`](../../../src/node115-twap-cancel-signing-input/README.md)
  (that README points back here).

## The bounded question

The function at `0x36aa9a0` was known to append a 9/18/29/38-byte suffix to a
writer-produced prefix, hash the result and return a record
(`RE-005-node115-rmp-signable-layout`), but the prefix and thus the hash input for any
action were unresolved, and no source reproduced the hash for TWAP cancel. For
action tag `0xa9` (`twapCancel`): what exact bytes are hashed, and what exact record
comes back?

Answer (observation, pinned): the hashed bytes are
`83 a4 "type" aa "twapCancel" a1 "a" <uint a> a1 "t" <uint t>` followed by
`nonce(8, BE) | 00 | [00 expiry(8, BE)]` or `nonce | 01 vault(20) | [00 expiry]`;
the digest is Keccak-256 (domain byte 1) of them; the tag is `0x61` iff the
selector's low byte is 3 else `0x62`. Example (a=1, t=2, nonce=0x0102030405060708,
no vault, no expiry), 32 bytes:

```text
83 a4 74797065 aa 7477617043616e63656c a1 61 01 a1 74 02 0102030405060708 00
-> 5f07dac3d5e01782799cf9f3260ae8ce3d00107075fbef13fae3266c6abf38de, tag 0x61
```

## Reproduce

Run from the repository root. `$HL_NODE_115` is the pinned ELF; `$OUT` is a new
empty scratch directory outside the repository. `verify_target.py`, `mutate.py`
and `oracle.py` refuse an existing `--outdir` and one inside the packet (exit 4,
nothing written); `oracle.py` also refuses the crate directory, and all three
resolve symlinks and `..` before checking. `$OUT` also keeps cargo's `target/`
out of the crate. Needs Python 3 (standard library only), GNU objdump and cargo;
no network.

```sh
P=research/work-items/RE-005-node115-twap-cancel-signing-input
C=src/node115-twap-cancel-signing-input
python3 -I $P/oracle/oracle.py --outdir "$OUT/oracle"
cmp "$OUT/oracle/corpus.tsv" $C/tests/oracle/corpus.tsv
python3 -I $P/oracle/oracle.py --outdir "$OUT/oracle-selftest" --selftest
cargo test --offline --locked --target-dir "$OUT/target" --manifest-path $C/Cargo.toml
cargo test --offline --locked --release --target-dir "$OUT/target" --manifest-path $C/Cargo.toml
python3 -I $P/verify_target.py --elf "$HL_NODE_115" --outdir "$OUT/verify"
diff -r "$OUT/verify/decoded" $P/raw/decoded
python3 -I $P/verify_target.py --elf "$HL_NODE_115" --outdir "$OUT/verify-selftest" --selftest
python3 -I $P/mutate.py --outdir "$OUT/mutate"
python3 -I $P/mutate.py --outdir "$OUT/mutate-selftest" --selftest
python3 -I $P/check_manifest.py . $P/MANIFEST.sha256
git status --porcelain
```

`MANIFEST.sha256` lists every packet file, every file of the crate (source, tests,
lockfile, corpus) and the unmodified dependency sources, with paths relative to the
repository root, in the sha256sum line format that `tools/verify_packets.py`
resolves. `check_manifest.py` also reports unlisted files. After the sequence above
the manifest check is clean and `git status --porcelain` lists only the two new
directories (cargo `target/` is ignored).

Tool versions used: Python 3.12.3, GNU objdump 2.42, cargo/rustc 1.99.1. The
repository pins Rust 1.95.0 (`rust-toolchain.toml`); that toolchain was not
available offline, so `rust-version = "1.95"` is declared but **not verified**.
Exit codes: `verify_target.py` and `mutate.py` return 0 only if every check passes;
1 on any mismatch, survivor, build error or missing test result; 3 on environment
errors (objdump/cargo/ELF); 2/4 on usage or a refused `--outdir`. Declared side
effects: none besides the new `--outdir` (and cargo target directories inside it).
The target is only read and disassembled; it is never executed or emulated.

## Evidence

Coordinates are virtual addresses. For `.text` the file offset is VA - `0x1000`
(program header `LOAD 0x1418300 -> 0x1419300`); `.rodata` VA equals file offset.
FDE half-open ranges come from `.eh_frame_hdr` and the FDEs it indexes (the
verifier parses them itself) and are pinned with SHA-256 of each body in
`pins.json`. Analysis was complete for every listed window (linear decode of the
whole FDE), not a range sample.

| role | FDE range | bytes |
| --- | --- | ---: |
| serializer (entry, suffix, hash, result) | `0x36aa9a0..0x36aade6` | 1,094 |
| action dispatcher | `0x36b1600..0x36b3f7d` | 10,621 |
| cancel writer used on this path | `0x46abec0..0x46ac018` | 344 |
| other cancel writer copy (`twap-action-wire`) | `0x46ac020..0x46ac252` | 562 |
| other dispatcher that calls that copy | `0x36b3f80..0x36b687d` | 10,621 |
| map header / marker byte | `0x3d4f6d0..0x3d4f999` / `0x3d52310..0x3d5235e` | 713 / 78 |
| uint writer + u16/u32/u64 helpers | `0x3d517e0..0x3d51a52`, `0x3d51d10..0x3d51e9d`, `0x3d51f40..0x3d520cb`, `0x3d520d0..0x3d52264` | 626/397/395/404 |
| string writer | `0x41c6110..0x41c6606` | 1,270 |
| other copy's uint / string helpers | `0x3d51450..0x3d517d5`, `0x41c6610..0x41c6824` | 901 / 532 |
| sponge update / finalize / permutation | `0x5cda910..0x5cdad3a`, `0x5cdad40..0x5cdb03d`, `0x5cda380..0x5cda902` | 1,066 / 765 / 1,410 |

### Path (observation)

1. `0x36aa9a0(rdi=result, rsi=action, edx=selector, rcx=suffix record)` saves
   `edx` in `ebp` and `rcx` in `r15`, builds an empty `Vec` and a writer
   `{vec*, dword 0x01000400, byte 0}` (`0x36aa9b2`, `0x36aa9dc`), and calls
   `0x36b1600(out, action, writer)` at `0x36aa9f6`.
2. The dispatcher reads the action tag `[rsi]`, subtracts `0x86` and jumps through
   the signed-dword table at `0x799f5c` (`0x36b1605..0x36b1628`). The table has 93
   entries that land inside the dispatcher; exactly index `0x23` (tag `0xa9`) goes
   to `0x36b1e3c`. That arm passes payload `action+8`, the names `Action`/`TwapCancel`
   (`0x79d5a6`, `0x79d714`), the key `type` (`0x45a144`), the action name
   `twapCancel` (`0x79c888`) and the writer, and calls `0x46abec0` at `0x36b1ea1`.
   `0x46abec0` has exactly one direct call/jump site in `.text` (that one) and no
   `RELATIVE` data reference.
3. `0x46abec0` reads the writer from descriptor `+0x40` and tests writer byte
   `+0xb` (`cmp BYTE PTR [r14+0xb],0x0`). The spec dword `0x01000400` is stored
   little-endian, so that byte is 1: struct-map mode. It calls the map header with
   length 3, writes the strings `type` and `twapCancel`, then the keys `a` (`0x7d9f99`)
   and `t` (`0x7d9f88`) around the integers `a = u32 [payload+8]` and
   `t = u64 [payload+0]` through `0x3d517e0`, and stores `0x8000000000000004` (Ok).
4. Writers: `0x3d4f6d0` with length < 16 uses base `0x80`, and `0x3d52310` computes
   `0x80|len`, so length 3 gives `0x83`. `0x41c6110` with length < 32 uses base `0xa0`
   (`0xa0|len` via the same marker helper) and copies the text with the imported
   `memcpy` slot `0x64df508`. `0x3d517e0` is the smallest-width unsigned encoder:
   `< 0x100` and bit 7 clear: the byte itself; `< 0x100` with bit 7 set: `cc n`;
   `< 0x10000`: `cd` + BE16; high dword zero: `ce` + BE32; else `cf` + BE64.
   The three data helpers write their marker byte and a byte-swapped value.
5. Back in `0x36aa9a0` the Ok tag is checked (`0x36aaa05/0d`; anything else goes to
   an unwrap panic), and the suffix is appended exactly as in
   `RE-005-node115-rmp-signable-layout`: nonce at record `+0x10` big-endian; vault
   present iff record byte `+0x18 == 1` (marker `01` and 20 bytes from `+0x19`,
   otherwise marker `00`); then, iff record dword `+0 == 1`, a zero marker and the
   big-endian u64 from `+0x8`.
6. `0x36aab2a..0x36aabeb` zeroes a 0xe0-byte sponge state, stores rate `0x88` at
   `+0xd0` and the domain word `1` at `+0xd8`, then calls update through slot
   `0x64e0148` with the whole buffer and finalize through `0x64e0150` with output
   length 32. Both slots are `R_X86_64_RELATIVE` with addends `0x5cda910` and
   `0x5cdad40`; the permutation slot `0x64ecb70` has addend `0x5cda380`.
7. Update takes the no-permutation path for any length below rate minus cursor
   (cursor 0, rate 136): it XORs the input into the state with 32-byte vector, 4-byte
   word and byte loops and publishes the length at `+0xc8`. Finalize XORs the domain
   byte at the absorbed length, `0x80` at rate-1, runs the permutation once and
   copies the first 32 bytes (32 < 136, no second permutation).
8. The result record at `rdi`: word0 `1`, word1 pointer to a fresh 1-byte allocation
   that holds `0x62 - (bpl == 3)`, word2 `1`, digest at `+0x18..+0x38`, `0x539` at
   `+0x38`, zeros at `+0x40..+0x58`. `bpl` is the low byte of the selector, so the
   selector `0x103` gives `0x61`.

Raw material kept beside this file: `raw/decoded/*.txt` (linear decode of every
window, one `va<TAB>text` line per instruction, regenerated and diffed by the
reproduce step), `raw/verify/` (check table, bit-flip summary, findings),
`raw/mutations.tsv`, the two selftest transcripts, and `pins.json` (134 instruction
facts with bytes and decoder text, 17 FDE windows with body hashes, 3 relocation
slots, the `memcpy` import, 6 rodata strings, 6 call-site sets, caller counts and
the jump-table census).

### The two cancel writer copies (observation)

The task note asked for a byte comparison of `0x46abec0` and `0x46ac020` before
reusing the older cancel model. They are different code:

| | `0x46abec0` (this path) | `0x46ac020` (`twap-action-wire`) |
| --- | --- | --- |
| mode byte | writer `+0xb` | writer `+0x1b` |
| header | calls map/array helpers (`0x3d4f6d0` / `0x3d50270`) | inline `0x83 | ((mode^1)<<4)` |
| strings | `0x41c6110` | `0x41c6610` |
| integers | `0x3d517e0` (+ u16/u32/u64 helpers) | `0x3d51450` |
| keys `a`, `t` | rodata pointers, string writer | inline `a1 61`, `a1 74` |
| field order and sources | `type`, `a` = u32 `+8`, `t` = u64 `+0` | same |

In struct-map mode the two copies share the contract checked here: header `0x83`,
the same two strings, the same order and field widths, and the same integer
thresholds (`0x100`, `0x10000`, 32-bit shift) and markers (`cc`, `cd`, `ce`) for the
second copy's integer helper, and the same `0xa0` fixstr boundary. Not compared:
the second copy's `cf` arm and big-endian stores, its string arms above 31 bytes
and its array mode. So the equality in map mode is an **inference from partial
structural agreement**, not a proof of instruction equivalence. The crate therefore
writes its own bytes from `0x46abec0` and uses `node115-twap-action-wire` only as a
dev-dependency consistency check (132 asset/id pairs) between the two readings.

### Inferences and unresolved

* Inference: the 8-byte value at record `+0x10` is the nonce and `+0x8` the expiry
  (named by the earlier packet); the one-byte tag is a `String` because word0/word2
  are 1 (capacity/length); not needed for the bytes.
* Inference: the payload layout `t` at `+0`, `a` at `+8` is read straight from the
  writer's loads; the Rust field names `asset`/`twap_id` follow the older crate.
* Unresolved: which selector value and suffix record a `twapCancel` carries
  at the call sites that earlier packets already found (see "Next question");
  the permutation body
  `0x5cda380` is pinned by FDE and body hash only. That it is the standard
  Keccak-f[1600] rests on RE-009 and the OpenSSL comparison in RE-001, and is
  consistent with (not independently proven by) the 665 digests below.
* Unresolved: behavior for malformed raw option bytes. Reading the branches, any
  vault byte other than 1 and any expiry dword other than 1 behave as "absent", but
  the typed API does not expose them.

## Implementation and comparison

* Crate: `src/node115-twap-cancel-signing-input/` (`Cargo.toml`, `Cargo.lock`,
  `src/lib.rs`, `tests/`). No crates.io dependency; path dependencies are the
  permutation (through a one-line adapter manifest, as `node115-noop-preimage`
  does) and, for tests only, `node115-twap-action-wire`. `[workspace]` is empty
  and the crate is not added to any root workspace. Output buffer is a 73-byte
  stack array; no heap use in the library.
* Oracle first: `ORACLE_FROZEN.txt` records the generator and corpus SHA-256 and the
  UTC time they were fixed, before any crate source existed. The oracle writes
  MessagePack by hand from the specification and uses its own Keccak (round
  constants from the FIPS 202 LFSR, offsets from the triangular-number walk), checked
  against Keccak-256 public vectors (`""`, `"abc"`, the fox sentence) and against
  `hashlib.sha3_256` for lengths 0..400. The corpus has 665 rows: anchor 1, integer
  grid 154 (11 asset x 14 id values around 127/128, 255/256, 65535/65536, u32 and u64
  maxima), suffix combinations 56, selectors 64 (3, others, `0x103`, `0xffffff03`,
  ...), nonce 32 + 8 single bytes, 20 vault bytes, vault zero 2, expiry 22,
  single-field changes 6, seeded random 300. Preimage lengths cover 32..73.
* Rust tests (11, `cargo test`, debug and release): corpus denominator and classes,
  preimage, digest, tag and the 88-byte returned record against the oracle for all
  665 rows each; hand-typed anchor; Keccak public vectors plus the 135/136 limit;
  suffix length classes (9/18/29/38, max 73); present-but-zero versus absent;
  selector low-byte rule; consistency with `node115-twap-action-wire`.
* Static target checks (`verify_target.py`): ELF SHA-256 and size; 17 FDEs and body
  hashes; 134 instruction facts (address is a decoded instruction start, decoder
  text, exact bytes); relocation slots; `memcpy` import; six rodata strings; the
  `0xa9` table entry and uniqueness; call-site sets; caller counts. These checks
  show that the pinned facts still describe the pinned ELF; they do not by
  themselves validate what the instructions mean. As a sensitivity control of the
  pin check itself (integrity, not semantics), every single-bit flip of the 661
  pinned instruction bytes (5,288 flips) changes the byte layer and the body
  hash, and 5,278 also change the decoder text; none goes unnoticed. Selftest:
  baseline first, then 13 pin/ELF corruptions each rejected with its own
  finding code and id, 3 CLI guards, and a meta control that runs the selftest on
  a broken baseline and requires it to fail: 17/17.
* Mutation (`mutate.py`): 31 compiled mutants (field order/name, header count,
  integer width boundaries 127/255/65535/u32 max, markers, byte order, suffix flags
  and markers, padding byte, padding position, rate, lane order, tag, selector
  width, record constant and slot, asset width, block limit, two in the permutation
  dependency) x debug and release = 62 builds, each built (`cargo test --no-run`)
  and run (`cargo test`) separately, each required to run all 11 tests and fail at
  least one named expected test: 62/62 killed. The first run killed 60/62: the
  record-pointer mutant survived because the test used address 0; the test was
  strengthened (see `ORACLE_FROZEN.txt`, amendment 1). Selftest 10/10: killable
  mutant exits 0; survivor, compile error, wrong-test failure, missing pattern,
  broken baseline, a cargo that starts failing after the baseline, and three
  `--outdir` refusals all behave as required.
* Raw/normalized comparison, two-build identity and helper/relocation closure with
  a native build: not applicable. No binary-equivalence claim exists; comparisons are
  between a frozen independent oracle and the Rust source, and static facts of the
  target.

## Results and limitations

| metric | result |
| --- | --- |
| oracle corpus rows, each checked for input, digest, tag, record | 665/665 |
| Rust tests, debug / release | 11/11 / 11/11 |
| pinned instruction facts | 134/134 |
| mutants killed by an expected test | 62/62 |
| verifier / mutation / oracle selftest controls | 17/17 / 10/10 / 11/11 |

Pin-check sensitivity (integrity of the pins, not a semantic check): 5,288 of
5,288 single-bit flips of the pinned instruction bytes are noticed.

Not covered: signing and the outer hash; the selector value and suffix record a
`twapCancel` carries at the call chain above `0x36aa9a0` (that chain is traced by
earlier packets, see below); native allocation, buffer growth (`0x43bd910`, `0x43bd550`), the unwrap panic path
and unwind; register/stack ABI; inputs of 136 bytes or more; other action types
(only the `0xa9` arm was read); the permutation instructions; non-`twapCancel`
arms of the shared serializer. Valid typed inputs and normally returning helpers are
premises. Static reading only: nothing was executed or emulated, so expected values
rest on the reading of the bytes plus agreement with an independent oracle, not on
a captured native result. The one-block claim is established for lengths below 136
by the update/finalize structure (11 pinned facts), extending the four shapes
checked in RE-001. `make verify` and `make catalogue-check` could not complete in
the clean worktree used (LFS objects, including the ELF, are unmaterialised pointers
there; the failures are in unrelated files), and `make test` was not run because its
discovery includes captured-instruction emulation. This packet's manifest was
checked with the resolver functions of `tools/verify_packets.py` (43 rows, 0
mismatches) and `check_manifest.py`. No component gate is requested.

Prior work this packet builds on and does not recount. Already in the tree before
it: the `0x46ac020` cancel encoding and its Rust model
(`RE-010-node115-twap-action-wire`, `src/node115-twap-action-wire`); the 9/18/29/38-byte
suffix rule and the two post-processors (`RE-005-node115-rmp-signable-layout`);
the one-block absorb/finalize for Noop (`RE-001-node115-noop-preimage`) and the
permutation (`RE-009-sponge-permutation-115`, `src/node115-sponge-permutation`);
PR #2202 and #3268 (cancel decode and state path, not this hash). The callers of the
post-processors were also traced before: `RE-005-node115-rmp-signable-caller-tags`
(`0x36aadf0` is called only at `0x36c208b` in `0x36c2050`, `0x36aaf10` only at
`0x36c5388` in `0x36c5350`; the tag handed to the serializer is each dispatcher's
own entry `edx` low byte on every reaching path) and
`RE-005-node115-rmp-signable-chain-top` (the tag source bytes `[[arg3+0x10]]` at
`0x3713300`/`0x37133b3` and `[arg2+0x11d]` at `0x38d9c60`/`0x38d9e07`). What this
packet adds is only the binding of the `twapCancel` arm to writer `0x46abec0` on
the `0x36aa9a0` path, the composition of prefix, suffix, hash and tag into one
typed call, and the oracle and checks around it.

Next question (narrowed by those packets): they fix where the tag comes from, not
what it is for a cancel. Open for `twapCancel` (action tag `0xa9`): (1) whether `0xa9`
reaches the post-processors on the direct pad of the two dispatchers
(`0xa9` is not among the 21 arm discriminants that the caller-tags packet lists, so
its partition suggests so; not re-checked here); (2) what the two tag source
bytes denote and whether they equal 3 for a TWAP cancel (the chain-top packet's own
open question), which decides `0x61` versus `0x62`; (3) how the suffix record
(`rcx` at the two dispatcher calls: a frame-assembled record in `0x3713300`, a
frame address in `0x38d9c60`) is built; (4) who consumes the returned
digest-and-tag record after the post-processors write the `0x007e` / `0x01a2` words.
