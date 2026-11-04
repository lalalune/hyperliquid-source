# RE-005: node 115 `rmp_signable` tag writers — who writes the staging dword behind obj +0x1e8, and the byte at arg2 +0xbd5

- Component ID: `serialization` (RE-005, Serialization/signing:
  `bincode_fork/*`, `l1/action/rmp_signable.rs`).
- Target release and full SHA-256: node #115, Linux x86-64, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`;
  no submodule commit is changed by this packet.
- Claim status: **observation** for both writer trails below, all
  re-derived from the pinned target bytes by the checker;
  **unresolved** for every naming or semantic claim listed under the
  boundary.

## The bounded question

The tag-source packet (RE-005-node115-rmp-signable-tag-source)
established that on the grand_b path the serializer's tag byte is
loaded fresh from the context object's +0x1e8 field in FDEs
`0x2ae41e0` (B2) and `0x2cde430` (B3) — where the only in-FDE store
writes the low byte of the dword at obj +0xa0 during the entry staging
arm — and from `[arg2 +0xbd5]` at both call sites in FDE `0x2e098e0`
(B4). It left the next question open: who writes the dword at
obj +0xa0 that the +0x1e8 store takes its low byte from, and who
writes offset +0xbd5 of B4's arg2 object? This packet answers both,
one level up.

## Why this item

The operator action is answering the one question the tag-source
packet explicitly leaves open. The basis for the expected behaviour
is the serializer's own contract: its emitted byte is 0x61 iff the
source byte is 3, else 0x62 (the chain-top packet's claim), so a
reconstruction of the signing payload must know which values the
source byte can take and which code decides them. The loss when it
is wrong is a payload whose tag byte differs from the node's — a
signature over different bytes. Independence by repro case: the
other open RE-005 packets cover the varint size-state (#2257), the
u64 reader state (#2300), the `rmp_signable` .rodata census (#2311),
the serializer (#2399), the caller tags (#2419), the varint readers
(#2412, #2422), the field1-5 caller arguments (#2433), the chain top
(#2432) and the tag sources themselves (#2444); none traces the
record-staging helpers above B2/B3 or the caller above B4. The
record head emitter `0x1506840` is an owner of the scratch-name-pair
packet (#2317, role `consumer_defaults`) and is referenced here, not
re-traced.

## Exact scope

| role | FDE half-open range | bytes | body SHA-256 |
| --- | --- | ---: | --- |
| record_constructor | `0x163a4b0..0x163a66c` | 444 | `579d70a866d9befafc51745673ad60ec4bd4d0c261e33deea54d8fea06690b88` |
| chain_class_writer | `0x564cce0..0x564cf36` | 598 | `e69561afd60a4ae323867f1eb25f2a6997c85c488524e15bf0ca9f9fed100e92` |
| spec_builder | `0x564d700..0x564df8c` | 2,188 | `d80ed0188335a8ce1b4587d9248f8010c61b066fb162a5129e90f968905fe7bf` |
| buffer_converter | `0x2b7b640..0x2b7b79c` | 348 | `1ce5b5a8e849cc065b72f30af834a79f75454bd412d8c67df9137859bbcc8003` |
| b2_tls_caller | `0x2b404b0..0x2b40666` | 438 | `05ef87dc8cdf209d34d246b129dfe209764fe409efda8ee0ad73ceebb54fedac` |
| b2_b3_caller | `0x2ae1690..0x2ae27b2` | 4,386 | `6ca0595c13836bca0cb0173bd591a09d6da6791532e23a5a71c63715380727d9` |
| b4_caller_stager | `0x2af77f0..0x2af8bd3` | 5,091 | `427127960a40d09aaf71aa648cfdece33894eb95f6eca673582da4997ff0d2d0` |

Referenced, not owned (owners of the tag-source packet #2444; only
the listed instructions are re-pinned here): B2 `0x2ae41e0..0x2ae6d66`,
B3 `0x2cde430..0x2ce0dd1`, B4 `0x2e098e0..0x2e11140`. The two caller
owners exceed the ~4 KB full-export guideline slightly; full exports
are retained so that every pin in them is validated as a native
instruction start and the trail-2 census runs over a fully decoded
body.

## Trail 1: the +0xa0 staging dword is a chain-class byte written by traced code

Both staging arms build the same 0x250-byte record on the frame —
B2 directly, B3 through the buffer converter `0x2b7b640` (its only
direct caller is B3, at `0x2cde533`) — and run the same helper chain
over it. All four helpers are reached only through relocation-bound
slots, and the slot census is part of the evidence:

- emitter slot `0x64e0a80` → `0x1506840`: called at B2 `0x2ae4281`,
  B3 `0x2cde525`, and two further FDEs (`0x2aeaef0`, `0x2cb6500`) off
  this path; it consumes the record head B2/B3 initialised and is
  traced as an owner in #2317.
- constructor slot `0x64e1d08` → `0x163a4b0`: called at B2 `0x2ae42dc`,
  converter `0x2b7b69b`, and 14 sites inside FDE `0x564e1a0`.
- spec slot `0x64e73c0` → `0x564d700`: called **only** at B2 `0x2ae42f5`
  and converter `0x2b7b6ac`.
- value producer slot `0x64e1da8` → `0x165de90`: called **only** at
  B2 `0x2ae430b` and converter `0x2b7b6b8`.
- apply slot `0x64e73c8` → `0x564cce0`: called **only** at B2
  `0x2ae437a` and converter `0x2b7b73f`.

What each helper does to the record's +0x90 span (the qword whose
low byte becomes the staging dword):

1. **Constructor `0x163a4b0`** (record = arg1, key = arg2): copies
   the key (the 7-byte name `hl-node`, built by the converter at
   `0x2b7b663`/`0x2b7b66c` from `0x92a890`) into record +0x20 and
   default-writes the body: sentinels at +0x38/+0x50/+0x68, zero
   qwords at +0x80, **+0x90 (`0x163a4db`)**, +0xa0, +0xb0, …, `0x3e7`
   at +0x110, `0x1020700` at +0x1e8. A disp32 store census over the
   constructor body for offsets 0x80/0x90/0xa0 finds exactly these
   three zeroing stores.
2. **Spec builder `0x564d700`** (out = arg1, record = arg2): its
   only stores through the record pointer in the whole body are
   `0x564d725` (record +0xb0 = the `0x92ac70` pointer) and
   `0x564d72c` (record +0xb8 = 0x30) — the 48-byte description string
   `Reference implementation of Hyperliquid protocol`. It copies
   the record **out** to its frame (`0x564d74b`, memcpy through the
   bound memcpy slot) and builds the derived struct in arg1
   (including the build-stamp string at out +0x90, `0x564de7f` —
   a different struct, not the record). A disp32 store census for
   the +0x88..+0x98 span through the record register finds **zero**
   hits: the spec builder never touches record +0x90.
3. **Apply `0x564cce0`** (record = arg1, value = arg2): the writer.
   It fetches the value's `chain` field (name at `0x92a7be`, getter
   `0x4e4ca30`, call at `0x564cd06`) and classifies it by length and
   xor-compared immediates, decoded from the bytes by the checker:
   length 5 `Local` → 0 (`0x564cd32`), length 7 `Sandbox` → 1
   (`0x564cd97`), `Testnet` → 2 (`0x564cd9c`), `Mainnet` → 3
   (`0x564cd6b`). It fetches the value's `key` field (name at
   `0x92ab2c`) into the string at record +0x78, converts the value's
   +0x48 range through slot `0x64ebcb0` (a converted tag dword of
   0x10 aborts via the panic stub at slot `0x64df830`), copies the
   converted struct over record +0x0..+0x78, and stores the class
   as a single byte: **`0x564ceb5`, `mov BYTE PTR [rbx+0x90], bpl`
   (encoding `4088ab90000000`, unique in the body)**. A disp32
   store census over the apply body for the +0x88..+0x98 span finds
   exactly two stores: the byte store at +0x90 and the `key` string
   field store at +0x88 (`0x564cec7`), whose 8-byte range ends at
   +0x8f and does not touch +0x90. Failure modes write nothing: a
   missing `chain` field calls the panic stub `0x1680c10`
   (int3-terminated), and an unrecognised name loads the
   `called \`Result::unwrap()\` on an \`Err\` value` string
   (`0x92a732`, 43 bytes) and calls the panic formatter at slot
   `0x64df6a0` → `0x1680c30`, which ends in `int3` — no class byte
   is stored on either path.

The staging arms then carry the byte into the context object: B2
stores the record +0x90 qword to obj +0xa0 at `0x2ae447f` and the
low byte to obj +0x1e8 at `0x2ae44ce`; B3's converter applies the
same chain to its frame record and memcpys its 0x98-byte head
(`0x2b7b75d`) into the buffer B3 stages at obj +0x10 (`0x2cde55e`),
so obj +0xa0 takes the same byte before B3's +0x1e8 store at
`0x2cde56b`. In the converter's default branch (value tag qword
`0x8000000000000001`) the apply call is skipped, out dword +0x0 is
set to 0x10 (`0x2b7b6f2`), and B3 diverts away from the memcpy arm —
the +0x1e8 store is not reached on that branch.

Callers: B2 has exactly two direct call sites in `.text` — the
b2_b3_caller `0x2ae1690` at `0x2ae1a47` (obj = its frame object at
rsp+0x5aa8, set at `0x2ae19b7`) and the b2_tls_caller `0x2b404b0`
at `0x2b40577` (obj = `[[arg3]]`, loaded at `0x2b40573`, inside the
TLS flag save/set/restore idiom whose word store is pinned at
`0x2b40560`). B3 has exactly one, the b2_b3_caller at `0x2ae1eeb`
(arg1 = frame holder at rsp+0x80). One raw direct-call hit reaches
the b2_b3_caller (at `0x2cd83a2`, inside FDE `0x2cd8370`) and one
reaches the b2_tls_caller (at `0x2453673`, inside FDE `0x24535c0`);
neither is needed by the writer claims.

**Verdict (trail 1):** the +0xa0 staging dword is not raw input. It
is the chain-class byte (Local 0, Sandbox 1, Testnet 2, Mainnet 3)
written at `0x564ceb5` over the constructor's zeroed qword, so the
serializer emits 0x61 exactly when the produced value's `chain`
field is `Mainnet`, and 0x62 for the other three recognised names;
an unrecognised name aborts before any byte is written.

## Trail 2: the +0xbd5 byte is copied verbatim by the caller's staging memcpy

B4's only direct call site in `.text` is `0x2af80c5`, inside the
b4_caller_stager `0x2af77f0` (Z). At that site arg2 is `r13`, loaded
from the frame slot [rsp+0x20] at `0x2af80bf`; the slot is written
exactly once, at `0x2af7f49`, with `rax = obj +0xca0` (computed at
`0x2af7f42`, obj = Z's arg1 in rbx). So B4's arg2 object is the
+0xca0 sub-object of Z's own input object.

On Z's entry path for mode byte `[obj +0x1aca] == 0`, Z stages that
sub-object from the object itself: `lea r15,[rdi+0xca0]` at
`0x2af7839`, then a memcpy through the bound memcpy slot at
`0x2af784b` with length **0xbd8** (`0x2af7840`) — which covers
offset +0xbd5 — followed by movups tail copies (`[obj +0xbd8]` →
`[obj +0x1878]` at `0x2af7851`/`0x2af786d`, and onward) that continue
the same clone past the memcpy's range. The staged copy's +0xbd5
byte is therefore the input object's own +0xbd5 byte, copied
verbatim.

The negative is byte-exact: **Z's 5,091-byte body contains zero
occurrences of the byte sequence `d5 0b 00 00`**, so no instruction
in Z — in any encoding, as a displacement or as an immediate —
references offset +0xbd5 at all. B4's own body contains exactly
three occurrences: the two tag-byte loads pinned by #2444
(`0x2e09b01`, `0x2e09f87`) and `add rsi,0xbd5` at `0x2e0b060`, which
forms the field's address for a descriptor passed to `0x2378130`
and writes nothing. Z itself has no direct call site in `.text`.

**Verdict (trail 2):** no traced code computes the +0xbd5 byte. It
arrives as input data in Z's arg1 object and is carried into B4's
arg2 object by Z's staging memcpy — input-determined at exactly
this offset.

## Boundary

- Trail 1 ends at the value: the `chain` name string inside the
  value produced by `0x165de90` / `0x165dfb0` from the spec is
  input data. Where that string originates at runtime (the value
  producer reads a record copy and a thread-local registry) is
  above this packet's traced set and is not claimed.
- Trail 2 ends at Z's arg1 object: whoever writes its +0xbd5 field
  is above `0x2af77f0`, which is reached indirectly (no direct
  `.text` call site); the trail is data-only from there.
- Whether any given action family ever carries the Mainnet class
  (byte 3) at runtime is not decidable from static bytes and is
  not claimed; the classification itself, its four values, and its
  two abort paths are fully determined by the pinned bytes.

## Validation

`tools/rmp_signable_tag_writers_static.py` re-derives every claim
from the authenticated artifact: relocation bindings for all nine
slots, byte pins for every cited instruction (each validated as a
native instruction start against the retained exports, and against
fresh decodes of the three referenced #2444 bodies), the direct-call
and per-slot censuses, the disp32 store censuses, the classification
names and values decoded from the immediates, and the trail-2 raw
byte census. `tests/test_rmp_signable_tag_writers_static.py`
regenerates the packet byte-identically and counterfactually mutates
the load-bearing bytes (the constructor zeroing store, the apply
byte store, a classification immediate, the staging memcpy length,
the `chain` name, the Z/B4 `0xbd5` sequences). Captured code is
never executed. Run with the artifact materialised:

```
python3 -m pytest tests/test_rmp_signable_tag_writers_static.py
make catalogue-check
```

## Next question

Where does the `chain` name string inside the value produced by
`0x165de90` / `0x165dfb0` come from — which field of the spec built
by `0x564d700`, and which input record or registry entry supplies
it — and, symmetrically, which constructor or staging path first
writes the +0xbd5 field of the object `0x2af77f0` receives?
