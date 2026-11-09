# RE-001: the options-map host 0x609e510 (node #115)

## Question

What does `0x609e510` do — the host that #4334 and #4337 both cite as
the caller of the delimiter pre-step `0x6098510` and (wrongly) of the
wrapper `0x60985e0`? It resolves the open unknown left by #4337
("0x609e510 host identity") and #4334 ("what the release helper
0x5d35070 does"), and it corrects the wrapper's caller attribution.

## Answer (read from the binary)

`0x609e510` (FDE `0x609e510..0x609f073`, `0x138`-byte frame, stack
canary at `0x128(%rsp)`) is the options-map host: given a
Configurable object, an option name, and a caller map, it resolves
the (possibly id-prefixed) name against the object's id, verifies the
resolved name is one of the object's own names, serializes the
object's options with the caller's config, parses the serialization
back into pairs, and merges those pairs into the caller map —
existing keys win. It has 21 direct callers (see `callers.tsv`).

### Signature

```
0x609e510(Status* out, const ConfigOptions* opts,
          const Configurable* object, const std::string* name,
          std::string* out_name,
          std::unordered_map<std::string, std::string>* map) -> Status*
```

Returns `out`. `*out` is set to kOk on entry and stays kOk on every
silent early return.

### Steps

1. **`*out = kOk`** (code 0, subcode 0, empty message) at
   `0x609e547..0x609e55d`.
2. **Empty-name gate.** `name.size == 0` jumps to the empty path
   `0x609e9e3`; a name equal to the `.bss` string at `0x6508980`
   (size compare at `0x609e574`, `memcmp` at `0x609e9d0..0x609e9db`)
   takes the same path. The empty path erases `out_name` (string
   replace of `[0, len)` with 0 chars from the literal at `0x4376fd`),
   clears the caller map via `0x5d5b300`, and returns `*out` (kOk).
3. **Null-object path.** `object == null` jumps to `0x609ea30`: the
   id-configure helper `0x609a410` runs with an empty id string, its
   Status is moved into `*out`, and the function returns.
4. **Id resolution.** GetId via vtable slot 15 (`0x78`) writes the
   object's id into a stack string; then `0x609a410(Status tmp,
   name, id, out_name, map)` at `0x609e5bf`. The tmp Status is moved
   into `*out` (old message freed) and the id string is freed; a
   non-kOk `*out` returns at `0x609ea03`. (The helper's seven
   outcomes are #4334's: empty input -> id, input == `.bss` string
   -> id, no `'='` -> input, parses with no `'id'` key and a
   non-empty id -> id with the parsed entries surviving in the map,
   no `'id'` key and an empty id -> input with the map cleared,
   `'id'` key present -> `map['id']` with the entry erased, parse
   failure -> input with the map cleared and the error discarded.)
5. **Name gate.** The object's vtable slot 16 (`0x80`) is compared
   against GOT `0x64eceb8` (the base predicate `0x5d2e770`). If it
   differs, slot 16 is called as `(object, out_name)` at `0x609ed18`:
   false returns, true proceeds to the copy path. If it is the base,
   the host inlines the same two comparisons: `out_name` empty
   returns; `Name()` (slot 14, `0x70`) compared by `strlen` +
   `memcmp` with `out_name`, equal proceeds; else `NickName()` (slot
   18, `0x90`) compared the same way, equal proceeds, else return.
   Every gate failure is silent — `*out` stays kOk and the map is
   untouched.
6. **ConfigOptions copy.** The `0x50`-byte ConfigOptions at `opts` is
   copied to a stack copy C1 at `0xd0(%rsp)`: u32 `+0x00`, u8 `+0x04`,
   the delimiter string at `+0x08` (SSO-aware: length `<= 15` inline
   at `0xe8`, length `== 1` as a single byte at `0x609ed30`, length
   `> 15` via `_M_create` + `memcpy` at `0x609ed40`), u32 `+0x28`,
   u8 `+0x2c` (sanity_level per #4146), u64 `+0x30`
   (file_readahead_size per #4146), 16 bytes `+0x38`, and the
   shared_ptr at `+0x48` (refcount bump: plain `addl` at `0x609e7a7`,
   or `lock addl` at `0x609ed98` when the `__libc_single_threaded`
   flag byte at GOT `0x64ed290` is 0).
7. **Delimiter force.** `_M_replace(&C1.string, 0, len, ";", 1)` at
   `0x609e7c7` makes the copy's delimiter the 1-byte literal at
   `0x43d5c7` (`;`) — not the `"; "` (`0x4409b0`) slot 9 forces.
8. **Serialize.** `0x6098510(Status tmp, object, &C1, S0)` at
   `0x609e80f` truncates S0 and calls `0x6097630` with an empty
   prefix. A non-kOk tmp Status frees S0, releases C1's shared_ptr,
   frees the id temp, and returns (`0x609e93e`).
9. **Parse.** A stack `unordered_map<string, string>` is built at
   `0x70(%rsp)` (buckets = `&single_bucket`, count 1, before_begin
   null, elements 0, max_load_factor 1.0f, next_resize 0,
   single_bucket null) and `0x60c1190(Status at 0x60(%rsp), S0,
   &map)` runs at `0x609e896`. On parse failure the Status message is
   freed, the map is destroyed via `0x5d36110`, and the function
   returns. Note the Status (`0x60`) and the map (`0x70`) overlap in
   the message-string tail slots (`0x70`/`0x78` alias the map's
   buckets/count); this is benign — the message is empty on success
   (the Status write touches only `0x60..0x70`) and the map is dead
   on failure.
10. **Merge.** The parsed map's nodes are walked (first node =
    `map+0x10` before_begin, next = `node+0x00`). Per node the key is
    looked up in the caller map: a linear scan of the caller map's
    node chain while the caller map has `<= 20` elements (`cmp $0x14`
    at `0x609e8d8`), else the hash path (`0x609eb30`:
    `_Hash_bytes(key, size, seed 0xc70f6907)`, bucket = hash %
    bucket_count, walk the bucket chain comparing the hash at
    `node+0x48`, the key size at `node+0x10`, and the key bytes via
    `memcmp`). A key already present keeps the caller's value and the
    walk moves on; an absent key allocates a `0x50`-byte node
    (`operator new` at `0x609ec00`), copies the key string
    (`node+0x08`) and value string (`node+0x28`) SSO-aware, stores
    the hash at `node+0x48`, runs `_M_need_rehash(bucket_count,
    element_count, 1)` at `0x609ecc5` with a rehash at `0x609edba`
    when needed, links the node into the bucket and the before_begin
    chain, and bumps the element count (`0x609ed0b`). This is
    insert-if-absent — the opposite of the map parser, which assigns
    through `0x60c0e90` (operator[] semantics, last duplicate wins).
11. **Teardown.** Every exit after the copy releases C1's shared_ptr
    (`0x609e961..0x609e9a5`): a null control is skipped; a combined
    `(weak << 32 | use) == 0x100000001` disposes (slot `0x10`) and
    destroys (slot `0x18`) inline at `0x609ef48`; a zero flag byte
    takes the `lock xadd -1` path at `0x609ef3a`; otherwise the use
    count is decremented plainly and, when the old use count was 1,
    the release helper `0x5d35070` runs at `0x609ef8e`. The id-temp
    string is then freed and the function returns through the canary
    check.

### The release helper 0x5d35070

FDE `0x5d35070..0x5d350bc`: the shared_ptr counted-base release,
called when use_count reaches 0. It calls the dispose slot (vtable
`+0x10`), then decrements weak_count at `+0x0c` (plain `addl`, or
`lock xadd` when the `__libc_single_threaded` flag byte is 0), and
when weak_count reaches 0 it tail-calls the destroy slot (vtable
`+0x18`). It has 654 direct call sites binary-wide — a shared
helper, not a host-specific routine; the in-packet site is
`0x609ef91`.

### The map destructor 0x5d36110

FDE `0x5d36110..0x5d361d5`: the `unordered_map<string, string>`
destructor — walks the before_begin chain (`map+0x10`), destroys
each node's key/value strings SSO-aware, and frees the node. 484
direct call sites binary-wide; the in-packet site is `0x609e939`
(after the merge loop, and on the parse-failure path).

### The base slot-16 predicate 0x5d2e770

FDE `0x5d2e770..0x5d2e832`: `bool (object, name)` — false when the
name is empty, else true iff `Name()` (slot `0x70`) equals the name
(`strlen` + `memcmp`) or `NickName()` (slot `0x90`) equals it. It
has **zero** direct call sites binary-wide: it is reached only
through the vtable slot and through the GOT guard comparison at
`0x609e64b`. 44 `R_X86_64_RELATIVE` entries carry this addend
binary-wide (43 vtable slots + the GOT guard entry at `0x64eceb8`).
Both Configurable vtables (`0x64d39b8`, 22 slots; `0x64cdad0`, 21
slots) carry it at slot 16 (offset `0x80`), with slot 14 = Name,
slot 15 = GetId `0x5d32a30`, slot 17 = Inner (`0x5d2ca00`, returns
nullptr), slot 18 = NickName (`0x5d2ca10`, returns the empty
string). See `vtables.tsv`.

### Correction: the wrapper's sole caller

#4334 and #4337 state the reset-and-serialize wrapper `0x60985e0`
has its sole caller at `0x609e0a9` "in `0x609e510`". That is wrong:
`0x609e0a9 < 0x609e510`, and the FDE containing it is
`0x609de80..0x609e29e` — slot 12 (`0x609de80`), whose whole-function
excerpt is re-shipped in this packet. The wrapper's sole caller is
inside slot 12, not inside this host.

### Literals

| address | bytes | role |
|---|---|---|
| `0x43d5c7` | `3b` (`;`) | delimiter forced into the ConfigOptions copy |
| `0x4376fd` | `00` + `/home/ubuntu/hl/code_Mainnet/z_vendor/futures-channel/src/oneshot.rs` + NUL | location identity, passed with n=0 in the empty path (never read there) |
| `0x44b52b` | `={};` | map-parser split set (cited from #4320) |
| `0x445245` | `=` | serializer separator (cited from #4337) |
| `0x4409b0` | `; ` | delimiter slot 9 forces (cited from #4334) — contrast with `;` here |
| `0x6508980` | (in `.bss`) | default name: equality with it means "empty" (10 lea sites) |

### Callers

`0x609e510` has 21 direct callers; see `callers.tsv` for the sites
and their containing FDEs. Two are inside already-pinned functions:
`0x61ca53b` is in the custom-parse delegate `0x61ca3d0` (#4320) and
`0x60952ca` is in FDE `0x6095180..0x60956da`, next to the empty-Status
stub `0x60956f0` and PrepareOptions `0x6095e70`. The remaining
containing FDEs are recorded in the TSV without a C++ claim.

### Open unknowns

- The host `0x609e510`'s C++ name (behavior pinned; the name is not
  established from the binary).
- Slot 16's C++ name (behavior pinned: Name-or-NickName equality).
- The `.bss` string `0x6508980` content and identity
  (runtime-initialized; 10 lea sites).
- The `0x4376fd` location string's role (a Rust source path with a
  leading NUL byte; passed with n=0 in the empty path).
- ConfigOptions `+0x00`/`+0x04`/`+0x28`/`+0x38` C++ names and
  defaults (still open from #4334).
- The `0x30`-byte option-group element's `+0x00..+0x18` fields and
  C++ name (still open from #4337).
- Why the host forces `;` (1 byte) while slot 9 forces `; ` (2
  bytes); only the outcome is pinned.
- The map-parse internal call site `0x60c1c2e` (inside `0x60c1190`
  itself) — recursion/iteration detail not pinned.
- Per-caller argument shapes: which of the 21 callers pass
  id-prefixed names vs plain names (the host handles all forms via
  `0x609a410`).

### Verification

`verify.py` checks the artifact digest, the manifest, byte-identical
regeneration of all 7 excerpts, the 8 FDE ranges, raw-binary spot
bytes, the literals, the caller census (including the 654/484 shared
helper counts and the 44 base-predicate relocs), semantic-only
records, and the 24 model tests.
