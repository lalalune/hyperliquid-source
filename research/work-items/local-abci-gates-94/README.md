# node-runtime: node #94 local abci_state startup gates (540/840 s local-state age gate, height tolerance, 600 s freshness panic)

Question: when node #94 starts from a local abci_state, which constants decide
that the local height is "too far behind" or "from stale hardfork", which
`tolerance` value is logged and what it decides, and what does the
`use an abci state within … seconds` check compare? Where does the can1357
lead (`node/local_abci_state.rs`, `node/startup.rs`) differ?

- Component ID: `node-runtime` (`docs/COMPONENTS.md`: CLI, startup, gossip,
  stream services; path rule `node/*`).
- Target: `artifacts/node/94/hl-node`, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `1f8c67c63ca4794c9689235471c60297f8a5c985`. Reference lead:
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`, used
  only for seed addresses and claims to test; no code, comments or names
  copied.
- Claim status: observation for byte-level facts, inference where marked,
  unresolved where listed. Partial `node-runtime` research; no gate change.
- Scope: seventy-one fixed windows in `0x22689f0` (the lead's
  `local_abci_state.rs` seed), its helpers `0x1459ca0`, `0x254e7b0`,
  `0x144a710`, `0x3994ea0`, `0x33de620` and `0x3bacce0`, five windows of the gossip loader
  `0x4741dc0`, the other `0x227a0e0` caller `0x226c2d0`, its two callers `0x227a0e0` and `0x22b47c0`, `0x2271d00`,
  its caller `0x22ae8a0` and the panic shim `0x157b810`.
  Excluded: what `0x226bb20` sends and decodes, how the timestamp is produced,
  what the 0x58-byte map values hold besides `+0x4c`, the rest of the `0x22ae8a0`
  state machine, and release #115.

## Reproduce

```sh
make verify
python3 tools/local_abci_gates_static.py --json > research/work-items/local-abci-gates-94/records.json
python3 -m unittest tests.test_local_abci_gates_static -v
```

The producer authenticates the input against `provenance/artifacts.json`, parses
sections, `.eh_frame` FDEs (`tools/fde_extents.py`) and `.rela.dyn`
`R_X86_64_RELATIVE` entries, and never executes the target. It needs only
Python 3 (run here with 3.14.7 on macOS arm64; under 1 s). `records.json` is
its complete output; the test suite regenerates and compares it.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47, in 71
windows (2640 instructions), one per checked byte window. All 171 `records.json`
VAs (values and keys) that fall inside a window are instruction starts there, except `slot_refs`
and `record_refs` entries, which are ModRM-byte addresses inside instructions. The other code VAs
are FDE starts, call targets and branch targets outside the windows.

Format templates are decoded as rustc 1.94 packs them: a byte below 0x80 is a
literal length, and `0xc0` is a placeholder followed by the length of the next
literal; `0x00` ends the template. Every literal length decodes to printable
text that ends exactly at the next marker. Reading placeholder *k* as format
argument *k* is an inference.

## Evidence

### How `ip_to_heights` is filled (observation)

The peer loop `0x2269cd8..0x226a41a` runs before the selection below.

1. **Peer list:** `0x2269c63` stores `[[rbx+0x3c30]]` to `[rbx+0x49c8]` and
   clears the map root and length (`[rbx+0x49b0]`, `[rbx+0x49c0]`). The list's
   data pointer is `[+0x8]` and its length `[+0x10]`; entries are 5 bytes
   (`lea rcx,[rcx+rcx*4]`, stride `lea rcx,[rax+0x5]`). An empty list goes
   straight to the `got heights` log (`0x2269cd2 → 0x226a41a`). Each entry's
   first 4 bytes and fifth byte are copied to `[rbx+0x49d0]` and
   `[rbx+0x49d4]`.
2. **Query:** the code logs `… @@ querying height @@ [rpc_ip: {}]` (template
   `0x1dd96c`, argument `&[rbx+0x49d0]`). It then stores 2 to `[rbx+0x3c88]`
   and calls `0x226bb20` (`0x2269e87`). That FDE, `0x226bb20..0x226c2c8`,
   contains the `gossip_rpc_request` 10.0 s timeout window `0x226bb82` checked
   by [#211](https://github.com/lalalune/hyperliquid-source/pull/211). A
   result word equal to `r12 + 0x41` goes to `0x226a8bc` (pending). All
   three paths back to the next peer set `r12 = 0x8000000000000000`
   (`0x2269fe2`, `0x226a079`, `0x226a2dc`). Its value on the first entry is
   not checked.
3. **Reply:** a result word other than `0x8000000000000040` goes to the error
   log (`0x2269f4e → 0x226a1fa`). Otherwise `[rsp+0x128]` must be 2, else the
   30-byte `incorrect rpc response variant` (rebuilt from `0x3d79ef` and
   `0x3d79fd`) goes to the same log. If bit 0 of `[rsp+0x130]` is set,
   `0x28523b0` is called with `&[rbx+0x49b0]`, the current peer and the
   values `[rsp+0x138]`, `[rsp+0x140]` (`0x2269fdd`), then the next peer
   (`0x226a403`). If clear, the code logs
   `… ERROR >>> … @@ no heights from node @@ [rpc_ip: {}]` (template `0x1ebdb6`)
   and moves on to the next peer.
4. **Errors:** both error cases log
   `… ERROR >>> … @@ unable to query height: {} @@ [rpc_ip: {}]` (template
   `0x1ee557`) and continue with the next peer (`0x226a414 → 0x2269cd8`).
5. **No local-height filter:** no `[rbx+0xb0]` (local height) operand appears
   anywhere in `0x2269cd8..0x226a41a`.

So `[[[rbx+0x49c8]]+0x10]`, used by the single-entry exception below, is the
number of peers queried. Inference: `0x28523b0` is a `BTreeMap` insert keyed
by peer IP, the reply is `Option<(initial_height, latest_height)>`, and
request tag 2 asks for heights. Model `collect_heights` checks the
skip/insert rules.

### Where `initial_height` and `latest_height` come from (observation)

Window `0x226a53f..0x226a6d2` follows the `got heights` log (template
`0x1e7641`, `… @@ got heights @@ [ip_to_heights: {}]`, whose argument is
`&[rbx+0x49b0]`). It reads `[rbx+0x49c0]`, the length word of the map whose
root and height are `[rbx+0x49b0]` and `[rbx+0x49b8]`:

1. **Guard:** length > 1 goes to the loop (`ja` at `0x226a54f`). Length 0 goes
   to `0x226a6d2` (`0x226a551`). Length 1 goes to the loop only if
   `[[[rbx+0x49c8]]+0x10] == 1`; otherwise also to `0x226a6d2` (`0x226a566`).
2. **Selection:** an iterator over the map is built on the stack and advanced
   by calls to `0x27df4f0` (`0x226a5df`, `0x226a659`, `0x226a68a`), each
   returning `rdx` as a value pointer. `r15 = [rdx]`, `r14 = [rdx+8]` from the
   first entry. For each later entry `(rbp, r13) = ([rdx], [rdx+8])`, the
   current pair is kept only if `r15 > rbp`, or `r15 == rbp` and `r14 > r13`
   (`seta`/`seta`/`cmove` at `0x226a691..0x226a6a0`). Otherwise both are
   replaced (`cmove` at `0x226a6a6`, `0x226a6aa`). The loop back-edge is
   `0x226a6b6 → 0x226a680`.
3. **Error:** `0x226a6d2` allocates 43 bytes and copies three 16-byte pieces
   from `0x3d7964`, `0x3d7974` and `0x3d797f` to offsets 0, 0x10 and 0x1b.
   Together they read `unable to find at least 2 valid rpc heights`. The tool
   rebuilds the string from the three `movups` operands.
4. **Result:** `0x226a719` stores `r13`, `r15`, `r14` and 0x2b to
   `[rbx+0x3bd8..0x3bf0]`. On the loop path `r13 = 0x8000000000000040` and
   `r12b = 1`. On the error path `r15 = 0x2b` and `r14` is the string
   pointer, and `r12b = 0`. A set `r12b` jumps to `0x226a912` (`0x226a74d`).
   The only call in between is `0x28b37f0`, and `r14` and `r15` are
   callee-saved. That window reaches the status-log window at `0x226a974`
   without writing `r14` or `r15`, which are then logged as `initial_height`
   and `latest_height`.
5. **Retry:** the error path (`0x226a753..0x226a8bc`) formats
   `AsyncSleepRetry::retry desc=[…] n_tries=…` (template `0x1f2256`, LEA at
   `0x226a7eb`) and jumps back to `0x2269bcc` (`0x226a8b7`).

Model (`select_heights`): with `values` in iteration order, the pair used is
the lexicographic maximum of `(initial_height, latest_height)`. It is
checked against Python `max` on 500 random lists. Inference: the map is a
`BTreeMap` keyed by peer, from the `{root, height, length}` layout and the
`ip_to_heights` label. `[[[rbx+0x49c8]]+0x10]` is the queried peer count (see above).

### The three heights are named by the status log (observation)

Window `0x226a974..0x226ab0a` runs straight up to the gate. It:

- stores `r15` to `[rsp+0xc8]`, `r14` to `[rsp+0xd0]`, and `[rbx+0xb0]` to
  `[rsp+0xd8]`;
- passes pointers to those three slots as arguments 2, 3 and 4 of a log call
  (`0x226aad8`, template `0x1ef6dd`);
- then frees a buffer and reaches `0x226ab0a`.

The template decodes to
`{} WARN >>> {} @@ queried gossip status @@ [local_height: {}] @ [initial_height: {}] @ [latest_height: {}]`.
Its placeholders 2, 3 and 4 are labelled `local_height`, `initial_height`
and `latest_height`.

A scan of the whole FDE for `[rsp+disp32]` operands with these three
displacements finds only the three stores, the three LEAs and the gate's four
reads. No other instruction names these slots. Aliasing through a different
base register is not excluded.

### Height gate in `0x22689f0` (observation)

Window `0x226ab0a..0x226ab88`, with `x = [rsp+0xd8]`:

1. If `x >= 0xffffffffffffb1e0`, then `y = u64::MAX`; otherwise
   `y = x + 0x4e20` (20000). Both arms use the same constant: `add` at
   `0x226ab1d`, `lea` at `0x226ab52`.
2. If `y <= [rsp+0xd0]`, the message is `local height is too far behind` (30
   bytes, `0x3d79b2`, selected at `0x226ab49`).
3. Otherwise, if `x < [rsp+0xc8]`, the message is
   `local height is from stale hardfork` (35 bytes, `0x3d798f`, selected at
   `0x226ab81`).
4. Otherwise control goes to `0x226adb1`.

With the status-log labels above (placeholder *k* read as argument *k*), the
rule is: too far behind iff
`local_height.saturating_add(20000) <= latest_height`; otherwise stale
hardfork iff `local_height < initial_height`.

### Logged tolerance in `0x22689f0` (observation)

- **540.0:** `0x226900c` loads 540.0 (`.rodata` `0x20a3d8`). It then branches
  to the join `0x2269164` if `[rbx+0xc18] != 1` (`0x226901b`) or
  `[rbx+0xc20] != rax` (`0x226902e`). `[rbx+0xc20] < rax` goes to
  `0x2269760`, which LEAs `assertion failed: freeze_height >= self.…`.
- **840.0:** `0x226915c` loads 840.0 (`0x20a230`) and falls into the join,
  which stores `xmm0` to `[rsp+0xe0]` at `0x2269168`. The
  `applying hardfork to frozen local abci_state` log call (`0x226911b`,
  template `0x1ed136`) precedes it.
- **Only two branches into the join:** a scan of every `jcc`/`jmp` rel8 and
  rel32 in the FDE finds exactly these two branches into `0x2269164`.
- **Only two `[rsp+0xe0]` operands:** the store at `0x2269168` and a LEA at
  `0x226928a`. That LEA's pointer goes to `[rsp+0x48]`, and `&[rsp+0x48]` is
  argument 2 of a five-argument log call (`0x2269333`, template `0x1f5428`).
- **Argument 2 is the tolerance:** in that template, placeholder 2 sits
  between `… @@ initializing with local abci_state @@ [tolerance: ` and
  `] @ [pre_fork_context: `.

Inference: the logged tolerance is 840 on the frozen-state hardfork path and
540 otherwise. Indirect branches are not resolved, so a jump-table entry into
`0x2269164` is not excluded.

### What the tolerance decides: local state or peer heights (observation)

The join continues into window `0x2269171..0x22691fd` with `rax = &[rbx+0x60]`:

1. **Tolerance stays in `xmm0`:** the 540 path goes from its load straight to
   the join through a `cmp` and a `jne`. From the join to the call at
   `0x2269199`, the only `xmm0` instruction is the store `movsd [rsp+0xe0],xmm0`.
   The other instructions are integer moves and LEAs.
2. **Add:** the 12 bytes at `[rbx+0x60]` are copied to `[rsp+0x120]`. Slot
   `0x576efb8` (RELATIVE to `0x1459ca0`) is called with
   `rdi = &[rsp+0x3c10]` and `rsi = &[rsp+0x120]`.
3. **`0x1459ca0` (whole FDE `0x1459ca0..0x1459df7`):** it multiplies `xmm0`
   by 1e9 (`.rodata` `0x20a220`). It then clamps the product to
   `[-2^63, 2^63]` and truncates it to i64, so NaN becomes 0 and values above
   9.223372036854775e18 become `i64::MAX`. The i64 is floor-divided into
   seconds and nanoseconds: `imul` by `0x112e0be826d694b3`, `sar 26`, then a
   sign fix-up. It then calls the same two slots as the 600 s freshness add,
   `0x576e8a8` with `rsi` pointing at bytes 4..12 of the copy, and `0x576e8b0`.
   On overflow it panics with the 38-byte ``NaiveDateTime + TimeDelta` overflowed``.
4. **Compare with now:** slot `0x576e8a0`, the same clock slot as the
   freshness check, fills `[rsp+0x120..0x12c]`. The sum `(r12d, r14d, ebp)`
   is compared with it lexicographically: `setge` on the first field,
   `setae` on the second, `jb` on the third. If the sum is not less than now,
   control goes to `0x22691fd` (`0x22691cf`/`0x22691e0` → `0x22693b1`, then
   `jne` → `0x22691fd`). If it is less, control goes to `0x22693c3`
   (`0x22691f7`, or the fall-through at `0x22693bd`).
5. **Not older than the tolerance:** from `0x22691fd` the path reaches the
   `initializing with local abci_state @@ [tolerance: {}]` log at `0x2269333`.
   It may detour once through `0x226977e`, a call through slot `0x576e8b8`
   with `esi = 1` that jumps back to `0x2269279`. After the log it copies
   0x3ae8 bytes from `[rsp+0x18]` to the stack, allocates 0x3ae8 bytes
   (`je 0x22697d3` on failure), copies them into the allocation, clears
   `[rbx+0x49f0]` and jumps to `0x226ad84` (`0x22693ac`).
6. **Older:** `0x22693c3` sets `r14 = &[rbx+0x3b70]` and chooses root or
   validator node IPs (next section). It copies the chosen 24-byte Vec
   from `[rsp+0x7700..0x7718]` to `[r14]` (`0x22696e2..0x22696f7`). It then
   stores `[rbx+0x3b88] = r14` (`0x22696fc`), clears `[rbx+0x49e8]` and jumps
   to `0x2268b7f` (`0x2269719`).
7. **Peer list is that Vec:** with `r14` unchanged, `0x2268b7f` stores
   `[rbx+0x3b90] = r14` and `[rbx+0x3b98] = &[rbx+0x3b90]`. Those are the
   first word of the AsyncSleepRetry record, and the record's descriptor is
   `gossip rpc height` (`0x3d7953`, 17 bytes). `rcx = &[rbx+0x3b98]` reaches
   `0x2268c63` through `jmp 0x2268c1c` (`0x2268bed`) and is stored to
   `[rbx+0x3c30]`. The peer loop reads `[[rbx+0x3c30]]` into `[rbx+0x49c8]`
   (`0x2269c63`). So `[[rbx+0x49c8]]` is `&[rbx+0x3b70]`, and the loop's
   `[+0x8]`/`[+0x10]` are the chosen Vec's data pointer and length. A census
   of every `[rbx+disp32]` ModRM in the FDE finds these displacements only at
   the sites listed in `records.json` (`stale_gate.record_refs`), so no
   other `rbx`-relative instruction stores them. Writes through other base
   registers are not excluded.

Model: `tolerance_nanos` and `nanos_split` give `(540, 0)` and `(840, 0)`.
`nanos_split` equals Python `divmod(n, 10**9)` on 2009 values, including
both i64 extremes. `uses_local_state` is the negation of the strict
lexicographic `<`.

Inference: the tolerance is in seconds. The local abci_state is used as is
(boxed and returned) iff `state_time + tolerance >= now`. Otherwise the node
asks the root or validator node IPs for heights and applies the height gate. Equivalently, the local
state is used directly iff it is at most 540 s old, or 840 s on the
frozen-state hardfork path. ### Which state and which peers (observation)

- **The state:** window `0x2268f3f..0x2268fa4` sets `rdi = &[rbx+0x88]`,
  stores it to `[rsp+0x18]` and calls slot `0x5773aa8` (`0x3751e80`). The
  arguments are the 0x1fc8-byte linked result at `[rsp+0x120]`,
  `&[rsp+0x7700]` and `&[rsp+0xf0]`. It then sets `[rbx+0x49f0] = 1` and,
  straight-line, copies `[rbx+0xe8]` to `[rbx+0x60]` (8 bytes) and
  `[rbx+0xf0]` to `[rbx+0x68]` (4 bytes). So the 12 bytes the gate adds the
  tolerance to are bytes `+0x60..+0x6c` of the object at `[rbx+0x88]`. The
  same `+0x60` is the date-time offset of the 600 s check (`[r15+0x60]`).
  `[rsp+0x18]` is not written again before `0x226926e` loads it into `r14`,
  the source of the fresh path's 0x3ae8-byte copy. That write census comes
  from the objdump listing, not from the tool. So the boxed state is
  `[rbx+0x88]`.
- **Selector:** `r13` is set by `mov r13,r15` at `0x2268f80`. The state-0
  arm loads `r15 = [rbx+0x80]` (`0x2268a5a`). In the objdump listing of
  `0x22689f0..0x2268f80`, the only other `r15` write is `0x2268e9a`, on
  the retries-exhausted path that jumps to `0x226a945` (`0x2268ea7`). No
  `r13` write lies between `0x2268f80` and the `test r13,r13` at
  `0x22693ca`.
- **Root (`r13 != 0`):** the code calls slot `0x5773ac0` (`0x4742cc0`) on `r13`.
  That function does a `lock cmpxchg` add of 0x10 on `[rdi+8]` and has a
  contended slow path. It then calls slot `0x5773ac8` (`0x4779e30`) and
  clones the Vec at the returned pointer `+0x10` with `0x254e7b0` into
  `[rsp+0x7700]`. `0x254e7b0` allocates `len * 5` bytes with alignment 1
  (`lea r14,[r12+r12*4]`) and `memcpy`s, so it is a 5-byte-element Vec
  clone. A `lock xadd -0x10` on `[r13]` follows, with a wake path to
  `0x22697e8`. The code then logs
  `… @@ using root node ips @@ [root_node_ips: {}]` (template `0x1fc1a0`)
  with argument 3 `&[rsp+0x8] = &[rsp+0x7700]`, the clone, and jumps to
  the shared tail `0x22696c8`.
- **Validator (`r13 == 0`, `je 0x22695db`):** the code calls slot `0x5773ad0`
  (`0x3994ea0`) with `rdi = &[rsp+0x7700]`, `rsi = &[rbx+0x980]` and
  `edx = [rbx+0x97a]` (a byte). Both offsets lie inside the 0x3ae8-byte
  object at `[rbx+0x88]` (`+0x8f8`, `+0x8f2`). It then logs
  `… @@ using validator node ips` (template `0x1e65d2`, no value argument)
  and falls into the tail.
- **`0x3994ea0` (whole FDE):** it calls slot `0x57732e8` (`0x33de620`) with
  `edi =` the byte. `0x33de620` jumps through `0x58a6b4` on that byte:
  - Arms 1, 2 and 3 return the lazily initialised statics `0x57861d8`,
    `0x57861f8` and `0x5786218`.
  - Arm 0 panics with the 13-byte `invalid chain` (`esi = 0x1b`, read as
    13·2+1). Its Location is `l1/src/chain_ext.rs:116:29`.

  From the returned object, `[+0]` (tested for zero) and `[+8..+0x18]`, it
  builds a two-ended iterator state and places `&[rbx+0x980]` after it. It
  then calls `0x3bacce0` to fill `rdi`. The same slot is
  called with the boxed state's byte `+0x8f2` on the `fresh` path of
  `0x22b47c0` (`0x22b4b5b`).
- **`0x3bacce0` (whole FDE):** a `filter_map(..).collect()` into a Vec of
  5-byte elements.
  - The set side: the returned static is a B-tree set (root `[+0]`, height
    `[+8]`, length `[+0x10]`, copied to iterator `+0x40`). Its nodes hold u16
    `len` at `+0xe6` and 20-byte keys from `+8`. The first element comes
    from `0x330f150`, which counts down iterator `+0x40`; the rest is the
    same walk inlined.
  - The lookup side: for each key it searches the B-tree map at
    `[iterator+0x48]+0x150` (root; height at `+0x158`), that is
    `(&state+0x8f8)+0x150`. The map nodes hold 0x58-byte values from `+8`,
    20-byte keys from `+0x3d0`, u16 `len` at `+0x4ae` and edges at `+0x4b0`.
    Keys are compared with `memcmp(…, 0x14)` (slot `0x576e488`, a GLOB_DAT
    of the dynamic symbol `memcmp`), so the order is bytewise.
  - The filter: on a hit it reads the tag byte at value `+0x4c` and four bytes
    at `+0x4d`. A miss or tag 2 skips the key. Otherwise it pushes
    `{tag, 4 bytes}` (5 bytes). The first push allocates 0x14 bytes
    (capacity 4); later pushes grow via `0x32d6a00` with element size 5.
    No element returns `{cap 0, ptr 1, len 0}`.
- **Tail:** both paths copy `[rsp+0x7700..0x7718]` to `[rbx+0x3b70]`, the
  peer list above.

Observation: which path runs is fixed by the caller, through future field
`+0x80` (`r15 = [rbx+0x80]` at `0x2268a5a`, `r13 = r15` at `0x2268f80`):

- `0x227a0e0` builds the future at `&[rbx+0x60]`. Straight before the call
  it stores `[rbx+0xe0] = [rbx+0x50] + 0x10`, where `[rbx+0x50]` is the Ok
  payload (niche `2^63 + 0x40`) of slot `0x5773b80` → `0x4741dc0`. That
  loader references `Last load of FileModTimeTracker failed: ` and panics
  with the 54-byte `assertion failed: !res.read().root_node_ips.is_empty()`
  at `node/src/gossip_config.rs:90:13`. So this caller always takes the root
  path, with the gossip config's root node IPs.
- `0x22b47c0` builds the future at `&[rbx+0x3b28]` and, on the straight line
  into the call, stores `0` at `[rbx+0x3ba8]` (future `+0x80`, `0x22b48ed`).
  So this caller (the lead's `async_touch_state_poll`) always takes the
  validator path.

Inference: future `+0x80` is an `Option<&RwLock<GossipConfig>>` (the `+0x10`
is past an `Arc` header), and the lead's `EmptyRootNodeIps` assertion text is
this one. The lead uses `root_node_ips` on every startup; the binary uses them
only from `0x227a0e0`. No concatenation with a second list
(such as reserved peers) occurs on either path inside the checked windows.
Inference: byte `+0x8f2` of the state is a chain id (the lead's
`HlChain`: 0 local, 1 sandbox, 2 testnet, 3 mainnet). The only accessor in the
lead's `chain_ext.rs` that panics `invalid chain` for chain 0 is
`foundation_self_signer_addresses` (a per-chain `BTreeSet`). So validator node
IPs are the foundation self-signer addresses, in byte order, that have an entry
in a state map keyed by address whose value carries a set 5-byte node IP at
`+0x4c`. The 5-byte element matches the root-node-IP clone, and tag 2 reads
as `None` of an `Option` around a two-variant, IPv4-sized node IP. Neither lead
`NodeIp` (`{Localhost, Ip(IpAddr)}` in `gossip_config.rs`, `NodeIp(IpAddr)`
in `hl_node.rs`) would fit in 5 bytes. Which
state map this is (validator profiles, by the `node_ip` schema string the lead
cites) is not proven. The lead's startup has no such source: it only uses
`root_node_ips` and reserved peers.

### What the future returns (observation)

The entry stores `rdi` to `[rsp+0xb8]` and sets `r12 = 0x8000000000000000`.
The return block at `0x226ad84` writes three words
`{r12, r14, r12}` to `[[rsp+0xb8]]`, sets `[rbx+0x49f1] = 1` and returns.
A scan of every rel8/rel32 `jcc`/`jmp` in the FDE finds exactly two
branches into it, `0x2268dd2` and `0x22693ac`; the stale path falls into it.
`0x226ad80` is also entered from `0x226ad6b` and `0x226af31`, and `0x226ad6d`
from `0x226af2b`, both on the gate-pass path. Indirect edges are not
resolved. A pending poll writes `r12 + 3` and sets the state
byte to 3 (`0x226a8bc..0x226a912`).

| Path | Word 0 | Words 1–2 |
| --- | --- | --- |
| No usable file | `0x8000000000000002` | — |
| Not older than the tolerance | `0x8000000000000000` | box of the 0x3ae8-byte state |
| Height gate passes | `0x8000000000000000` | box of the 0x3ae8-byte state |
| Height gate rejects | Vec capacity (= length) | pointer, length |
| Pending | `r12 + 3` | — |

- **File:** state 0 formats `{}/hyperliquid_data/{}.{}` (template
  `0x1f2309`) with `abci_state` (`0x569db40`, a RELATIVE `&str` of length 10)
  and `rmp` (3 bytes). It then calls slot `0x576e9e8` (`0x144a710`), which
  tests `(st_mode & 0xf000) == 0x8000`, i.e. `is_file`. If it is not a file,
  control goes to `0x2268db2`. A read result `[rsp+0x120] == 2` drops the
  error and also goes there. A decode result whose first word is
  `0x8000000000000000` falls into `0x2268da8`. All three paths add 2 to
  `r12 = 0x8000000000000000` and jump to the return block.
- **Gate pass (`0x226adb1`):** it copies the 0x3ae8 bytes at
  `rsi = &[rbx+0x88]` (set in the gate window) and logs
  `… @@ initializing with local abci_state` (template `0x1e97e3`, with no
  tolerance field). It then boxes the state, frees the peer Vec if its
  capacity is non-zero, and returns.
- **Gate reject (`0x226ab88`):** it copies the state to `[rsp+0x7700]` and stores
  the selected message `(rbp, r13)` to `[rsp+0x20..0x30]`. It then logs
  `… @@ considering local abci state as stale @@ [stale_reason: {}] @ [node_ips: {}]`
  (template `0x1f402c`). Argument 3 is `&[rsp+0xe8] = r12`, and
  `r12 = &[rsp+0x20]` from `0x226aab4`; in the objdump listing there is no
  other `r12` write before `0x226ac42`. Argument 4 is `&[rsp+0x48] = &[rbx+0x3b70]`.
  The path then clones `[rbx+0x3b80] * 5` bytes from `[rbx+0x3b78]`, drops
  the state copy (`0x225a3b0`), frees the original Vec and returns
  `{len, ptr, len}`.

Inference: the output is a three-variant enum whose niche lives in word 0.
The consumer below names the variants: `fresh` (`Box` of the state: fresh by
age, or height accepted), `stale` (the queried peer `Vec`: rejected by
height) and `missing` (no usable `abci_state.rmp`). Polls can also return
pending. The message chosen by the height gate is only logged as
`stale_reason`; it is not returned. `startup_outcome` models the word-0
decoding.

### Who consumes the outcome (observation)

A scan of every `e8`/`e9` in `.text` finds exactly two direct calls to
`0x22689f0`: `0x227a250` in `0x227a0e0` and `0x22b4919` in `0x22b47c0`.
Both first test word 0 against `0x8000000000000000 + 3` (pending).

- **Variant names (`0x227a0e0`):** the code computes
  `index = word0 ^ 2^63` if word 0 is negative, else 1 (`cmovs`). It
  indexes a length table (`0x3d8398`, 8-byte entries) and a relative-offset
  table (`0x3d83b0`, 4-byte entries). Entries 0, 1 and 2 decode to `fresh`,
  `stale` and `missing`. The name is logged as
  `… @@ using local AbciState: {}` (template `0x1fa1bc`). Then
  `word0 == 0x8000000000000000` (fresh) moves 0x3ae8 bytes out of the box,
  frees it (`esi = 0x3ae8`) and jumps to `0x227aac6`. The other variants go to
  `0x227a457`.
- **Dispatch (`0x22b47c0`):** the same index computation. Index 0 (fresh)
  goes to `0x22b4b48`, which reads byte `+0x8f2` of the boxed state and calls
  slot `0x57732e8`, the first call `0x3994ea0` also makes. Index 2 (missing)
  and index 1 (stale, `0x22b4b83`) both set `[rbx+0x3b1c] = 1` and jump to
  `0x22b5047`. That path logs
  `… @@ running non-validator to get initial abci state for consensus`
  (template `0x1f4129`), with an optional once-style detour (`0x22b50c6`
  to `0x22b5b2e`, back to `0x22b50cc`).

In `0x22b47c0`, a `fresh` local state skips the non-validator bootstrap and a
`stale` or `missing` state runs it. Words 1 and 2 are loaded into
`[rsp+0x28]` and `r13` (`0x22b4a9e`). Word 0 stays in `[rsp+0x8]` for
`stale`, and is replaced by `0x8000000000000000` for `missing` (`0x22b4ae8`).
No checked path produces `0x8000000000000001`.

### What `stale` and `missing` feed (observation)

- **Handoff (`0x22b512e..0x22b51b9`):** after the log, the bootstrap stores
  `[rsp+0x8]`, `rbp = [rsp+0x28]` and `r13` to `[rbx+0x3b28..0x3b40]`. It
  then calls `0x227a0e0` with `rsi = &[rbx+0x3b28]`. So for `stale` the
  first three words of that future are the stale peer `Vec`
  `{len, ptr, len}`, and for `missing` word 0 is `2^63`.
- **`0x227a0e0` entry (`0x227a12f..0x227a1ab`):** it copies future
  `[+0..+0x18]` to `[+0x18]` and then to `[rsp+0xb4b0]`. It calls slot
  `0x5773b80` (`0x4741dc0`) with `rdx = &[rsp+0xb4b0]` and `esi = [+0x4a60]`
  (only the low byte is used). Its only other direct caller, `0x226c860`,
  stores `2^63` to word 0 of its future first (`0x226c823`).
- **Loader (`0x4741dc0`):** `rbx = [rdx]` is negated, and `jno` goes to
  `0x4742194` unless word 0 is `2^63`.
  - **`Some(vec)`:** it copies the three words to `[rsp+0x138]` and skips
    the file. If the length `[rsp+0x148]` is zero it panics with the
    `root_node_ips` assertion below.
  - **`None`:** it builds the 27-byte `override_gossip_config.json` and tests
    it with `is_file` (`0x144a710`) as given, with no directory joined. If it
    is a file, the `FileModTimeTracker` path loads it and compares the
    file's chain byte `[rsp+0x172]` with the expected byte `[rsp+0xf]`
    (`0x47428f7`). A mismatch calls slot `0x5773b40` (`0x4b283dc`, an
    `assert_failed`-shaped thunk) with kind 0, `&expected`, `&file_chain`, no
    message and Location `node/src/gossip_config.rs:89:13`: an `assert_eq!`
    one line above the `root_node_ips` assertion (`:90:13`). Otherwise
    `0x474223b` jumps through `0x6f9ab4` on the low byte of `esi`.
  - **The jump table:** arms 0 and 3 share `0x474224f`, which returns the
    file name as an error (word 0 `2^63 + 0x3b`; the caller's Ok is
    `2^63 + 0x40`). Arm 1 allocates one 5-byte root (tag 0,
    `54.95.235.126`). Arm 2 allocates two (tag 0, `13.231.133.202` and
    `54.249.160.165`). Both store `{n, ptr, n}` to `[rsp+0x138]`, the same
    slot as `Some`. Table entries 4 and 5 land outside the FDE.

Since `0x22b47c0` always takes the validator path, a `stale` result here
carries the validator node IPs that were queried when the height gate
rejected the local state.
The next `0x227a0e0` run then uses those same IPs as its root node IPs, and
never reads `override_gossip_config.json`. Only `missing`, and the other
caller, fall back to the file or to the compiled roots.

### Freshness check in `0x2271d00`: panic at `hl_node.rs:346:9` (observation)

Window `0x2271d52..0x2271e8c`, with `r15 = [rbx+0x740]`:

1. **Message arguments:** the f64 600.0 is stored at `[rsp+0x138]`. The
   12-byte value at `[r15+0x60]` is copied to `[rsp+0x140]`. Those two
   addresses are the arguments of the panic template.
2. **Add 600:** the call through RELATIVE slot `0x576e8a8` (to `0x15206e0`)
   gets `rsi = &[rsp+0xc4]` (bytes 4..12 of the 12-byte copy), `edx = 600`
   (`0x258`) and `ecx = 0`.
3. **Day carry:** the returned carry `[rsp+0x18]` is range-checked and
   divided by 86400, truncating toward zero. The sequence is `imul` by
   `0x1845c8a0ce512957`, then `(rdx >> 63) + (rdx >> 13)` in 32 bits; the
   model is checked on 2010 values.
4. **Add days:** the days and the 4-byte head of the copy go to slot
   `0x576e8b0` (`0x151f870`). A zero result branches away to `0x227236d`.
5. **Clock read:** slot `0x576e8a0` (`0x151cba0`) fills `[rsp+0x10..0x1c]`.
6. **Compare:** the tuple `(ebp, r12d, r14d)` is compared with
   `([rsp+0x10], [rsp+0x14], [rsp+0x18])` lexicographically: signed
   `setge` on the first field, unsigned `setae`/`jae` on the others. If the
   first tuple is less, control goes to `0x2271e38`.
7. **Panic:** `0x2271e38` calls slot `0x576e098` (`0x157b810`) with template
   `0x1ed194` and Location `0x569e948`. The template is
   `use an abci state within {} seconds to ensure node_ips are up to date. abci_state_time={}`,
   with two placeholders. The Location is
   `/home/ubuntu/hl/code_Mainnet/node/src/hl_node.rs`, line 346, column 9.
   The next instruction jumps to `ud2` at `0x227283d`.
8. **Panic shim:** `0x157b810`'s FDE ends exactly at its call through slot
   `0x57706e0` (to `0x4ecdcf0`), and the call is preceded by a
   `can_unwind`-style word store of 1. Its shape matches a `panic_fmt` shim.

Inference: the 12 bytes are a date-time {date, seconds of day, fraction}. The
check panics iff `abci_state_time + 600 s < now`, and the same 600 is printed
as the f64 `600.0` in the message.

### Where the freshness check runs (observation)

- **Dispatch:** `0x2271d00` dispatches on the byte `[rdi+0x756]` through the
  table at `0x3d5f10`. Entry 0 is `0x2271d38`, which runs straight-line into
  the freshness window.
- **Strings:** the same FDE LEAs `check_reachability_firewall_ips`
  (`0x2271f1e`) and `failed to load firewall ips` (`0x22722c1`).
- **Callers:** a scan of every `e8`/`e9` in `.text` finds exactly two direct
  calls to `0x2271d00`, both in `0x22ae8a0`, at `0x22aef61` and `0x22affe7`.
  The lead calls `0x22ae8a0` the hl-node startup orchestrator. After each
  call, a set `al` leads to `mov cl,0xa` or `mov cl,0xb` and a jump to
  `0x22b02dd`.
- **Second call site:** the second call follows a log call whose template
  (LEA at `0x22aff7c`, outside the checked windows and not checked by the tool)
  reads `@@ checking reachability first before changing validator ip from {} to {}`.

Inference: following rustc's async layout, state 0 is the first poll. So the
600 s freshness panic is the first step of the future the lead names
`poll_check_reachability_firewall_ips`. The orchestrator polls it from two
states, 0xa and 0xb, and treats a set `al` as pending.

## Comparison with the lead

- **Height quorum:** `startup.rs` `select_height_quorum` keeps fresh
  statuses, errors if fewer than `MIN_VALID_RPC_HEIGHTS = 2`, sorts by
  `latest_height` and takes the median `fresh[len / 2]`. The binary takes the
  lexicographic maximum of `(initial_height, latest_height)` over all map
  entries. It accepts a single entry when exactly one peer was queried. Its
  error path retries through `AsyncSleepRetry` instead of returning. For
  example, entries `(1, 100), (2, 3), (1, 200)` give the median `(1, 100)` in
  the lead's model but `(2, 3)` in the binary.
- **Height collection:** the lead's `query_root_heights` returns an error from
  the whole startup on any RPC error. It records a `None` reply as Missing and
  classifies a status as Stale when `latest_height + MAX_LOCAL_HEIGHT_LAG <
  local_height`. The binary logs `unable to query height` and skips the peer
  on an error or a wrong reply variant. It logs `no heights from node` and
  skips the peer on an empty reply. It does not read the local height in the
  loop, so it has no stale filter there.
- **0x4e20:** `NODE_IP_FRESHNESS_TOLERANCE = Duration::from_secs(0x4e20)`
  cites "`add 0x4e20` in the stale-time branch at `0x226ab1d`". That `add` is
  the height gate above: its saturating sum is compared with `[rsp+0xd0]` and
  selects `local height is too far behind`. No time value is involved in that
  window.
- **Freshness check:** the lead's `StateFileTooOld` (age > 0x4e20 s,
  returned as a stale reason) does not match the binary. In the binary the
  `use an abci state within … seconds` message belongs to a 600 s check that
  panics at `hl_node.rs:346:9`, at the start of the future the lead itself
  names `poll_check_reachability_firewall_ips` (in `hl_node.rs`). The lead
  places the message in `local_abci_state.rs`.
- **Height lag:** `MAX_LOCAL_HEIGHT_LAG` is 200 in `local_abci_state.rs` and
  1_000 in `startup.rs`; the binary uses 20000. `startup.rs:500` tests
  `target - local > LAG`. The binary rejects at
  `local_height.saturating_add(20000) <= latest_height`, which includes
  equality: for example, local 0 and latest 20000 is "too far behind".
  The binary logs the compared value as `latest_height`; the lead calls it
  `target_height`.
- **Local-state age:** the lead has no 540/840 s gate. Its only age check is
  `StateFileTooOld` at 0x4e20 s, which returns a stale reason. In the binary,
  the logged tolerance decides whether the local state is used without
  querying peers at all: 540 s, or 840 s after the hardfork branch.
- **Who is queried:** the lead's `query_root_heights` iterates
  `connect_candidates`, which is root plus reserved peer IPs. The binary
  queries one cloned 5-byte-entry list: the root node IPs if `[rbx+0x80]`
  is set (`using root node ips`), otherwise a list derived from the local
  state (`using validator node ips`). The lead has no validator-node-IP
  source.
- **Gossip override:** the lead's `gossip_config.rs` types `0x4741DC0` as
  `(out, uint8 expected_chain, const void *data_dir_path)` and joins the
  file name to the data directory. It has the same fallback roots, and the
  same Local/Mainnet error. In the binary the third argument is an optional
  root list, which replaces the file entirely when present. The file name is
  tested as the bare relative `override_gossip_config.json`. The lead returns
  `UnsupportedChain` and `EmptyRootNodeIps` errors; the binary panics on both
  (`assert_eq!` at `gossip_config.rs:89:13`, `assert!` at `:90:13`).
- **Outcome:** the lead's `run_startup` either keeps a linked state when
  `is_linked_state_usable` holds (non-zero height, non-empty node_ips, and
  overlap with the configured IPs, with no time check), or refreshes and
  bootstraps from gossip itself. The binary future decides by age first,
  then by the height gate. It returns the boxed local state, the queried
  peer list (with the reason only logged), or `None` when
  `/hyperliquid_data/abci_state.rmp` is not a readable, decodable file.
  These are the binary's own `fresh` / `stale` / `missing` names.
- **`0x22B47C0`:** the lead's `base/production.rs` names it
  `base_production__async_touch_state_poll` from its `async_touch` spans.
  It is also a direct caller of this local abci_state future, and on
  `stale` or `missing` it logs `running non-validator to get initial abci
  state for consensus`. The lead places that message in
  `startup.rs::run_non_validator_for_initial_state`.
- **Stale hardfork:** the lead's stale-hardfork reason compares the local
  height with a peer initial height. That matches the operand order here
  (`local_height < initial_height`, tested only when not too far behind).

## Controls

`tests/test_local_abci_gates_static.py` (73 tests) regenerates
`records.json` and checks eleven models: the gossip root source, the validator node-IP filter, the peer-reply collection, the height selection, the height gate
including saturation, the day division against exact truncating division,
the lexicographic compare, the tolerance-to-nanoseconds conversion, the
nanosecond floor split against `divmod`, the local-state gate, and the
output word-0 decoding. It refuses each of these corruptions:

- The gate constant changed to 200.
- Either message's first byte changed.
- The 540.0 or 840.0 constant changed.
- An extra `je` into the join planted.
- An extra `[rsp+0xe0]` operand planted.
- The log template literal changed.
- The added seconds changed to 0x4e20.
- The Location file changed.
- The panic slot's RELATIVE addend redirected.
- The freshness template text changed.
- An extra direct call to `0x2271d00` planted.
- A status-log argument pointer swapped.
- A status-log field label broken.
- An extra height-slot operand planted.
- Dispatch-table entry 0 moved.
- The selection loop's `seta` changed to `setb`.
- A byte of the 43-byte heights error changed.
- The `AsyncSleepRetry::retry` or `got heights` template changed.
- A byte of `incorrect rpc response variant` changed.
- The `no heights from node` template changed.
- A `[rbx+0xb0]` operand planted in the peer loop.
- The request tag changed to 3.
- The stale gate's `jb` changed to `jae`.
- The 1e9 scale changed to 1e6.
- A byte of the `NaiveDateTime + TimeDelta` overflow text changed.
- The `0x576efb8` RELATIVE addend redirected.
- An extra `[rbx+0x3b90]` store planted.
- The root-node-ips template text changed.
- The validator slot's RELATIVE addend redirected.
- The `abci_state` file stem, the stale-log template or the `is_file` mode
  test changed.
- An extra branch into the return block planted.
- A variant-name byte changed.
- An extra direct call to `0x22689f0` planted.
- The `invalid chain` text changed.
- The map value stride (0x58) or the skipped tag (2) changed.
- Caller B's `[rbx+0x3ba8] = 0` store changed, or the gossip loader slot's
  RELATIVE addend redirected.
- The loader's `jno` flipped, a default root byte changed, the override
  file name changed, or the chain assertion's Location moved.

The module passes with GNU binutils or with LLVM tools only on `PATH`; the
producer does not use either.

## Related open packets

None of these is imported or relied on here; they are cited so overlapping
claims can be compared.

- [#352](https://github.com/lalalune/hyperliquid-source/pull/352) pins the
  same saturating `min(A + 20000, u64::MAX) <= B` and `A < C` reason
  comparisons in `0x22689f0`, without naming the operands.
- [#363](https://github.com/lalalune/hyperliquid-source/pull/363) and
  [#408](https://github.com/lalalune/hyperliquid-source/pull/408) follow slot
  `0x5773aa8` → `0x3751e80` and its argument setup at `0x2268f61`, the call
  that builds the state at `[rbx+0x88]` here.
- [#459](https://github.com/lalalune/hyperliquid-source/pull/459) binds
  `0x15206e0` and `0x151f870` to chrono Locations (time shift with day carry,
  date day shift), which matches their use in the 600 s check.

## Unresolved

- What `0x226bb20` sends for request tag 2 and how it decodes the reply.
- The exact path from `0x2269034` to `0x226915c`, and any jump-table edge into
  the join.
- What the `FileModTimeTracker` path of `0x4741dc0` validates, and what
  the rest of `0x227a0e0` does with the config. Which state map
  `(&state+0x8f8)+0x150` is and what its tag values 0 and 1 mean, and which
  fields of the `0x3751e80` result (see #363) hold the state time.
- What `[rbx+0x740]+0x60` holds, and which orchestrator paths reach states
  0xa and 0xb.
- The identities of `0x15206e0`, `0x151f870` (see #459), `0x151cba0` and
  `0x4ecdcf0` (inferred above, not proven here).
