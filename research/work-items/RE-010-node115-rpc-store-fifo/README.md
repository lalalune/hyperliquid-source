# Node #115 RPC store replacement and FIFO eviction

Backlog HL115-076. Target SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Original ELF virtual addresses; static inspection only, no captured execution or
emulation. This closes a logical successful-mutation contract, not the RPC service.

## Prior work and useful gap

PR #2568 maps transaction/block store ownership, descriptor initialization and
wrappers. PR #2523 covers read-side materialization. Neither establishes whether
updates refresh the retention queue or what the 100000 bound measures. This packet
follows both store mutations and their full-key lookup/removal handoffs. It reuses
those owner bindings rather than presenting another discovery of the RPC objects.

| Family | Lock wrapper | Mutation | Entry | Removal |
| --- | --- | --- | --- | --- |
| Transaction | 0x4fbbdc0 | 0x57e69b0 | 0x4dccbc0 | 0x4ddd570 |
| Block | 0x4fbb300 | 0x57e6d40 | 0x4dcae10 | 0x4ddf0e0 |

The wrapper copies all 32 key bytes and passes the descriptor at lock+8. Entry and
removal use the same exact 32-byte identity: flat searches `0x57f5ee0/0x57fb730`
and tree search loops compare through imported `memcmp` with length32. No numeric
endianness reinterpretation or truncated hash identity is introduced in the source.

## Observed mutation order

Both descriptors contain a 32-byte-key ring at +0..+0x20, a keyed value map at
+0x20, and a limit qword at +0x40. The credited constructor `0x4faf560` initializes
both limit fields to 100000 (`0x4faf5ae`, `0x4faf68b`). This packet authenticates
those descriptor inputs; the prior packet owns the surrounding lock construction.

* An occupied entry replaces its value. Transaction replacement swaps an owned
  pointer and decrements the old reference; the zero-count destructor is the bound
  `0x64e4cb8 -> 0x5a8e7c0`. Block replacement copies the whole 0x178-byte value and
  then releases the old owned fields. Both go directly to the limit check, bypassing
  ring append. The key keeps its first insertion position.
* A vacant entry inserts into the map, grows the key ring if full, and appends the
  supplied 32-byte key at `(head + length) mod capacity`. It increments queue length
  once. Growth boundaries are `0x64e5f48 -> 0x57fed30` and
  `0x64ebce0 -> 0x5800210`.
* While queue length exceeds +0x40, pop its front, advance/wrap head, decrement
  queue length, remove that exact key from the map, and release the removed payload
  when present. A missing map removal does not undo the queue pop. Both occupied
  and vacant continuations contain this drain check.

Thus, for valid state reached from an empty descriptor through these successful
mutations, the bound is on distinct retained keys and eviction is first-insertion
FIFO. It is inclusive: exactly 100000 keys remain; the next new key evicts the
oldest one. Replacing the oldest value does not protect it from that eviction.
After eviction, reinserting the key gives it a new queue position. This is a
mutation contract, not evidence about every read endpoint or concurrent operation.

## Map/helper boundary

The packet includes complete entry, flat-search and removal FDEs, and both
32-byte tree removal searches (`0x51d94e0/0x51d6cd0`). It binds occupied/vacant
results, equality branches, map value offsets, calls, ring updates and cleanup
handoffs. Native tree balancing/conversion/insertion, ring growth, allocator and
payload destructor internals remain explicit successful-helper prerequisites.
Physical collection equivalence and panic/unwind behavior are not claimed.

`src/node115-rpc-store-fifo` performs real owned map replacement/insertion and
queue eviction. Generic payloads remain opaque; the two native payload layouts
share this logical key/queue policy. Standard map/queue implementations substitute
storage representation, not an invented helper result. The source can consume
valid state from empty without a supplied occupied/vacant stub. Its public state
inspection methods are for reconstruction/testing, not native RPC endpoints.

## Validation

```
python3 research/work-items/RE-010-node115-rpc-store-fifo/verify.py --target artifacts/node/115/hl-node
cargo +1.95.0 test --manifest-path src/node115-rpc-store-fifo/Cargo.toml
cargo +1.95.0 test --release --manifest-path src/node115-rpc-store-fifo/Cargo.toml
cargo +1.95.0 fmt --check --manifest-path src/node115-rpc-store-fifo/Cargo.toml
cargo +1.95.0 clippy --manifest-path src/node115-rpc-store-fifo/Cargo.toml --all-targets -- -D warnings
```

Six tests pass in debug and release, plus formatting/Clippy. A birth-timestamp
oracle, without a retention queue, checks 17408 sequential states over limits0..16.
The tests distinguish keys that differ only at the tail, repeated occupied updates,
eviction/reinsertion, zero limit, owned payload replacement/drop, and the actual
100000-key boundary. Payload-drop checks verify owned source lifecycle, not
native destructor equivalence. The native helper returns no trace and the source
insert likewise consumes/drops replaced values.

`verification.json` records static denominator and corruption counts. The verifier
requires Python and Capstone5.0.7, authenticates the original digest and FDEs, and
checks semantic mutations after bypassing only whole-file/window hash guards for
the already authenticated original. Controls cover both occupied branches,
inclusive limits, full key comparisons, queue length/front/append fields, copies,
initial limits and helper edges. Repository checks are reported in the PR.

All component gates remain false. No changes to imports or full-scope claims.
New source/evidence independently authored under MIT; no unlicensed inferred code.
