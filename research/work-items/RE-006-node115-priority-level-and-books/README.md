# RE-006: Node #115 Sub-Level Priority Queue Splicing, In-Place `modify_order_sz` Diffs, and `Books` Strides

- **Target binary**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`)
- **Target SHA-256**: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Component**: `orderbook` (`l1/src/book/book/impl_insert_order.rs`, `l1/src/book/book_orders.rs`, `l1/src/book/level.rs`, `l1/src/slab/slab.rs`, `l1/src/books.rs`)
- **Implementation**: `src/node115-orderbook/src/priority_level.rs`

## Scope and Method

This packet binds 7 complete node #115 `.text` FDEs (`3,876 B` total) plus the `0x4dce580` BTreeMap range comparator window and 14 `.data.rel.ro` relocated panic `Location` records directly to `artifacts/node/115/hl-node`, and implements the recovered sub-level priority queue splicing and in-place size-modification semantics in `src/node115-orderbook/src/priority_level.rs`.

## Directly Observed Binary Evidence

### 1. Sub-Level Priority Queue Insertion (`0x5911890..0x5911b27`, 663 B) & Comparator (`0x4dce580`)
- **`0x591192e`**: Branches on `dword ptr [order + 0xd8] == 1` (`priority: Option<u32>` discriminant; payload `u32` at `+0xdc`).
- **Non-priority path (`0x5911998..0x59119f1`)**: Copies `0x110`-byte order record, calls `0x58df360` with `insert_before = None` (`push 0`), and initializes `level + 0x20` (`first_non_priority` cursor) to `Some(new_slot)` if previously `None`.
- **Priority path (`0x5911939..0x5911ad4`)**:
  - Queries `level.priority_orders` (`level + 0x50`) via `0x4dce580` with range `(Excluded((oid, prio)), Unbounded)` and takes `.next()` via `0x4e188f0`.
  - In `0x4dce580` (`0x4dce5c7..0x4dce629`), key comparison orders **`priority` descending** (`cmp upper.prio, lower.prio; seta`) and breaks ties by **`oid` ascending** (`cmp lower.oid, upper.oid; seta; cmove`).
  - Falls back to `level + 0x20` (`first_non_priority`) when no strictly-lower-priority / later-OID order exists, then calls `0x58df360` (`insert_before`) to splice the order into the doubly-linked level queue.
  - Inserts `(oid, prio) -> slot` into `level + 0x50` (`0x4dbe910`, panic `l1/src/book/book/impl_insert_order.rs:537:45` at `0x64b6558`) and appends a `32`-byte (`shl rax, 5`) ring record into `level + 0x30..0x48`.

### 2. Slab `insert_before` & `remove_unlink` (`0x58df360..0x58df78b`, 1,067 B; `0x58dfbc0..0x58dff1c`, 860 B)
- **`0x58df360`**: Uses `0x110`-byte (`272 B`) slab entries (`slab.rs:78:21` at `0x64b6630`), patches neighbour `prev`/`next` pointers (`book_orders.rs:81:40` / `89:40`), updates `book_total` (`qtys/mod.rs:831:1`), and pushes a `0x2b8`-byte (`696 B`) diff event into the diff `Vec`.
- **`0x58dfbc0`**: Advances `level + 0x20` (`cursor`) to `removed.next` when `cursor == Some(slot)`, removes from `level + 0x50` via `0x4de02d0` if `priority.is_some()`, saturating-subtracts `level.total_sz` (`+0x70`) and `level.order_count` (`+0x78`), unlinks neighbours (`book_orders.rs:137:44` / `145:44`), and checks `px >= 0` (`level.rs:32:54`).

### 3. In-Place Size Modification (`0x25da200..0x25da3d7`, 471 B; `0x5192060..0x519223f`, 479 B)
- Compares `new_sz` against `[order + 0xe0]` (`old_sz`); returns immediately if equal (`0x25da218`).
- Stores `new_sz`, pushes a `0x2c8`-byte (`712 B`) `tag = 2` diff event (`old_sz`, `new_sz`, `px`, `side`, `oid`, 20-byte `user`), updates both `book_total` and `level.total_sz` (`[level + 0x70]`) via `sat_sub(old_sz)` (`qtys/impl_sz.rs:9:1`) then `sat_add(new_sz)` (`qtys/mod.rs:831:1`), and enforces `px >= 0` (`level.rs:32:54`).

### 4. `Books` Container Strides (`0x22e7590..0x22e761a`, 138 B; `0x276e000..0x276e0c6`, 198 B)
- **`0x22e7590` (`l1/src/books.rs:19:47` at `0x6437540`)**: Indexes spot `Book` slice with `(idx + idx*8) << 5 = 288 B` (`0x120`) stride.
- **`0x276e000` (`l1/src/books.rs:14:16` at `0x6437528`, `perp_dex.rs:29:29` at `0x6483e08`)**: Splits `perp_asset` by `10_000`, indexes `PerpDex` with `pdi << 9 = 512 B` (`0x200`) stride, then indexes `PerpDex.books` with `288 B` (`0x120`) stride.

## Inferences and Open Scope

- Struct names (`PriorityLevelQueue`, `PriorityKey`, `LevelDiffEvent`) are logical reconstructions of the verified memory offsets and control flow; full binary serialization of the `0x2b8`/`0x2c8`-byte diff structs remains out of scope for this packet.
- This packet extends `orderbook` behavioral coverage and does not by itself claim the full `identity` gate.
