# RE-005 node115 timeout-cache registration cell: the lookup is the only path that can write it

## Question

The timeout-cache packets (#2953,
`RE-005-node115-timeout-cache-object-fields`, and #2964,
`RE-005-node115-timeout-cache-count148-owner`) pinned the
vendored tokio signal registry whose globals live in the
OnceCell at `0x64fee20`: a per-signal Vec of 0x20-byte entry
records — object pointer `+0x00`, pending byte `+0x08`,
registration cell `+0x10` (tag dword at `+0x10`,
registration-id dword at `+0x14`), embedded `std::sync::Once`
state word `+0x18`. #2964 pinned the cell's semantics for
the lookup path and left the edge open, in its words:
"Whether the vendored fork's lazy registration can write a
record's `+0x10` cell on paths other than the lookup's: the
cell semantics are pinned for the lookup path only."

Can the lazy registration write a record's `+0x10` cell on
any path other than the lookup's — and if so, by which call
path?

## Answer

No. For this registry (globals at `0x64fee20`) the cell can
be written only on the lookup path:

```
lookup 0x5cde710
  -> record_once_shim 0x5cdf535
  -> std once slow-path helper 0x5c87d50 (GOT 0x64df9f0)
  -> entry-init vtable 0x64c57a0
       +0x18: entry_init_direct  0x5cdf630
       +0x20: entry_init_closure 0x5cdf460
  -> reg_register 0x5cdbf20          (produces the tag/id pair)
  -> the cell stores in the entry-init body
       mov [rbx],ebp ; mov [rbx+4],r14d   (rbx = record+0x10)
```

Every link of that chain is unique, and the censuses below
close each alternative: the stores exist nowhere else, the
entry-init bodies are reachable through nothing but that
one vtable, the vtable is materialised by nothing but the
shim, the shim is called by nothing but the lookup, the
insert is called by nothing but the entry-init pair, and a
record pointer itself can only be obtained inside the
lookup/drain pair — of which the drain never stores to the
cell.

## Evidence

### 1. The cell stores exist only in the two entry-init bodies

Each entry-init body ends its registration with the same
store pair, with `rbx` holding the cell pointer it received
through the once-shim environment (the record base `+0x10`
the lookup passed in):

| body | insert call | tag store | id store |
|---|---|---|---|
| `entry_init_closure` `0x5cdf460` | `0x5cdf48c` | `0x5cdf4c6` `mov [rbx],ebp` | `0x5cdf4c8` `mov [rbx+4],r14d` |
| `entry_init_direct` `0x5cdf630` | `0x5cdf65c` | `0x5cdf696` `mov [rbx],ebp` | `0x5cdf698` `mov [rbx+4],r14d` |

A whole-`.text` scan for the pair's byte pattern
(`89 2b 44 89 73 04`) finds exactly three sites: the two
above and `0x5d08ac6`, inside an unrelated UTF-8 string
body (`0x5d08910`, 656 bytes) that decodes code points
(`0x110000` bound checks) and stores a four-dword result
pair into its caller's out-struct — it references no
registry global and calls no registry body. The idiom is
not unique; the binding is by reachability, below.

### 2. The entry-init bodies are reachable only through one vtable, materialised only by the shim

Neither entry-init body has a direct branch caller anywhere
in `.text` (whole-`.text` E8/E9 census). Their only data
references in the entire ELF are two `R_X86_64_RELATIVE`
addends — `0x64c57b8` (direct form) and `0x64c57c0`
(closure form) — which are the `+0x18`/`+0x20` method words
of a single closure vtable at `0x64c57a0` (remaining words:
`0`, `8`, `8`). A raw absolute-qword scan outside `.text`
finds exactly those two slots and nothing else.

A RIP-relative reference census over `.text` finds exactly
one materialisation of the vtable's address: the `lea` at
`0x5cdf566` inside `record_once_shim`, which passes the
vtable, the caller Location struct at `0x64c5788`
(`std/src/sync/once.rs:219`, col 20) and the record's Once
to std's once slow-path helper (GOT slot `0x64df9f0` →
body `0x5c87d50`). The helper invokes the closure through
the vtable (`call *0x20(%rax)` at `0x5c87e44`). No other
body loads the vtable.

The globals side is the exact twin: `once_globals`
`0x5cdf582` passes the globals-init vtable `0x64c5760`
(methods `0x5cdf6c0` direct / `0x5cdf4f0` closure, named by
the addends at `0x64c5778`/`0x64c5780`) to the same helper
slot, and that vtable is likewise materialised only by its
shim (`lea` at `0x5cdf5ab`).

### 3. The shim's only caller is the lookup

The whole-`.text` direct-branch census finds exactly one
call site to `record_once_shim`: `0x5cde869`, inside
`lookup`. The lookup computes the record from the Vec
globals (bounds `cmp` against `vec_len` at `0x5cde7bc`,
base load `vec_ptr` at `0x5cde7c5`, stride `0x20`), tests
the Once word at record `+0x18` (`0x5cde7d4`), and when it
is nonzero calls the shim with `rdi = record+0x10` — the
shim reads the Once word through `+0x8` of that base
(`0x5cdf535`) and, after the once completes, the lookup
re-reads the cell tag (`0x5cde7dc`) and, for tag 2, the id
(`0x5cde82f`). The shim has no relocation, RIP-relative or
raw-qword references anywhere.

### 4. The value source has no other callers either

The stored pair is produced by the vendored
signal-hook-registry insert `reg_register` `0x5cdbf20`.
Its only direct callers in `.text` are the two entry-init
bodies (`0x5cdf48c`, `0x5cdf65c`); it has no relocation,
RIP-relative or raw references — so no other path can even
obtain a fresh (tag, id) pair to store. `reg_register`
never receives a record pointer (its arguments are an
out-slot, the signal number and a context pointer); the
disp-`0x10`/`0x14` store census over its body finds only
stores to its own fresh Arc allocation (`0x5cdbf92`, the
globals pointer at that object's `+0x10`), its own table
nodes (`0x5cdc309`) and bucket bytes (`0x5cdc9b0`), and the
stack. After unpacking the pair, each entry-init body
drops the returned registration handle through the shared
drop glue `0x5cdf710` (calls at `0x5cdf4ba`/`0x5cdf68a`;
the glue is called from 16 bodies binary-wide, but in this
cluster only from the entry-init pair).

### 5. Record pointers are confined to the lookup and the drain

A record pointer can only be computed from the Vec globals
`0x64fee28`/`0x64fee30`. The RIP-relative census for those
globals finds exactly two referencing bodies: `lookup` and
the driver `drain` `0x5ce7380`. A store census (disp
`0x10`/`0x14`, all store families) over every body that
can hold a record pointer gives:

| body | disp-0x10/0x14 stores |
|---|---|
| `lookup` | `0x5cde739` — stack spill only |
| `drain` | `0x5ce7531` — stack spill only (its record access is the pending-byte `xchg` at `0x5ce7496` and reads) |
| `ctor_grower` `0x5cfe910` | `0x5cfe97a` stack; `0x5cfeaba` the globals out-struct — at construction it writes the record's `+0x00`/`+0x08`/`+0x18` fields (`0x5cfe9b0`/`0x5cfe9b3`/`0x5cfe9b8`) and never the cell |
| `vec_drop_glue`, `handle_drop_148` | none |
| `record_once_shim` | `0x5cdf54d` — its stack closure environment (`rax` = `rsp+0x18`), not a record |
| `entry_init_closure`, `entry_init_direct` | none at disp `0x10`/`0x14` — the cell stores are at disp 0/+4 from the cell pointer (§1) |
| `driver_init` `0x5ce71f0` | `0x5ce7238` stack; `0x5ce7289` its own caller out-struct — it never references the Vec globals |

### 6. The surrounding surface agrees

The lookup's only direct caller in `.text` is the park
slow-path `refresh` `0x5cee650` (#2947), so the lookup
path itself has a single entry. `once_globals` is called
from `lookup` (twice, at `0x5cde849`/`0x5cde8a3`), `drain`
(`0x5ce7564`) and `driver_init` (`0x5ce732a`) — all three
only ensure the globals exist; none writes a cell.
Neighbouring cluster bodies that also drop registration
handles (`0x5cdfa50`, `0x5cdfc90`, `0x5cdfe50`) reference
neither the Vec globals, `reg_register`, the shim nor the
vtable, so they cannot name a record of this registry.
`driver_init` reads the global signal fd at `0x64fee24`;
who produces that fd is a separate open edge owned by
another packet (#2952's follow-up) and is not addressed
here.

## Open gaps

- The censuses cover direct branches, RIP-relative
  materialisations, `.rela.dyn` addends and raw absolute
  qwords. A function pointer copied out of the vtable into
  a heap structure at runtime would leave no static trace;
  but the vtable is loaded only by the shim, so any such
  copy would still have to originate on the lookup path.
- The claim is scoped to the registry whose OnceCell is
  `0x64fee20` (the #2953/#2964 registry). Other subsystems
  in the binary keep their own state (cf. the UTF-8 body in
  §1) and are out of scope by construction.
- The producer of the global signal fd at `0x64fee24` is
  not addressed (separate open edge, above).

## Verification

`tools/timeout_cache_regcell_paths_static.py` re-derives
every pin from the materialised artifact: PT_LOAD map, FDE
ranges and sha256 of 20 bodies, `.rela.dyn` resolution of
the once-helper GOT slot, both closure vtables, both
`std/src/sync/once.rs:219` Location structs, 31 byte pins,
the whole-`.text` direct-branch caller census for fourteen
targets, the RIP-relative reference census for the two
vtables, the two Locations and the five registry globals
plus the chain bodies, the `.rela.dyn` addend and raw-qword
censuses, the cell store-pair byte-pattern census, and the
disp-`0x10`/`0x14` store census over the ten
record-touching bodies.
`tests/test_timeout_cache_regcell_paths_static.py`
compares its canonical output against this packet's
`records.json` and asserts the chain conclusions directly
(8 tests, none skipped against the materialised artifact).
`MANIFEST.sha256` covers the packet folder.
