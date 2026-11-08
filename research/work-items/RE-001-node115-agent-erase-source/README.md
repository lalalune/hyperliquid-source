# First-match agent erase source evidence

Bounded shared agent-state progress for #3914; the broader nonce/replay issue remains open. Static predecessor: #2283. Original node115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. No target execution/emulation.

The packet binds 11 full FDEs, 7,047 bytes, 1,702 instructions and 1,709 facts. Its 27 controls change owner/key offsets, name matching, row deletion, singleton/replacement writes, duration/date helper targets, leap handling, statuses and fallback data. Each control must fail fact validation after original-target authentication with the global digest/window checks intentionally bypassed.

| Native evidence | Logical source behavior |
| --- | --- |
| `3be79a0..3be7e79`, `4717440`, `3ee6c20`, `3ec6620` | Full20-byte owner lookup, create absent owner with empty agent vector before scanning |
| `3be7b30..3be7b4c`, imported `bcmp` | Length plus exact name bytes; first match only |
| `3be7b80..3be7ba4`, imported `memmove` | Shift tail and decrement length, preserving remaining order |
| `3be7d36..3be7d4a` | Copy removed row+0x24 full20-byte address |
| `458e08`, `15ed960` | Native f64 `6.0` (`0000000000001840`) converts to seconds6/nanos0 |
| `162a9a0`, `16290d0` | Add time, handle leap nanos/date carry; checked date addition |
| `4679d0` | Fallback packed date `0x7fffd6de`, second86399, nanos999999999; CE day95745399 |
| `3900d60`, `370cdc0` | Build empty BTreeSet then insert the full32-byte address/time record |
| `3eca790` | Actual keyed follow-up map insertion/replacement; old root/height/length replaced |
| `392ffe0` | Drop old set; no merging of old records |

At `3be7bdB` and `3be7be4` the local set starts empty. `370ce41..370ce8f` initializes the first leaf and writes both 16-byte halves. At `3ecaac6..3ecaaf0` the existing follow-up set is returned and overwritten by all three words of the new set; the caller drops the old set. A missing-owner no-match still retains the created owner entry and leaves the follow-up map unchanged.

The fixed6-second selected path cannot hit duration-range rejection. Native `162a9c9..162aa12` subtracts 1e9 leap nanoseconds before positive-second addition. Ordinary seconds then carry across midnight; canonical valid input plus6 can exceed the supported date only at its upper boundary, selecting the pinned maximum timestamp. The owned constructor excludes malformed dates/time projections.

Validation: four debug/release Rust tests, strict Clippy and formatting, plus 4,000 independent Python list/dict action cases (1,300 accepted,2,700 no-match) with complete projected-state comparisons. Fixture SHA-256 `53e8fc6889aa8a65b5123d2c6f6bf1a3acdb1c8dc950b98134a420c2e59d540d`. Owned reference agreement and static facts are not native-runtime differential execution.

Unobserved record fields are opaque and retained. Physical collection balancing/hashing, allocation/destructor failures, malformed String sentinels, outer authorization/signing and complete nonce/replay semantics are outside scope. Full-component gates remain false.
