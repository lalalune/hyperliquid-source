# RE-009: what does the OwnedDbDir constructor do with a path containing "checkpoint" in node #94?

- Component ID: `RE-009` (storage/state roots)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: hyperliquid-source `1f8c67c63ca4794c9689235471c60297f8a5c985`;
  can1357 reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only as a claim to test
- Claim status: observation for bytes, branches and the search model; inference for type names and
  layout meaning; unresolved items are listed at the end
- Scope included: constructor FDE `0x158e870`, its substring search, panic path, singleton arguments,
  allocation size, and its 3 slot callers
- Scope excluded: the inside of the singleton registry `0x1439a40`, drop order, which bundles each
  caller opens, node #115, and any execution

## Reproduce

From the repository root (Python standard library only; the binary is read, never executed):

```sh
python3 tools/owned_db_dir_guard.py --out research/work-items/RE-009-owned-db-dir-guard-94
python3 -m unittest tests.test_owned_db_dir_guard
```

The tool checks the input SHA-256 first and fails on a mismatch. It reads sections through
`tools/elf_index.py`, FDE extents through `tools/fde_extents.py`, and RELATIVE addends from
`.rela.dyn`. No objdump or readelf output feeds `owned-db-dir-guard.json`, so the binutils version
cannot change it.

## Evidence

Addresses are ELF virtual addresses. FDE ends are exclusive. The function is FDE
`[0x158e870, 0x158ede9)`, Location `db/src/owned_db_home.rs:21:9`.

Needle. The bytes spell `checkpoint`, case sensitive, in three agreeing forms:

- movabs `"checkpoi"` plus xor `"nt"` at 0x158e89c/0x158e8ba and again at 0x158e8dd/0x158e8ef
- 16 bytes of `c` at 0x208fb0 and 16 bytes of `t` at 0x204ef0
- `heckpoint`, length 9, at 0x25f8eb for the vector verifier `0x158ef30`

Search regimes by path length:

| Length | Path | Constant site |
|---|---|---|
| below 10 | no compare | 0x158e88c, 0x158e8d7 |
| exactly 10 | one compare | 0x158e8dd |
| 11 to 24 | scalar loop, one byte step | 0x158e892, 0x158e8cc |
| 25 to 73 | 16-byte windows, then a tail at length-25 | 0x158e95c, 0x158e9a3, 0x158e9df |
| 74 and up | 64-byte blocks first | 0x158e94d, 0x158ebe8, 0x158ebed |

The tool reads these bounds from their immediate bytes and models which match starts the miss path
examines. For every path length from 0 to 512, the model covers each start from 0 to length-10 and
nothing past it: 0 missing starts and 0 starts past the end. So the search behaves as a plain
substring test over those lengths.

Hit path. All three search paths reach 0x158e8ff: scalar at 0x158e8c4, vector at 0x158ea10, tail at
0x158ed9e. That block does this:

| VA | Observation |
|---|---|
| 0x158e904 | argument formatter 0x158f020, which pads the raw `(ptr, len)` at `+8`/`+0x10` |
| 0x158e910 | template 0x1f8d0b: `OwnedDbDir invalid dir {}` |
| 0x158e917 | Location 0x56757d0: `db/src/owned_db_home.rs:21:9` |
| 0x158e923 | call slot 0x576e098, target 0x157b810 |
| 0x158e929 | jump to 0x158edb3, which is `ud2` |

Target 0x157b810 stores the arguments and Location, then calls slot 0x57706e0 at 0x157b836; the next
byte is `int3`. The same slot takes the singleton duplicate message at its own failure site. No
return path from the hit block reaches the singleton call or the allocation.

Miss path. 0x158ea16 passes `("OwnedDbDir", 10)` and the path `(ptr, len)` to slot 0x576f4e0, target
0x1439a40, whose key template at 0x1f05cd decodes to `{}::{}`. So the key is
`OwnedDbDir::<path>`. The constructor then allocates 0x58 bytes at 0x158eadd and copies in two counts
of 1, the 3-word path and the 6-word singleton result.

Callers. A `.text` scan finds 0 direct `e8`/`e9` calls and 3 slot calls through 0x5770888:

| Site | FDE | Path template | Compares bundle with 3 |
|---|---|---|---|
| 0x257399e | 0x2573900 | 0x2573982 | yes |
| 0x4872579 | 0x4872470 | 0x4872564 | no (loop) |
| 0x4883953 | 0x48838c0 | 0x4883937 | yes |

Each builds the argument from template 0x1e938e, `{}/{}`, just before the call.

Inferences, kept apart from the observations above:

- Target 0x157b810 is `core::panicking::panic_fmt`, from its shape and its uses. A path containing
  `checkpoint` therefore panics, and construction does not continue.
- The allocation is `ArcInner<{path, SingletonSet}>`: strong, weak, then 3 + 6 words.
- The path is string shaped: the panic formatter pads its bytes directly, with no lossy display step.
- Each caller's `{}/{}` is a data directory plus a bundle name.

The reference `db/owned_db_home.rs` disagrees in two places:

- `OwnedDbHome::new` says such paths log `OwnedDbDir invalid dir` and that construction still
  proceeds. The binary has no continuing path from the hit block.
- `OwnedDbDirGuard::new` builds `format!("OwnedDbDir{path}")` and registers it under
  `type_name::<OwnedDbDirGuard>()`. The binary passes `OwnedDbDir` and the path as two separate
  strings, so the key has `::` between them and no Rust type name.

A rebuild from the reference would accept a data directory the binary refuses.

## Implementation and comparison

Not yet implemented. No Rust path, build or binary comparison exists in this packet.

## Results and limitations

Results, all from `owned-db-dir-guard.json`:

- needle forms agreeing: 3 of 3
- search model: 513 lengths, 0 missing starts, 0 starts past the end
- slot callers: 3, each with a `{}/{}` template before the call

Limits:

- The model runs to length 512. Longer paths repeat the block loop, but they are not enumerated.
- The model tests the windows, not the bit tests inside each window.
- The panic reading depends on the `panic_fmt` inference above. A panic hook or abort setting is
  not analysed, so the process outcome after the panic is out of scope.
- Direct and slot calls are counted. A reach through another pointer table would not appear.
- The registry internals are out of scope; a separate singleton lifecycle PR covers them.
- No progress gate is requested.

Next question: which bundle indexes reach each of the 3 callers, and does any path ever place an
owned bundle directory under the `{}/checkpoint` root?
