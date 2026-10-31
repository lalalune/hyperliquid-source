# RE-009: which marker file finishes an EvmState checkpoint in node #94?

- Component ID: `RE-009` (storage/state roots)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: hyperliquid-source `1f8c67c63ca4794c9689235471c60297f8a5c985`;
  can1357 reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only as a claim to test
- Claim status: observation for bytes, call sites and branches; inference for the "legacy" reading,
  the checkpoint create callee and bundle meaning; unresolved items are listed at the end
- Scope included: marker path builder `0x15867a0`, its 11 direct call sites, the touch helper
  `0x144fd70`, the bundle save `0x1589870` ordering, and the probe branches of the 3 plain-marker readers
- Scope excluded: what a reader does after the probe, checkpoint selection policy, RocksDB checkpoint
  internals, `lt_hashes.json`, node #115, and any execution

## Reproduce

From the repository root (Python standard library only; the binary is read, never executed):

```sh
python3 tools/checkpoint_bundle_markers.py --out research/work-items/RE-009-checkpoint-bundle-markers-94
python3 -m unittest tests.test_checkpoint_bundle_markers
sha256sum -c research/work-items/RE-009-checkpoint-bundle-markers-94/MANIFEST.sha256
```

Run the last command from inside the work item folder. The tool checks the input SHA-256 first
and fails on a mismatch. It reads sections through `tools/elf_index.py`, FDE extents through
`tools/fde_extents.py`, and RELATIVE addends from `.rela.dyn`. No objdump or readelf output feeds
any generated file, so the binutils version cannot change the results.

Generated files:

- `checkpoint-bundle-markers.json`: templates, names, pins, site census, reader joins
- `marker-sites.tsv`: the 11 call sites as a table

## Evidence

Addresses are ELF virtual addresses. FDE ends are exclusive.

Marker path builder, FDE `[0x15867a0, 0x1586929)`, no first-party Location:

| VA | Bytes | Observation |
|---|---|---|
| 0x15867f2 | `40 0f b6 c6` | bundle index from `sil`, no bound check |
| 0x15867f9 / 0x1586804 | `lea rcx` | pointer table 0x5675538 and length table 0x25f7b8 |
| 0x1586814 | `ff 15` slot 0x576e000 | pads the name into a new String |
| 0x158683c | `ff 15` slot 0x576e078 | transforms that String; slot target 0x1345580 |
| 0x1586869 | `lea rsi` | template 0x1f2f3e |
| 0x1586878 | `ff 15` slot 0x576e040 | formats the result |

The template at 0x1f2f3e decodes to `{}/CHECKPOINT_COMPLETE_{}`. Argument 1 is the directory
`(ptr, len)` from `rdx`/`rcx`; argument 2 is the transformed String. Table rows:

| Index | Name | Length | Marker file |
|---|---|---|---|
| 0 | `Exchange` | 8 | `CHECKPOINT_COMPLETE_EXCHANGE` |
| 1 | `Rpc` | 3 | `CHECKPOINT_COMPLETE_RPC` |
| 2 | `EvmState` | 8 | `CHECKPOINT_COMPLETE_EVMSTATE` |

Row 3 has length word `0x656c203e2064696d`, which is ASCII text, so the table ends at 3 rows.

The transform is uppercase. At 0x134568a the scalar loop tests `byte - 0x61 < 0x1a` and xors `0x20`.
The vector loop uses the same three constants at 0x2041b0 (`0x9f`), 0x204eb0 (`0x19`) and 0x2092e0
(`0x20`). All three names are ASCII and shorter than 16 bytes, so the scalar rule covers them.
The bytes `CHECKPOINT_COMPLETE_EVMSTATE` and `CHECKPOINT_COMPLETE_EvmState` appear 0 times in the
file; the name exists only at run time.

Call census: a byte scan of `.text` finds 11 `e8` calls to `0x15867a0`.

- 8 pass `mov esi, 2`, which is `EvmState`.
- 3 pass a stack byte: `0x1589a38`, `0x332d6fd`, `0x332d77f`.
- 6 are followed by the touch slot; 5 are followed by the `is_file` slot.

`0x1589a38` sits in `0x1589870`, whose 2 direct callers both set `ecx = 2` (`0x1589e14`, `0x326af73`).
So `0x332d440` is the only function where a bundle other than 2 can reach the builder under this
direct-call census.

Touch helper `0x144fd70` (slot 0x576f668): `is_file` true returns `None` (`0x144fd8f`, `0x144fd93`).
Otherwise it creates the parent directory, then calls slot 0x576f670 with `rdi = 1`, `rsi = 0`
(`0x144fe47`, `0x144fe4c`), the empty byte slice, plus the path. Callers pass Location
`base/src/fu.rs:254:23` from 0x566a9f8. `is_file` (0x144a710) masks `st_mode` with `0xf000` and
compares with `0x8000`.

Bundle save `0x1589870`: `db_hub.rs:72` and `:74` unwraps at 0x5675580 and 0x56755b0. Its path calls
`0x158da60` at 0x15899c3, unwraps, then builds the marker at 0x1589a38 and touches it at 0x1589a51.
A failed create panics before the marker exists. The touch result is only dropped (`0x1589a57` to
`0x1589a62`), so a failed touch does not panic here.

Plain marker: template 0x1fd4ee decodes to `{}/CHECKPOINT_COMPLETE`. A RIP-relative load scan of
`.text` finds exactly 3 uses, all readers:

| Plain lea | Plain branch | Marker probe | Both hits join | Marker miss |
|---|---|---|---|---|
| 0x28d1ace | 0x28d1af6 | 0x28d1b3e | 0x28d1b73 | 0x28d1bcc |
| 0x332e4d9 | 0x332e501 | 0x332e54b | 0x332e57f | 0x332e5d8 |
| 0x459ac6e | 0x459ac96 | 0x459acde | 0x459ad13 | 0x459ad6c |

Each reader runs `is_file` on the plain path. On a miss it probes
`CHECKPOINT_COMPLETE_EVMSTATE`. Either hit reaches the same address.

Inferences, kept apart from the observations above:

- A checkpoint is loadable when `CHECKPOINT_COMPLETE` or `CHECKPOINT_COMPLETE_EVMSTATE` is a regular
  file. This reads the join as the accept path; the code after the join is out of scope.
- Plain `CHECKPOINT_COMPLETE` is a legacy name. No code in the scan formats it for a touch, so #94
  appears to accept it without writing it.
- `0x158da60` creates the RocksDB checkpoint. It is reached with the `db_hub.rs:74` unwrap and
  the bundle subdirectory path, but this packet does not walk its FFI calls.
- The marker files are empty, from the empty slice passed to the write slot.

The reference `db/db_home.rs` disagrees in two places:

- `is_loadable` tests `CHECKPOINT_COMPLETE` or a regular file `<child>/EvmState`. The binary tests
  `CHECKPOINT_COMPLETE_EVMSTATE`; the pinned readers have no `EvmState` file probe between the two
  branches.
- The doc comment on `copy_bundle_to_checkpoint` says callers touch `CHECKPOINT_COMPLETE`. The plain
  template has no touch site, and all 6 touch sites use the suffixed builder.

A fixture built from the reference would mark a checkpoint with the wrong file name for this binary.

## Implementation and comparison

Not yet implemented. No Rust path, build or binary comparison exists in this packet.

## Results and limitations

Results, all from `checkpoint-bundle-markers.json`:

- bundle names: 3 of 3 table rows decoded
- builder call sites: 11 classified, 0 unclassified
- touch 6, probe 5; immediate 2: 8, stack byte: 3
- plain template sites: 3 of 3 are readers with a joined hit

Limits:

- The call census covers direct `e8` calls. A builder reached through a pointer would not appear.
- The stack byte in `0x332d440` comes from the caller. Whether `Exchange` or `Rpc` markers are
  written in practice is unresolved.
- The non-ASCII half of the uppercase callee is not analysed; no bundle name reaches it.
- Whether old on-disk checkpoints with plain markers exist is unknown. No chain data was read.
- The packet makes no claim about which function picks a checkpoint or how a rejected one is reported.
- No progress gate is requested.

Next question: which caller of `0x332d440` passes bundle indexes 0 and 1, and does a bundle copy
ever write `CHECKPOINT_COMPLETE_EXCHANGE` or `CHECKPOINT_COMPLETE_RPC` in #94?
