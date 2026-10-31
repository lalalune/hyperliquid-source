# RE-001: periodic slice snapshot, consumer record and result continuation

Component: foundation/static seed/call/data validation. Bounded question: what does node94's periodic slice loop actually call after copying, and how does it handle the consumer's raw result? Maintainer RE-001 requests original ranges and xrefs. This is static research, not a filesystem implementation or a live defect.

Target: node #94,91,774,280 bytes, SHA-2563b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f. Base1f8c67c63ca4794c9689235471c60297f8a5c985. Pinned can1357 base/u.rs at999556f6e0a474b8312db96ec3149e1c44e97c23 labels432f9c0 a periodic byte writer and144a890 a write helper. Those are leads, not accepted source semantics. Actual consumer bytes construct wc/-l slices and parse a numeric value; a writer API is not established. No inferred Rust is copied.

## Exact scopes

| Linked VA interval, end exclusive | Bytes | SHA-256 |
| --- | ---: | --- |
| 0x432f9c0..0x432fc09 |585 |9f6a1d423e231ee18e9fedabdef34e846c68d6efad755a9375a05dad403d90ee |
| 0x144a890..0x144accc |1084 |633cf40de5cafca38d054af567337b72c91cdd3d65e15da29ada8047520fa028 |

records.json retains complete original bodies/FDEs/CIEs and controls. capstone-5.0.6.txt covers all1,669 bytes and427 instructions contiguously, starting at the FDE starts. Those are unwind-described scopes, not a complete function/caller census. Coordinates are linked ELF VAs, resolved through unique file-backed section mappings, with no runtime rebase.

## Observed local protocol

1. The normal loop resets requested seconds to60. The indirect call target is bound by GLOB_DAT import to nanosleep, with both pointers addressing the local timespec. Only raw return-1 takes the errno-access path. errno4 reuses the remaining timespec; other errno values select the original sleep diagnostic. The source Location is rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/std/src/sys/thread/unix.rs:550:17. Linux's errno header names4 EINTR; the nanosleep ABI specifies remaining duration on interruption. This does not measure actual scheduling intervals.
2. The fast path performs lock cmpxchg byte0->1 at state+0x10, then loads the slice pointer from+0x20 and length from+0x28. It obtains storage (or uses raw pointer1 for zero length), then calls the verified memcpy import with that pointer/length. Slow acquisition is an opaque helper and not a proved locking implementation.
3. The release cmpxchg byte1->0 precedes the consumer call. A selected slow-release helper also precedes that call. This is local instruction ordering, not a complete memory-safety/liveness or synchronization proof.
4. Slot576e990 is RELATIVE-bound to144a890. The caller passes the copied pointer/length and a Location for base/src/u.rs:361:11. Inside that consumer, a length guard precedes comparison of the last four bytes with .lz4. A six-word record contains `(ptr(wc),2,ptr(-l),2,supplied_pointer,supplied_length)` before the opaque call1455c00. The literal bytes are at219c50 and219c52. This is a command-like record, not proof that a process or filesystem operation has run.
5. The consumer contains unsigned decimal digit/multiply-by10 paths, checked multiplication/addition on the long route, and observed normal returns of raw tag0 plus numeric word or tag1 plus an error carrier. Complete Unicode trimming/parser semantics are outside scope.
6. The caller tests AL's low bit. Zero bypasses use of the payload; nonzero dereferences the carrier and calls through its first table slot. If the selected calls return normally, both paths free the copied storage as applicable and reach the60-second loop backedge. The numeric zero-tag payload is not stored/returned by this caller. Callback/destructor identity and its possible nonlocal effects remain unknown; no guaranteed infinite-runtime or error-recovery contract is asserted.

The dynamic bindings are checked in the actual RELA/dynsym/dynstr contents, not assumed from import-like addresses: nanosleep576e8d0, __errno_location576e8d8, memcpy576dfe0 (GLOB_DAT); consumer576e990 ->144a890, source5666be0 ->1ef2de, sleep source5752288 ->1e451a (RELATIVE). Their original pointer slots and Location records are retained. Original capture files, imports and pins remain untouched.

Primary ABI context: https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/asm-generic/errno-base.h and https://man7.org/linux/man-pages/man2/nanosleep.2.html . The source provenance/ABI labels do not authenticate signatures or execute the target.

## Reproduce

Windows/Python3.12.14, PYTHONUTF8=1, PYTHONIOENCODING=utf-8, repository root:

```text
python tools/periodic_slice_consumer.py --check research/work-items/RE-001-periodic-slice-consumer-94/records.json
python -m unittest discover -s tests -p test_periodic_slice_consumer.py -v
python research/work-items/RE-001-periodic-slice-consumer-94/verify_native.py
python -O research/work-items/RE-001-periodic-slice-consumer-94/verify_native.py
python -m unittest discover -s tests -v
python tools/doctor.py
python tools/artifacts.py verify
python tools/verify_imports.py
python tools/catalogue.py --check
python tools/reproduce.py
git diff --check
```

Regular analyzer/tests are stdlib only. Optional native regeneration uses Capstone5.0.6 on PYTHONPATH. Actual official Windows wheel capstone-5.0.6-py3-none-win_amd64.whl SHA-256761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064 was verified from https://pypi.org/pypi/capstone/5.0.6/json before loading. No project dependencies, hooks or global runtimes change. No capture, wc, nanosleep or captured callee is executed.

## Results and limitations

Six focused tests pass: complete report; digest rejection;13 actual code and six data/path/Location mutations below the digest gate; six scoped relocation retargets; three import-name mutations; complete427-instruction export byte coverage. Report --check passes. Native normal/-O replay is byte-identical. Before this packet the periodic-writer name was an unvalidated lead; the packet supplies actual call/data/result relationships without adopting that name. Raw transient controls, exports and logs are retained outside the contribution under periodic-*.

Full tooling is not claimed green. make is unavailable, so required targets ran through Python. Doctor lacks GPG/native analysis/Rust tools. Artifact byte hashes match before missing GPG stops signatures. Partial Windows reference checkout (reserved node/aux.rs) blocks imports; catalogue-check is stale and reproduce stops at artifact verification. The completed full-suite result is recorded in the PR. Capstone does not make these missing prerequisites pass; no hosted CI/container result is claimed.

Full suite completed:287 tests in116.935s, seven failures,32 errors,nine skips, the same failure counts as baseline281. git diff --check passes.

No recovered Rust, full command-launch/file-I/O behavior, complete synchronization, parser ABI, caller census, exact timing, component gate or equivalence is claimed. Machine-code excerpts retain artifact rights; new code/text is independent. Next: validate1455c00 and the slow lock helpers before assigning a high-level periodic-writer/line-counter API or synchronization guarantee.
