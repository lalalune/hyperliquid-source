# RE-001: node #115 JsonRpcResult local dispatch and constructor

**Required hosted checks passed; prepared for maintainer review.** Task RE-001. Component allocation `foundation` is tentative, not proven source/type ownership. The bounded gap was whether #115 contains the diagnostic-associated alternative constructor and how one local caller handles its result. This packet newly binds two #115 FDE ranges, their native instruction rows and selected local operations. No #94 acceptance credit or generic type schema is transferred.

Target: node #115, 105,896,032 bytes, SHA256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. Bounds and file offsets are retained in `candidates.json`; VAs differ from body file offsets by 0x1000 here. No inferred reference source is copied or required.

## Actual observations

The constructor is `[0x1751380,0x17514d6)`, 342 bytes / 79 instructions. The caller is `[0x1707010,0x17077b2)`, 1,954 bytes / 410 instructions. These 489 rows over 2,296 bytes are declared evidence denominators, not a function census or reconstruction percentage. [Local operations and explicit unknowns](observations.md), [machine-readable evidence](evidence.json).

The diagnostic occurs once at readonly ELF VA/file offset `0x480c41`. Native decoding confirms its LEA at `0x175144c` and the direct incoming call at `0x17074ee`. The constructor's ordered calls target `0x16fdba0` then, conditionally on the raw sentinel, `0x16fdf90`. Its ordinary arm copies 104 local bytes. The caller retains object/delimiter and tagged-output paths. Both alternative helpers' schemas, opaque post-object semantics and source ownership remain unresolved.

## Reproduce without native or captured execution

With Python 3.12+ standard library and the authenticated complete #115 capture, from repository root:

```sh
python3 -I -B research/work-items/RE-001-node115-jsonrpc-result-dispatch/verify_packet.py \
  --binary artifacts/node/115/hl-node
```

The owned reader authenticates the complete file, all 135,313 ordered unwind-header rows, actual supported CIE/FDE fields, all 489 retained instruction-byte rows and selected field evidence controls. The controls corrupt evidence bytes and FDE extents; they are not runtime parser inputs. No subprocess, repository import, native decoder, network request or captured program is launched. The extended verifier was added after the hosted job. Its local Python 3.14.7 replay passed and rejected 40 evidence corruptions (38 selected field changes and two FDE-extent changes); It was subsequently reproduced in the required-check run below.

## Required hosted validation

All eight frozen commands passed. The unchanged full test runner completed all **76 files**, reporting **382 cases** and **4 skips**, with zero failed files.

[Run 41510269507](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41510269507), execution `e4b02d796d47c2757095a97ad597791f8052f878`, checked source `8fd8db680ec4bfef40996e5616bce3d5156d0b86` plus the frozen 24-file packet under Python 3.12.3. It was one job, attempt 1, under a 25-minute ceiling with up to 15 minutes for the test command. No retry was launched.

| Command | Exit | Timed out | Seconds |
| --- | ---: | --- | ---: |
| `catalogue-generate` | 0 | False | 0.766 |
| `packet-full-input` | 0 | False | 1.267 |
| `doctor` | 0 | False | 0.264 |
| `verify` | 0 | False | 0.565 |
| `catalogue-check` | 0 | False | 0.766 |
| `reproduce` | 0 | False | 5.276 |
| `test` | 0 | False | 647.668 |
| `verify-after-test` | 0 | False | 0.515 |

The job retained sealed read-only/noexec originals and ran the unchanged tests in a separate writable offline copy, supporting their hard-link and executable-marker fixtures. Both stages used UID/GID 65534, empty supplementary groups, zero capabilities, no-new-privileges and a distinct loopback-only network namespace. Compiler paths and captured-emulation opt-ins were absent. Canonical `make catalogue` regenerated the new work-item count, then immutable input hashes and strict source pins were checked after testing. Actual skips, tool identities and limitations remain in [the receipt audit](validation/required-audit.json) and [qualification](qualification/required-validation.json).

The independent collector verified GitHub's single archive digest, size and every retained file. The hosted extended packet reader matches its earlier local output except Python version. This final packet adds seven actual receipt data files and updates status/prose/manifest afterward; its verifier, field bindings, core observations and original exports are unchanged. The canonical generated README/banner updates accompany the packet. No component or comparison gate changed.

## Original native evidence

[Run 41499013810](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41499013810), execution `a50750f0da242beda28002f1662c7eab735ae02e`, succeeded on attempt 1 as one job with a 12-minute ceiling. It acquired the pinned complete capture through Git LFS and reproduced the complete-input candidate reader under Python 3.12.3. The two selected ranges were decoded using one GNU objdump 2.42 version query and exactly two static decodes: `-D -z -b binary -m i386:x86-64 -M intel --insn-width=16 --adjust-vma=<ELF-VA>`. The actual executable hash and complete command stdout/stderr are retained in `receipts/`.

Before native analysis, receipts qualified UID/GID 65534, no supplementary groups, zero capabilities, no-new-privileges, a distinct loopback-only network namespace, read-only/noexec payload/input mounts and EROFS write controls. Complete capture, excerpt and payload hashes matched afterward. The independently downloaded archive was 26,181 bytes, SHA256 `e794a70b0ad64ca50968a3b6230a64a1255213e4c2254c12253431080f6dd402`; it matches GitHub's digest. [Artifact and per-file audit](artifact-audit.json).

The original native job proved full-input binding and selected static instruction observations; subsequent required repository results are above. No Rust build, runtime parser test or whole-ELF identity result is claimed. No new native tool or repository program ran on the Mac. New code/prose is independently authored; captured evidence retains upstream rights. All incomplete gates remain false. No accepted-work Points or payment is claimed; acceptance remains a maintainer decision.

Next research question: establish the alternative helpers' field requirements and opaque post-object contract on #115. Ordinary PR-triggered CI is not claimed by these external receipts; the prepared commit suppresses another automatic workflow under the one-job operator limit. All claims remain tied to the tested source and evidence scope.
