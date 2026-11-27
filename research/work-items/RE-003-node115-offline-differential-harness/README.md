# RE-003: offline differential admission & bubblewrap isolation controller

- Component: cross-component harness infrastructure (RE-003); no component gate requested.
- Target: Linux x86-64 node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Target execution status: **`not-run`**. Neither `artifacts/node/115/hl-node` nor `artifacts/visor/hl-visor` was executed by this work item.
- Protocol implemented: `research/work-items/RE-003-node115-offline-differential-protocol`.
- Claim status: observation / harness-control verification against harmless ephemeral synthetic stubs only.

## What this packet implements

`harness.py` implements the fail-closed admission, isolation, and comparison controller required by `RE-003-node115-offline-differential-protocol`:

1. **Admission gate (`admit_case`)**:
   - Verifies exact SHA-256 digests of target executable, independent build, and fixture before starting any process.
   - Validates fixture existence, non-empty size, maximum byte limit, and declared format (`utf8`, `json`, `bytes`).
   - Rejects any proxy, credential, token, key, or secret environment variable in the allowlist.
   - Rejects any normalization mask absent from or altered relative to the reviewed allowlist.
   - Enforces the **separate execution-approval gate**: any path resolving inside `artifacts/` or matching a captured `hl-node` / `hl-visor` SHA-256 is hard-refused with terminal outcome `not-run` unless an explicit `ExecutionApproval` matches the exact `(bounded_question, target_sha256, fixture_sha256, policy_id)`.
   - Fails closed (`failed`) if `bwrap` or `x86_64` isolation is unavailable; never falls back to unsandboxed host execution.
2. **Isolation runner (`run_isolated`)**:
   - Launches each bounded case inside `bubblewrap` (`bwrap --unshare-all --new-session --die-with-parent --seccomp <fd>`), isolating user, mount, PID, IPC, UTS, network, and cgroup namespaces.
   - Installs a classic BPF x86-64 seccomp filter (`--seccomp`) returning `EPERM` on `socket(41)`, `socketpair(53)`, `clone(56)`, `fork(57)`, `vfork(58)`, `ptrace(101)`, `mount(165)`, `umount2(166)`, `unshare(272)`, `setns(308)`, and `clone3(435)`.
   - Clears the host environment (`--clearenv`), passes only the declared allowlist (`LC_ALL=C`, `TZ=UTC`, `PATH=/usr/bin:/bin`), binds `/usr` and `/input` read-only, provides an ephemeral per-run `/scratch` directory, enforces `RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE`, output-byte caps, and kills the entire process group on wall-clock timeout.
   - Flags any non-zero exit, timeout, signal, output-cap breach, or undeclared file write inside `/scratch` as `failed` (never `match`).
3. **Comparison & terminal outcomes (`execute_case`)**:
   - Uses exclusively the 5 RE-003 outcomes: `match`, `mismatch`, `rejected`, `failed`, `not-run`.
   - Preserves raw stdout/stderr bytes and SHA-256 digests; never masks exit status, errors, or unapproved differences.

## Verified positive & negative controls (`--self-test`)

All 9 controls from the `RE-003-node115-offline-differential-protocol` acceptance table plus the captured-artifact approval gate (`C10`) were verified on harmless synthetic Python stubs (`records.json`):

| Control | Expected | Actual |
| --- | --- | --- |
| `C1_valid_deterministic_match` | `match` | `match` |
| `C2_repeatability_byte_for_byte` | `match` (identical SHA-256) | `match` |
| `C3_wrong_hash_rejected` | `rejected` (0 processes launched) | `rejected` |
| `C4_invalid_and_oversized_fixture_rejected` | `rejected` (0 processes launched) | `rejected` |
| `C5_socket_denied_seccomp` | `failed` (`EPERM` on `socket`) | `failed` |
| `C6_write_outside_scratch_denied` | `failed` (`EROFS` on `/input`) | `failed` |
| `C7_spawn_and_timeout_denied` | `failed` (`EPERM` on spawn + timeout kill) | `failed` |
| `C8_value_mismatch_preserved` | `mismatch` (raw `42` vs `43`) | `mismatch` |
| `C9_unapproved_mask_rejected` | `rejected` (0 processes launched) | `rejected` |
| `C10_captured_node115_approval_gate` | `not-run` (0 processes launched) | `not-run` |

## Reproduction

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-003-node115-offline-differential-harness/harness.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_offline_differential_harness_115 -v
(cd research/work-items/RE-003-node115-offline-differential-harness && sha256sum -c MANIFEST.sha256)
```

## Limitations

- Requires Linux x86-64 with unprivileged `bubblewrap` (`bwrap`) and seccomp-BPF enabled; on hosts without `bwrap`, `admit_case` fails closed rather than falling back to host execution.
- Validates the controller only against harmless synthetic stubs. No captured node #115 or visor executable was run, no target behavior is claimed, and no component gate in `research/progress.json` is flipped.
