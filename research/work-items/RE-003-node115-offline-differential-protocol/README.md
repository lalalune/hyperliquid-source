# RE-003: offline differential protocol design for node #115

- Component: cross-component test-harness design; no component gate requested.
- Target: Linux x86-64 node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/base commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Bounded question: what evidence and controls must exist before a future, separately authorized offline comparison may execute a bounded node #115 code path?
- Status: design only. Neither the captured node nor visor was executed; no differential result is claimed.
- Scope included: admission, fixture identity, isolation requirements, control cases, comparison records, and the separate execution-approval gate.
- Scope excluded: a runner or sandbox implementation, target execution, a reconstructed function, runtime equivalence, network access, chain activity, signing, and any completion gate.

This work item is named separately from the existing `RE-003-node115-priority-prefix` packet. That packet contains a bounded static finding; it does not define this harness protocol.

## Why this task is needed

`docs/TASKS.md` makes RE-003 the prerequisite for execution-based checks in RE-004 and RE-005. `docs/SCOPE.md` keeps captured node and visor execution outside the default workflow and requires a separately approved, isolated offline harness. `docs/REPRODUCIBILITY.md` covers authenticated artifacts and static inventory reproduction, not a target-execution protocol. This design records the missing boundary without enabling or performing execution.

## Admission and fixture identity

Before a future run, freeze one bounded question and record all of the following in its evidence packet:

1. The exact node target and full SHA-256 from `provenance/artifacts.json`; `make verify` must pass against the same checkout.
2. The independent implementation's source commit, lockfile, build command, toolchain, executable hash, and license/provenance. It must not contain transplanted target bytes or an inferred unlicensed implementation.
3. The component, function/interface evidence, call boundary, state assumptions, and the specific behavior that is sufficiently established to compare. Unknown behavior is not an oracle.
4. Each fixture's stable ID, provenance/license, format version, byte length, SHA-256, intended branch/boundary, independently justified expected result, and sanitization record. Use small synthetic or licensed/sanitized inputs; exclude live account data, keys, credentials, and unbounded chain data.
5. Exact tool versions, platform/architecture, deterministic environment, arguments, permitted input/output paths, resource limits, and the proposed isolation mechanism.

Reject before execution if either executable identity, fixture hash, source revision, interface, expected-result provenance, or scope differs from the frozen record. Never derive expected results from the executable under test. A fixture or oracle change creates a new evidence revision; it does not overwrite the original.

## Isolation contract

The future runner must fail closed unless every control below is available and verified for the exact run:

- Run one bounded case as an unprivileged user with no capabilities and `no_new_privs`; do not mount the user's home, repository credentials, environment files, sockets, or unrelated workspace.
- Expose the target, independent build, and frozen fixtures read-only. Provide only a fresh, per-run scratch directory for explicitly allowed outputs; discard it after retaining sanitized evidence.
- Use a network namespace with no interfaces or routes and a syscall policy that denies network creation and use. A missing namespace or enforcement facility is a hard stop; do not fall back to ordinary host execution.
- Deny privilege changes, tracing, mounts, and child-process creation after launch. Apply wall-clock, CPU, memory, process-count, and output-size limits; terminate the entire process group on a limit or timeout.
- Start from a minimal declared environment with proxy variables and credential variables absent. Record the environment allowlist, locale, timezone, architecture, and relevant CPU features; do not copy a user shell environment into the sandbox.
- Keep the harness controller outside the target sandbox. Capture exit status, raw stdout/stderr, normalized values, allowed file outputs, and denied-operation events. Any denied operation, unexpected file write, timeout, signal, or undeclared output makes the case a failed run, never a match.

The protocol specifies controls; it does not assert that a sandbox implementation or kernel policy has already been installed or tested.

## Positive and negative controls

Before any target execution is considered, validate the future controller with harmless test programs that are not project artifacts:

| Control | Expected result |
| --- | --- |
| Valid fixture and a deterministic stub with a known result | The controller records the exact fixture, stub identity, output, and exit status. |
| Same stub and fixture repeated with the same declared environment | Raw outputs and recorded result match byte for byte. |
| Wrong target hash, wrong source hash, or changed fixture bytes | Admission rejects before starting a process. |
| Missing, malformed, oversized, or out-of-scope fixture | Admission rejects before starting a process. |
| Stub attempts a socket operation | The operation is denied and the case is recorded as failed. |
| Stub attempts a write outside its scratch directory | The write is denied and the case is recorded as failed. |
| Stub attempts to spawn a child or exceed a resource limit | The attempt is denied or the process group is terminated; the case is recorded as failed. |
| Two admitted programs produce different values | The controller records a mismatch with raw values; it does not normalize away the difference or call it a pass. |
| A normalization mask is absent or differs from the reviewed allowlist | Comparison rejects; no implicit normalization is permitted. |

These are required future acceptance cases, not tests run by this design PR.

## Comparison and retained record

Compare only the outputs and state explicitly justified by the bounded question. Preserve raw bytes and values. Any normalization must list each exact field/byte range, reason, source evidence, and a negative control proving an unapproved difference remains visible. Never mask identity, status, errors, ordering, or bytes merely to obtain equality.

For every future run retain a machine-readable record beside the fixture packet containing: target and independent-build hashes; source and reference commits; fixture IDs/hashes; command and environment allowlist; isolation policy identity; tool versions; start/end status; raw output hashes; comparison method and masks; positive/negative control results; and limitations. Redact no evidence silently: if output could contain secrets or personal data, reject the fixture before execution rather than publishing raw output.

Use only `match`, `mismatch`, `rejected`, `failed`, or `not-run` as terminal outcomes. `not-run` is the current status. A mismatch is evidence to investigate, not proof that the independent code or captured code is correct. A match is limited to the tested fixture and established behavior; it does not establish whole-function, component, network, or whole-node equivalence.

## Separate approval gate

This design is not authorization to execute the captured node. Before a future target run, obtain a new, explicit approval for the exact bounded question, target hash, command/arguments, fixture hashes, allowed scratch path, isolation policy, and resource limits. Approval for another task, a Python instruction evaluator, static analysis, or this design does not transfer. Without that approval, the target remains `not-run`.

## Reproduction and limitations

- Platform: WSL Ubuntu on Windows x86-64; Python 3.12.3, GNU binutils 2.42, GnuPG 2.4.4, and Git 2.54.0.windows.1 for the mounted repository. Tests use the local Git wrapper to keep temporary repositories on Linux Git.
- Exact repository checks: `make doctor`; `make verify`; `make test`; `make catalogue-check`.
- `make doctor`: `analysis_ready: true`; `exact_rebuild_ready: false`, as the project has not accepted recovered build manifests, exact target build provenance, or an integrated comparison harness.
- `make verify`: passed. Target and supervisor signatures, imported source hashes, 29 evidence-packet manifests and 457 entries all verified.
- `make test`: passed; 76 test files attempted, 0 failed. Environment-gated cases that require an explicitly supplied archive, Rust toolchain, or Capstone version remain skipped by their test guards.
- `make catalogue-check`: passed; generated scope and progress match the pinned inputs.
- `cd research/work-items/RE-003-node115-offline-differential-protocol && sha256sum -c MANIFEST.sha256`: passed for this README.
- This design is read-only with respect to the target artifacts and pinned submodules.
- No captured executable, supervisor, fixture, or independent node build was run as part of this work.
- No isolated controller exists or was tested here; the positive and negative cases above remain acceptance requirements.
- No behavior result, reconstruction percentage, or component gate is claimed.
- Next question: after this protocol is reviewed, which single #115 interface has enough static evidence and a separately approved synthetic fixture to justify the first isolated comparison?
