# Optional decoder follow-up — 2026-11-05

The original six-test suite failed on Python without Capstone: the independent
disassembly method imported it unconditionally. The reviewer report was
reproduced on the original head using `python3 -S -m unittest discover`.
Only that method now explicitly skips when Capstone is absent. The other five
real native/frozen/control tests still execute. With Capstone installed all
six execute and pass; a skip is not a decoder or compiler pass.

Actual commands, before failure, both passing modes, timing and log hashes are
in portability-checks.json and its projected raw logs (only owned workspace
prefix replaced; external originals preserved). No source, evaluator, captured
input, expected result, acceptance gate or catalogue changes.

The original packet's CI-pending note records its submission-time state. Later
full CI passed at exact prior head `4ce7f634f11c8d158d52d197e3e36262707d59a4`: [run41830765148](https://github.com/lalalune/hyperliquid-source/actions/runs/41830765148),584files/0failed with declared optional skips retained.
That receipt is historical; the new follow-up head's full CI is pending.
This follow-up is part of the same PR and is not a new submission.
