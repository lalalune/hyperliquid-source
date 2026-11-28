"""Check #115's slow selector for adjacent, explicitly supplied states."""

import argparse
from dataclasses import dataclass

U64_MAX = (1 << 64) - 1


@dataclass(frozen=True)
class SelectorState:
    context_mode: int
    freeze_tag: int
    freeze_target: int
    cadence: int


def gate(height: int, state: SelectorState) -> str:
    """Classify whether the selected path reaches the local raw-root call."""
    is_10k = height % 10_000 == 0
    active_freeze = state.freeze_tag == 1
    past_target = active_freeze and state.freeze_target < height
    if not is_10k and past_target:
        return "invariant-before-mode"
    if state.context_mode == 2:
        return "skips-mode-2"
    if past_target:
        return "invariant-after-mode"
    if is_10k:
        return "eligible-10000"
    if active_freeze and state.freeze_target == height:
        return "eligible-freeze"
    if state.cadence == 0:
        return "invalid-materialized-cadence"
    if height % state.cadence == 0:
        return "eligible-periodic"
    return "skips-cadence"


def pair(height: int, at_h: SelectorState, at_h1: SelectorState) -> tuple[str, str]:
    if not 0 <= height < U64_MAX:
        raise ValueError("H and H+1 must be distinct unsigned 64-bit heights")
    for state in (at_h, at_h1):
        for value, limit in zip(
            (state.context_mode, state.freeze_tag, state.freeze_target, state.cadence),
            (1 << 32, 1 << 32, 1 << 64, 1 << 64),
        ):
            if not 0 <= value < limit:
                raise ValueError("mode/tag must be u32 and target/cadence must be u64")
    return gate(height, at_h), gate(height + 1, at_h1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("height", type=int, help="sequential checkpoint height H")
    for name in ("--at-h", "--at-h1"):
        parser.add_argument(
            name, type=int, nargs=4, required=True,
            metavar=("MODE", "FREEZE_TAG", "FREEZE_TARGET", "CADENCE"),
        )
    args = parser.parse_args()
    try:
        results = pair(args.height, SelectorState(*args.at_h), SelectorState(*args.at_h1))
    except ValueError as error:
        parser.error(str(error))
    for height, status in enumerate(results, start=args.height):
        print(f"{height}\t{status}")


if __name__ == "__main__":
    main()
