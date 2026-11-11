#!/usr/bin/env python3
"""Finite checks of the hand-recovered tie decisions; no binary execution.

This does not decode/interpret instructions. The seed selection formula below
is a mathematical transcription of the documented pointer-selection dataflow.
Its ordering oracle is independent lexicographic (key, original position) order.
It complements, and cannot replace, the original-artifact static verifier.
"""
import itertools
import json


def seed_order(keys):
    # Strict comparisons keep each pair's original order on equality.
    lo_l, hi_l = (1, 0) if keys[1] < keys[0] else (0, 1)
    lo_r, hi_r = (3, 2) if keys[3] < keys[2] else (2, 3)
    lower_right = keys[lo_r] < keys[lo_l]
    upper_right = keys[hi_r] < keys[hi_l]
    middle_l = lo_r if upper_right else hi_l
    if lower_right:
        middle_l = lo_l
    first = lo_r if lower_right else lo_l
    middle_r = hi_l if lower_right else lo_r
    last = hi_l if upper_right else hi_r
    if upper_right:
        middle_r = hi_r
    if keys[middle_r] < keys[middle_l]:
        middle_l, middle_r = middle_r, middle_l
    return [first, middle_l, middle_r, last]


def main():
    seeds = 0
    tie_control_rejected = False
    for keys in itertools.product(range(4), repeat=4):
        expected = sorted(range(4), key=lambda i: (keys[i], i))
        assert seed_order(keys) == expected
        seeds += 1
        # Deliberately reverse one equal pair: the stability oracle must notice.
        altered = expected.copy()
        for i in range(3):
            if keys[altered[i]] == keys[altered[i + 1]]:
                altered[i], altered[i + 1] = altered[i + 1], altered[i]
                assert altered != expected
                tie_control_rejected = True
                break
    assert tie_control_rejected
    partitions = 0
    # Native forward low writes and backward high writes followed by reverse
    # readout preserve input order in both partitions, including equal keys.
    for n in range(9):
        for keys in itertools.product(range(3), repeat=n):
            for inclusive in (False, True):
                low, high_backwards = [], []
                for i, key in enumerate(keys):
                    belongs = key <= 1 if inclusive else key < 1
                    if belongs:
                        low.append(i)
                    else:
                        high_backwards.insert(0, i)
                observed = low + high_backwards[::-1]
                expected = sorted(range(n), key=lambda i: (
                    not (keys[i] <= 1 if inclusive else keys[i] < 1), i))
                assert observed == expected
                partitions += 1
    print(json.dumps({"four_key_seed_orders": seeds,
                      "stable_partition_cases": partitions,
                      "equal_order_corruption_rejected": tie_control_rejected,
                      "method": "independent finite logical checks; no native execution"}, indent=2))


if __name__ == "__main__":
    main()
