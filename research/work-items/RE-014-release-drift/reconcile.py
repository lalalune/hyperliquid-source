#!/usr/bin/env python3
"""RE-014 reconciliation: join an independent per-function classification to ours on the #94 start.

Usage: reconcile.py OUR_TSV XCHECK_CSV. The xcheck CSV needs columns class, old_start, new_start.
Prints a deterministic JSON cross-tab: for every (our class, their class) the row count; where both
sides paired the function, how many chose the same #115 partner; and, where we paired it, how many of
our pairs the cross-check's own `norm` digest calls equal (old_norm of our #94 row against new_norm of
our #115 partner), which separates duplicate assignment from a normalisation difference. Exits non-zero if the two
inputs do not cover exactly the same #94 starts. Uses no assert so it holds under python -O.
"""
import collections
import csv
import json
import sys


def load(path, start, partner, cls, delimiter):
    out = {}
    with open(path, newline='') as handle:
        for r in csv.DictReader(handle, delimiter=delimiter):
            if r[start]:
                out[int(r[start], 16)] = (r[cls], int(r[partner], 16) if r[partner] else None)
    return out


def norms(path):
    old, new = {}, {}
    with open(path, newline='') as handle:
        for r in csv.DictReader(handle):
            if r['old_start']:
                old[int(r['old_start'], 16)] = r['old_norm']
            if r['new_start']:
                new[int(r['new_start'], 16)] = r['new_norm']
    return old, new


def reconcile(ours, theirs, their_norms=None):
    if set(ours) != set(theirs):
        raise SystemExit(f'#94 starts differ: {len(set(ours) ^ set(theirs))} not in both')
    table = collections.defaultdict(lambda: {'rows': 0, 'same_partner': 0, 'other_partner': 0,
                                             'our_pair_their_norm_equal': 0, 'our_pair_their_norm_differs': 0})
    for start, (cls, partner) in ours.items():
        other_cls, other_partner = theirs[start]
        cell = table[f'{cls}|{other_cls}']
        cell['rows'] += 1
        if partner is not None and other_partner is not None:
            cell['same_partner' if partner == other_partner else 'other_partner'] += 1
        if partner is not None and their_norms is not None:
            equal = their_norms[0][start] == their_norms[1][partner]
            cell['our_pair_their_norm_equal' if equal else 'our_pair_their_norm_differs'] += 1
    return {'joined_94_rows': len(ours), 'cells': dict(sorted(table.items()))}


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    ours = load(sys.argv[1], 'start_94', 'start_115', 'class', '\t')
    theirs = load(sys.argv[2], 'old_start', 'new_start', 'class', ',')
    print(json.dumps(reconcile(ours, theirs, norms(sys.argv[2])), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
