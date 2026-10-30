#!/usr/bin/env python3
"""RE-014: pair node #94 and #115 FDE extents and classify release drift.

Static only: both captured binaries are digest-checked, extents come from
tools/fde_extents.py (RE-001) and instruction text comes from a GNU objdump
linear sweep of .text. No captured code is executed.
"""
import argparse
import bisect
import collections
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))  # also under python -I
RELEASES = ('94', '115')
OBJDUMP_ARGS = ('-d', '--no-show-raw-insn', '-w', '-j', '.text')

def gnu_objdump():
    """Return (path, version_line) for GNU objdump, or (None, reason) if unavailable.

    RE-014 fingerprints depend on GNU AT&T text. LLVM objdump accepts the name
    `objdump` on macOS but rejects GNU-only flags; treating any `objdump` as GNU
    caused false failures. Callers must skip or fail closed with the reason —
    never treat a missing/non-GNU tool as a passing check.
    """
    path = shutil.which("objdump")
    if not path:
        return None, "objdump not found on PATH"
    proc = subprocess.run([path, "--version"], capture_output=True, text=True,
                          env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"})
    text = (proc.stdout or "") + (proc.stderr or "")
    line = text.splitlines()[0] if text.strip() else "(empty --version)"
    if "GNU" not in line:
        return None, (
            f"objdump is not GNU binutils (got {line!r}); "
            "RE-014 fingerprints require GNU objdump"
        )
    return path, line


CLASSES = ('identical', 'moved_only', 'changed', 'duplicate_ordered', 'equivalent_unpaired', 'unmatched_94',
           'unmatched_115')
LIMITATIONS = (
    'Structural drift only, not behavioural equivalence. A function here is one FDE extent: split hot/cold parts '
    'are separate rows and code without unwind data is absent. objdump is a linear sweep, so data inside .text '
    'can mis-decode. moved_only means equal after masking only address-like operands (branch targets outside the '
    'extent and RIP-relative displacements; immediates are compared verbatim because both targets are PIE without '
    'text relocations); data those addresses point to is '
    'not compared, so a changed .rodata constant reached through RIP can still be moved_only. changed pairs are '
    'inferred from call-graph position plus a size bound, not proven to be the same source function. '
    'duplicate_ordered pairs equal masked bodies from a duplicate group by address order inside the same gap '
    'between call-graph anchors; which copy pairs with which is an inference. '
    'equivalent_unpaired rows have a masked twin on the other side (possibly already paired) but no pairing of '
    'their own. Unmatched rows have no masked twin and are not '
    'proven additions or removals. Path rows describe embedded strings only, not code ownership.')

INSN_RE = re.compile(r'^\s*([0-9a-f]+):\t(.*)$')
SYMBOL_RE = re.compile(r'\s*<[^>]*>')
BRANCH_RE = re.compile(r'^(call|jmp|j[a-z]{1,3}|loop[a-z]*|jrcxz|jecxz)\s+(?:0x)?([0-9a-f]+)$')
RIP_RE = re.compile(r'-?0x[0-9a-f]+\(%rip\)')


def target_kind(target, starts, plt):
    if target in starts:
        return 'fde'
    if plt[0] <= target < plt[1]:
        return 'plt'
    return 'unknown'


def normalize(text, start, end, starts, plt):
    """Mask address-like operands in one objdump instruction.

    Returns (masked text, mask labels, direct call target or None). Intra-extent branches keep their
    extent-relative offset; other direct targets keep only their kind (FDE start, PLT or unknown).
    """
    text = ' '.join(SYMBOL_RE.sub('', text.split('#', 1)[0]).split())
    for prefix in ('notrack ', 'bnd '):
        if text.startswith(prefix):
            text = text[len(prefix):]
    branch = BRANCH_RE.match(text)
    if branch:
        op, target = branch.group(1), int(branch.group(2), 16)
        if start <= target < end:
            return f'{op} +{target - start:#x}', (), None
        kind = target_kind(target, starts, plt)
        return f'{op} @{kind}', (f'branch_{kind}',), target if op == 'call' and kind == 'fde' else None
    masks = []
    if RIP_RE.search(text):
        masks.append('rip')
        text = RIP_RE.sub('RIP', text)
    return text, tuple(masks), None


def fingerprint(extents, read, lines, plt):
    """Per-extent raw and masked SHA-256, mask counts and ordered unique direct FDE callees.

    `extents` are (start, end) pairs sorted by start; `read(start, end)` returns the extent bytes;
    `lines` is objdump output covering them.
    """
    rows = [{'start': s, 'end': e, 'size': e - s, 'raw': hashlib.sha256(read(s, e)).hexdigest(),
             'norm': hashlib.sha256(), 'insns': 0, 'masks': collections.Counter(), 'callees': []}
            for s, e in extents]
    starts = {r['start'] for r in rows}
    i = 0
    for line in lines:
        m = INSN_RE.match(line)
        if not m:
            continue
        va = int(m.group(1), 16)
        while i < len(rows) and va >= rows[i]['end']:
            i += 1
        if i == len(rows):
            break
        row = rows[i]
        if va < row['start']:
            continue
        masked, labels, callee = normalize(m.group(2), row['start'], row['end'], starts, plt)
        row['norm'].update(masked.encode() + b'\n')
        row['insns'] += 1
        row['masks'].update(labels)
        if callee is not None and callee not in row['callees']:
            row['callees'].append(callee)
    for row in rows:
        if row['insns'] == 0:
            raise ValueError(f"No instructions decoded inside extent {row['start']:#x}")
        row['norm'] = row['norm'].hexdigest()
    return rows


def unique_by(rows, key):
    counts = collections.Counter(r[key] for r in rows)
    return {r[key]: r for r in rows if counts[r[key]] == 1}


def verdict(x, y):
    return 'identical' if x['raw'] == y['raw'] else 'moved_only' if x['norm'] == y['norm'] else 'changed'


def match(old, new):
    """Deterministically pair rows. Returns {old_start: (new_start, evidence)}.

    Seeds are hashes unique on both sides (raw first, then masked). Each pair then propagates to
    unpaired callees and callers whose masked hash is unique within that neighbourhood, and to
    callees at the same call position when both callee lists have equal length, sizes are within 2x and
    neither body has a masked twin anywhere on the other side.
    """
    pairs, taken = {}, set()
    norms = ({r['norm'] for r in old}, {r['norm'] for r in new})
    by_old = {r['start']: r for r in old}
    by_new = {r['start']: r for r in new}
    for key in ('raw', 'norm'):
        left = unique_by([r for r in old if r['start'] not in pairs], key)
        right = unique_by([r for r in new if r['start'] not in taken], key)
        for value in sorted(left.keys() & right.keys()):
            pairs[left[value]['start']] = (right[value]['start'], f'unique-{key}-hash')
            taken.add(right[value]['start'])
    callers = ({}, {})
    for side, rows in enumerate((old, new)):
        for r in rows:
            for c in r['callees']:
                callers[side].setdefault(c, []).append(r['start'])
    work = sorted(pairs)
    while work:
        a = by_old[work.pop(0)]
        b = by_new[pairs[a['start']][0]]
        added = []

        def pair(x, y, evidence):
            pairs[x['start']] = (y['start'], f"{evidence}-of-{a['start']:#x}")
            taken.add(y['start'])
            added.append(x['start'])
        for relation, xs, ys in (('callee', a['callees'], b['callees']),
                                 ('caller', callers[0].get(a['start'], []), callers[1].get(b['start'], []))):
            left = unique_by([by_old[s] for s in xs if s not in pairs], 'norm')
            right = unique_by([by_new[s] for s in ys if s not in taken], 'norm')
            for value in sorted(left.keys() & right.keys()):
                pair(left[value], right[value], f'{relation}-norm')
        if len(a['callees']) == len(b['callees']):
            for ca, cb in zip(a['callees'], b['callees']):
                x, y = by_old[ca], by_new[cb]
                if (ca not in pairs and cb not in taken and x['norm'] not in norms[1] and y['norm'] not in norms[0]
                        and x['size'] <= 2 * y['size'] and y['size'] <= 2 * x['size']):
                    pair(x, y, 'callee-position')
        if added:
            work = sorted(set(work) | set(added))
    return pairs


def monotonic_anchors(pairs):
    """Longest chain of pairs increasing in both releases (ties broken by lowest #115 start)."""
    items = sorted((a, b) for a, (b, _) in pairs.items())
    tails, tail_idx, prev = [], [], [-1] * len(items)
    for i, (_, b) in enumerate(items):
        k = bisect.bisect_left(tails, b)
        if k:
            prev[i] = tail_idx[k - 1]
        if k == len(tails):
            tails.append(b)
            tail_idx.append(i)
        else:
            tails[k], tail_idx[k] = b, i
    chain, i = [], tail_idx[-1] if tail_idx else -1
    while i >= 0:
        chain.append(items[i])
        i = prev[i]
    return chain[::-1]


def order_duplicates(old, new, pairs):
    """Pair leftover equal-masked duplicates by address order inside each gap between monotonic anchors.

    A masked-hash group is paired in a gap only when that gap holds the same number of its members on
    both sides; other members stay unpaired. Returns {old_start: (new_start, evidence)}.
    """
    taken = {b for b, _ in pairs.values()}
    chain = monotonic_anchors(pairs)
    left_keys, right_keys = [a for a, _ in chain], [b for _, b in chain]
    groups = {}
    for side, rows, used, keys in ((0, old, pairs, left_keys), (1, new, taken, right_keys)):
        for r in rows:
            if r['start'] not in used:
                gap = bisect.bisect_left(keys, r['start'])
                groups.setdefault((r['norm'], gap), ([], []))[side].append(r['start'])
    out = {}
    for (_, gap), (xs, ys) in sorted(groups.items()):
        if xs and len(xs) == len(ys):
            for a, b in zip(sorted(xs), sorted(ys)):
                out[a] = (b, f'duplicate-order-gap-{gap}')
    return out


def classify(old, new):
    """Return sorted TSV rows: class, raw/masked verdicts, both coordinates, evidence."""
    pairs = match(old, new)
    ordered = order_duplicates(old, new, pairs)
    pairs = {**pairs, **ordered}
    taken = {b for b, _ in pairs.values()}
    by_new = {r['start']: r for r in new}
    # A masked twin anywhere on the other side, paired or not: such a row is a duplicate, not unmatched.
    twins = {r['norm'] for r in old} & {r['norm'] for r in new}
    rows = []
    for a in old:
        if a['start'] in pairs:
            b_start, evidence = pairs[a['start']]
            b = by_new[b_start]
            cls = 'duplicate_ordered' if a['start'] in ordered else verdict(a, b)
            rows.append([cls, str(a['raw'] == b['raw']).lower(), str(a['norm'] == b['norm']).lower(),
                         hex(a['start']), a['size'], hex(b_start), b['size'], evidence])
        else:
            rows.append(['equivalent_unpaired' if a['norm'] in twins else 'unmatched_94', '', '',
                         hex(a['start']), a['size'], '', '', f"masked-{a['norm'][:16]}"])
    for b in new:
        if b['start'] not in taken:
            rows.append(['equivalent_unpaired' if b['norm'] in twins else 'unmatched_115', '', '',
                         '', '', hex(b['start']), b['size'], f"masked-{b['norm'][:16]}"])
    return sorted(rows, key=lambda r: (int(r[3] or '-1', 16), int(r[5] or '-1', 16)))


def path_strings(datas, paths):
    """Check each catalogue path difference as an embedded `<crate>/src/<file>` string.

    #94 embeds absolute build paths and #115 relative ones, so a hit must start at a path boundary;
    std's `std/src/time.rs` must not count as `l1/src/time.rs`.
    """
    def present(data, needle):
        pos = data.find(needle)
        while pos >= 0:
            if pos == 0 or chr(data[pos - 1]) not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-':
                return True
            pos = data.find(needle, pos + 1)
        return False
    out = []
    for listed in ('absent115', 'added115'):
        for path in paths[listed]:
            crate, file = path.split('/', 1)
            needle = f'{crate}/src/{file}'.encode()
            out.append({'catalogue_list': listed, 'path': path,
                        **{f'string_in_{r}': present(datas[r], needle) for r in RELEASES}})
    return out


def dumps(obj):
    return json.dumps(obj, indent=2, sort_keys=True) + '\n'


def tsv_bytes(rows):
    handle = io.StringIO()
    writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
    writer.writerow(['class', 'raw_equal', 'masked_equal', 'start_94', 'size_94', 'start_115', 'size_115', 'evidence'])
    writer.writerows(rows)
    return handle.getvalue().encode()


def require_pie_without_textrel(data, secs):
    """Fail closed unless code cannot hold absolute image addresses as immediates.

    In an ET_DYN image with no text relocations every image address in code is RIP-relative, so
    immediates are constants and are compared verbatim instead of masked.
    """
    if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1 or int.from_bytes(data[16:18], 'little') != 3:
        raise ValueError('Expected a little-endian 64-bit ET_DYN (PIE) image')
    dynamic = secs.get('.dynamic')
    if dynamic is None:
        raise ValueError('No .dynamic section')
    for at in range(dynamic['offset'], dynamic['offset'] + dynamic['size'], 16):
        tag, value = int.from_bytes(data[at:at + 8], 'little'), int.from_bytes(data[at + 8:at + 16], 'little')
        if tag == 0:
            return
        if tag == 22 or (tag == 30 and value & 4):
            raise ValueError('Text relocations present; immediates could be image addresses')
    raise ValueError('Unterminated .dynamic section')


def load_release(release):
    from artifacts import check
    from elf_index import sections
    from fde_extents import fde_extents
    rel = f'artifacts/node/{release}/hl-node'
    item = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files'] if i['path'] == rel)
    check(ROOT / rel, item)
    data = (ROOT / rel).read_bytes()
    secs = {s['name']: s for s in sections(data)}
    text, plt = secs['.text'], secs['.plt']
    _, extents, _ = fde_extents(data)
    spans = [(f['start'], f['end']) for f in extents if f['section'] == '.text']
    require_pie_without_textrel(data, secs)

    def read(start, end):
        offset = text['offset'] + start - text['address']
        return data[offset:offset + end - start]
    objdump, version_or_reason = gnu_objdump()
    if not objdump:
        raise RuntimeError(version_or_reason)
    proc = subprocess.Popen([objdump, *OBJDUMP_ARGS, str(ROOT / rel)], stdout=subprocess.PIPE, text=True,
                            env={'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'})
    rows = fingerprint(spans, read, proc.stdout, (plt['address'], plt['address'] + plt['size']))
    proc.stdout.close()
    if proc.wait() != 0:
        raise RuntimeError('objdump failed')
    return item['sha256'], data, rows


def run(output_dir):
    if output_dir.exists() and any(output_dir.iterdir()):
        raise SystemExit(f'{output_dir} is not empty; choose a fresh output directory')
    digests, datas, rows = {}, {}, {}
    for release in RELEASES:
        digests[release], datas[release], rows[release] = load_release(release)
    objdump, version = gnu_objdump()
    if not objdump:
        raise RuntimeError(version)
    table = classify(rows['94'], rows['115'])
    catalogue = json.loads((ROOT / 'research/catalogue/components.json').read_text())['path_totals']
    paths = path_strings(datas, catalogue)
    tsv = tsv_bytes(table)
    counts, size94, size115 = collections.Counter(), collections.Counter(), collections.Counter()
    for r in table:
        counts[r[0]] += 1
        size94[r[0]] += r[4] or 0
        size115[r[0]] += r[6] or 0
    masks = {r: dict(sorted(sum((x['masks'] for x in rows[r]), collections.Counter()).items())) for r in RELEASES}
    summary = {
        'binary_sha256': digests,
        'objdump': version,
        'objdump_command': 'objdump ' + ' '.join(OBJDUMP_ARGS) + ' <binary>',
        'text_extents': {r: len(rows[r]) for r in RELEASES},
        'instructions': {r: sum(x['insns'] for x in rows[r]) for r in RELEASES},
        'masked_operands': masks,
        'classes': {c: counts[c] for c in CLASSES},
        'class_bytes_94': {c: size94[c] for c in CLASSES},
        'class_bytes_115': {c: size115[c] for c in CLASSES},
        'catalogue_path_strings': dict(sorted(collections.Counter(
            f"{p['catalogue_list']}:94={str(p['string_in_94']).lower()},115={str(p['string_in_115']).lower()}"
            for p in paths).items())),
        'drift_tsv_sha256': hashlib.sha256(tsv).hexdigest(),
        'limitations': LIMITATIONS,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / 'node-94-115-drift.tsv').write_bytes(tsv)
    (output_dir / 'node-94-115-paths.json').write_text(dumps(paths))
    (output_dir / 'node-94-115-drift.json').write_text(dumps(summary))
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output-dir', type=Path, default=ROOT / 'work/drift')
    summary = run(p.parse_args().output_dir)
    print(dumps(summary), end='')


if __name__ == '__main__':
    main()
