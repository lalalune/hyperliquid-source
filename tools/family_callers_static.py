#!/usr/bin/env python3
"""Pin the callers of the RE-006 gate family's remaining inner bodies.

Question (open edge 2 of RE-006-node115-gate-callee, PR #2608): the
gate callee's six-site pattern appears in six inner bodies -- two
clone triples -- but only the first triple's first two bodies
(0x2bbbba0, 0x2bbd0b0) have packeted callers (PR #2605/#2598: the
sub-lookup 0x2bb7270 and the helper 0x2c62820, three sites each).
Who calls the third body 0x2bbc750 and the whole 0x549xxxx mirror
triple (0x5493080 / 0x5493c30 / 0x5494720)?

Method: a raw byte scan of .text for every reference form to the
six body starts (e8/e9 rel32, rip-relative lea/load with and
without REX, ff15/ff25 through any GOT slot whose relocation
addend names a body) is a superset of every instruction-boundary
reference, so the negatives are exact.  Each candidate is then
validated against the decoded instruction rows of its containing
FDE, and every validated call site is pinned with the argument
bindings of its preceding 16 rows -- in particular rcx, the table
argument each inner body frame-saves and forwards to the gate.
The two already-packeted bodies are censused as controls and must
reproduce the #2598 result exactly.  Every string or file offset
resolves through the section table (.rodata identity-mapped,
.text delta 0x1000, .data.rel.ro delta 0x2000).
"""
import bisect
import hashlib
import json
import re
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifacts import ROOT  # noqa: E402
from elf_index import sections  # noqa: E402
from gate_callee_static import (  # noqa: E402
    _bindings, _body_export, _decode, _digest, _fde_index,
    _rela_entries, _section_bytes)

PACKET_DIR = ROOT / 'research' / 'work-items' / 'RE-006-node115-family-callers'
UPSTREAM_MAIN = '05bc2de303c05525b71e7e257426e741bc66a390'
NODE_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
NODE_SIZE = 105896032
EXPORT_MAX = 4096

TARGETS = {
    'inner_c750': (0x2BBC750, 0x2BBD0A3),
    'inner_fam_b1': (0x5493080, 0x5493C2D),
    'inner_fam_b2': (0x5493C30, 0x549471A),
    'inner_fam_b3': (0x5494720, 0x5495073),
}
CONTROLS = {
    'inner_ca': (0x2BBBBA0, 0x2BBC74D),
    'inner_s3': (0x2BBD0B0, 0x2BBDB9A),
}
BODIES = dict(TARGETS)
BODIES.update(CONTROLS)
# The caller map #2598 pinned for the two control bodies; the census
# below must reproduce it exactly or the method does not validate.
KNOWN_CALLERS = {
    'inner_ca': {0x2BB7270: 3},
    'inner_s3': {0x2C62820: 3},
}


class PacketError(AssertionError):
    """The artifact does not authenticate against node 115."""


def _hx(value):
    return f'0x{value:x}'


# === FROZEN DATA (injected) ===
FROZEN = {'bodies': {'inner_c750': [45860688, 45863075, '1e485c8260263eee0fb80e2871c1aaabde9f381b30e9159662d64e5a991a04fa'], 'inner_fam_b1': [88682624, 88685613, '3f64074e76c5885610e7e95dd1b66853e70f74d1e0b406fb3b9e25ac2c9abae3'], 'inner_fam_b2': [88685616, 88688410, 'ce21c020d8136334be1bb89799253a295aeab1ab10c688d4d5ef4744294f0c9e'], 'inner_fam_b3': [88688416, 88690803, '22fd22d11c09bf61900af25dcb36f4d1cf63865c696382add27794a1004db4ee'], 'inner_ca': [45857696, 45860685, 'f3e69ec027f6e24352c49415a533d2cc5e75443ce6681b3c6b51331a3446fa35'], 'inner_s3': [45863088, 45865882, '889874f504716879ed3af8bfab1a9f7909972bfee409b4125910ce5a114c1a6e']}, 'caller_digests': {'2a8a000-2a8a353': ['04a0a2001c365010a367114592cbc7389e5722d02205397d1ac99cad5ce790b0'], '2a8a360-2a8a5f2': ['5708405efc97313985930b07270964ce566d7fdac06a671c5485fb86d9f5c45d'], '2bb7270-2bb9893': ['6dbf7f8390953d24bdd5b7a225e83f3e1614fb79ee6b3f40d423f8728d44234b'], '2bb98a0-2bba0f5': ['c2a3d152b392078059824faab212a9ffbcce4fe16491afd70a968fd6cf4554e8'], '2bba100-2bbad77': ['19e6440ce606792af59b7315575552b625049198043174ce1c6e84eaa93e7ed1'], '2bbbb40-2bbbb96': ['e813a8fefda38cde3ac3e2880a9f77ba095fb643240c41fed70334911d2e81fe'], '2bdf8f0-2beafa1': ['225649f70f438609a3bf19555e1a01ce18bee7dfa80fb5179ba16225e4fa437c'], '2c62820-2c64862': ['9176b5c3361b91321a3b0cd99c2e90bf4538c1d7b21a68d63f68d5082e33fe96'], '548ebd0-548f424': ['d7152e5e368f3cc257a2043f31de8bd8d8f87909b49ef60a857da1fa330a1a39'], '548f430-54900a7': ['46ac35608029b946108866412311b1b42c3b6c4d178f143e16adbd67139148b2'], '5493020-5493076': ['cd2511971d2c4312923d3dec15b2eddf9d7aad54a818f0e3480b219bb053c70e'], '54a9c70-54b66a2': ['c8b4563b262d24c124d4ee54a7e00146f41aeb8dc57799cdf5db6970562fceac'], '54b66b0-54c2ae8': ['824ba23a3fbf24fe416e3f682d908c73e0c3504d82c6f1c8f20c79a61ee44d03'], '55a1de0-55a2044': ['ad83b6d25c3ca802603ebe57cb044f94f705516ab8f1cf7cab8c26c32945af1d'], '55a2050-55a22b4': ['25b2daca6bba5b9b7683215326b80fc163ec77df0567c4d1c9204268a262bf73'], '55a22c0-55a254f': ['f25ad7238419beb1b70fe6470fdce8e9dfea17eb9f8926073d0421a7fb81772b'], '55a2550-55a27df': ['c10d8e2cccf4fb9b5480dfc6b20c2febb72dce40a9bb9b15db2cb4a788f15bb2'], '55defd0-55e16ca': ['33773d4f76f1b5f3cb9790d204e74484410ba56dedeb90451221ee829c785c64'], '55e16d0-55e3762': ['22651e5a99e6a1279013c659838c4b561df8dd2d2e6ad97b0f8ce31b6b783b30']}, 'site_pins': {'0x2a8a054': ['e8f7261300', 'call   0x2bbc750'], '0x2a8a483': ['e8c8221300', 'call   0x2bbc750'], '0x2bb9f7f': ['e8cc270000', 'call   0x2bbc750'], '0x2bba400': ['e84b230000', 'call   0x2bbc750'], '0x2bba847': ['e8041f0000', 'call   0x2bbc750'], '0x2bbbb53': ['e8f80b0000', 'call   0x2bbc750'], '0x2be7e17': ['e83449fdff', 'call   0x2bbc750'], '0x2be8b84': ['e8c73bfdff', 'call   0x2bbc750'], '0x2be9991': ['e8ba2dfdff', 'call   0x2bbc750'], '0x2bb7bb9': ['e8e23f0000', 'call   0x2bbbba0'], '0x2bb8f8c': ['e80f2c0000', 'call   0x2bbbba0'], '0x2bb9515': ['e886260000', 'call   0x2bbbba0'], '0x55dfb48': ['e83335ebff', 'call   0x5493080'], '0x55dff4d': ['e82e31ebff', 'call   0x5493080'], '0x55e10b9': ['e8c21febff', 'call   0x5493080'], '0x55e1eb8': ['e8731debff', 'call   0x5493c30'], '0x55e2446': ['e8e517ebff', 'call   0x5493c30'], '0x55e33d2': ['e85908ebff', 'call   0x5493c30'], '0x548f278': ['e8a3540000', 'call   0x5494720'], '0x548f730': ['e8eb4f0000', 'call   0x5494720'], '0x548fb77': ['e8a44b0000', 'call   0x5494720'], '0x5493033': ['e8e8160000', 'call   0x5494720'], '0x54b3288': ['e89314feff', 'call   0x5494720'], '0x54b4304': ['e81704feff', 'call   0x5494720'], '0x54b4f9d': ['e87ef7fdff', 'call   0x5494720'], '0x54bf8a9': ['e8724efdff', 'call   0x5494720'], '0x54c0884': ['e8973efdff', 'call   0x5494720'], '0x54c150d': ['e80e32fdff', 'call   0x5494720'], '0x55a1e32': ['e8e928efff', 'call   0x5494720'], '0x55a20a2': ['e87926efff', 'call   0x5494720'], '0x55a23e3': ['e83823efff', 'call   0x5494720'], '0x55a2673': ['e8a820efff', 'call   0x5494720'], '0x2c62ff8': ['e8b3a0f5ff', 'call   0x2bbd0b0'], '0x2c63586': ['e8259bf5ff', 'call   0x2bbd0b0'], '0x2c644d2': ['e8d98bf5ff', 'call   0x2bbd0b0']}}


def _raw_ref_scan(data, secs, targets, slots):
    """Raw references to any target start in .text (superset scan)."""
    text_sec = next(s for s in secs if s['name'] == '.text')
    va0, fo0, size = text_sec['address'], text_sec['offset'], text_sec['size']
    blob = data[fo0:fo0 + size]
    wanted = set(targets)
    out = {t: {'call': [], 'jmp': [], 'lea': [], 'load': [],
               'slot_call': [], 'slot_jmp': []} for t in targets}
    for match in re.finditer(rb'\xe8', blob):
        i = match.start()
        va = va0 + i
        tgt = va + 5 + struct.unpack_from('<i', blob, i + 1)[0]
        if tgt in wanted:
            out[tgt]['call'].append(va)
    for match in re.finditer(rb'\xe9', blob):
        i = match.start()
        va = va0 + i
        tgt = va + 5 + struct.unpack_from('<i', blob, i + 1)[0]
        if tgt in wanted:
            out[tgt]['jmp'].append(va)
    for match in re.finditer(rb'\xff', blob):
        i = match.start()
        if i + 6 > size:
            continue
        va = va0 + i
        b1 = blob[i + 1]
        if b1 in (0x15, 0x25):
            slot = va + 6 + struct.unpack_from('<i', blob, i + 2)[0]
            if slot in slots:
                kind = 'slot_call' if b1 == 0x15 else 'slot_jmp'
                out[slots[slot]][kind].append(va)
    for i in range(size - 7):
        va = va0 + i
        b0, b1 = blob[i], blob[i + 1]
        if 0x48 <= b0 <= 0x4F and b1 in (0x8B, 0x8D) \
                and (blob[i + 2] & 0xC7) == 0x05:
            tgt = va + 7 + struct.unpack_from('<i', blob, i + 3)[0]
            if tgt in wanted:
                out[tgt]['lea' if b1 == 0x8D else 'load'].append(va)
        elif b0 in (0x8B, 0x8D) and (b1 & 0xC7) == 0x05:
            tgt = va + 6 + struct.unpack_from('<i', blob, i + 2)[0]
            if tgt in wanted:
                out[tgt]['lea' if b0 == 0x8D else 'load'].append(va)
    return out


def analyze(data):
    if len(data) != NODE_SIZE \
            or hashlib.sha256(data).hexdigest() != NODE_SHA256:
        raise PacketError('artifact does not authenticate as node 115')
    secs = sections(data)
    relas = _rela_entries(data, secs)
    fdes = _fde_index(data)
    starts = sorted(fdes)

    def owner(va):
        i = bisect.bisect_right(starts, va) - 1
        if i < 0 or not (starts[i] <= va < fdes[starts[i]][0]):
            raise PacketError(f'candidate {_hx(va)} is inside no FDE')
        return starts[i]

    bodies = {}
    for name, (start, end) in BODIES.items():
        dg = _digest(data, secs, start, end)
        if FROZEN['bodies'].get(name) not in (None, [start, end, dg]):
            raise PacketError(f'body {name} range or digest drift')
        if fdes.get(start, (None,))[0] != end:
            raise PacketError(f'body {name} is not an FDE extent')
        bodies[name] = {'start': _hx(start), 'end': _hx(end),
                        'size': end - start, 'sha256': dg,
                        'exported': True, 'role': 'target'
                        if name in TARGETS else 'control'}

    # No relocation addend names any of the six bodies, so no GOT
    # slot can reach them; the slot arm of the scan must stay empty.
    body_starts = {start for start, _e in BODIES.values()}
    slot_of = {}
    for r_offset, _rtype, _sym, addend in relas:
        if addend in body_starts:
            slot_of[r_offset] = addend
    if slot_of:
        raise PacketError(f'relocation addends name family bodies: '
                          f'{ { _hx(k): _hx(v) for k, v in slot_of.items()} }')

    raw = _raw_ref_scan(data, secs, body_starts, slot_of)
    raw_counts = {name: {kind: len(raw[start][kind])
                         for kind in raw[start]}
                  for name, (start, _e) in BODIES.items()}

    decoded = {}

    def rows_of(start):
        if start not in decoded:
            decoded[start] = _decode(data, secs, start, fdes[start][0])
        return decoded[start]

    censuses = {}
    caller_ranges = {}
    total_sites = 0
    for name, (start, end) in BODIES.items():
        sites = {}
        by_caller = {}
        for va in raw[start]['call']:
            cstart = owner(va)
            rows = rows_of(cstart)
            row = rows.get(va)
            if row is None or not row[0].startswith('e8'):
                continue  # raw-pattern hit inside another instruction
            disp = struct.unpack('<i', bytes.fromhex(row[0][2:10]))[0]
            if va + 5 + disp != start:
                continue
            if FROZEN['site_pins'].get(_hx(va)) not in (None, list(row)):
                raise PacketError(f'call site {_hx(va)} pin drift')
            sites[_hx(va)] = {
                'caller_fde': _hx(cstart),
                'pin': list(row),
                'bindings': _bindings(rows, va),
            }
            by_caller.setdefault(cstart, []).append(va)
            caller_ranges[cstart] = fdes[cstart][0]
        for kind in ('jmp', 'lea', 'load', 'slot_call', 'slot_jmp'):
            if raw[start][kind]:
                raise PacketError(
                    f'unexpected {kind} references to {name}: '
                    f'{[_hx(v) for v in raw[start][kind]]}')
        censuses[name] = {
            'sites': sites,
            'by_caller': {_hx(s): len(v)
                          for s, v in sorted(by_caller.items())},
            'raw_candidates': raw_counts[name],
        }
        total_sites += len(sites)

    for name, known in KNOWN_CALLERS.items():
        got = {int(s, 16): n for s, n in
               censuses[name]['by_caller'].items()}
        if got != known:
            raise PacketError(
                f'control census for {name} drifted from #2598: '
                f'{got} != {known}')

    callers = {}
    for cstart in sorted(caller_ranges):
        cend = caller_ranges[cstart]
        dg = _digest(data, secs, cstart, cend)
        key = f'{cstart:x}-{cend:x}'
        if FROZEN['caller_digests'].get(key) not in (None, [dg]):
            raise PacketError(f'caller FDE {key} digest drift')
        exported = cend - cstart <= EXPORT_MAX
        cname = f'caller_{cstart:x}'
        callers[cname] = {'start': _hx(cstart), 'end': _hx(cend),
                          'size': cend - cstart, 'sha256': dg,
                          'exported': exported, 'role': 'caller'}
        bodies[cname] = callers[cname]

    counters = {
        'bodies': len(bodies),
        'exported_bodies': sum(1 for b in bodies.values()
                               if b['exported']),
        'target_bodies': len(TARGETS),
        'control_bodies': len(CONTROLS),
        'caller_fdes': len(callers),
        'target_sites': sum(len(censuses[n]['sites']) for n in TARGETS),
        'control_sites': sum(len(censuses[n]['sites']) for n in CONTROLS),
        'total_sites': total_sites,
        'jmp_sites': 0, 'lea_refs': 0, 'load_refs': 0,
        'slot_refs': 0, 'rela_addends': 0,
    }
    return {
        'artifact': {'sha256': NODE_SHA256, 'size': NODE_SIZE},
        'upstream_main': UPSTREAM_MAIN,
        'bodies': bodies,
        'censuses': censuses,
        'counters': counters,
        'method_note': (
            'the raw scan covers e8/e9 rel32, rip-relative lea/load '
            'with and without a REX prefix, and ff15/ff25 through '
            'any slot whose relocation addend names a body (there '
            'are none); it is a superset of every instruction-'
            'boundary reference, so zero validated jmp/lea/load/'
            'slot references is an exact negative; raw e8 candidates '
            'that fall inside another instruction are dropped by '
            'the decoded-row validation and counted per body in '
            'raw_candidates'),
        'verdict': (
            'the gate family caller map is complete: '
            'inner_fam_b1 and inner_fam_b2 mirror the first triple '
            'exactly -- one caller each (0x55defd0, the mirror '
            'sub-lookup; 0x55e16d0, the mirror helper), three sites '
            'each, the table argument frame-saved and reloaded from '
            'one stack slot at all three sites -- while the two '
            'rbx-element bodies, inner_c750 and inner_fam_b3, are '
            'called from six and nine FDEs (9 and 14 sites): a '
            'same-size sub-lookup-shaped pair (0x2bba100 / '
            '0x548f430, two sites each), two 86-byte shims that '
            'shuffle the argument registers and forward their own '
            'rdx as the table argument (0x2bbbb40 / 0x5493020), '
            'context-embedded callers that pass lea [ctx+0x90] as '
            'the table argument, and repeat calls inside the large '
            'FDEs 0x2bdf8f0 / 0x54a9c70 / 0x54b66b0 whose later '
            'sites reload a frame-saved table pointer; no body of '
            'the six is reached by a jump, a lea, a load or a GOT '
            'slot anywhere in the binary'),
    }


def _all_ranges(records):
    out = []
    for body in records['bodies'].values():
        out.append((int(body['start'], 16), int(body['end'], 16)))
    return sorted(set(out))


def generate(data, out_dir):
    records = analyze(data)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    fdes = _fde_index(data)
    retained = set(_all_ranges(records))
    lines = []
    for start in sorted(fdes):
        end, line = fdes[start]
        if (start, end) in retained:
            lines.append(line)
    if len(lines) != len(retained):
        raise AssertionError(
            f'frames cover {len(lines)} of {len(retained)} FDEs')
    (out_dir / 'frames.txt').write_text('\n'.join(lines) + '\n')
    for name, body in records['bodies'].items():
        if not body['exported']:
            continue
        start, end = int(body['start'], 16), int(body['end'], 16)
        fname = f'{name}_full_body_{start:x}_{end:x}_objdump.txt'
        (out_dir / fname).write_text(_body_export(data, start, end))
    return records


def _verify():
    with tempfile.TemporaryDirectory() as tmp:
        generate((ROOT / 'artifacts/node/115/hl-node').read_bytes(), tmp)
        generated = {p.name: p.read_bytes() for p in Path(tmp).iterdir()}
    committed = {p.name: p.read_bytes() for p in PACKET_DIR.iterdir()
                 if p.name != 'README.md' and p.name != 'MANIFEST.sha256'}
    ok = generated == committed
    print(json.dumps({'matches': ok,
                      'packet': 'RE-006-node115-family-callers'}))
    return 0 if ok else 1


def main(argv):
    if len(argv) == 3 and argv[1] == 'generate':
        artifact = ROOT / 'artifacts/node/115/hl-node'
        generate(artifact.read_bytes(), argv[2])
        return 0
    if len(argv) == 2 and argv[1] == 'verify':
        return _verify()
    raise SystemExit(
        'usage: family_callers_static.py (generate <out-dir> | verify)')


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
