"""Check a fresh native regeneration against the frozen packet, without changing it."""
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('regenerated_packet', type=Path)
args = parser.parse_args()
packet = Path(__file__).resolve().parent
fresh = args.regenerated_packet.resolve()
names = ['summary.json', 'selected-bodies.json', 'versions.json']
names += ['native/' + p.name for p in sorted((packet / 'native').iterdir()) if p.is_file()]
actual_names = sorted(str(p.relative_to(fresh)) for p in fresh.rglob('*') if p.is_file())
if actual_names != sorted(names):
    raise SystemExit('Regenerated file inventory differs')
for name in names:
    if (fresh / name).read_bytes() != (packet / name).read_bytes():
        raise SystemExit('Regeneration differs: ' + name)
summary = json.loads((packet / 'summary.json').read_text())
assert summary['projection_matches'] == 135313
assert len(summary['corruption_controls']) == 9
print(f'Frozen native packet reproduces byte-for-byte: {len(names)} files, '
      f"{summary['projection_matches']} FDE projections; 9 comparator corruptions rejected.")
