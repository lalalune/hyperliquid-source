"""Hash durable packet files; omit the manifest itself and Python caches."""
import hashlib
from pathlib import Path

packet = Path(__file__).resolve().parent
rows = []
for path in sorted(packet.rglob('*')):
    if '__pycache__' in path.parts or path.suffix == '.pyc':
        continue
    if path.is_symlink():
        raise ValueError('Packet symlink refused')
    if path.is_file() and path.name != 'MANIFEST.sha256':
        rows.append(hashlib.sha256(path.read_bytes()).hexdigest() + '  '
                    + path.relative_to(packet).as_posix())
(packet / 'MANIFEST.sha256').write_bytes(('\n'.join(rows) + '\n').encode('utf-8'))
