"""Attack parser assumptions with frozen native records and reject wrong target input."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from reconcile import compare, parse

packet = Path(__file__).resolve().parent
gnu_text = (packet / 'native/gnu-selected-frames.txt').read_text()
llvm = parse(packet / 'native/llvm-selected-frames.txt', 'llvm')[1]
baseline = parse(packet / 'native/gnu-selected-frames.txt', 'gnu')
compare(baseline[1], llvm)
if baseline[2] != 1:
    raise SystemExit('Selected CIE-only control is absent')
outcomes = {}
with tempfile.TemporaryDirectory(prefix='node115-cfa-controls-') as directory:
    root = Path(directory)
    cases = {
        'changed_inherited_cie_cfa': gnu_text.replace('rsp+8', 'rsp+16', 1),
        'unsupported_cfa_register': gnu_text.replace('rsp+8', 'rax+8', 1),
        'missing_referenced_cie': gnu_text.replace('FDE cie=00000000', 'FDE cie=ffffffff', 1),
    }
    for name, text in cases.items():
        path = root / (name + '.txt')
        path.write_text(text)
        try:
            compare(parse(path, 'gnu')[1], llvm)
        except ValueError as error:
            outcomes[name] = str(error)
        else:
            raise SystemExit('Native corruption accepted: ' + name)
    wrong_repo = root / 'wrong-repository'
    target = wrong_repo / 'artifacts/node/115/hl-node'
    target.parent.mkdir(parents=True)
    target.write_bytes(b'not the authenticated node115 image\n')
    output = root / 'must-not-exist'
    result = subprocess.run([sys.executable, str(packet / 'reconcile.py'),
                             str(wrong_repo), str(root / 'no-native'), str(output)],
                            capture_output=True, text=True)
    if result.returncode != 1 or 'Target identity mismatch' not in result.stderr or output.exists():
        raise SystemExit('Wrong-target refusal did not precede native reads/output')
    outcomes['wrong_target_before_native_reads_and_output'] = 'rejected, no output created'
print(json.dumps({'native_parser_and_input_controls': outcomes, 'rejected': len(outcomes)}, indent=2))
