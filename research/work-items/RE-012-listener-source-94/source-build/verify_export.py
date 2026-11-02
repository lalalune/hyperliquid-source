"""Offline selected-export consistency; full ELF provenance needs compare.py."""
import hashlib
import json
from pathlib import Path

from compare import compare, masked, need

HERE = Path(__file__).resolve().parent


def main():
    record = json.loads((HERE / 'comparison.json').read_text())
    target = (HERE / 'target-body.bin').read_bytes()
    candidate = (HERE / 'candidate-body.bin').read_bytes()
    target_fields, candidate_fields = record['target_mask_fields'], record['candidate_mask_fields']
    need(hashlib.sha256(target).hexdigest() == record['target_body_sha256'], 'target body hash')
    need(hashlib.sha256(candidate).hexdigest() == record['candidate_body_sha256'], 'candidate body hash')
    need(len(target) == 305 and len(candidate) == 364, 'complete selected extents')
    for raw, fields in ((target, target_fields), (candidate, candidate_fields)):
        for field in fields:
            offset = field['offset']
            need(field['width'] == 4 and raw[offset - 2:offset] == b'\xff\x15', 'only actual call displacement positions')
    need(masked(target, target_fields) == (HERE / 'target-relocation-masked.bin').read_bytes(), 'target mask replay')
    need(masked(candidate, candidate_fields) == (HERE / 'candidate-relocation-masked.bin').read_bytes(), 'candidate mask replay')
    result = compare(target, target_fields, candidate, candidate_fields)
    need(result == record['comparison'] and not result['raw_equal'] and not result['relocation_only_equal'], 'negative comparison preserved')
    need(len(target_fields) == 7 and len(candidate_fields) == 9, 'actual call counts')
    controls = {}
    controls['identity'] = compare(candidate, candidate_fields, candidate, candidate_fields)
    changed = bytearray(candidate); changed[candidate_fields[0]['offset']] ^= 1
    controls['actual_displacement_change'] = compare(candidate, candidate_fields, bytes(changed), candidate_fields)
    changed = bytearray(candidate); changed[0] ^= 1
    controls['nonrelocation_change'] = compare(candidate, candidate_fields, bytes(changed), candidate_fields)
    wrong = [dict(f) for f in candidate_fields]; wrong[0]['symbol'] = 'wrong_import'
    controls['import_identity_change'] = compare(candidate, candidate_fields, candidate, wrong)
    controls['truncation'] = compare(candidate, candidate_fields, candidate[:-1], candidate_fields)
    need(controls == record['normalization_controls'], 'all five controls replay')
    summary = json.loads((HERE / 'build-summary.json').read_text())
    for artifact in ('liblibc.rlib', 'libmio.rlib', 'mio.o'):
        item = summary['linux_artifacts_repeat'][artifact]
        need(item['identical'] and item['initial_sha256'] == item['portable_sha256'], 'Linux repeated artifact hash')
    print(json.dumps({'status': 'pass', 'complete_windows': 1, 'raw_equal': 0,
                      'relocation_only_equal': 0, 'unmatched': 1, 'normalizer_controls': 5,
                      'linux_artifacts_repeat': 3, 'captured_execution': False,
                      'scope': 'selected-export consistency; re-run compare.py on authenticated full ELF and rebuilt object for external provenance'}, indent=2))


if __name__ == '__main__':
    main()
