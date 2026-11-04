#!/usr/bin/env python3
"""Static filter projections parameterized by opaque query results."""
import argparse
import verify


def operands(data):
    image = verify.Image(data)
    return {'mode_value': image.get(0x5b2b16f, 1)[0],
            'special_result': [image.get(a, 1)[0] for a in (0x4fbf450, 0x4fbf648)],
            'collector_branches': [image.get(a, 2).hex() for a in (0x5b7bde4, 0x5b7bff2, 0x5b7c191)],
            'report_flag_branch': image.get(0x5b2b251, 2).hex()}


def projection(query_low_byte, mode_low_byte, op, route=0):
    record = query_low_byte == op['special_result'][route]
    value = int(mode_low_byte == op['mode_value']) if record else query_low_byte
    branch = op['collector_branches'][0]
    if branch == '0f85':
        drop = value != 0
    elif branch == '0f84':
        drop = value == 0
    else:
        raise ValueError('unmodelled native collector branch')
    return record, not drop


def report(flag, mode, count, op):
    branch = op['report_flag_branch']
    first = bool(flag) if branch == '0f84' else not flag if branch == '0f85' else None
    verify.require(first is not None, 'unmodelled native report branch')
    return first and mode == op['mode_value'] and count != 0


def evaluate(data):
    image, op = verify.Image(data), operands(data)
    verify.require(op == {'mode_value': 3, 'special_result': [2, 2],
                         'collector_branches': ['0f85', '0f84', '741d'],
                         'report_flag_branch': '0f84'}, 'native filter operands')
    # The second/third collector edges jump to append on zero; the first loops on nonzero.
    counts = {'record_keep': 0, 'record_drop': 0, 'plain_keep': 0, 'plain_drop': 0}
    for q in range(256):
        for mode in range(256):
            actual = projection(q, mode, op)
            expected = (q == 2, q == 0 or (q == 2 and mode != 3))
            verify.require(actual == expected and projection(q, mode, op, 1) == expected, 'two query-site relations')
            counts[('record_' if actual[0] else 'plain_') + ('keep' if actual[1] else 'drop')] += 1
    report_true = 0
    for flag in range(256):
        for mode in range(256):
            for count in (0, 1):
                actual = report(flag, mode, count, op)
                verify.require(actual == (flag != 0 and mode == 3 and count != 0), 'report conjunction')
                report_true += actual
    counterfactuals = []
    for va, value, label, q, mode in [(0x4fbf450, 3, 'special query result', 2, 0),
                                     (0x5b2b16f, 2, 'mode selector', 2, 3),
                                     (0x5b7bde5, 0x84, 'collector polarity', 0, 0)]:
        changed = bytearray(data)
        changed[image.off(va)] = value
        mutated = projection(q, mode, operands(changed))
        original = projection(q, mode, op)
        verify.require(mutated != original, 'native operand counterfactual: ' + label)
        counterfactuals.append({'operand': label, 'va': hex(va), 'new_byte': value,
                               'query': q, 'mode': mode, 'original_record_keep': list(original), 'mutated_record_keep': list(mutated)})
    changed = bytearray(data)
    changed[image.off(0x5b2b252)] = 0x85
    verify.require(report(0, 3, 1, operands(changed)) and not report(0, 3, 1, op), 'report flag counterfactual')
    return {'native_operands': op, 'query_mode_cases': 65536, 'partition': counts,
            'report_cases': 131072, 'report_true_cases': report_true,
            'counterfactuals': counterfactuals, 'report_counterfactual': {'va': '0x5b2b252', 'new_byte': 133, 'flag': 0, 'mode': 3, 'count': 1},
            'rows': [{'query_low_byte': 0, 'record': False, 'kept': 'all modes'},
                     {'query_low_byte': 2, 'record': True, 'kept': 'mode != 3'},
                     {'query_low_byte': 'all other byte values', 'record': False, 'kept': False}],
            'order': ['collect with side-vector recording', 'rebuild collection', 'store 32-byte rebuilt header', 'optional report', 'copy 104-byte state to output'],
            'limits': 'The query routine remains opaque; raw 0/1/2 meanings are not assigned. All 256 byte values are a local projection domain, not proof of reachable query outputs. Timing, tracing, locks, sorting, deduplication, allocation and IP-policy semantics are not reconstructed. No target execution or emulation.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    data = verify.TARGET.read_bytes()
    verify.require(verify.sha(data) == verify.DIGEST, 'wrong target')
    text = verify.encoded(evaluate(data))
    if args.write:
        (verify.PACKET / 'relations.json').write_text(text)
    else:
        verify.require((verify.PACKET / 'relations.json').read_text() == text, 'relations drift')
    print('PASS: native query-result substitution, collection polarity and report conjunction')
