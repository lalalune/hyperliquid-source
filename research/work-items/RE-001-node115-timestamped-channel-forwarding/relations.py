#!/usr/bin/env python3
"""Bound timestamped forwarding decisions to native operands; never execute target code."""
import argparse
from fractions import Fraction
import itertools
import json
import math
import struct
import verify


def operands(data):
    image = verify.Image(data)
    read = lambda va, n=1: int.from_bytes(image.get(va, n), 'little')
    return {
        'first_compare_condition': read(0x2e07446),
        'forward_continue_tag': read(0x2e07350),
        'receive_pending_state': read(0x2e074e4),
        'wait_pending_state': read(0x2e074ea),
        'terminal_state': read(0x2e07543),
        'zero_wait_jne': read(0x2d4f7c2),
        'divisor': struct.unpack('<d', image.get(0x458d50, 8))[0],
        'infinity': struct.unpack('<d', image.get(0x459010, 8))[0],
        'resume_targets': [hex(0x616080 + x) for x in struct.unpack('<5i', image.get(0x616080, 20))],
        'accepted_send_tag': read(0x2ced9f2),
    }


def signed32(value):
    return value - (1 << 32) if value & (1 << 31) else value


def earlier(timestamp, now, condition):
    if timestamp[0] != now[0]:
        if condition == 0x9c:
            return signed32(timestamp[0]) < signed32(now[0])
        if condition == 0x92:
            return timestamp[0] < now[0]
        raise AssertionError('unsupported counterfactual condition')
    return timestamp[1:] < now[1:]


def delay(timestamp, now, supplied_difference, o):
    if earlier(timestamp, now, o['first_compare_condition']):
        return 0.0, False
    seconds, nanos = supplied_difference
    if seconds < 0 and nanos > 0:
        seconds += 1
        nanos -= 1_000_000_000
    value = max(0.0, float(seconds) + float(nanos) / o['divisor'])
    return (0.0 if value == o['infinity'] or math.isnan(value) else value), True


def transition(phase, receive_pending, record_tag, duration, wait_pending, send_tag, o):
    events = []
    if phase == 'receive':
        events.append('receive')
        if receive_pending:
            return events, o['receive_pending_state']
        if record_tag == 0:
            return events + ['cleanup'], o['terminal_state']
        events.append('sample_clock')
    events.append('wait_adapter')
    nested = duration != 0.0
    if o['zero_wait_jne'] == 0x74:
        nested = not nested
    if nested:
        events.append('nested_wait')
        if wait_pending:
            return events, o['wait_pending_state']
    events.append('forward')
    if send_tag == o['forward_continue_tag']:
        return events + ['next_receive'], 'loop'
    return events + ['cleanup'], o['terminal_state']


def evaluate(data):
    o = operands(data)
    verify.require(o['first_compare_condition'] == 0x9c and o['forward_continue_tag'] == 5,
                   'comparison and forward operands')
    verify.require([o[k] for k in ['receive_pending_state', 'wait_pending_state', 'terminal_state']] == [3, 4, 1],
                   'continuation state operands')
    verify.require(o['zero_wait_jne'] == 0x75 and o['divisor'] == 1_000_000_000.0 and o['infinity'] == math.inf,
                   'zero wait and duration constants')
    verify.require(o['resume_targets'] == ['0x2e071e8', '0x2e07242', '0x2e0724f', '0x2e071f1', '0x2e072bc'],
                   'worker resume targets')
    verify.require(o['accepted_send_tag'] == 5, 'sender tag binding')
    comparison_cases = 0
    triples = list(itertools.product((0, 1, 0x7fffffff, 0x80000000, 0xffffffff), (0, 1, 0xffffffff), (0, 1, 0xffffffff)))
    for a, b in itertools.product(triples, repeat=2):
        expected = (signed32(a[0]), a[1], a[2]) < (signed32(b[0]), b[1], b[2])
        verify.require(earlier(a, b, o['first_compare_condition']) == expected, 'mixed lexicographic order')
        comparison_cases += 1
    duration_cases = 0
    for seconds, nanos in itertools.product((-(1 << 63), -3, -1, 0, 1, 3, 1 << 52, (1 << 63) - 1),
                                            (-1_000_000_000, -500_000_000, -1, 0, 1, 500_000_000, 999_999_999)):
        value, called = delay((1, 0, 0), (0, 0, 0), (seconds, nanos), o)
        exact = max(Fraction(0), Fraction(seconds) + Fraction(nanos, 1_000_000_000))
        expected = float(exact)
        verify.require(called and math.isclose(value, expected, rel_tol=0, abs_tol=2 * math.ulp(expected)),
                       'independent rational duration bound')
        duration_cases += 1
    verify.require(delay((0xffffffff, 0, 0), (0, 0, 0), (10, 0), o) == (0.0, False),
                   'earlier timestamp bypasses difference helper')
    verify.require(delay((1, 2, 3), (1, 2, 3), (0, 0), o) == (0.0, True),
                   'equal timestamp takes difference path')
    transition_cases = 0
    for phase, pending, record, duration, waiting, tag in itertools.product(
            ('receive', 'wait'), (False, True), (0, 1, 2, 0xffffffff), (0.0, -0.0, 0.25),
            (False, True), (0, 1, 4, 5, 6, 255)):
        events, state = transition(phase, pending, record, duration, waiting, tag, o)
        if phase == 'receive' and pending:
            verify.require((events, state) == (['receive'], 3), 'receive suspension')
        elif phase == 'receive' and record == 0:
            verify.require((events, state) == (['receive', 'cleanup'], 1), 'terminal record before clock/wait')
        elif duration != 0 and waiting:
            verify.require(state == 4 and 'forward' not in events, 'wait suspension before forward')
        else:
            verify.require('forward' in events and state == ('loop' if tag == 5 else 1), 'exact forward continuation')
        if phase == 'wait':
            verify.require('receive' not in events and 'sample_clock' not in events, 'wait resume retains held record')
        if duration == 0.0:
            verify.require('nested_wait' not in events, 'zero duration bypass')
        transition_cases += 1
    controls = []
    for va, value, witness in [
        (0x2e07446, 0x92, 'signed timestamp'),
        (0x2e07350, 4, 'forward continue'),
        (0x2d4f7c2, 0x74, 'zero delay')]:
        changed = bytearray(data)
        changed[verify.Image(data).off(va)] = value
        altered = operands(changed)
        if witness == 'signed timestamp':
            before = delay((0xffffffff, 0, 0), (0, 0, 0), (10, 0), o)
            after = delay((0xffffffff, 0, 0), (0, 0, 0), (10, 0), altered)
        else:
            args = ('wait', False, 1, 0.0, True, 5)
            before, after = transition(*args, o), transition(*args, altered)
        verify.require(before != after, 'counterfactual survived')
        controls.append({'va': hex(va), 'byte': value, 'witness': witness, 'before': before, 'after': after})
    return json.loads(verify.encoded({'comparison_cases': comparison_cases, 'duration_cases': duration_cases,
        'transition_cases': transition_cases, 'native_operands': {**o, 'infinity': '+infinity'},
        'counterfactuals': controls,
        'limits': 'Date difference and poll outcomes are supplied boundaries. These relations establish local ordering and projection, not runtime timing, fairness, concurrency, message delivery, or complete receiver/timer semantics. No target instructions are executed or emulated.'}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    data = verify.TARGET.read_bytes()
    verify.require(verify.sha(data) == verify.DIGEST, 'wrong target')
    output = verify.encoded(evaluate(data))
    if args.write:
        (verify.PACKET / 'relations.json').write_text(output)
    else:
        verify.require((verify.PACKET / 'relations.json').read_text() == output, 'relations drift')
    print('PASS: timestamped forwarding, duration bounds and three operand counterfactuals')
