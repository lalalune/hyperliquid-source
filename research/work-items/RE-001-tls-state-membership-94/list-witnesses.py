#!/usr/bin/env python3
"""Illustrate the observed pointer-store sequence on synthetic circular lists.

This is an instruction-derived static interpretation control, not target execution
or a Rust implementation. Arbitrary/corrupted pointer graphs are not admitted.
"""
import json

NEXT, PREV = 0xc8, 0xd0


def cycle(nodes):
    return {(node, NEXT): nodes[(i+1) % len(nodes)] for i,node in enumerate(nodes)} | {
            (node, PREV): nodes[(i-1) % len(nodes)] for i,node in enumerate(nodes)}


def insert(mem, obj, head):
    mem[obj,NEXT] = obj
    mem[obj,PREV] = obj
    if head is not None:
        rdx = mem[obj,PREV]
        rcx = mem[head,PREV]
        mem[rdx,NEXT] = rcx
        mem[head,PREV] = rdx
        rsi = mem[obj,PREV]
        rdi = mem[rsi,NEXT]
        mem[obj,PREV] = rdi
        r8 = mem[head,PREV]
        mem[r8,NEXT] = head
        mem[rdi,NEXT] = obj
    return mem[obj,NEXT]


def remove(mem, obj, head):
    if obj == head:
        r9 = mem[obj,NEXT]
        if r9 == obj:
            return None
        head = r9
    r11 = mem[obj,NEXT]
    r10 = mem[obj,PREV]
    rax = mem[r11,PREV]
    mem[r10,NEXT] = rax
    rsi = mem[obj,NEXT]
    mem[rsi,PREV] = r10
    rdx = mem[obj,PREV]
    rdi = mem[rdx,NEXT]
    mem[obj,PREV] = rdi
    rcx = mem[rsi,PREV]
    mem[rcx,NEXT] = rsi
    mem[rdi,NEXT] = obj
    return head


def valid_cycle(mem, nodes):
    if not nodes:
        return
    expected = cycle(nodes)
    for key,value in expected.items():
        assert mem[key] == value, (key,value,mem[key])


def main():
    records = []
    for size in range(4):
        old = list(range(1,size+1))
        mem = cycle(old)
        head = insert(mem, 100, old[0] if old else None)
        expected = old + [100]
        valid_cycle(mem, expected)
        assert head == (old[0] if old else 100)
        records.append(dict(operation='insert',old_nodes=size,valid_cycle=True,head=head))
    for size in range(1,5):
        old = list(range(1,size+1))
        for obj in old:
            mem = cycle(old)
            head = remove(mem,obj,old[0])
            remain = [n for n in old if n != obj]
            valid_cycle(mem,remain)
            assert mem[obj,NEXT] == obj and mem[obj,PREV] == obj
            assert head == (remain[0] if remain else None)
            records.append(dict(operation='remove',old_nodes=size,removed=obj,valid_cycle=True,detached_selflinked=True,head=head))
    print(json.dumps(dict(cases=len(records),witnesses=records,captured_binary_executed=False,claim='conditional pointer-topology interpretation only'),indent=2))


if __name__ == '__main__':
    main()
