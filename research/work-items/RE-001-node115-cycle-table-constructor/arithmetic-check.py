#!/usr/bin/env python3
"""Integer identities and retained-data checks; not a target instruction evaluator."""
import hashlib
import json
import verify

C = 0x51eb851f
B = 1 << 39
MIN, MAX = -(1 << 31), (1 << 31)-1


def quotient(value, multiplier=C):
    product = value * multiplier
    return (product >> 39) + (1 if product < 0 else 0)


def trunc400(value):
    return value // 400 if value >= 0 else -((-value)//400)


def main():
    data=(verify.ROOT/'artifacts/node/115/hl-node').read_bytes()
    verify.require(len(data)==105896032 and hashlib.sha256(data).hexdigest()==verify.SHA,'node115 identity')
    elf=verify.Elf(data)
    immediate=int.from_bytes(elf.read(0x1628dd7,4),'little')
    verify.require(immediate==C,'authenticated reciprocal')
    verify.require(C*400-B==112 and 112*(1<<31)<B,'all-i32 reciprocal error bound')
    values={MIN,MIN+1,MAX-1,MAX,-801,-800,-799,-401,-400,-399,-1,0,1,399,400,401,799,800,801}
    for cycle in (-5368709,-2,-1,0,1,2,5368708):
        values.update(v for r in range(400) if MIN<=(v:=cycle*400+r)<=MAX)
    rows=[]
    for value in sorted(values):
        q=quotient(value);want=trunc400(value);rem=value-q*400
        residue=rem+(400 if rem<0 else 0)
        verify.require(q==want and 0<=residue<400 and residue==value%400,'quotient/residue identity')
        rows.append(dict(input_i32=value,quotient=q,residue=residue))
    table=elf.read(0x46be3b,400)
    table_rows=[]
    for residue,flag in enumerate(table):
        limit=52+((0x406>>(flag&31))&1)
        low=flag&7
        offset=low if low>=3 else low+7
        verify.require(flag<32 and limit in (52,53) and 3<=offset<=9,'observed flag bounds')
        table_rows.append(dict(residue=residue,flag=flag,second_input_limit=limit,offset=offset,span=366-(flag>>3)))
    # Genuine operand counterfactual on the authenticated immediate, with an
    # independent integer-division witness. No patched program is executed.
    changed=immediate^1
    verify.require(quotient(400,changed)!=trunc400(400),'reciprocal counterfactual witness')
    print(json.dumps(dict(target_sha256=verify.SHA,proof=dict(multiplier=C,scale=B,error_numerator=C*400-B,
        max_abs_i32=1<<31,error_bound_numerator=112*(1<<31),bound_strictly_below_scale=True,
        explanation='positive error < 1/400 cannot cross a residue step; negative signed-floor plus one yields truncation; Euclidean correction bounds the table index'),
        sampled_integer_identities=rows,table_rows=table_rows,table_sha256=hashlib.sha256(table).hexdigest(),
        counterfactual=dict(immediate_va='0x1628dd7',original=C,changed=changed,witness=400,expected=trunc400(400),changed_quotient=quotient(400,changed)),
        captured_binary_executed=False,limits='Scalar integer identities and table records only; no full constructor evaluator, valid-calendar or native behavior claim'),indent=2))


if __name__=='__main__':main()
