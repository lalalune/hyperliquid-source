#!/usr/bin/env python3
"""Finite algebra/sequence certificates; no machine code or native memory model."""
import itertools
import json


def need(ok,message):
    if not ok:raise ValueError(message)


def clamp(x,lo,hi):return max(lo,min(hi,x))


def split_relation():
    # Twelve insertion gaps in eleven ordered distinct items. Child labels are
    # stable identities, so split/reparent must retain each exactly once.
    results=[]
    for width,value_width in [(20,80),(20,0),(8,8)]:
        for i in range(12):
            keys=list(range(1,22,2));new=2*i;original=[(k,('value',k)) for k in keys]
            wanted=sorted(original+[(new,('value',new))])
            pivot=4 if i<5 else 5 if i<=6 else 6
            left=original[:pivot];promoted=original[pivot];right=original[pivot+1:]
            if i<=5:left.insert(i,(new,('value',new)));side='left';gap=i
            else:
                gap=0 if i==6 else i-7;right.insert(gap,(new,('value',new)));side='right'
            need(left+[promoted]+right==wanted,'split full relation')
            need(len(left) in (5,6) and len(right) in (5,6),'split occupancy')
            # For a child split, insert the new right child immediately after
            # the original left child. Partition at the promoted key boundary.
            old_children=[('old-child',j) for j in range(12)]
            expected_children=old_children[:i+1]+[('new-right',i)]+old_children[i+1:]
            lchild=old_children[:pivot+1];rchild=old_children[pivot+1:]
            if side=='left':lchild.insert(gap+1,('new-right',i))
            else:rchild.insert(gap+1,('new-right',i))
            need(lchild+rchild==expected_children,'split child identity/order')
            need(len(lchild)==len(left)+1 and len(rchild)==len(right)+1,'children counts')
            parent_links=[(side,j,c) for side,children in [('left',lchild),('right',rchild)] for j,c in enumerate(children)]
            need(len({c for _,_,c in parent_links})==13,'unique child ownership')
            results.append(dict(key_width=width,value_width=value_width,insertion=i,pivot=pivot,left=len(left),right=len(right),child_count=len(parent_links)))
    # Nonfull parent suffix shift, all legal counts/gaps, plus new root case.
    shifts=0
    for n in range(11):
        for i in range(n+1):
            a=list(range(n));b=a[:i]+['new']+a[i:]
            shifted=a.copy()+[None]
            for j in range(n,i,-1):shifted[j]=shifted[j-1]
            shifted[i]='new';need(shifted==b,'nonfull shift');shifts+=1
    return dict(full_splits=results,nonfull_gap_checks=shifts,new_root=dict(keys=1,children=2,height_delta=1),
                limit='Abstract ordered-token identity certificate, bound to all native copy/repair instructions by the manual induction; not execution of target instructions or proof of arbitrary corrupt trees.')


def arithmetic():
    small=0
    for x in range(-128,128):
        for a in range(128):
            actual=clamp(clamp(x-a,-128,127)+a,-128,127)
            need(actual==max(x,-128+a),'equal-size closed relation width8');small+=1
    lo=-(1<<63);hi=(1<<63)-1;wide=0
    for a in sorted(set([0,1,2,hi]+[1<<i for i in range(63)]+[(1<<i)-1 for i in range(1,64)])):
        for x in sorted(set([lo,lo+1,lo+a-1,lo+a,lo+a+1,-1,0,1,hi])):
            if not lo<=x<=hi:continue
            need(clamp(clamp(x-a,lo,hi)+a,lo,hi)==max(x,lo+a),'equal-size wide boundaries');wide+=1
    need(clamp(clamp(hi+1,lo,hi)-1,lo,hi)==hi-1,'sequential saturation counterexample')
    need(max(lo,lo+1)==lo+1,'same-size is not signed identity')
    return dict(exhaustive_width8_equal_size=small,width64_boundary_checks=wide,
                limit='Finite certificate supplements the general piecewise proof; sampled i64 boundaries alone are not an all-bits theorem.')


def check():return dict(tree=split_relation(),arithmetic=arithmetic())


if __name__=='__main__':print(json.dumps(check(),indent=2))
