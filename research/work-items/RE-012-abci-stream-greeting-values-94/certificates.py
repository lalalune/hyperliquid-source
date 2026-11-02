"""Finite index/algebra checks supporting the manual induction, not an ISA model.

No decoded instructions, register state, target memory or native evaluator enter
these checks. Independent sequence insertion is compared to the manually proved
split formulas; the unbounded tree/charge theorem still requires the written
induction and explicit external premises.
"""
import json


def need(ok, message):
    if not ok:
        raise ValueError(message)


def generate():
    nonfull=[]; split=[]; parent=[]
    for n in range(11):
        for gap in range(n+1):
            old=list(range(n)); new='new'
            direct=old[:gap]+[new]+old[gap:]
            moved={i if i<gap else i+1:value for i,value in enumerate(old)}
            moved[gap]=new
            need([moved[i]for i in range(n+1)]==direct,'paired sequence insertion')
            for width,base,end in [(20,0x320,0x3fc),(72,8,0x320)]:
                src=base+width*gap;dst=src+width;length=width*(n-gap)
                need(base<=src<=end and dst+length<=end,'suffix span capacity')
            nonfull.append([n,gap,n-gap])
            # Internal node has n+1 children. Insert a right child after the
            # existing gap's left child; all other child identities preserve order.
            children=list(range(n+1)); expected=children[:gap+1]+['right']+children[gap+1:]
            shifted={i if i<=gap else i+1:value for i,value in enumerate(children)}
            shifted[gap+1]='right'
            need([shifted[i]for i in range(n+2)]==expected,'parent child insertion')
            need(0x400+8*(n+2)<=0x460,'internal child span')
            # Every rewritten edge index, including scalar-prefix and four-wide
            # groups, forms exactly the half-open changed range.
            count=n-gap+1; prefix=count%4
            covered=list(range(gap+1,gap+1+prefix))
            for start in range(gap+1+prefix,n+2,4):covered.extend(range(start,start+4))
            need(covered==list(range(gap+1,n+2)),'child parent-index repair partition')
            parent.append([n,gap,count,prefix])
    for gap in range(12):
        if gap<=4:p,side,j=4,'left',gap
        elif gap==5:p,side,j=5,'left',5
        elif gap==6:p,side,j=5,'right',0
        else:p,side,j=6,'right',gap-7
        old=list(range(11)); left=old[:p];right=old[p+1:]
        chosen=left if side=='left' else right
        chosen.insert(j,'new')
        need(left+[old[p]]+right==old[:gap]+['new']+old[gap:],'split relation')
        need(sorted([len(left),len(right)])==[5,6],'split minimum occupancy')
        # The same pending insertion splits an internal node; its ordered child
        # intervals divide at p+1, and insertion adds the right child immediately
        # after the old gap's left child in the selected half.
        kids=list(range(12));lk=kids[:p+1];rk=kids[p+1:]
        (lk if side=='left' else rk).insert(j+1,'new-right')
        need(lk+rk==kids[:gap+1]+['new-right']+kids[gap+1:],'split child relation')
        need(len(lk)==len(left)+1 and len(rk)==len(right)+1,'split child counts')
        split.append(dict(gap=gap,pivot=p,side=side,new_gap=j,left_count=len(left),right_count=len(right)))

    # Manually traced unaligned copies. Overlap is permitted only when both
    # stores assign the same source offset to the same destination offset.
    copy_specs={
        'record2048':(2048,[(0,4),(3,4),(7,1),(8,4),(11,4),(15,8),(23,2025)]),
        'nested_hash32':(32,[(0,1),(1,4),(5,2),(7,1),(8,8),(15,8),(23,8),(31,1)]),
        'signature65':(65,[(0,16),(16,16),(32,16),(48,16),(64,1)]),
    }
    copies={}
    for name,(size,segments) in copy_specs.items():
        coverage=[0]*size
        for start,length in segments:
            need(0<=start and start+length<=size,'active copy bounds')
            for i in range(start,start+length):coverage[i]+=1
        need(all(n>=1 for n in coverage),'active copy coverage')
        copies[name]=dict(bytes=size,segments=segments,overlapping_bytes=sum(n>1 for n in coverage))

    # Boundary representatives accompany the written universally quantified
    # charge proof; this list is explicitly not exhaustive all-u64 execution.
    maximum=(1<<64)-1; charge=[]
    for k in [0,1,4,8,20,32,96,2048]:
        for old in sorted({0,1,maximum,maximum-k,min(maximum,max(0,maximum-k+1))}):
            total=old+k
            for limit in sorted({0,maximum,old,min(total,maximum),max(0,min(total,maximum)-1)}):
                overflow=total>maximum
                post=old if overflow else total
                refused=overflow or total>limit
                need(overflow==(old>maximum-k),'checked add threshold identity')
                if k==1 and not overflow:need((old>=limit)==(total>limit),'single byte old-limit equivalence')
                charge.append([old,k,limit,post,refused])
    for n in range(1,129):
        for completed in range(n):
            reserved=96*(n-completed)+85*completed
            need(reserved>=96,'map refund nonnegative')
            after=reserved-96
            need(after+85<=reserved,'row does not exceed reservation')
            need(after+85==96*(n-completed-1)+85*(completed+1),'map charge induction step')
    report=dict(schema=1,nonfull_cases=len(nonfull),full_split_cases=len(split),parent_repair_cases=len(parent),
                split=split,copy_coverage=copies,charge_boundary_cases=len(charge),
                group_cost=32,signature_cost=65,key_signature_cost=85,map_reservation_per_row=96,
                method='Independent finite index identities and boundary arithmetic; not native execution, not an instruction interpreter, not a replacement for manual induction.')
    return (json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
