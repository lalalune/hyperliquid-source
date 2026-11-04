"""Check sufficient reciprocal bounds against the actual formatter operands.

This is an arithmetic lemma, not an exhaustive CPU or compiler proof.
"""
import hashlib,json
import native
def prove(im):
 if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong115target')
 def u(a,n):return int.from_bytes(im.view.read(a,n),'little')
 specs=[(10000,64+u(0x46dbe19,1),u(0x46dbe05,8),(1<<64)-1),
        (100,u(0x46dbe2f,1),u(0x46dbe29,4),9999),
        (25,u(0x46dbe76,1),u(0x46dbe70,4),249)]
 if specs!=[(10000,75,0x346dc5d63886594b,(1<<64)-1),(100,19,0x147b,9999),(25,17,0x147b,249)]:raise ValueError('formatter operands changed')
 if u(0x46dbe1c,4)!=10000 or u(0x46dbe33,1)!=100 or u(0x46dbe79,1)!=100 or u(0x46dbe57,4)!=9999999:raise ValueError('formatter scale/loop changed')
 results=[]
 for divisor,shift,multiplier,maximum in specs:
  scale=1<<shift;delta=divisor*multiplier-scale
  if not 0<=delta<divisor or not maximum*delta<scale:raise ValueError('reciprocal sufficient bound failed')
  results.append(dict(divisor=divisor,shift=shift,multiplier=multiplier,maximum=maximum,delta=delta,max_error_numerator=maximum*delta,strict_bound=scale))
 if im.view.read(native.TABLE,200)!=b''.join(f'{n:02d}'.encode() for n in range(100)):raise ValueError('original digit table changed')
 return results
if __name__=='__main__':
 im=native.Image()
 try:print(json.dumps(prove(im),indent=2))
 finally:im.close()
