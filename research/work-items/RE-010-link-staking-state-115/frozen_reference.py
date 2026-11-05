"""Independent mathematical model preserved from the pre-Rust freeze script."""
def rows(m):return [{"key":k,"tag":t,"peer":p} for k,(t,p) in sorted(m.items())]
def state(rows):return {x["key"]:(x["tag"],x["peer"]) for x in rows}
def reference(mode,caller,payload,stakes,initial):
 # Manually transcribed branch and write contract, not instruction evaluation.
 a,b=(payload,caller) if mode=="request" else (caller,payload)
 m=dict(initial);writes=[];code=0
 if mode=="request":
  if a not in stakes:code=1
  elif a==b:code=2
  elif b in m and m[b][0]!=0:code=3
  elif a in m and m[a][0]!=0:code=4
  else:writes=[{"key":b,"tag":0,"peer":a}]
 else:
  if m.get(b)!=(0,a):code=5
  elif a in m and m[a][0]!=0:code=4
  else:writes=[{"key":b,"tag":1,"peer":a},{"key":a,"tag":2,"peer":b}]
 for w in writes:m[w["key"]]=(w["tag"],w["peer"])
 return {"outcome":code,"writes":writes,"relations":rows(m),"outerTag":14 if code==0 else 15,"innerTag":418 if code==0 else 367}
