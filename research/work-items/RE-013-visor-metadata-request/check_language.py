"""Abstract request/cache decision specifications, never a captured-instruction evaluator."""
import json

def require(value,message):
    if not value:raise ValueError(message)

def packed(error):return ((error&0xffffffff)<<32)|2

def procedural(entry,main,reloaded,probe,probe_error,error):
    if entry==2:return (3,None,None,0,0)
    if main!=0xffffffff:return (1,1 if entry==0 else None,None,1,0)
    original=packed(error)
    if reloaded==1:return (2,None,original,1,0)
    if probe==0xffffffff:
        cleanup=1
        if probe_error==14:return (2,1,original,2,cleanup)
    else:cleanup=0
    return (3,2,None,2,cleanup+1)

def declarative(entry,main,reloaded,probe,probe_error,error):
    bypass=entry==2
    success=not bypass and main!=0xffffffff
    saved_error=not bypass and not success and reloaded==1
    probe_needed=not bypass and not success and not saved_error
    preserve=probe_needed and probe==0xffffffff and probe_error==14
    fallback=probe_needed and not preserve
    tag=1 if success else 2 if saved_error or preserve else 3
    write=1 if (success and entry==0) or preserve else 2 if fallback else None
    word=packed(error) if tag==2 else None
    requests=0 if bypass else 2 if probe_needed else 1
    cleanup=int(probe_needed and probe==0xffffffff)+int(fallback)
    return tag,write,word,requests,cleanup

def wrapper(core_tag,core_word,core_mode,fallback_return,fallback_error,fallback_mode):
    # Conditional on already reaching the wrapper's post-admission branch.
    if core_tag!=3:return core_tag,core_word,core_mode if core_tag==1 else None
    if fallback_return==0xffffffff:return 2,packed(fallback_error),None
    return 0,None,fallback_mode&0xffffffff

def main():
    cases=[(0,0xffffffff,1,0xffffffff,14,5,(2,None,packed(5),1,0)),
           (1,0xffffffff,0,0xffffffff,14,5,(2,1,packed(5),2,1)),
           (0,0xffffffff,0,0xffffffff,38,5,(3,2,None,2,2)),
           (0,0xffffffff,0,0,14,5,(3,2,None,2,1)),
           (2,0,1,0,14,5,(3,None,None,0,0)),
           (0,7,0,0,0,5,(1,1,None,1,0)),
           (255,0,1,0,0,5,(1,None,None,1,0))]
    for *args,expected in cases:
        require(procedural(*args)==declarative(*args)==expected,'Explicit protocol fixture fails')
    scenarios=[(0,0,0),(7,0,0),(0xffffffff,0,14),(0xffffffff,7,38),
               (0xffffffff,0xffffffff,14),(0xffffffff,0xffffffff,38),(0xffffffff,0xffffffff,0xffffffff)]
    count=0
    for entry in range(256):
        for reloaded in range(256):
            error=(entry<<24)|(reloaded<<16)|5
            for ret,probe,probe_error in scenarios:
                a=procedural(entry,ret,reloaded,probe,probe_error,error)
                require(a==declarative(entry,ret,reloaded,probe,probe_error,error),'Abstract specifications differ')
                if a[0]==2:require(a[2]==packed(error),'Original error not preserved')
                count+=1
    # Pure integer projections, not an OS struct or a captured call fixture.
    modes=0
    for mode in range(65536):
        require(wrapper(1,None,mode,0,0,0)==(1,None,mode),'Mode projection differs')
        require(((mode&0xf000)==0x4000)==(0x4000<=mode<=0x4fff),'Mode bit interval differs')
        modes+=1
    require(wrapper(3,None,None,0xffffffff,37,0)==(2,packed(37),None),'Fallback error must be the later stat64 error')
    require(wrapper(2,packed(5),None,0xffffffff,37,0)==(2,packed(5),None),'Tag2 must bypass stat64')
    require(wrapper(3,None,None,7,37,0x12344000)==(0,None,0x12344000),'Fallback success projection fails')
    # Concrete witnesses contradict each listed false simplification.
    witnesses=['entry-cache-is-the-reloaded-cache','only-zero-is-success','probe-error-replaces-original',
               'probe-38-is-the-preserving-case','initial-cache-2-still-requests','success-always-writes-cache-1',
               'probe-success-proves-availability','wrapper-always-preserves-first-error']
    # Each counterexample is encoded in the explicit fixtures or wrapper rows above.
    require(cases[0][-1]!=cases[1][-1],'Reload witness is vacuous')
    require(procedural(0,7,0,0,0,5)[0]==1,'Nonzero-success witness is vacuous')
    require(procedural(0,0xffffffff,0,0xffffffff,14,5)[2]!=packed(14),'Original-error witness is vacuous')
    require(procedural(0,0xffffffff,0,0xffffffff,38,5)[0]==3,'Probe discriminator witness is vacuous')
    require(procedural(2,0,0,0,0,5)[3]==0,'Bypass witness is vacuous')
    require(procedural(255,0,0,0,0,5)[1] is None,'Cache-store witness is vacuous')
    require(procedural(0,0xffffffff,0,0,14,5)[0]==3,'Probe-success witness is vacuous')
    require(wrapper(3,None,None,0xffffffff,37,0)[1]!=packed(5),'Wrapper-error witness is vacuous')
    print(json.dumps({'scope':'Abstract decision-table/integer support for addressed manual proof; not native execution or a CPU comparator.',
        'explicitProtocolFixtures':len(cases),'cachePairScenarioRows':count,'entryCacheBytes':256,'reloadedCacheBytes':256,
        'returnProbeScenarios':len(scenarios),'modeProjectionWords':modes,'wrapperFixtures':3,
        'falseSimplificationWitnesses':witnesses,'capturedExecution':False,'instructionEvaluation':False},sort_keys=True))

if __name__=='__main__':main()
