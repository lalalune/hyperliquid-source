import itertools, random
MODEL = 'runtime_state_static'
COMPONENT = 'node94-runtime-bracket'
OWNERS = [42140400, 42141344, 42142288, 42143264]
MUTANTS = {
 'wrong_prior_state': ('prior == 2', 'prior == 3'),
 'wrong_after_state': ('after != 2', 'after != 3'),
 'invert_context': ('!context_present', 'context_present'),
 'wrong_enter_state': ('pub const BODY_STATE: u8 = 2;', 'pub const BODY_STATE: u8 = 3;'),
 'wrong_restore': ('(Route::RestorePriorState, Some(prior))', '(Route::RestorePriorState, Some(after))'),
 'wrong_flag_mask': ('word & 0xff00', 'word & 0x00ff'),
}
def corpus(data, model):
 model.build(data);inputs=[];expected=[]
 labels=['pre_body_state_failure','post_body_context_missing','post_body_state_failure','restore_prior_state']
 def add(p,a,c,w):
  b=model.bracket(p,a,bool(c));saved,cleared=model.saved_flags(w)
  route=0 if p==2 else 1 if not c else 2 if a!=2 else 3
  assert b['path']==labels[route] and saved==w and cleared==256*(w//256)
  inputs.append(f'{p} {a} {c} {w}')
  expected.append(f"{route} {b['body_state'] if b['body_state'] is not None else -1} {b['restored'] if b['restored'] is not None else -1} {saved} {cleared}")
 for p,a,c in itertools.product(range(256),range(256),[0,1]):add(p,a,c,((p*257)^(a*131))&65535)
 for w in range(65536):add(7,2,1,w)
 return '\n'.join(inputs)+'\n',expected
