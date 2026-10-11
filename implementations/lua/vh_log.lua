local J=require('json')
local native=require('vh_native')
local V={parse=J.parse,jcs=J.encode}
local O,A,N=J.object,J.array,J.null
local absent={}
local alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
local function fail(code,n,fork) error(O{code=code,version=n or N,message=code,fork=fork},0) end
local function get(v,k) if J.isobject(v) then return v[k] end end
local function has(v,k) return get(v,k)~=nil end
local function copy(v) local o=O{}; for k,x in pairs(v) do o[k]=x end; return o end
local function without(v,k) local o=copy(v); o[k]=nil; return o end
local function contains(a,v) for _,x in ipairs(a) do if x==v then return true end end; return false end
local function every(a,f) for _,x in ipairs(a) do if not f(x) then return false end end; return true end
local function integer(v) return type(v)=='number' and v==v and math.abs(v)~=math.huge and v==math.floor(v) end
local function strings(v) return J.isarray(v) and every(v,function(x) return type(x)=='string' end) end
function V.encode(bytes)
  local digits={}
  for i=1,#bytes do
    local carry=bytes:byte(i)
    for j=1,#digits do local n=digits[j]*256+carry; digits[j]=n%58; carry=n//58 end
    while carry>0 do digits[#digits+1]=carry%58; carry=carry//58 end
  end
  local out={}; for i=1,#bytes do if bytes:byte(i)~=0 then break end; out[#out+1]='1' end
  for i=#digits,1,-1 do out[#out+1]=alphabet:sub(digits[i]+1,digits[i]+1) end
  return table.concat(out)
end
function V.decode(s)
  if type(s)~='string' then return nil end
  local bytes={}
  for i=1,#s do
    local d=alphabet:find(s:sub(i,i),1,true); if not d then return nil end
    local carry=d-1
    for j=1,#bytes do local n=bytes[j]*58+carry; bytes[j]=n%256; carry=n//256 end
    while carry>0 do bytes[#bytes+1]=carry%256; carry=carry//256 end
  end
  local out={}; for i=1,#s do if s:sub(i,i)~='1' then break end; out[#out+1]='\0' end
  for i=#bytes,1,-1 do out[#out+1]=string.char(bytes[i]) end
  return table.concat(out)
end
function V.hash(s) return V.encode('\x12\x20'..native.sha(s)) end
local function check_hash(s)
  local b=V.decode(s)
  return not b and 'not-base58' or (#b==34 and b:sub(1,2)=='\x12\x20' and 'ok' or 'unsupported-algorithm')
end
function V.public_key(mk)
  if type(mk)~='string' or mk:sub(1,1)~='z' then return nil end
  local b=V.decode(mk:sub(2)); if b and #b==34 and b:sub(1,2)=='\xed\x01' then return b:sub(3) end
end
local function seed(hex)
  assert(type(hex)=='string' and #hex==64 and hex:match('^%x+$'),'seed must be 32-byte hex')
  return (hex:gsub('..',function(h) return string.char(tonumber(h,16)) end))
end
function V.multikey(s) return 'z'..V.encode('\xed\x01'..native.public_key(seed(s))) end
local function method_key(vm)
  if type(vm)~='string' then return nil end
  local a,b=vm:match('^did:key:([^#]+)#(.+)$')
  if a and a==b and V.public_key(a) then return a end
end
function V.signing_input(document,config)
  return native.sha(J.encode(config)) .. native.sha(J.encode(document))
end
function V.sign(document,s,options)
  options=options or O{}; local mk=V.multikey(s)
  local config=O{type='DataIntegrityProof',cryptosuite='eddsa-jcs-2022',verificationMethod=options.verificationMethod or ('did:key:'..mk..'#'..mk),created=options.created,proofPurpose='assertionMethod'}
  local value='z'..V.encode(native.sign(seed(s),V.signing_input(document,config)))
  config.proofValue=value; return config
end
function V.verify(document,proof)
  local ok,valid=pcall(function()
    if not J.isobject(proof) or proof.type~='DataIntegrityProof' or proof.cryptosuite~='eddsa-jcs-2022' or proof.proofPurpose~='assertionMethod' then return false end
    local mk=method_key(proof.verificationMethod); local value=proof.proofValue
    if not mk or type(value)~='string' or value:sub(1,1)~='z' then return false end
    local sig=V.decode(value:sub(2)); if not sig or #sig~=64 then return false end
    return native.verify(V.public_key(mk),V.signing_input(document,without(proof,'proofValue')),sig)
  end)
  return ok and valid or false
end
function V.scid(e) return V.hash(J.encode(without(e,'proof'))) end
function V.entry_hash(e,previous)
  local d=without(e,'proof'); d.versionId=previous; return V.hash(J.encode(d))
end
local function lines(log)
  local a={}; local start=1
  while true do local p=log:find('\n',start,true); if not p then if start<=#log then a[#a+1]=log:sub(start) end; return a end; a[#a+1]=log:sub(start,p-1); start=p+1 end
end
function V.create(input)
  local p=O{logVersion='vh-log:1.0',scid='{SCID}'}; for k,x in pairs(input.parameters) do p[k]=x end
  local e=O{versionId='{SCID}',versionTime=input.versionTime,parameters=p,state=input.state}
  local id=V.scid(e); e=J.parse((J.encode(e):gsub('{SCID}',function() return id end))); e.versionId='1-'..V.entry_hash(e,id)
  local proofs=A{}; for _,s in ipairs(input.signers) do proofs[#proofs+1]=V.sign(e,s,O{created=input.versionTime}) end; e.proof=proofs
  return O{log=J.encode(e)..'\n',scid=id,versionId=e.versionId}
end
function V.update(input)
  local ls=lines(input.log); local previous=J.parse(ls[#ls]).versionId
  local e=O{versionId=previous,versionTime=input.versionTime,parameters=input.parameters or O{},state=input.state}
  e.versionId=tostring(tonumber(previous:match('^(%d+)'))+1)..'-'..V.entry_hash(e,previous)
  local proofs=A{}; for _,s in ipairs(input.signers) do proofs[#proofs+1]=V.sign(e,s,O{created=input.versionTime}) end; e.proof=proofs
  return O{log=input.log..(input.log:sub(-1)=='\n' and '' or '\n')..J.encode(e)..'\n',versionId=e.versionId}
end
local function time(value)
  if type(value)~='string' then return nil end
  local body=value:match('^(.*)Z$') or value:match('^(.*)%+00:00$'); if not body then return nil end
  local y,mo,d,h,mi,s=body:match('^(%d%d%d%d)%-(%d%d)%-(%d%d)T(%d%d):(%d%d):(%d%d)$')
  if not y then return nil end
  y,mo,d,h,mi,s=tonumber(y),tonumber(mo),tonumber(d),tonumber(h),tonumber(mi),tonumber(s)
  local leap=y%4==0 and (y%100~=0 or y%400==0)
  local months={31,leap and 29 or 28,31,30,31,30,31,31,30,31,30,31}
  if mo<1 or mo>12 or d<1 or d>months[mo] or h>23 or mi>59 or s>59 then return nil end
  local previous=y-1; local days=365*y+previous//4-previous//100+previous//400+d
  for i=1,mo-1 do days=days+months[i] end
  return days*86400+h*3600+mi*60+s
end
local function parameters(raw,previous,n)
  for _,v in pairs(raw) do if v==N then fail('invalid-parameter',n) end end
  if (not previous and not has(raw,'logVersion')) or (has(raw,'logVersion') and raw.logVersion~='vh-log:1.0') then fail('unsupported-log-version',n) end
  if (previous and has(raw,'scid')) or (not previous and (type(raw.scid)~='string' or not has(raw,'updateKeys'))) then fail('invalid-parameter',n) end
  if has(raw,'updateKeys') and (not strings(raw.updateKeys) or not every(raw.updateKeys,V.public_key)) then fail('invalid-parameter',n) end
  if has(raw,'nextKeyHashes') and (not strings(raw.nextKeyHashes) or not every(raw.nextKeyHashes,function(h) return check_hash(h)=='ok' end)) then fail('invalid-parameter',n) end
  local p=copy(previous or O{nextKeyHashes=A{},witness=N,watchers=A{},ttl=3600})
  for _,k in ipairs({'logVersion','scid','updateKeys','nextKeyHashes','witness','watchers','ttl'}) do if has(raw,k) then p[k]=raw[k] end end
  p.deactivated=has(raw,'deactivated') and raw.deactivated or false
  if has(raw,'witness') then
    local w=raw.witness; if not J.isobject(w) then fail('invalid-parameter',n) end
    if next(w)==nil then p.witness=N
    else
      local ws=w.witnesses
      if not J.isarray(ws) or #ws==0 or not every(ws,function(x) local id=get(x,'id'); return type(id)=='string' and id:sub(1,8)=='did:key:' and V.public_key(id:sub(9)) end) then fail('invalid-parameter',n) end
      local ids={}; for _,x in ipairs(ws) do if ids[x.id] then fail('invalid-parameter',n) end; ids[x.id]=true end
      if not integer(w.threshold) or w.threshold<1 or w.threshold>#ws then fail('invalid-parameter',n) end
      p.witness=O{threshold=w.threshold,witnesses=ws}
    end
  end
  if has(raw,'watchers') and (not strings(raw.watchers) or not every(raw.watchers,function(u) return u:match('^[!-~]+$') and (u:match('^https://[^/?#]') or u:match('^http://[^/?#]')) end)) then fail('invalid-parameter',n) end
  if type(p.deactivated)~='boolean' or not integer(p.ttl) or p.ttl<0 or p.ttl>2147483648 then fail('invalid-parameter',n) end
  if previous and #previous.nextKeyHashes>0 then
    if not has(raw,'updateKeys') or not has(raw,'nextKeyHashes') then fail('prerotation-violation',n) end
    for _,key in ipairs(raw.updateKeys) do if not contains(previous.nextKeyHashes,V.hash(key)) then fail('prerotation-violation',n) end end
  end
  return p
end
local function verify_entry(e,previous,now)
  local n=previous and previous.n+1 or 1
  if previous and previous.p.deactivated then fail('entry-after-deactivation',n) end
  local count=0; for _ in pairs(e) do count=count+1 end
  if count~=5 or type(e.versionId)~='string' or type(e.versionTime)~='string' or not J.isobject(e.parameters) or not J.isobject(e.state) or not J.isarray(e.proof) then fail('invalid-entry',n) end
  local p=parameters(e.parameters,previous and previous.p,n)
  local keys=(not previous or #previous.p.nextKeyHashes>0) and p.updateKeys or previous.p.updateKeys
  local rule=(not previous or (has(e.parameters,'witness') and previous.p.witness==N)) and p.witness or previous.p.witness
  if #e.proof==0 then fail('invalid-proof',n) end
  for _,proof in ipairs(e.proof) do
    local mk=method_key(get(proof,'verificationMethod')); if not mk then fail('invalid-proof',n) end
    if not contains(keys,mk) then fail('unauthorized-key',n) end
    if not V.verify(without(e,'proof'),proof) then fail('invalid-proof',n) end
  end
  local number,h=e.versionId:match('^([1-9]%d*)%-([^%-]+)$')
  if not number or tonumber(number)~=n then fail('invalid-version-id',n) end
  local status=check_hash(h); if status=='not-base58' then fail('invalid-version-id',n) end
  if status~='ok' then fail('invalid-hash-algorithm',n) end
  if V.entry_hash(e,previous and previous.e.versionId or p.scid)~=h then fail('entry-hash-mismatch',n) end
  local t=time(e.versionTime); if not t or (previous and t<=previous.time) then fail('invalid-version-time',n) end
  if t>now+300 then fail('future-version-time',n) end
  if not previous then
    status=check_hash(p.scid); if status=='unsupported-algorithm' then fail('invalid-hash-algorithm',n) end
    if status~='ok' then fail('scid-mismatch',n) end
    local rest=without(e,'proof'); rest.versionId='{SCID}'
    local restored=J.parse((J.encode(rest):gsub(p.scid,'{SCID}')))
    if V.scid(restored)~=p.scid then fail('scid-mismatch',n) end
  end
  return {e=e,p=p,n=n,time=t,rule=rule}
end
local function verify_log(log,witness,now)
  local ls=lines(log); local entries={}; local failure
  if #ls==0 then return {entries=entries,lines=ls,failure=O{code='invalid-log',version=N,message='invalid-log'}} end
  for i,line in ipairs(ls) do
    local ok,value=pcall(function()
      local parsed,e=pcall(J.parse,line); if not parsed or not J.isobject(e) then fail('invalid-log',i) end
      return verify_entry(e,entries[#entries],now)
    end)
    if not ok then if not J.isobject(value) then error(value) end; failure=value; break end
    entries[#entries+1]=value
  end
  for i,e in ipairs(entries) do
    if e.rule~=N then
      local file=witness==absent and A{} or witness; local code
      if not J.isarray(file) or not every(file,function(r) return J.isobject(r) and type(r.versionId)=='string' and J.isarray(r.proof) end) then code='invalid-witness-file'
      else
        local allowed={}; for _,w in ipairs(e.rule.witnesses) do allowed[w.id]=true end
        local ids={}
        for _,r in ipairs(file) do
          local index; for j,x in ipairs(entries) do if x.e.versionId==r.versionId then index=j; break end end
          if index and index>=i then
            for _,proof in ipairs(r.proof) do
              local mk=method_key(get(proof,'verificationMethod'))
              if mk then local id='did:key:'..mk; if allowed[id] and V.verify(O{versionId=r.versionId},proof) then ids[id]=true end end
            end
          end
        end
        local count=0; for _ in pairs(ids) do count=count+1 end
        if count<e.rule.threshold then code='witness-threshold-not-met' end
      end
      if code then failure=O{code=code,version=i,message=code}; for j=#entries,i,-1 do entries[j]=nil end; break end
    end
  end
  return {entries=entries,lines=ls,failure=failure}
end
local function line_value(line) local ok,v=pcall(J.parse,line); if ok then return v end end
local function line_id(line) local id=get(line_value(line),'versionId'); if type(id)=='string' then return id end end
local function retained(v,source,id,warnings)
  local number=type(id)=='string' and id:match('^([1-9]%d*)%-'); if not number then fail('invalid-option') end
  local n=tonumber(number)
  if #v.entries<n then warnings[#warnings+1]=O{code='retained-version-not-found',message='retained version not found'}
  elseif v.entries[n].e.versionId~=id then fail('fork-detected',n,O{version=n,copies=A{O{source='retained',versionId=id},O{source=source,versionId=v.entries[n].e.versionId}}}) end
end
local function result(v,options,warnings,copies)
  local entries,ls,failure=v.entries,v.lines,v.failure; local target
  if has(options,'versionId') then
    for _,x in ipairs(entries) do if x.e.versionId==options.versionId then target=x end end
    if not target then for i=#entries+1,#ls do if line_id(ls[i])==options.versionId then error(failure,0) end end end
  elseif has(options,'versionNumber') then
    target=entries[options.versionNumber]; if not target and options.versionNumber<=#ls then error(failure,0) end
  elseif has(options,'versionTime') then
    local t=time(options.versionTime)
    if failure then local invalid_time=time(get(line_value(ls[#entries+1]),'versionTime')); if invalid_time and invalid_time<=t then error(failure,0) end end
    for _,x in ipairs(entries) do if x.time<=t then target=x end end
  else target=entries[#entries] end
  if not target then fail('not-found') end
  local first,last=entries[1],entries[#entries]
  if failure then warnings[#warnings+1]=O{code='invalid-entries',message=failure.message} end
  local meta=O{versionId=target.e.versionId,versionTime=target.e.versionTime,versionNumber=target.n,created=first.e.versionTime,updated=last.e.versionTime,scid=first.p.scid,
    deactivated=last.p.deactivated,ttl=last.p.ttl,witness=last.p.witness,watchers=last.p.watchers,updateKeys=target.p.updateKeys,nextKeyHashes=target.p.nextKeyHashes,warnings=warnings,copies=copies}
  return O{valid=true,state=target.e.state,metadata=meta,firstInvalidVersion=failure and #entries+1 or N,error=failure or N}
end
local function resolve_copies(input,now,options)
  local all={O{source='primary',log=input.log,witness=input.witness or absent}}
  for _,c in ipairs(input.copies or {}) do all[#all+1]=c end
  local warnings,status,cache=A{},{},{}
  local function get_log(i) if not cache[i] then cache[i]=verify_log(all[i].log,all[i].witness or absent,now) end; return cache[i] end
  local function invalid(i) status[i]='invalid'; warnings[#warnings+1]=O{code='copy-invalid',source=all[i].source,message='copy fails verification'} end
  for i,c in ipairs(all) do if has(c,'unavailable') then status[i]='unavailable'; warnings[#warnings+1]=O{code='copy-unavailable',source=c.source,message=c.unavailable} end end
  local ref
  for i in ipairs(all) do if not status[i] then if not get_log(i).failure then ref=i; break end; invalid(i) end end
  if not ref then return O{valid=false,error=get_log(1).failure} end
  local matched={[ref]=true}
  for i in ipairs(all) do
    if not status[i] and not matched[i] then
      local r,c=get_log(ref),get_log(i); local rl,cl=r.lines,c.lines
      if #cl==0 then invalid(i)
      else
        local same=#cl<=#rl and line_id(cl[#cl])==r.entries[#cl].e.versionId
        local extends=#cl>#rl and line_id(cl[#rl])==r.entries[#r.entries].e.versionId
        if same then matched[i]=true
        elseif extends and not c.failure then matched[i]=true; ref=i
        elseif c.failure then invalid(i)
        else
          local k=1; while k<=#rl and k<=#cl and line_id(rl[k])==line_id(cl[k]) do k=k+1 end
          fail('fork-detected',k,O{version=k,copies=A{O{source=all[ref].source,versionId=line_id(rl[k]) or ''},O{source=all[i].source,versionId=line_id(cl[k]) or ''}}})
        end
      end
    end
  end
  local r=get_log(ref)
  if has(input,'retainedVersionId') then retained(r,all[ref].source,input.retainedVersionId,warnings) end
  local copies=A{}; local count=0
  for i,c in ipairs(all) do
    local report=O{source=c.source}
    if status[i] then report.status=status[i]; if status[i]~='unavailable' then local ls=get_log(i).lines; report.versionId=line_id(ls[#ls]) end
    else
      local ls=get_log(i).lines; local behind=#ls<#r.lines; report.status=behind and 'behind' or 'current'; report.versionId=line_id(ls[#ls]); count=count+1
      if behind then warnings[#warnings+1]=O{code='copy-behind',source=c.source,message='copy is behind'} end
    end
    copies[#copies+1]=report
  end
  if count<(options.minCopies or 1) then fail('min-copies-not-met') end
  return result(r,options,warnings,copies)
end
function V.resolve(input)
  local ok,res=pcall(function()
    local now=time(input.now); if not now then fail('invalid-option') end
    local options=input.options; if options==nil or options==N then options=O{} end
    if not J.isobject(options) then fail('invalid-option') end
    for k in pairs(options) do if not contains({'versionId','versionTime','versionNumber','minCopies'},k) then fail('invalid-option') end end
    local count=0; for _,k in ipairs({'versionId','versionTime','versionNumber'}) do if has(options,k) then count=count+1 end end
    if count>1 or (has(options,'versionId') and type(options.versionId)~='string') or (has(options,'versionTime') and not time(options.versionTime)) then fail('invalid-option') end
    for _,k in ipairs({'versionNumber','minCopies'}) do if has(options,k) and (not integer(options[k]) or options[k]<1) then fail('invalid-option') end end
    if has(input,'copies') or (options.minCopies or 1)>1 then return resolve_copies(input,now,options) end
    local v=verify_log(input.log,input.witness or absent,now)
    if #v.entries==0 then return O{valid=false,error=v.failure} end
    local warnings=A{}; if has(input,'retainedVersionId') then retained(v,'primary',input.retainedVersionId,warnings) end
    return result(v,options,warnings)
  end)
  if ok then return res end
  if J.isobject(res) then return O{valid=false,error=res} end
  error(res)
end
function V.dispatch(op,input)
  if op=='jcs' then return O{output=J.encode(J.parse(input.text))}
  elseif op=='hash' then return O{output=V.hash(input.data)}
  elseif op=='key-hash' then return O{output=V.hash(input.multikey)}
  elseif op=='multikey' then return O{multikey=V.multikey(input.seed)}
  elseif op=='scid' then return O{scid=V.scid(input.entry)}
  elseif op=='entry-hash' then return O{hash=V.entry_hash(input.entry,input.previousVersionId)}
  elseif op=='sign' then return O{proof=V.sign(input.document,input.seed,input)}
  elseif op=='verify' then return O{valid=V.verify(input.document,input.proof)}
  elseif op=='witness' then return O{proof=V.sign(O{versionId=input.versionId},input.seed,input)}
  elseif op=='create' then return V.create(input)
  elseif op=='update' then return V.update(input)
  elseif op=='resolve' then return V.resolve(input)
  else error('unknown operation '..tostring(op)) end
end
return V
