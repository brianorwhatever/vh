-- did:vh (docs/didvh-profile.md). A did:vh DID log has the same format and
-- verification as a VH-Log log, so it is verified by vh_log with the did:vh
-- specialisation. This module adds the DID syntax, the srcLog/srcWitness and
-- DID URL rules, the resolution options, and DID Resolution metadata and errors.
local J=require('json')
local V=require('vh_log')
local O,A,N=J.object,J.array,J.null
local D={METHOD='did:vh:1.0',PREFIX='did:vh:'}

-- A did:vh error: code is a did:vh error code, vhLog the VH-Log error report behind it.
local Error={}
Error.__index=Error
Error.__tostring=function(e) return e.code..': '..e.message end
local function reject(code,message,vhLog) error(setmetatable({code=code,message=message,vhLog=vhLog},Error),0) end
function D.is_error(e) return getmetatable(e)==Error end

local function has(v,k) return J.isobject(v) and v[k]~=nil end
local function contains(a,v) for _,x in ipairs(a) do if x==v then return true end end; return false end
local function integer(v) return type(v)=='number' and v==v and math.abs(v)~=math.huge and v==math.floor(v) end
local function split(s,sep)
  local out,start={},1
  while true do
    local p=s:find(sep,start,true)
    if not p then out[#out+1]=s:sub(start); return out end
    out[#out+1]=s:sub(start,p-1); start=p+1
  end
end

-- ---------------------------------------------------------------- the DID

-- The SCID of a did:vh DID, or nil if it does not match the ABNF.
function D.parse_did(did)
  if type(did)~='string' or did:sub(1,#D.PREFIX)~=D.PREFIX then return nil end
  local scid=did:sub(#D.PREFIX+1)
  if #scid==46 and scid:match('^[1-9A-HJ-NP-Za-km-z]+$') then return scid end
end

local function natural(s) return s:match('^%d+$')~=nil and (s=='0' or s:sub(1,1)~='0') end
-- A well-formed method value: did:vh:<major>.<minor>.
local function method_syntax(v)
  local major,minor=v:match('^did:vh:(%d+)%.(%d+)$')
  return major~=nil and natural(major) and natural(minor)
end

-- The did:vh specialisation of VH-Log: method instead of logVersion, a closed
-- parameter set, and state.id = did:vh:<SCID> in every entry. With
-- expected_scid, the log's SCID must also be that of the DID being resolved.
function D.specialisation(expected_scid)
  return {version_parameter='method',version=D.METHOD,version_syntax=method_syntax,closed=true,
    check_state=function(state,scid)
      if expected_scid and scid~=expected_scid then return false end
      return state.id==D.PREFIX..scid
    end}
end

-- ---------------------------------------------------------------- create / update

-- {document, parameters, versionTime, signers} -> {log, did, scid, versionId}.
-- Like VH-Log generation, it does not validate its input.
function D.create(input)
  local out=V.create(O{state=input.document,parameters=input.parameters,versionTime=input.versionTime,signers=input.signers},D.specialisation())
  out.did=D.PREFIX..out.scid
  return out
end

-- {log, document, parameters?, versionTime, signers} -> {log, versionId}.
function D.update(input)
  return V.update(O{log=input.log,state=input.document,parameters=input.parameters,versionTime=input.versionTime,signers=input.signers})
end

-- ---------------------------------------------------------------- shared URL checks

-- Percent-decodes s as UTF-8, or nil if an escape or the UTF-8 is malformed.
local function percent_decode(s)
  local out,i={},1
  while i<=#s do
    local c=s:sub(i,i)
    if c=='%' then
      local h=s:sub(i+1,i+2)
      if not h:match('^%x%x$') then return nil end
      out[#out+1]=string.char(tonumber(h,16)); i=i+3
    else out[#out+1]=c; i=i+1 end
  end
  local decoded=table.concat(out)
  if not utf8.len(decoded) then return nil end
  return decoded
end

-- Unicode White_Space (profile §3.2).
local function whitespace(c)
  return (c>=0x09 and c<=0x0d) or c==0x20 or c==0x85 or c==0xa0 or c==0x1680 or (c>=0x2000 and c<=0x200a)
    or c==0x2028 or c==0x2029 or c==0x202f or c==0x205f or c==0x3000
end

local function is_octet(s) return #s<=3 and natural(s) and tonumber(s)<=255 end

local function is_loopback_host(host)
  if host=='localhost' or host=='[::1]' then return true end
  local parts=split(host,'.')
  if #parts~=4 or parts[1]~='127' then return false end
  for _,p in ipairs(parts) do if not is_octet(p) then return false end end
  return true
end

local function is_domain_name(host)
  local name=host:sub(-1)=='.' and host:sub(1,-2) or host
  if #name==0 or #name>253 then return false end
  local labels=split(name,'.')
  if labels[#labels]:match('^%d+$') then return false end -- an IPv4 literal, or ends in a number
  for _,l in ipairs(labels) do
    if #l==0 or #l>63 or not l:match('^[a-z0-9-]+$') or l:sub(1,1)=='-' or l:sub(-1)=='-' then return false end
  end
  return true
end

-- Splits scheme:rest (profile §3.1 steps 1–2); nil unless value is printable
-- ASCII with a scheme. The scheme is lowercased.
local function split_scheme(value)
  if type(value)~='string' or not value:match('^[!-~]+$') then return nil end
  local scheme,rest=value:match('^([A-Za-z][A-Za-z0-9+.-]*):(.*)$')
  if scheme then return scheme:lower(),rest end
end

-- Checks an http(s) authority (profile §3.1 step 4).
local function check_authority(authority,http)
  if authority:find('@',1,true) then return false end
  local host,port
  if authority:sub(1,1)=='[' then
    local close=authority:find(']',1,true); if not close then return false end
    host=authority:sub(1,close)
    local after=authority:sub(close+1)
    if after~='' then
      if after:sub(1,1)~=':' then return false end
      port=after:sub(2)
    end
  else
    local colon=authority:find(':',1,true)
    host=colon and authority:sub(1,colon-1) or authority
    if colon then port=authority:sub(colon+1) end
  end
  host=host:lower()
  if port and not (port:match('^%d+$') and #port<=5 and tonumber(port)<=65535) then return false end
  if http then return is_loopback_host(host) end
  return host:sub(1,1)~='[' and is_domain_name(host)
end

-- Checks the segments of a path that starts with '/' (profile §3). Each is
-- percent-decoded and must not be . or .. or contain /, \ or NUL. With strict
-- (the src DID URL parameter), it must also be non-empty and not start or end
-- with whitespace.
local function check_segments(path,strict)
  for _,raw in ipairs(split(path:sub(2),'/')) do
    local segment=percent_decode(raw)
    if not segment or segment=='.' or segment=='..' or segment:find('[/\\\0]') then return false end
    if strict then
      if segment=='' then return false end
      if whitespace(utf8.codepoint(segment,1)) or whitespace(utf8.codepoint(segment,utf8.offset(segment,-1))) then return false end
    end
  end
  return true
end

-- ---------------------------------------------------------------- srcLog / srcWitness

-- Validates a srcLog or srcWitness reference, which names a file (profile
-- §3.1), and returns its kind: web, loopback, file or other. Raises invalidOptions.
function D.check_ref(ref)
  local function invalid(why) reject('invalidOptions','reference '..tostring(ref)..': '..why) end
  local scheme,rest=split_scheme(ref)
  if not scheme then invalid('not a printable-ASCII absolute URL') end
  if rest:find('#',1,true) then invalid('must not have a fragment') end
  if scheme=='https' or scheme=='http' then
    if rest:sub(1,2)~='//' then invalid('missing authority') end
    local end_=rest:find('[/?]',3)
    local authority=end_ and rest:sub(3,end_-1) or rest:sub(3)
    local after=end_ and rest:sub(end_) or ''
    local path=after:match('^[^?]*')
    if not check_authority(authority,scheme=='http') then
      invalid(scheme=='http' and 'http is only allowed with a loopback host' or 'invalid https host')
    end
    if path=='' then invalid('must have a path') end
    if not check_segments(path,false) then invalid('invalid path segment') end
    return scheme=='http' and 'loopback' or 'web'
  end
  if scheme=='file' then
    if rest:find('?',1,true) then invalid('must not have a query') end
    local path
    if rest:sub(1,2)=='//' then
      local slash=rest:find('/',3,true); if not slash then invalid('file URL needs an absolute path') end
      local host=rest:sub(3,slash-1):lower()
      if host~='' and host~='localhost' then invalid('file URL host must be empty or localhost') end
      path=rest:sub(slash)
    else
      if rest:sub(1,1)~='/' then invalid('file URL needs an absolute path') end
      path=rest
    end
    if not check_segments(path,false) then invalid('invalid path segment') end
    return 'file'
  end
  if rest=='' then invalid('empty URL') end
  return 'other'
end

-- ---------------------------------------------------------------- the src DID URL parameter

-- Validates a (percent-decoded) src DID URL parameter and derives the srcLog
-- and srcWitness references from it (profile §3.2). Raises invalidDidUrl.
function D.src_references(src)
  local function invalid(why) reject('invalidDidUrl','src '..tostring(src)..': '..why) end
  local scheme,rest=split_scheme(src)
  if not scheme then invalid('not a printable-ASCII absolute URL') end
  if rest:find('[?#]') then invalid('must not have a query or fragment') end
  if scheme=='http' or scheme=='file' then invalid(scheme..' is not allowed in a DID URL') end
  if rest:sub(1,2)~='//' or #rest==2 or rest:sub(3,3)=='/' then invalid('not a hierarchical URL with an authority') end
  local base=rest:sub(-1)=='/' and rest:sub(1,-2) or rest
  if scheme=='https' then
    local slash=base:find('/',3,true)
    local authority=slash and base:sub(3,slash-1) or base:sub(3)
    local path=slash and base:sub(slash) or ''
    if not check_authority(authority,false) then invalid('invalid https host') end
    if path~='' and not check_segments(path,true) then invalid('invalid path segment') end
  end
  local location=scheme..':'..base
  return location..'/did.jsonl',location..'/did-witness.json'
end

-- ---------------------------------------------------------------- DID URLs

local URL_PARAMETERS={'src','versionId','versionTime','versionNumber'}
local OPTION_ONLY={'didLog','didWitness','srcLog','srcWitness','checkWatchers','extraWatchers','minCopies','includeDidLog'}

-- Parses a did:vh DID URL as a dereferencer does (profile §4) into
-- {did, options, fragment?}: src becomes the srcLog and srcWitness options, and
-- the version parameters become the options of the same name. Raises invalidDidUrl.
function D.parse_did_url(url)
  local function invalid(why) reject('invalidDidUrl',tostring(url)..': '..why) end
  if type(url)~='string' then invalid('not a string') end
  local hash=url:find('#',1,true)
  local before=hash and url:sub(1,hash-1) or url
  local fragment=hash and url:sub(hash+1) or nil
  local q=before:find('?',1,true)
  local did=q and before:sub(1,q-1) or before
  if not D.parse_did(did) then invalid('not a did:vh DID') end
  local options,seen=O{},{}
  if q then
    for _,pair in ipairs(split(before:sub(q+1),'&')) do
      local eq=pair:find('=',1,true)
      if not eq then invalid('query parameter '..pair..' has no value') end
      local key,value=percent_decode(pair:sub(1,eq-1)),percent_decode(pair:sub(eq+1))
      if not key or not value then invalid('malformed percent-encoding') end
      if contains(OPTION_ONLY,key) then invalid(key..' is a resolution option, not a DID URL parameter') end
      if contains(URL_PARAMETERS,key) then
        if seen[key] then invalid(key..' given more than once') end
        seen[key]=true
        if key=='src' then
          options.srcLog,options.srcWitness=D.src_references(value)
        elseif key=='versionNumber' then
          if not (value:match('^[1-9]%d*$') and #value<=16) then invalid('versionNumber must be a positive integer') end
          options.versionNumber=tonumber(value)
        else options[key]=value end
      end
    end
  end
  return O{did=did,options=options,fragment=fragment}
end

-- ---------------------------------------------------------------- resolve

local function is_watcher_url(u)
  return type(u)=='string' and u:match('^[!-~]+$')~=nil and (u:match('^https://[^/?#]') or u:match('^http://[^/?#]'))~=nil
end

-- did:vh resolution options validation (profile §5 step 2).
local function validate_options(o,remote)
  local function invalid(why) reject('invalidOptions',why) end
  local function positive_integer(v) return integer(v) and v>=1 end
  if not J.isobject(o) then invalid('resolution options must be an object') end
  if has(o,'didLog')==has(o,'srcLog') then invalid('exactly one of didLog and srcLog must be given') end
  if has(o,'didWitness') and has(o,'srcWitness') then invalid('at most one of didWitness and srcWitness may be given') end
  if has(o,'didLog') and type(o.didLog)~='string' then invalid('didLog must be a string') end
  if has(o,'didWitness') and not J.isarray(o.didWitness) then invalid('didWitness must be an array') end
  for _,key in ipairs({'srcLog','srcWitness'}) do
    if has(o,key) then
      local kind=D.check_ref(o[key])
      if remote and (kind=='file' or kind=='loopback') then
        invalid(key..': a resolver that serves other systems must not use local file or loopback references')
      end
    end
  end
  local selectors=0; for _,k in ipairs({'versionId','versionTime','versionNumber'}) do if has(o,k) then selectors=selectors+1 end end
  if selectors>1 then invalid('at most one of versionId, versionTime and versionNumber may be given') end
  if has(o,'versionId') and type(o.versionId)~='string' then invalid('versionId must be a string') end
  if has(o,'versionTime') and not V.time(o.versionTime) then invalid('versionTime must be a whole-second UTC ISO 8601 time') end
  if has(o,'versionNumber') and not positive_integer(o.versionNumber) then invalid('versionNumber must be a positive integer') end
  if has(o,'checkWatchers') and o.checkWatchers~='all' and not (integer(o.checkWatchers) and o.checkWatchers>=0) then
    invalid('checkWatchers must be a non-negative integer or "all"')
  end
  if has(o,'extraWatchers') then
    local ok=J.isarray(o.extraWatchers)
    if ok then for _,u in ipairs(o.extraWatchers) do if not (is_watcher_url(u) and u:sub(1,8)=='https://') then ok=false end end end
    if not ok then invalid('extraWatchers must be an array of https URLs') end
  end
  if has(o,'minCopies') and not positive_integer(o.minCopies) then invalid('minCopies must be a positive integer') end
  if has(o,'includeDidLog') and type(o.includeDidLog)~='boolean' then invalid('includeDidLog must be a boolean') end
end

local ERRORS={['not-found']='notFound',['invalid-option']='invalidOptions',['fork-detected']='logForked',
  ['min-copies-not-met']='insufficientCopies',['unsupported-log-version']='featureNotSupported'}

local function current_time() return os.date('!%Y-%m-%dT%H:%M:%SZ') end

local function resolve(did,options,context)
  local scid=D.parse_did(did)
  if not scid then reject('invalidDid',tostring(did)..' is not a did:vh DID') end
  validate_options(options,context.remote)
  if has(options,'srcLog') then reject('featureNotSupported','this resolver does not retrieve srcLog references') end
  if (has(options,'checkWatchers') and options.checkWatchers~=0) or (has(options,'extraWatchers') and #options.extraWatchers>0) then
    reject('featureNotSupported','this resolver does not retrieve copies from watchers')
  end
  local spec=D.specialisation(scid)
  local now=context.now or current_time()
  local log=options.didLog
  local witnessed=V.needs_witnessing(log,V.time(now) or V.time(current_time()),spec)
  if witnessed and has(options,'srcWitness') then reject('featureNotSupported','this resolver does not retrieve srcWitness references') end
  local vh_options=O{}
  for _,k in ipairs({'versionId','versionTime','versionNumber','minCopies'}) do vh_options[k]=options[k] end
  local result=V.resolve(O{log=log,witness=options.didWitness,now=now,options=vh_options},spec)
  local err=result.error
  if not result.valid then reject(ERRORS[err.code] or 'invalidDid',err.message,err) end
  local selected=has(options,'versionId') or has(options,'versionTime') or has(options,'versionNumber')
  if not selected and err~=N and err.code=='unsupported-log-version' then
    -- Entries after the last valid one may change the document or its keys (profile §5).
    reject('featureNotSupported',err.message,err)
  end
  local m=result.metadata
  local metadata=O{versionId=m.versionId,versionTime=m.versionTime,created=m.created,updated=m.updated,scid=m.scid,
    deactivated=m.deactivated,ttl=m.ttl,watchers=m.watchers}
  if m.witness~=N then metadata.witness=m.witness end
  local meta=O{contentType='application/did+json'}
  if #m.warnings>0 then meta.warnings=m.warnings end
  if options.includeDidLog==true then
    local lines=V.lines(log)
    local valid=result.firstInvalidVersion==N and #lines or result.firstInvalidVersion-1
    local kept={}; for i=1,valid do kept[i]=lines[i]..'\n' end
    meta.didLog=table.concat(kept)
    if witnessed then meta.didWitness=options.didWitness or A{} end
  end
  -- A deactivated DID's document is returned only for an explicit version selector (profile §5).
  return O{didResolutionMetadata=meta,didDocument=(m.deactivated and not selected) and N or result.state,didDocumentMetadata=metadata}
end

-- did:vh resolve(did, resolutionOptions) (profile §5), with a resolver context
-- {now?, remote?}. This resolver is offline: it verifies a log passed in didLog
-- (and didWitness), and returns featureNotSupported when it would have to
-- retrieve anything.
function D.resolve(did,options,context)
  context=context or {}
  local ok,res=pcall(resolve,did,options==nil and O{} or options,context)
  if ok then return res end
  if not D.is_error(res) then error(res,0) end
  local problem=O{title=res.code,detail=res.message,vhLog=res.vhLog}
  return O{didResolutionMetadata=O{error=res.code,problemDetails=problem},didDocument=N,didDocumentMetadata=O{}}
end

-- Runs fn, turning a did:vh error into {valid=false, error}.
local function rejected(fn)
  local ok,res=pcall(fn)
  if ok then res.valid=true; return res end
  if D.is_error(res) then return O{valid=false,error=res.code} end
  error(res,0)
end

-- The didvh-* driver operations (docs/interop-protocol.md), without the prefix.
function D.dispatch(op,input)
  if op=='create' then return D.create(input)
  elseif op=='update' then return D.update(input)
  elseif op=='resolve' then
    local now=input.now; if now==N then now=nil end
    return D.resolve(input.did,input.options,{now=now,remote=input.remote==true})
  elseif op=='ref' then return rejected(function() return O{kind=D.check_ref(input.ref)} end)
  elseif op=='src' then return rejected(function()
      if type(input.src)~='string' then reject('invalidDidUrl','src must be a string') end
      local srcLog,srcWitness=D.src_references(input.src)
      return O{srcLog=srcLog,srcWitness=srcWitness}
    end)
  elseif op=='did-url' then return rejected(function() return D.parse_did_url(input.didUrl) end)
  else error('unknown operation didvh-'..tostring(op)) end
end

return D
