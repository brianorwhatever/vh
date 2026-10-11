local native=require('vh_native')
local J={}
J.null=setmetatable({},{__tostring=function() return 'null' end})
local object_mt, array_mt={},{}
function J.object(t) return setmetatable(t or {},object_mt) end
function J.array(t) return setmetatable(t or {},array_mt) end
function J.isobject(v) return getmetatable(v)==object_mt end
function J.isarray(v) return getmetatable(v)==array_mt end
local function unicode(s) assert(utf8.len(s),'invalid Unicode'); return s end
function J.parse(text)
  assert(type(text)=='string','JSON text required')
  local pos=1
  local function space() local _,e=text:find('^[ \t\r\n]*',pos); pos=(e or pos-1)+1 end
  local function take() local c=text:sub(pos,pos); assert(c~='','unexpected EOF'); pos=pos+1; return c end
  local function expect(c) assert(take()==c,'invalid JSON') end
  local function str()
    local out={}
    while true do
      local c=take()
      if c=='"' then break end
      assert(c:byte()>=32,'control character')
      if c=='\\' then
        c=take()
        local escapes={['"']='"',['\\']='\\',['/']='/',b='\b',f='\f',n='\n',r='\r',t='\t'}
        if c=='u' then
          local function code() local s=text:sub(pos,pos+3); assert(#s==4 and s:match('^%x+$'),'unicode escape'); pos=pos+4; return tonumber(s,16) end
          local n=code()
          if n>=0xd800 and n<=0xdbff then
            expect('\\'); expect('u'); local low=code(); assert(low>=0xdc00 and low<=0xdfff,'lone surrogate'); n=0x10000+(n-0xd800)*1024+low-0xdc00
          else assert(n<0xdc00 or n>0xdfff,'lone surrogate') end
          c=utf8.char(n)
        else c=assert(escapes[c],'string escape') end
      end
      out[#out+1]=c
    end
    return unicode(table.concat(out))
  end
  local value
  value=function()
    space(); local c=take()
    if c=='"' then return str() end
    if c=='{' then
      local o=J.object(); space(); if text:sub(pos,pos)=='}' then pos=pos+1; return o end
      while true do
        space(); expect('"'); local k=str(); space(); expect(':'); o[k]=value(); space(); c=take()
        if c=='}' then return o end
        assert(c==',','object separator')
      end
    end
    if c=='[' then
      local a=J.array(); space(); if text:sub(pos,pos)==']' then pos=pos+1; return a end
      while true do
        a[#a+1]=value(); space(); c=take(); if c==']' then return a end; assert(c==',','array separator')
      end
    end
    for _,word in ipairs({'true','false','null'}) do
      if text:sub(pos-1,pos+#word-2)==word then pos=pos+#word-1; if word=='null' then return J.null end; return word=='true' end
    end
    pos=pos-1
    local start=pos
    if text:sub(pos,pos)=='-' then pos=pos+1 end
    if text:sub(pos,pos)=='0' then pos=pos+1
    else assert(text:sub(pos,pos):match('[1-9]'),'invalid number'); repeat pos=pos+1 until not text:sub(pos,pos):match('%d') end
    if text:sub(pos,pos)=='.' then pos=pos+1; assert(text:sub(pos,pos):match('%d'),'fraction'); repeat pos=pos+1 until not text:sub(pos,pos):match('%d') end
    if text:sub(pos,pos):match('[eE]') then
      pos=pos+1; if text:sub(pos,pos):match('[+-]') then pos=pos+1 end
      assert(text:sub(pos,pos):match('%d'),'exponent'); repeat pos=pos+1 until not text:sub(pos,pos):match('%d')
    end
    local n=tonumber(text:sub(start,pos-1))+0.0
    assert(n==n and n~=math.huge and n~=-math.huge,'non-finite number'); return n
  end
  local v=value(); space(); assert(pos>#text,'trailing JSON text'); return v
end
function J.number(n)
  if n==0 then return '0' end
  local sign=n<0 and '-' or ''
  local s=native.number(math.abs(n)):lower()
  local mantissa,exponent=s:match('^(.-)e([+-]?%d+)$')
  mantissa=mantissa or s; exponent=tonumber(exponent) or 0
  local whole=mantissa:match('^[^.]+'); local point=#whole+exponent
  local digits=mantissa:gsub('%.',''):gsub('0+$','')
  while digits:sub(1,1)=='0' do digits=digits:sub(2); point=point-1 end
  local body
  if point>0 and point<=21 then
    if #digits<=point then body=digits..string.rep('0',point-#digits) else body=digits:sub(1,point)..'.'..digits:sub(point+1) end
  elseif point<=0 and point> -6 then body='0.'..string.rep('0',-point)..digits
  else local power=point-1; body=digits:sub(1,1)..(#digits>1 and '.'..digits:sub(2) or '')..'e'..(power>=0 and '+' or '')..tostring(power) end
  return sign..body
end
local function quote(s)
  unicode(s)
  local escapes={['"']='\\"',['\\']='\\\\',['\b']='\\b',['\f']='\\f',['\n']='\\n',['\r']='\\r',['\t']='\\t'}
  return '"'..s:gsub('[%z\1-\31\\"]',function(c) return escapes[c] or string.format('\\u%04x',c:byte()) end)..'"'
end
local function utf16(s)
  local a={}
  for _,c in utf8.codes(s) do
    if c>0xffff then c=c-0x10000; a[#a+1]=string.pack('>I2',0xd800+(c//1024)); c=0xdc00+(c%1024) end
    a[#a+1]=string.pack('>I2',c)
  end
  return table.concat(a)
end
function J.encode(v)
  if v==J.null then return 'null' end
  if type(v)=='string' then return quote(v) end
  if type(v)=='number' then return J.number(v) end
  if type(v)=='boolean' then return tostring(v) end
  local parts={}
  if J.isarray(v) then for _,x in ipairs(v) do parts[#parts+1]=J.encode(x) end; return '['..table.concat(parts,',')..']' end
  assert(J.isobject(v),'unsupported JSON value')
  local keys={}; for k in pairs(v) do keys[#keys+1]=k end
  table.sort(keys,function(a,b) return utf16(a)<utf16(b) end)
  for _,k in ipairs(keys) do parts[#parts+1]=quote(k)..':'..J.encode(v[k]) end
  return '{'..table.concat(parts,',')..'}'
end
return J
