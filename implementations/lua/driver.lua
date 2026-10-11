local V=require('vh_log')
local J=require('json')
for line in io.lines() do
  local id=J.null
  local ok,result=pcall(function()
    local request=J.parse(line); id=request.id or J.null
    return V.dispatch(request.op,request.input)
  end)
  local response=ok and J.object{id=id,ok=true,result=result} or J.object{id=id,ok=false,error=tostring(result)}
  io.write(J.encode(response),'\n'); io.flush()
end
