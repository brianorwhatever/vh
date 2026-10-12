-module(vh_native).
-export([parse/1,quote/1,number/1,utf16_compare/2,integer/1,int/1,to_int/1,sha/1,hash/1,check_hash/1,valid_key/1,method_key/1,multikey/1,sign/2,verify/3,time/1,version/1,retained_version/1,url/1,run/0]).
parse(Text) ->
  try
    Finish=fun(Acc,Old)->{maps:from_list(lists:reverse(Acc)),Old} end,
    {Value,_,Rest}=json:decode(Text,ok,#{object_finish=>Finish}),
    true=lists:all(fun(C)->lists:member(C," \t\r\n") end,binary_to_list(Rest)),
    {ok,from_native(Value)}
  catch _:_ -> {error,<<"invalid JSON">>} end.
from_native(M) when is_map(M) -> {obj,maps:map(fun(_,V)->from_native(V) end,M)};
from_native(A) when is_list(A) -> {arr,[from_native(V)||V<-A]};
from_native(S) when is_binary(S) -> {str,S};
from_native(N) when is_number(N) -> {num,float(N)};
from_native(true) -> {boolean,true};
from_native(false) -> {boolean,false};
from_native(null) -> null.
quote(S) -> iolist_to_binary([<<"\"">>,[escape(C)||C<-binary_to_list(S)],<<"\"">>]).
escape($") -> <<"\\\"">>;
escape($\\) -> <<"\\\\">>;
escape(8) -> <<"\\b">>;
escape(12) -> <<"\\f">>;
escape(10) -> <<"\\n">>;
escape(13) -> <<"\\r">>;
escape(9) -> <<"\\t">>;
escape(C) when C<32 -> io_lib:format("\\u~4.16.0b",[C]);
escape(C) -> <<C>>.
utf16_compare(A,B) ->
  X=unicode:characters_to_binary(A,utf8,{utf16,big}), Y=unicode:characters_to_binary(B,utf8,{utf16,big}),
  if X<Y -> lt; X>Y -> gt; true -> eq end.
integer({num,N}) -> N==trunc(N);
integer(_) -> false.
int(N) -> {num,float(N)}.
to_int({num,N}) -> trunc(N);
to_int(_) -> 0.
number(N) when N==0 -> <<"0">>;
number(N) ->
  S=float_to_binary(abs(N),[short]),
  {M,E}=case binary:split(S,<<"e">>) of [A,B]->{A,binary_to_integer(B)}; [A]->{A,0} end,
  [Whole|_]=binary:split(M,<<".">>),
  D0=binary:replace(M,<<".">>,<<>>,[global]),
  D1=string:trim(D0,trailing,"0"),
  {D,P}=leading(D1,byte_size(Whole)+E), K=byte_size(D),
  Body=if P>0,P=<21,K=<P -> <<D/binary,(binary:copy(<<"0">>,P-K))/binary>>;
    P>0,P=<21 -> <<(binary:part(D,0,P))/binary,".",(binary:part(D,P,K-P))/binary>>;
    P=<0,P> -6 -> <<"0.",(binary:copy(<<"0">>,-P))/binary,D/binary>>;
    true -> Power=P-1, Sign=if Power>=0 -> <<"+">>; true -> <<>> end,
      Frac=if K>1 -> <<".",(binary:part(D,1,K-1))/binary>>; true -> <<>> end,
      <<(binary:part(D,0,1))/binary,Frac/binary,"e",Sign/binary,(integer_to_binary(Power))/binary>> end,
  if N<0 -> <<"-",Body/binary>>; true -> Body end.
leading(<<"0",Rest/binary>>,P) -> leading(Rest,P-1);
leading(D,P) -> {D,P}.
alphabet() -> <<"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz">>.
encode(B) -> <<(binary:copy(<<"1">>,zeros(B)))/binary,(digits(binary:decode_unsigned(B),<<>>))/binary>>.
zeros(<<0,Rest/binary>>) -> 1+zeros(Rest); zeros(_) -> 0.
digits(0,Acc) -> Acc;
digits(N,Acc) -> C=binary:at(alphabet(),N rem 58),digits(N div 58,<<C,Acc/binary>>).
decode(S) ->
  N=lists:foldl(fun(C,A)-> {I,1}=binary:match(alphabet(),<<C>>),A*58+I end,0,binary_to_list(S)),
  B=if N==0 -> <<>>; true -> binary:encode_unsigned(N) end,
  <<(binary:copy(<<0>>,ones(S)))/binary,B/binary>>.
ones(<<"1",Rest/binary>>) -> 1+ones(Rest); ones(_) -> 0.
sha(S) -> crypto:hash(sha256,S).
hash(S) -> encode(<<16#12,16#20,(sha(S))/binary>>).
check_hash({str,S}) -> try case decode(S) of <<16#12,16#20,_:32/binary>> -> <<"ok">>; _ -> <<"unsupported-algorithm">> end catch _:_ -> <<"not-base58">> end;
check_hash(_) -> <<"not-base58">>.
key(<<"z",S/binary>>) -> <<16#ed,1,Pk:32/binary>>=decode(S),Pk.
valid_key({str,S}) -> try key(S),true catch _:_ -> false end;
valid_key(_) -> false.
method_key({str,<<"did:key:",S/binary>>}) -> try
  [A,A]=binary:split(S,<<"#">>,[global]),key(A),{ok,A}
  catch _:_ -> {error,nil} end;
method_key(_) -> {error,nil}.
seed(S) -> 64=byte_size(S), B=binary:decode_hex(S),32=byte_size(B),B.
multikey(S) -> {Pk,_}=crypto:generate_key(eddsa,ed25519,seed(S)), <<"z",(encode(<<16#ed,1,Pk/binary>>))/binary>>.
sign(S,Message) -> <<"z",(encode(crypto:sign(eddsa,none,Message,[seed(S),ed25519])))/binary>>.
verify(K,{str,<<"z",S/binary>>},Message) -> try
  Sig=decode(S),64=byte_size(Sig), <<R:32/binary,_:32/binary>>=Sig,
  admissible_point(key(K)) andalso admissible_point(R) andalso crypto:verify(eddsa,none,Message,Sig,[key(K),ed25519])
  catch _:_ -> false end;
verify(_,_,_) -> false.
time({str,S}) -> try
  {match,[Y,Mo,D,H,Mi,Sec]}=re:run(S,<<"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:Z|\\+00:00)$">>,[{capture,all_but_first,binary}]),
  [Yi,Moi,Di,Hi,Mii,Si]=[binary_to_integer(X)||X<-[Y,Mo,D,H,Mi,Sec]],
  true=calendar:valid_date({Yi,Moi,Di}),true=Hi<24,true=Mii<60,true=Si<60,
  {ok,calendar:datetime_to_gregorian_seconds({{Yi,Moi,Di},{Hi,Mii,Si}})}
  catch _:_ -> {error,nil} end;
time(_) -> {error,nil}.
version({str,S}) -> try
  {match,[N,H]}=re:run(S,<<"^([1-9][0-9]*)-([^-]+)$">>,[{capture,all_but_first,binary}]),{ok,{binary_to_integer(N),H}}
  catch _:_ -> {error,nil} end;
version(_) -> {error,nil}.
retained_version({str,S}) -> try
  {match,[N]}=re:run(S,<<"^([1-9][0-9]*)-">>,[{capture,all_but_first,binary}]),{ok,binary_to_integer(N)}
  catch _:_ -> {error,nil} end;
retained_version(_) -> {error,nil}.
url({str,S}) -> re:run(S,<<"^[\\x21-\\x7e]+$">>)=/=nomatch andalso re:run(S,<<"^https?://[^/?#]">>)=/=nomatch;
url(_) -> false.
run() -> io:setopts(standard_io,[binary,{encoding,utf8}]),loop().
loop() -> case io:get_line(standard_io,"") of
  eof -> nil;
  {error,R} -> erlang:error(R);
  Line ->
    Parsed=parse(Line), Id=case Parsed of {ok,{obj,M}} -> maps:get(<<"id">>,M,null); _ -> null end,
    Response=try
      {ok,Request}=Parsed,
      Op=json_value:text(json_value:get(Request,<<"op">>)), Input=json_value:get(Request,<<"input">>),
      case vh_log:dispatch(Op,Input) of
        {ok,V} -> json_value:object([{<<"id">>,Id},{<<"ok">>,{boolean,true}},{<<"result">>,V}]);
        {error,E} -> erlang:error({driver,E})
      end
    catch _:_ -> json_value:object([{<<"id">>,Id},{<<"ok">>,{boolean,false}},{<<"error">>,{str,<<"invalid request or operation">>}}]) end,
    io:put_chars(standard_io,[json_value:jcs(Response),<<"\n">>]),loop()
  end.

% Profile §2; OTP checks curve membership and the equation.
admissible_point(<<N:256/little-unsigned-integer>>) ->
  Y = N band 57896044618658097711785492504343953926634992332820282019728792003956564819967,
  Y < 57896044618658097711785492504343953926634992332820282019728792003956564819949 andalso not lists:member(Y, [0, 1, 2707385501144840649318225287225658788936804267575313519463743609750303402022, 55188659117513257062467267217118295137698188065244968500265048394206261417927, 57896044618658097711785492504343953926634992332820282019728792003956564819948]).
