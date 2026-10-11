type t =
  | Null
  | Bool of bool
  | Number of float
  | String of string
  | Array of t list
  | Object of (string * t) list

exception Invalid of string

let invalid s = raise (Invalid s)
let obj = function Object x -> x | _ -> invalid "expected object"
let arr = function Array x -> x | _ -> invalid "expected array"
let str = function String x -> x | _ -> invalid "expected string"
let get k j = match List.assoc_opt k (obj j) with Some x -> x | None -> Null
let has k j = List.mem_assoc k (obj j)
let remove k j = Object (List.filter (fun (n, _) -> n <> k) (obj j))
let set k v j = Object (List.filter (fun (n, _) -> n <> k) (obj j) @ [ (k, v) ])

let utf8 b u =
  let add n = Buffer.add_char b (Char.chr n) in
  if u < 0x80 then add u
  else if u < 0x800 then (
    add (0xc0 lor (u lsr 6));
    add (0x80 lor (u land 63)))
  else if u < 0x10000 then (
    add (0xe0 lor (u lsr 12));
    add (0x80 lor ((u lsr 6) land 63));
    add (0x80 lor (u land 63)))
  else (
    add (0xf0 lor (u lsr 18));
    add (0x80 lor ((u lsr 12) land 63));
    add (0x80 lor ((u lsr 6) land 63));
    add (0x80 lor (u land 63)))

let units s =
  let rec loop i out =
    if i = String.length s then List.rev out
    else
      let c = Char.code s.[i] in
      let n, u =
        if c < 128 then (1, c)
        else if c >= 194 && c <= 223 then (2, c land 31)
        else if c >= 224 && c <= 239 then (3, c land 15)
        else if c >= 240 && c <= 244 then (4, c land 7)
        else invalid "invalid UTF-8"
      in
      if i + n > String.length s then invalid "short UTF-8";
      let u = ref u in
      for k = 1 to n - 1 do
        let d = Char.code s.[i + k] in
        if d land 192 <> 128 then invalid "UTF-8 continuation";
        u := (!u lsl 6) lor (d land 63)
      done;
      if
        (n = 2 && !u < 128)
        || (n = 3 && !u < 2048)
        || (n = 4 && !u < 65536)
        || !u > 0x10ffff
        || (!u >= 0xd800 && !u <= 0xdfff)
      then invalid "invalid Unicode";
      let out =
        if !u < 65536 then !u :: out
        else
          let v = !u - 65536 in
          (0xdc00 lor (v land 1023)) :: (0xd800 lor (v lsr 10)) :: out
      in
      loop (i + n) out
  in
  loop 0 []

let parse text =
  let n = String.length text and p = ref 0 in
  let ws () =
    while !p < n && List.mem text.[!p] [ ' '; '\t'; '\r'; '\n' ] do
      incr p
    done
  in
  let take c =
    if !p >= n || text.[!p] <> c then invalid "unexpected token" else incr p
  in
  let hex4 () =
    if !p + 4 > n then invalid "unicode escape";
    let v = ref 0 in
    for _ = 1 to 4 do
      let c = text.[!p] in
      incr p;
      let d =
        if c >= '0' && c <= '9' then Char.code c - 48
        else if c >= 'a' && c <= 'f' then Char.code c - 87
        else if c >= 'A' && c <= 'F' then Char.code c - 55
        else invalid "hex"
      in
      v := (!v * 16) + d
    done;
    !v
  in
  let string () =
    take '"';
    let b = Buffer.create 32 in
    let rec loop () =
      if !p >= n then invalid "unterminated string";
      let c = text.[!p] in
      incr p;
      if c = '"' then ()
      else if c = '\\' then (
        if !p >= n then invalid "escape";
        let e = text.[!p] in
        incr p;
        (match e with
        | '"' | '\\' | '/' -> Buffer.add_char b e
        | 'b' -> Buffer.add_char b '\b'
        | 'f' -> Buffer.add_char b '\012'
        | 'n' -> Buffer.add_char b '\n'
        | 'r' -> Buffer.add_char b '\r'
        | 't' -> Buffer.add_char b '\t'
        | 'u' ->
            let u = hex4 () in
            let u =
              if u >= 0xd800 && u <= 0xdbff then (
                take '\\';
                take 'u';
                let l = hex4 () in
                if l < 0xdc00 || l > 0xdfff then invalid "lone surrogate";
                0x10000 + ((u - 0xd800) lsl 10) + l - 0xdc00)
              else if u >= 0xdc00 && u <= 0xdfff then invalid "lone surrogate"
              else u
            in
            utf8 b u
        | _ -> invalid "escape");
        loop ())
      else (
        if Char.code c < 32 then invalid "control";
        Buffer.add_char b c;
        loop ())
    in
    loop ();
    let s = Buffer.contents b in
    ignore (units s);
    s
  in
  let rec value () =
    ws ();
    if !p >= n then invalid "empty";
    match text.[!p] with
    | '"' -> String (string ())
    | '{' ->
        incr p;
        ws ();
        let rec fields acc =
          if !p < n && text.[!p] = '}' then (
            incr p;
            Object acc)
          else
            let k = string () in
            ws ();
            take ':';
            let v = value () in
            let acc = List.filter (fun (n, _) -> n <> k) acc @ [ (k, v) ] in
            ws ();
            if !p < n && text.[!p] = ',' then (
              incr p;
              ws ();
              if !p < n && text.[!p] = '}' then invalid "trailing comma";
              fields acc)
            else (
              take '}';
              Object acc)
        in
        fields []
    | '[' ->
        incr p;
        ws ();
        if !p < n && text.[!p] = ']' then (
          incr p;
          Array [])
        else
          let rec items acc =
            let v = value () in
            ws ();
            if !p < n && text.[!p] = ',' then (
              incr p;
              items (v :: acc))
            else (
              take ']';
              Array (List.rev (v :: acc)))
          in
          items []
    | 'n' -> literal "null" Null
    | 't' -> literal "true" (Bool true)
    | 'f' -> literal "false" (Bool false)
    | '-' | '0' .. '9' ->
        let start = !p in
        if text.[!p] = '-' then incr p;
        let digits () =
          let start = !p in
          while !p < n && text.[!p] >= '0' && text.[!p] <= '9' do
            incr p
          done;
          if !p = start then invalid "number"
        in
        if !p < n && text.[!p] = '0' then incr p else digits ();
        if !p < n && text.[!p] = '.' then (
          incr p;
          digits ());
        if !p < n && (text.[!p] = 'e' || text.[!p] = 'E') then (
          incr p;
          if !p < n && (text.[!p] = '+' || text.[!p] = '-') then incr p;
          digits ());
        let f = float_of_string (String.sub text start (!p - start)) in
        if not (Float.is_finite f) then invalid "nonfinite number";
        Number f
    | _ -> invalid "token"
  and literal s v =
    let l = String.length s in
    if !p + l > n || String.sub text !p l <> s then invalid "literal";
    p := !p + l;
    v
  in
  let j = value () in
  ws ();
  if !p <> n then invalid "trailing input";
  j

external number : float -> string = "vh_number"

let quote s =
  ignore (units s);
  let b = Buffer.create 32 in
  Buffer.add_char b '"';
  String.iter
    (fun c ->
      Buffer.add_string b
        (match c with
        | '"' -> "\\\""
        | '\\' -> "\\\\"
        | '\b' -> "\\b"
        | '\012' -> "\\f"
        | '\n' -> "\\n"
        | '\r' -> "\\r"
        | '\t' -> "\\t"
        | c when Char.code c < 32 -> Printf.sprintf "\\u%04x" (Char.code c)
        | c -> String.make 1 c))
    s;
  Buffer.add_char b '"';
  Buffer.contents b

let rec serialize ?(canonical = false) = function
  | Null -> "null"
  | Bool b -> string_of_bool b
  | Number f -> if Float.is_finite f then number f else invalid "nonfinite"
  | String s -> quote s
  | Array xs -> "[" ^ String.concat "," (List.map (serialize ~canonical) xs) ^ "]"
  | Object xs ->
      let xs =
        if canonical then
          List.sort (fun (a, _) (b, _) -> compare (units a) (units b)) xs
        else xs
      in
      "{"
      ^ String.concat ","
          (List.map (fun (k, v) -> quote k ^ ":" ^ serialize ~canonical v) xs)
      ^ "}"

let canonicalize j = serialize ~canonical:true j
let parse_result s = try Ok (parse s) with Invalid s -> Error s
