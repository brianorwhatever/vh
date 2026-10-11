let () =
  try
    while true do
      let line = input_line stdin in
      let id = ref Json.Null in
      let response =
        try
          let req = Json.parse line in
          id := Json.get "id" req;
          match
            Vh_log.perform (Json.str (Json.get "op" req)) (Json.get "input" req)
          with
          | Ok result ->
              Json.Object [ ("id", !id); ("ok", Json.Bool true); ("result", result) ]
          | Error e ->
              Json.Object
                [ ("id", !id); ("ok", Json.Bool false); ("error", Json.String e) ]
        with e ->
          Json.Object
            [
              ("id", !id);
              ("ok", Json.Bool false);
              ("error", Json.String (Printexc.to_string e));
            ]
      in
      print_endline (Json.serialize response);
      flush stdout
    done
  with End_of_file -> ()
