with Ada.Unchecked_Deallocation;
with Interfaces.C;
with System;
with Ada.Strings.UTF_Encoding.Wide_Wide_Strings;

package body JSON is
   use type Interfaces.C.int;
   Allocations : Value_Access := null;
   function Track (V : Value_Access) return Value_Access is
   begin
      V.Next_Allocation := Allocations;
      Allocations := V;
      return V;
   end Track;
   overriding
   procedure Initialize (Scope : in out Storage_Scope) is
   begin
      Scope.Mark := Allocations;
   end Initialize;
   overriding
   procedure Finalize (Scope : in out Storage_Scope) is
      procedure Free is new Ada.Unchecked_Deallocation (Value, Value_Access);
      V : Value_Access;
   begin
      while Allocations /= Scope.Mark loop
         V := Allocations;
         Allocations := V.Next_Allocation;
         Free (V);
      end loop;
   end Finalize;
   function Format
     (N : Interfaces.C.double; O : System.Address) return Interfaces.C.int
   with Import, Convention => C, External_Name => "vh_number";
   function Obj return Value_Access
   is (Track (new Value'(Tag => Object_Value, others => <>)));
   function Arr return Value_Access
   is (Track (new Value'(Tag => Array_Value, others => <>)));
   function Str (S : String) return Value_Access
   is (Track
         (new Value'
            (Tag    => String_Value,
             Text   => To_Unbounded_String (S),
             others => <>)));
   function Num (N : Long_Float) return Value_Access
   is (Track (new Value'(Tag => Number_Value, Number => N, others => <>)));
   function Bool (B : Boolean) return Value_Access
   is (Track (new Value'(Tag => Boolean_Value, Flag => B, others => <>)));
   function Nil return Value_Access
   is (Track (new Value));
   function S (V : Value_Access) return String
   is (To_String (V.Text));
   function Len (V : Value_Access) return Natural
   is (Natural (V.Children.Length));
   function At_Index (V : Value_Access; I : Positive) return Value_Access
   is (V.Children (I).Item);
   function Has (V : Value_Access; Key : String) return Boolean is
   begin
      for M of V.Children loop
         if To_String (M.Key) = Key then
            return True;
         end if;
      end loop;
      return False;
   end;
   function Get (V : Value_Access; Key : String) return Value_Access is
   begin
      for M of V.Children loop
         if To_String (M.Key) = Key then
            return M.Item;
         end if;
      end loop;
      return Nil;
   end;
   procedure Put (V : Value_Access; Key : String; Item : Value_Access) is
   begin
      for I in 1 .. Len (V) loop
         if To_String (V.Children (I).Key) = Key then
            V.Children.Replace_Element (I, (To_Unbounded_String (Key), Item));
            return;
         end if;
      end loop;
      V.Children.Append (Member'(To_Unbounded_String (Key), Item));
   end;
   procedure Add (V : Value_Access; Item : Value_Access) is
   begin
      V.Children.Append (Member'(Null_Unbounded_String, Item));
   end;
   procedure Remove (V : Value_Access; Key : String) is
   begin
      for I in 1 .. Len (V) loop
         if To_String (V.Children (I).Key) = Key then
            V.Children.Delete (I);
            return;
         end if;
      end loop;
   end;
   function Copy (V : Value_Access) return Value_Access is
      R : Value_Access := Track (new Value'(V.all));
   begin
      R.Children.Clear;
      for M of V.Children loop
         R.Children.Append (Member'(M.Key, Copy (M.Item)));
      end loop;
      return R;
   end;
   function Order_Key (T : String) return Wide_String;
   function Parse (Text : String) return Value_Access is
      P : Integer := Text'First;
      procedure WS is
      begin
         while P <= Text'Last
           and then Text (P) in ' ' | ASCII.HT | ASCII.CR | ASCII.LF
         loop
            P := P + 1;
         end loop;
      end;
      procedure Need (C : Character) is
      begin
         if P > Text'Last or else Text (P) /= C then
            raise Invalid_JSON;
         end if;
         P := P + 1;
      end;
      function Hex return Natural is
         N : Natural := 0;
         D : Natural;
      begin
         for I in 1 .. 4 loop
            if P > Text'Last then
               raise Invalid_JSON;
            end if;
            case Text (P) is
               when '0' .. '9' =>
                  D := Character'Pos (Text (P)) - 48;

               when 'a' .. 'f' =>
                  D := Character'Pos (Text (P)) - 87;

               when 'A' .. 'F' =>
                  D := Character'Pos (Text (P)) - 55;

               when others     =>
                  raise Invalid_JSON;
            end case;
            N := N * 16 + D;
            P := P + 1;
         end loop;
         return N;
      end;
      function String_Parse return String is
         R    : Unbounded_String;
         C    : Character;
         U, L : Natural;
      begin
         Need ('"');
         while P <= Text'Last loop
            C := Text (P);
            P := P + 1;
            if C = '"' then
               declare
                  W : Wide_String := Order_Key (To_String (R));
               begin
                  null;
               end;
               return To_String (R);
            elsif C = '\' then
               if P > Text'Last then
                  raise Invalid_JSON;
               end if;
               C := Text (P);
               P := P + 1;
               case C is
                  when '"' | '\' | '/' =>
                     Append (R, C);

                  when 'b'             =>
                     Append (R, ASCII.BS);

                  when 'f'             =>
                     Append (R, ASCII.FF);

                  when 'n'             =>
                     Append (R, ASCII.LF);

                  when 'r'             =>
                     Append (R, ASCII.CR);

                  when 't'             =>
                     Append (R, ASCII.HT);

                  when 'u'             =>
                     U := Hex;
                     if U in 16#D800# .. 16#DBFF# then
                        Need ('\');
                        Need ('u');
                        L := Hex;
                        if L not in 16#DC00# .. 16#DFFF# then
                           raise Invalid_JSON;
                        end if;
                        U := 16#10000# + (U - 16#D800#) * 1024 + L - 16#DC00#;
                     elsif U in 16#DC00# .. 16#DFFF# then
                        raise Invalid_JSON;
                     end if;
                     Append
                       (R,
                        Ada.Strings.UTF_Encoding.Wide_Wide_Strings.Encode
                          (Wide_Wide_String'
                             (1 => Wide_Wide_Character'Val (U))));

                  when others          =>
                     raise Invalid_JSON;
               end case;
            elsif Character'Pos (C) < 32 then
               raise Invalid_JSON;
            else
               Append (R, C);
            end if;
         end loop;
         raise Invalid_JSON;
      end;
      function Read_Value return Value_Access is
         R     : Value_Access;
         K     : Unbounded_String;
         Start : Integer;
         N     : Long_Float;
      begin
         WS;
         if P > Text'Last then
            raise Invalid_JSON;
         end if;
         case Text (P) is
            when '"'              =>
               return Str (String_Parse);

            when '{'              =>
               P := P + 1;
               R := Obj;
               WS;
               if P <= Text'Last and then Text (P) = '}' then
                  P := P + 1;
                  return R;
               end if;
               loop
                  WS;
                  K := To_Unbounded_String (String_Parse);
                  WS;
                  Need (':');
                  Put (R, To_String (K), Read_Value);
                  WS;
                  exit when P <= Text'Last and then Text (P) = '}';
                  Need (',');
               end loop;
               Need ('}');
               return R;

            when '['              =>
               P := P + 1;
               R := Arr;
               WS;
               if P <= Text'Last and then Text (P) = ']' then
                  P := P + 1;
                  return R;
               end if;
               loop
                  Add (R, Read_Value);
                  WS;
                  exit when P <= Text'Last and then Text (P) = ']';
                  Need (',');
               end loop;
               Need (']');
               return R;

            when 't'              =>
               Need ('t');
               Need ('r');
               Need ('u');
               Need ('e');
               return Bool (True);

            when 'f'              =>
               Need ('f');
               Need ('a');
               Need ('l');
               Need ('s');
               Need ('e');
               return Bool (False);

            when 'n'              =>
               Need ('n');
               Need ('u');
               Need ('l');
               Need ('l');
               return Nil;

            when '-' | '0' .. '9' =>
               Start := P;
               if Text (P) = '-' then
                  P := P + 1;
               end if;
               if P > Text'Last then
                  raise Invalid_JSON;
               end if;
               if Text (P) = '0' then
                  P := P + 1;
               else
                  if Text (P) not in '1' .. '9' then
                     raise Invalid_JSON;
                  end if;
                  while P <= Text'Last and then Text (P) in '0' .. '9' loop
                     P := P + 1;
                  end loop;
               end if;
               if P <= Text'Last and then Text (P) = '.' then
                  P := P + 1;
                  if P > Text'Last or else Text (P) not in '0' .. '9' then
                     raise Invalid_JSON;
                  end if;
                  while P <= Text'Last and then Text (P) in '0' .. '9' loop
                     P := P + 1;
                  end loop;
               end if;
               if P <= Text'Last and then Text (P) in 'e' | 'E' then
                  P := P + 1;
                  if P <= Text'Last and then Text (P) in '+' | '-' then
                     P := P + 1;
                  end if;
                  if P > Text'Last or else Text (P) not in '0' .. '9' then
                     raise Invalid_JSON;
                  end if;
                  while P <= Text'Last and then Text (P) in '0' .. '9' loop
                     P := P + 1;
                  end loop;
               end if;
               N := Long_Float'Value (Text (Start .. P - 1));
               declare
                  B : aliased String (1 .. 64);
                  Q : Interfaces.C.int :=
                    Format (Interfaces.C.double (N), B'Address);
               begin
                  if Q < 0 then
                     raise Invalid_JSON;
                  end if;
               end;
               return Num (N);

            when others           =>
               raise Invalid_JSON;
         end case;
      end;
      R : Value_Access;
   begin
      R := Read_Value;
      WS;
      if P <= Text'Last then
         raise Invalid_JSON;
      end if;
      return R;
   exception
      when others =>
         raise Invalid_JSON;
   end;
   function Quote (T : String) return String is
      Validated : constant Wide_String := Order_Key (T);
      R         : Unbounded_String := Null_Unbounded_String;
      H         : constant String := "0123456789abcdef";
   begin
      R := To_Unbounded_String ("""");
      for C of T loop
         case C is
            when '"' | '\' =>
               Append (R, '\');
               Append (R, C);

            when ASCII.BS  =>
               Append (R, "\b");

            when ASCII.HT  =>
               Append (R, "\t");

            when ASCII.LF  =>
               Append (R, "\n");

            when ASCII.FF  =>
               Append (R, "\f");

            when ASCII.CR  =>
               Append (R, "\r");

            when others    =>
               if Character'Pos (C) < 32 then
                  Append (R, "\u00");
                  Append (R, H (Character'Pos (C) / 16 + 1));
                  Append (R, H (Character'Pos (C) mod 16 + 1));
               else
                  Append (R, C);
               end if;
         end case;
      end loop;
      Append (R, '"');
      return To_String (R);
   end;
   function Order_Key (T : String) return Wide_String is
      Result               : Wide_String (1 .. T'Length * 2);
      Used                 : Natural := 0;
      P                    : Integer := T'First;
      N, B, Width, Minimum : Natural;
   begin
      while P <= T'Last loop
         B := Character'Pos (T (P));
         P := P + 1;
         if B < 128 then
            N := B;
            Width := 1;
            Minimum := 0;
         elsif B in 16#C2# .. 16#DF# then
            N := B mod 32;
            Width := 2;
            Minimum := 128;
         elsif B in 16#E0# .. 16#EF# then
            N := B mod 16;
            Width := 3;
            Minimum := 2048;
         elsif B in 16#F0# .. 16#F4# then
            N := B mod 8;
            Width := 4;
            Minimum := 65536;
         else
            raise Invalid_JSON;
         end if;
         for I in 2 .. Width loop
            if P > T'Last then
               raise Invalid_JSON;
            end if;
            B := Character'Pos (T (P));
            P := P + 1;
            if B not in 16#80# .. 16#BF# then
               raise Invalid_JSON;
            end if;
            N := N * 64 + B mod 64;
         end loop;
         if N < Minimum
           or else N > 16#10FFFF#
           or else N in 16#D800# .. 16#DFFF#
         then
            raise Invalid_JSON;
         end if;
         if N > 65535 then
            Used := Used + 1;
            Result (Used) :=
              Wide_Character'Val (16#D800# + (N - 65536) / 1024);
            Used := Used + 1;
            Result (Used) :=
              Wide_Character'Val (16#DC00# + (N - 65536) mod 1024);
         else
            Used := Used + 1;
            Result (Used) := Wide_Character'Val (N);
         end if;
      end loop;
      return Result (1 .. Used);
   end Order_Key;
   function Canonical (V : Value_Access) return String is
      R : Unbounded_String;
      B : aliased String (1 .. 64);
      N : Interfaces.C.int;
      M : Members.Vector := V.Children;
   begin
      case V.Tag is
         when Null_Value                 =>
            return "null";

         when Boolean_Value              =>
            return (if V.Flag then "true" else "false");

         when String_Value               =>
            return Quote (S (V));

         when Number_Value               =>
            N := Format (Interfaces.C.double (V.Number), B'Address);
            if N < 0 then
               raise Invalid_JSON;
            end if;
            return B (1 .. Integer (N));

         when Object_Value | Array_Value =>
            if V.Tag = Object_Value then
               for I in 2 .. Natural (M.Length) loop
                  declare
                     X : Member := M (I);
                     J : Natural := I;
                  begin
                     while J > 1
                       and then Order_Key (To_String (X.Key))
                                < Order_Key (To_String (M (J - 1).Key))
                     loop
                        M.Replace_Element (J, M (J - 1));
                        J := J - 1;
                     end loop;
                     M.Replace_Element (J, X);
                  end;
               end loop;
               Append (R, '{');
            else
               Append (R, '[');
            end if;
            for I in 1 .. Natural (M.Length) loop
               if I > 1 then
                  Append (R, ',');
               end if;
               if V.Tag = Object_Value then
                  Append (R, Quote (To_String (M (I).Key)));
                  Append (R, ':');
               end if;
               Append (R, Canonical (M (I).Item));
            end loop;
            Append (R, (if V.Tag = Object_Value then '}' else ']'));
            return To_String (R);
      end case;
   end;
end JSON;
