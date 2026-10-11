\ Gforth bindings to the generic native runtime.
[IFUNDEF] c-library require libcc.fs [THEN]
c-library vhforth_v2
s" vhforth" add-lib
\c void v_reset(void);
c-function j-reset v_reset  -- void
\c long v_parse(const char*, long);
c-function j-parse v_parse a n -- n
\c long v_string(const char*, long);
c-function j-string v_string a n -- n
\c const char* v_data(long);
c-function j-data v_data n -- a
\c long v_size(long);
c-function j-size v_size n -- n
\c long v_type(long);
c-function j-type v_type n -- n
\c long v_number(long);
c-function j-number v_number n -- n
\c long v_integer(long);
c-function j-integer v_integer n -- n
\c long v_integral(long);
c-function j-integral v_integral n -- n
\c long v_bool(long);
c-function j-bool v_bool n -- n
\c long v_truth(long);
c-function j-truth v_truth n -- n
\c long v_object(void);
c-function j-object v_object  -- n
\c long v_array(void);
c-function j-array v_array  -- n
\c long v_get(long, const char*, long);
c-function j-get v_get n a n -- n
\c long v_has(long, const char*, long);
c-function j-has v_has n a n -- n
\c void v_set(long, const char*, long, long);
c-function j-set v_set n a n n -- void
\c void v_del(long, const char*, long);
c-function j-del v_del n a n -- void
\c long v_at(long, long);
c-function j-at v_at n n -- n
\c void v_push(long, long);
c-function j-push v_push n n -- void
\c long v_clone(long);
c-function j-clone v_clone n -- n
\c long v_equal(long, long);
c-function j-equal v_equal n n -- n
\c long v_keys(long);
c-function j-keys v_keys n -- n
\c long v_dump(long);
c-function j-dump v_dump n -- n
\c long v_cat(long, long);
c-function j-cat v_cat n n -- n
\c long v_slice(long, long, long);
c-function j-slice v_slice n n n -- n
\c long v_replace(long, long, long);
c-function j-replace v_replace n n n -- n
\c long v_find(long, long);
c-function j-find v_find n n -- n
\c long v_split(long, long);
c-function j-split v_split n n -- n
\c long v_nfc(long);
c-function j-nfc v_nfc n -- n
\c long v_utf16cmp(long, long);
c-function j-utf16cmp v_utf16cmp n n -- n
\c long v_decimal(long);
c-function j-decimal v_decimal n -- n
\c long v_sha(long);
c-function j-sha v_sha n -- n
\c long v_public(long);
c-function j-public v_public n -- n
\c long v_sign(long, long);
c-function j-sign v_sign n n -- n
\c long v_verify(long, long, long);
c-function j-verify v_verify n n n -- n
\c long v_read(void);
c-function j-read v_read  -- n
\c void v_write(long);
c-function j-write v_write n -- void
\c long v_init(void);
c-function j-init v_init -- n
end-c-library
j-init 0< [IF] -400 throw [THEN]
