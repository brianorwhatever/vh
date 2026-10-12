#include "vh_log.h"
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <setjmp.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef json_object J;
typedef struct allocation {
    void *pointer;
    struct allocation *next;
} Allocation;
typedef struct json_allocation {
    J *value;
    struct json_allocation *next;
} JsonAllocation;
struct vh_context {
    Allocation *memory;
    JsonAllocation *json;
    jmp_buf *trap;
    J *error;
};
typedef struct {
    char *data;
    size_t size, capacity;
} Buffer;
typedef struct {
    J *entry, *parameters, *rule;
    int number;
    int64_t time;
} Entry;
typedef struct {
    Entry *entries;
    size_t count;
    J *lines, *failure;
} Verified;
static const char *alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static void *alloc(vh_context *c, size_t size) {
    void *p = calloc(1, size ? size : 1);
    Allocation *a = malloc(sizeof(*a));
    if (!p || !a)
        abort();
    a->pointer = p;
    a->next = c->memory;
    c->memory = a;
    return p;
}
static J *track(vh_context *c, J *v) {
    if (v) {
        JsonAllocation *a = alloc(c, sizeof(*a));
        a->value = v;
        a->next = c->json;
        c->json = a;
    }
    return v;
}
vh_context *vh_context_new(void) { return calloc(1, sizeof(vh_context)); }
void vh_context_free(vh_context *c) {
    if (!c)
        return;
    for (JsonAllocation *a = c->json; a; a = a->next)
        json_object_put(a->value);
    Allocation *a = c->memory;
    while (a) {
        Allocation *next = a->next;
        free(a->pointer);
        free(a);
        a = next;
    }
    free(c);
}
static char *copy(vh_context *c, const char *s, size_t n) {
    char *p = alloc(c, n + 1);
    memcpy(p, s, n);
    return p;
}
static char *text(vh_context *c, const char *s) { return copy(c, s, strlen(s)); }
static J *object(vh_context *c) { return track(c, json_object_new_object()); }
static J *array(vh_context *c) { return track(c, json_object_new_array()); }
static J *string_n(vh_context *c, const char *s, size_t n) {
    return track(c, json_object_new_string_len(s, (int)n));
}
static J *string(vh_context *c, const char *s) { return string_n(c, s, strlen(s)); }
static J *number(vh_context *c, double n) { return track(c, json_object_new_double(n)); }
static J *boolean(vh_context *c, int b) { return track(c, json_object_new_boolean(b)); }
static int type(J *v, enum json_type t) { return json_object_is_type(v, t); }
static int is_number(J *v) { return type(v, json_type_double) || type(v, json_type_int); }
static const char *s(J *v) { return type(v, json_type_string) ? json_object_get_string(v) : ""; }
static size_t slen(J *v) {
    return type(v, json_type_string) ? (size_t)json_object_get_string_len(v) : 0;
}
static double num(J *v) { return json_object_get_double(v); }
static int integer(J *v) { return is_number(v) && isfinite(num(v)) && num(v) == floor(num(v)); }
static J *get(J *v, const char *key) {
    J *out = NULL;
    if (type(v, json_type_object))
        json_object_object_get_ex(v, key, &out);
    return out;
}
static int has(J *v, const char *key) {
    J *out = NULL;
    return type(v, json_type_object) && json_object_object_get_ex(v, key, &out);
}
static void set(J *v, const char *key, J *value) {
    json_object_object_add(v, key, json_object_get(value));
}
static void push(J *v, J *value) { json_object_array_add(v, json_object_get(value)); }
static size_t len(J *v) { return type(v, json_type_array) ? json_object_array_length(v) : 0; }
static J *at(J *v, size_t i) {
    return type(v, json_type_array) ? json_object_array_get_idx(v, i) : NULL;
}
static int equal(J *a, J *b) { return json_object_equal(a, b); }
static J *report(vh_context *c, const char *code, int version) {
    J *r = object(c);
    set(r, "code", string(c, code));
    set(r, "message", string(c, code));
    set(r, "version", version ? number(c, version) : NULL);
    return r;
}
_Noreturn static void fail(vh_context *c, const char *code, int version) {
    c->error = report(c, code, version);
    longjmp(*c->trap, 1);
}
_Noreturn static void throw_report(vh_context *c, J *r) {
    c->error = r;
    longjmp(*c->trap, 1);
}
static void append(vh_context *c, Buffer *b, const char *s, size_t n) {
    if (b->size + n + 1 > b->capacity) {
        size_t cap = (b->size + n + 1) * 2;
        char *p = alloc(c, cap);
        if (b->size)
            memcpy(p, b->data, b->size);
        b->data = p;
        b->capacity = cap;
    }
    memcpy(b->data + b->size, s, n);
    b->size += n;
    b->data[b->size] = 0;
}
static void adds(vh_context *c, Buffer *b, const char *s) { append(c, b, s, strlen(s)); }
static void addc(vh_context *c, Buffer *b, char ch) { append(c, b, &ch, 1); }
static int hex4(const char *p) {
    int n = 0;
    for (int i = 0; i < 4; i++) {
        unsigned char ch = (unsigned char)p[i];
        if (!isxdigit(ch))
            return -1;
        n = n * 16 + (ch <= '9' ? ch - '0' : tolower(ch) - 'a' + 10);
    }
    return n;
}
/* json-c replaces lone surrogates and truncates member names at NUL.
 * Reject both before parsing loses information. NUL string values are valid. */
static int unicode_escapes(const char *p) {
    int quoted = 0, contains_nul = 0;
    size_t n = strlen(p);
    for (size_t i = 0; i < n; i++) {
        if (p[i] == '"') {
            if (quoted && contains_nul) {
                size_t next = i + 1;
                while (next < n && strchr(" \t\r\n", p[next]))
                    next++;
                /* In valid JSON only a member name is followed by a colon.
                 * The tokener still validates the complete JSON grammar. */
                if (next < n && p[next] == ':')
                    return 0;
            }
            quoted = !quoted;
            contains_nul = 0;
        } else if (quoted && p[i] == '\\') {
            if (++i >= n)
                return 0;
            if (p[i] == 'u') {
                if (i + 4 >= n)
                    return 0;
                int cp = hex4(p + i + 1);
                if (cp < 0)
                    return 0;
                if (cp == 0)
                    contains_nul = 1;
                i += 4;
                if (cp >= 0xd800 && cp <= 0xdbff) {
                    if (i + 6 >= n || p[i + 1] != '\\' || p[i + 2] != 'u')
                        return 0;
                    int low = hex4(p + i + 3);
                    if (low < 0xdc00 || low > 0xdfff)
                        return 0;
                    i += 6;
                } else if (cp >= 0xdc00 && cp <= 0xdfff)
                    return 0;
            }
        }
    }
    return 1;
}
static int finite_json(J *v) {
    if (is_number(v))
        return isfinite(num(v));
    if (type(v, json_type_array)) {
        for (size_t i = 0; i < len(v); i++)
            if (!finite_json(at(v, i)))
                return 0;
    }
    if (type(v, json_type_object)) {
        json_object_object_foreach(v, key, value) {
            (void)key;
            if (!finite_json(value))
                return 0;
        }
    }
    return 1;
}
/* Force integer tokens through json-c's binary64 path, including values
 * outside uint64_t. Strings and their escapes are copied verbatim. */
static char *binary64_tokens(vh_context *c, const char *input) {
    Buffer b = {0};
    int quoted = 0;
    for (size_t i = 0; input[i];) {
        char ch = input[i];
        if (quoted) {
            addc(c, &b, ch);
            i++;
            if (ch == '\\' && input[i])
                addc(c, &b, input[i++]);
            else if (ch == '"')
                quoted = 0;
        } else if (ch == '"') {
            quoted = 1;
            addc(c, &b, ch);
            i++;
        } else if (ch == '-' || (ch >= '0' && ch <= '9')) {
            size_t start = i;
            int fractional = 0;
            while (input[i] && strchr("0123456789.eE+-", input[i])) {
                if (input[i] == '.' || input[i] == 'e' || input[i] == 'E')
                    fractional = 1;
                i++;
            }
            append(c, &b, input + start, i - start);
            if (!fractional)
                adds(c, &b, "e0");
        } else {
            addc(c, &b, ch);
            i++;
        }
    }
    return b.data ? b.data : text(c, "");
}
static J *parse(vh_context *c, const char *input, int *valid) {
    *valid = 0;
    if (!unicode_escapes(input))
        return NULL;
    input = binary64_tokens(c, input);
    struct json_tokener *tok = json_tokener_new();
    if (!tok)
        abort();
    json_tokener_set_flags(tok, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    size_t n = strlen(input);
    J *v = json_tokener_parse_ex(tok, input, (int)n + 1);
    enum json_tokener_error error = json_tokener_get_error(tok);
    size_t end = json_tokener_get_parse_end(tok);
    json_tokener_free(tok);
    track(c, v);
    while (end < n && strchr(" \t\r\n", input[end]))
        end++;
    *valid = error == json_tokener_success && end >= n && finite_json(v);
    return v;
}
static void quote(vh_context *c, Buffer *b, const char *p, size_t n) {
    addc(c, b, '"');
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)p[i];
        switch (ch) {
        case '"':
            adds(c, b, "\\\"");
            break;
        case '\\':
            adds(c, b, "\\\\");
            break;
        case '\b':
            adds(c, b, "\\b");
            break;
        case '\f':
            adds(c, b, "\\f");
            break;
        case '\n':
            adds(c, b, "\\n");
            break;
        case '\r':
            adds(c, b, "\\r");
            break;
        case '\t':
            adds(c, b, "\\t");
            break;
        default:
            if (ch < 32) {
                char escape[7];
                snprintf(escape, sizeof escape, "\\u%04x", ch);
                adds(c, b, escape);
            } else
                addc(c, b, (char)ch);
        }
    }
    addc(c, b, '"');
}
static char *format_number(vh_context *c, double d) {
    if (d == 0)
        return "0";
    char raw[64];
    double a = fabs(d);
    for (int precision = 1; precision <= 17; precision++) {
        snprintf(raw, sizeof raw, "%.*g", precision, a);
        if (strtod(raw, NULL) == a)
            break;
    }
    char *ep = strchr(raw, 'e');
    int exponent = ep ? atoi(ep + 1) : 0;
    if (ep)
        *ep = 0;
    char *dot = strchr(raw, '.');
    int point = (int)(dot ? dot - raw : (ptrdiff_t)strlen(raw)) + exponent;
    char digits[32];
    size_t k = 0;
    for (size_t i = 0; raw[i]; i++)
        if (raw[i] != '.')
            digits[k++] = raw[i];
    while (k && digits[k - 1] == '0')
        k--;
    digits[k] = 0;
    size_t zero = 0;
    while (digits[zero] == '0') {
        zero++;
        point--;
    }
    if (zero) {
        memmove(digits, digits + zero, k - zero + 1);
        k -= zero;
    }
    Buffer b = {0};
    if (d < 0)
        addc(c, &b, '-');
    if (point > 0 && point <= 21) {
        for (int i = 0; i < point; i++)
            addc(c, &b, (size_t)i < k ? digits[i] : '0');
        if ((size_t)point < k) {
            addc(c, &b, '.');
            adds(c, &b, digits + point);
        }
    } else if (point <= 0 && point > -6) {
        adds(c, &b, "0.");
        for (int i = 0; i < -point; i++)
            addc(c, &b, '0');
        adds(c, &b, digits);
    } else {
        addc(c, &b, digits[0]);
        if (k > 1) {
            addc(c, &b, '.');
            adds(c, &b, digits + 1);
        }
        char exp[20];
        snprintf(exp, sizeof exp, "e%+d", point - 1);
        adds(c, &b, exp);
    }
    return b.data;
}
static uint32_t next_utf8(const unsigned char **p) {
    uint32_t cp = *(*p)++;
    if (cp < 0x80)
        return cp;
    int n = cp < 0xe0 ? 1 : cp < 0xf0 ? 2 : 3;
    cp &= (1u << (6 - n)) - 1;
    while (n-- > 0)
        cp = (cp << 6) | (*(*p)++ & 63);
    return cp;
}
static uint16_t *utf16(vh_context *c, const char *s) {
    uint16_t *out = alloc(c, (strlen(s) + 1) * sizeof(*out));
    size_t n = 0;
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        uint32_t cp = next_utf8(&p);
        if (cp < 0x10000)
            out[n++] = (uint16_t)cp;
        else {
            cp -= 0x10000;
            out[n++] = (uint16_t)(0xd800 + (cp >> 10));
            out[n++] = (uint16_t)(0xdc00 + (cp & 1023));
        }
    }
    return out;
}
typedef struct {
    const char *key;
    uint16_t *sort;
} Key;
static int key_compare(const void *a, const void *b) {
    const uint16_t *x = ((const Key *)a)->sort, *y = ((const Key *)b)->sort;
    while (*x && *x == *y) {
        x++;
        y++;
    }
    return *x < *y ? -1 : *x > *y ? 1 : 0;
}
static void canonical(vh_context *c, J *v, Buffer *b) {
    if (!v)
        adds(c, b, "null");
    else if (type(v, json_type_boolean))
        adds(c, b, json_object_get_boolean(v) ? "true" : "false");
    else if (is_number(v))
        adds(c, b, format_number(c, num(v)));
    else if (type(v, json_type_string))
        quote(c, b, s(v), slen(v));
    else if (type(v, json_type_array)) {
        addc(c, b, '[');
        for (size_t i = 0; i < len(v); i++) {
            if (i)
                addc(c, b, ',');
            canonical(c, at(v, i), b);
        }
        addc(c, b, ']');
    } else {
        size_t count = json_object_object_length(v), i = 0;
        Key *keys = alloc(c, count * sizeof(*keys));
        json_object_object_foreach(v, key, value) {
            (void)value;
            keys[i].key = key;
            keys[i++].sort = utf16(c, key);
        }
        qsort(keys, count, sizeof(*keys), key_compare);
        addc(c, b, '{');
        for (i = 0; i < count; i++) {
            if (i)
                addc(c, b, ',');
            quote(c, b, keys[i].key, strlen(keys[i].key));
            addc(c, b, ':');
            canonical(c, get(v, keys[i].key), b);
        }
        addc(c, b, '}');
    }
}
static char *jcs(vh_context *c, J *v) {
    Buffer b = {0};
    canonical(c, v, &b);
    return b.data;
}
static J *clone_object(vh_context *c, J *v) {
    J *out = object(c);
    if (type(v, json_type_object)) {
        json_object_object_foreach(v, key, value) { set(out, key, value); }
    }
    return out;
}
static char *encode(vh_context *c, const unsigned char *bytes, size_t n) {
    size_t zeros = 0;
    while (zeros < n && bytes[zeros] == 0)
        zeros++;
    unsigned *digits = alloc(c, (n * 2 + 1) * sizeof(*digits));
    size_t count = 0;
    for (size_t i = zeros; i < n; i++) {
        unsigned carry = bytes[i];
        for (size_t j = 0; j < count; j++) {
            carry += digits[j] * 256;
            digits[j] = carry % 58;
            carry /= 58;
        }
        while (carry) {
            digits[count++] = carry % 58;
            carry /= 58;
        }
    }
    char *out = alloc(c, zeros + count + 1);
    memset(out, '1', zeros);
    for (size_t i = 0; i < count; i++)
        out[zeros + i] = alphabet[digits[count - 1 - i]];
    return out;
}
static unsigned char *decode(vh_context *c, const char *s, size_t *size) {
    size_t n = strlen(s), zeros = 0;
    while (zeros < n && s[zeros] == '1')
        zeros++;
    unsigned char *b = alloc(c, n + 1);
    size_t count = 0;
    for (size_t i = zeros; i < n; i++) {
        const char *p = strchr(alphabet, s[i]);
        if (!p)
            return NULL;
        unsigned carry = (unsigned)(p - alphabet);
        for (size_t j = 0; j < count; j++) {
            carry += b[j] * 58;
            b[j] = (unsigned char)(carry & 255);
            carry >>= 8;
        }
        while (carry) {
            b[count++] = (unsigned char)(carry & 255);
            carry >>= 8;
        }
    }
    unsigned char *out = alloc(c, zeros + count + 1);
    for (size_t i = 0; i < count; i++)
        out[zeros + i] = b[count - 1 - i];
    *size = zeros + count;
    return out;
}
static char *hash_n(vh_context *c, const char *data, size_t size) {
    unsigned char b[34] = {0x12, 0x20};
    crypto_hash_sha256(b + 2, (const unsigned char *)data, size);
    return encode(c, b, 34);
}
static char *hash(vh_context *c, const char *data) { return hash_n(c, data, strlen(data)); }
static int check_hash(vh_context *c, const char *s) {
    size_t n = 0;
    unsigned char *b = decode(c, s, &n);
    return !b ? 0 : n == 34 && b[0] == 0x12 && b[1] == 0x20 ? 1 : 2;
}
static unsigned char *public_key(vh_context *c, J *mk) {
    if (!type(mk, json_type_string) || s(mk)[0] != 'z')
        return NULL;
    size_t n = 0;
    unsigned char *b = decode(c, s(mk) + 1, &n);
    return b && n == 34 && b[0] == 0xed && b[1] == 1 ? b + 2 : NULL;
}
static void signer(vh_context *c, const char *seed, unsigned char pk[32], unsigned char sk[64]) {
    if (strlen(seed) != 64)
        fail(c, "invalid-seed", 0);
    unsigned char raw[32];
    for (size_t i = 0; i < 32; i++) {
        if (!isxdigit((unsigned char)seed[i * 2]) || !isxdigit((unsigned char)seed[i * 2 + 1]))
            fail(c, "invalid-seed", 0);
        char hex[3] = {seed[i * 2], seed[i * 2 + 1], 0};
        raw[i] = (unsigned char)strtoul(hex, NULL, 16);
    }
    crypto_sign_seed_keypair(pk, sk, raw);
}
static char *multikey(vh_context *c, const char *seed) {
    unsigned char b[34] = {0xed, 1}, sk[64];
    signer(c, seed, b + 2, sk);
    char *encoded = encode(c, b, 34);
    Buffer out = {0};
    addc(c, &out, 'z');
    adds(c, &out, encoded);
    return out.data;
}
static char *method_key(vh_context *c, J *vm) {
    if (!type(vm, json_type_string) || strncmp(s(vm), "did:key:", 8))
        return NULL;
    const char *p = s(vm) + 8, *sep = strchr(p, '#');
    if (!sep || sep == p || strchr(sep + 1, '#'))
        return NULL;
    size_t n = (size_t)(sep - p);
    if (strlen(sep + 1) != n || memcmp(p, sep + 1, n))
        return NULL;
    char *mk = copy(c, p, n);
    return public_key(c, string(c, mk)) ? mk : NULL;
}
static void signing_input(vh_context *c, J *document, J *config, unsigned char out[64]) {
    char *a = jcs(c, config), *b = jcs(c, document);
    crypto_hash_sha256(out, (const unsigned char *)a, strlen(a));
    crypto_hash_sha256(out + 32, (const unsigned char *)b, strlen(b));
}
static J *sign(vh_context *c, J *document, const char *seed, J *options) {
    char *mk = multikey(c, seed);
    Buffer vm = {0};
    adds(c, &vm, "did:key:");
    adds(c, &vm, mk);
    addc(c, &vm, '#');
    adds(c, &vm, mk);
    J *config = object(c);
    set(config, "type", string(c, "DataIntegrityProof"));
    set(config, "cryptosuite", string(c, "eddsa-jcs-2022"));
    set(config, "verificationMethod",
        has(options, "verificationMethod") ? get(options, "verificationMethod")
                                           : string(c, vm.data));
    if (has(options, "created"))
        set(config, "created", get(options, "created"));
    set(config, "proofPurpose", string(c, "assertionMethod"));
    unsigned char data[64], pk[32], sk[64], sig[64];
    signing_input(c, document, config, data);
    signer(c, seed, pk, sk);
    crypto_sign_detached(sig, NULL, data, 64, sk);
    Buffer value = {0};
    addc(c, &value, 'z');
    adds(c, &value, encode(c, sig, 64));
    set(config, "proofValue", string(c, value.data));
    return config;
}
static int verify(vh_context *c, J *document, J *proof) {
    if (!type(proof, json_type_object) || strcmp(s(get(proof, "type")), "DataIntegrityProof") ||
        strcmp(s(get(proof, "cryptosuite")), "eddsa-jcs-2022") ||
        strcmp(s(get(proof, "proofPurpose")), "assertionMethod"))
        return 0;
    char *mk = method_key(c, get(proof, "verificationMethod"));
    J *value = get(proof, "proofValue");
    if (!mk || !type(value, json_type_string) || s(value)[0] != 'z')
        return 0;
    size_t n = 0;
    unsigned char *sig = decode(c, s(value) + 1, &n);
    if (!sig || n != 64)
        return 0;
    J *config = clone_object(c, proof);
    json_object_object_del(config, "proofValue");
    unsigned char data[64];
    signing_input(c, document, config, data);
    return crypto_sign_verify_detached(sig, data, 64, public_key(c, string(c, mk))) == 0;
}
static J *without_proof(vh_context *c, J *e) {
    J *d = clone_object(c, e);
    json_object_object_del(d, "proof");
    return d;
}
static char *scid(vh_context *c, J *e) { return hash(c, jcs(c, without_proof(c, e))); }
static char *entry_hash(vh_context *c, J *e, const char *previous) {
    J *d = without_proof(c, e);
    set(d, "versionId", string(c, previous));
    return hash(c, jcs(c, d));
}
static char *replace(vh_context *c, const char *input, const char *from, const char *to) {
    Buffer b = {0};
    size_t n = strlen(from);
    const char *p = input, *next;
    while ((next = strstr(p, from))) {
        append(c, &b, p, (size_t)(next - p));
        adds(c, &b, to);
        p = next + n;
    }
    adds(c, &b, p);
    return b.data;
}
static J *lines(vh_context *c, const char *log) {
    J *out = array(c);
    const char *p = log, *next;
    while ((next = strchr(p, '\n'))) {
        push(out, string_n(c, p, (size_t)(next - p)));
        p = next + 1;
    }
    if (*p)
        push(out, string(c, p));
    return out;
}
static J *create(vh_context *c, J *input) {
    J *p = clone_object(c, get(input, "parameters"));
    if (!has(p, "logVersion"))
        set(p, "logVersion", string(c, "vh-log:1.0"));
    if (!has(p, "scid"))
        set(p, "scid", string(c, "{SCID}"));
    J *e = object(c);
    set(e, "versionId", string(c, "{SCID}"));
    set(e, "versionTime", get(input, "versionTime"));
    set(e, "parameters", p);
    set(e, "state", get(input, "state"));
    char *id = scid(c, e);
    int valid = 0;
    e = parse(c, replace(c, jcs(c, e), "{SCID}", id), &valid);
    if (!valid)
        fail(c, "invalid-json", 0);
    Buffer version = {0};
    adds(c, &version, "1-");
    adds(c, &version, entry_hash(c, e, id));
    set(e, "versionId", string(c, version.data));
    J *proofs = array(c), *options = object(c);
    set(options, "created", get(input, "versionTime"));
    J *signers = get(input, "signers");
    for (size_t i = 0; i < len(signers); i++)
        push(proofs, sign(c, e, s(at(signers, i)), options));
    set(e, "proof", proofs);
    Buffer log = {0};
    adds(c, &log, jcs(c, e));
    addc(c, &log, '\n');
    J *out = object(c);
    set(out, "log", string(c, log.data));
    set(out, "scid", string(c, id));
    set(out, "versionId", get(e, "versionId"));
    return out;
}
static J *update(vh_context *c, J *input) {
    const char *log = s(get(input, "log"));
    J *ls = lines(c, log);
    if (!len(ls))
        fail(c, "invalid-log", 0);
    int valid = 0;
    J *previous = parse(c, s(at(ls, len(ls) - 1)), &valid);
    if (!valid)
        fail(c, "invalid-log", 0);
    const char *id = s(get(previous, "versionId"));
    J *e = object(c);
    set(e, "versionId", string(c, id));
    set(e, "versionTime", get(input, "versionTime"));
    set(e, "parameters", has(input, "parameters") ? get(input, "parameters") : object(c));
    set(e, "state", get(input, "state"));
    char prefix[40];
    snprintf(prefix, sizeof prefix, "%lld-", strtoll(id, NULL, 10) + 1);
    Buffer version = {0};
    adds(c, &version, prefix);
    adds(c, &version, entry_hash(c, e, id));
    set(e, "versionId", string(c, version.data));
    J *proofs = array(c), *options = object(c);
    set(options, "created", get(input, "versionTime"));
    J *signers = get(input, "signers");
    for (size_t i = 0; i < len(signers); i++)
        push(proofs, sign(c, e, s(at(signers, i)), options));
    set(e, "proof", proofs);
    Buffer output = {0};
    adds(c, &output, log);
    if (!*log || log[strlen(log) - 1] != '\n')
        addc(c, &output, '\n');
    adds(c, &output, jcs(c, e));
    addc(c, &output, '\n');
    J *out = object(c);
    set(out, "log", string(c, output.data));
    set(out, "versionId", get(e, "versionId"));
    return out;
}
static int parse_time(J *v, int64_t *out) {
    if (!type(v, json_type_string))
        return 0;
    const char *p = s(v);
    size_t n = slen(v);
    if (n != 20 && n != 25)
        return 0;
    if (p[4] != '-' || p[7] != '-' || p[10] != 'T' || p[13] != ':' || p[16] != ':' ||
        (n == 20 ? strcmp(p + 19, "Z") : strcmp(p + 19, "+00:00")))
        return 0;
    for (int i = 0; i < 19; i++)
        if (i != 4 && i != 7 && i != 10 && i != 13 && i != 16 && (p[i] < '0' || p[i] > '9'))
            return 0;
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, sec = 0;
    if (sscanf(p, "%4d-%2d-%2dT%2d:%2d:%2d", &y, &mo, &d, &h, &mi, &sec) != 6)
        return 0;
    int leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    int days[] = {31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (mo < 1 || mo > 12 || d < 1 || d > days[mo - 1] || h > 23 || mi > 59 || sec > 59)
        return 0;
    y -= mo <= 2;
    int era = (y >= 0 ? y : y - 399) / 400, yoe = y - era * 400,
        doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1,
        doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    *out = ((int64_t)era * 146097 + doe) * 86400 + h * 3600 + mi * 60 + sec;
    return 1;
}
static int strings(J *v) {
    if (!type(v, json_type_array))
        return 0;
    for (size_t i = 0; i < len(v); i++)
        if (!type(at(v, i), json_type_string))
            return 0;
    return 1;
}
static int contains(J *a, J *v) {
    for (size_t i = 0; i < len(a); i++)
        if (equal(at(a, i), v))
            return 1;
    return 0;
}
static J *parameters(vh_context *c, J *raw, J *previous, int n) {
    json_object_object_foreach(raw, key, value) {
        (void)key;
        if (!value)
            fail(c, "invalid-parameter", n);
    }
    if ((!previous && !has(raw, "logVersion")) ||
        (has(raw, "logVersion") && strcmp(s(get(raw, "logVersion")), "vh-log:1.0")))
        fail(c, "unsupported-log-version", n);
    if (previous ? has(raw, "scid")
                 : !type(get(raw, "scid"), json_type_string) || !has(raw, "updateKeys"))
        fail(c, "invalid-parameter", n);
    if (has(raw, "updateKeys")) {
        J *keys = get(raw, "updateKeys");
        if (!strings(keys))
            fail(c, "invalid-parameter", n);
        for (size_t i = 0; i < len(keys); i++)
            if (!public_key(c, at(keys, i)))
                fail(c, "invalid-parameter", n);
    }
    if (has(raw, "nextKeyHashes")) {
        J *hashes = get(raw, "nextKeyHashes");
        if (!strings(hashes))
            fail(c, "invalid-parameter", n);
        for (size_t i = 0; i < len(hashes); i++)
            if (check_hash(c, s(at(hashes, i))) != 1)
                fail(c, "invalid-parameter", n);
    }
    J *p = clone_object(c, previous);
    if (!previous) {
        set(p, "nextKeyHashes", array(c));
        set(p, "witness", NULL);
        set(p, "watchers", array(c));
        set(p, "ttl", number(c, 3600));
    }
    const char *keys[] = {"logVersion", "scid",     "updateKeys", "nextKeyHashes",
                          "witness",    "watchers", "ttl"};
    for (size_t i = 0; i < 7; i++)
        if (has(raw, keys[i]))
            set(p, keys[i], get(raw, keys[i]));
    set(p, "deactivated", has(raw, "deactivated") ? get(raw, "deactivated") : boolean(c, 0));
    if (has(raw, "witness")) {
        J *w = get(raw, "witness");
        if (!type(w, json_type_object))
            fail(c, "invalid-parameter", n);
        if (!json_object_object_length(w))
            set(p, "witness", NULL);
        else {
            J *ws = get(w, "witnesses"), *ids = array(c);
            if (!type(ws, json_type_array) || !len(ws))
                fail(c, "invalid-parameter", n);
            for (size_t i = 0; i < len(ws); i++) {
                J *id = get(at(ws, i), "id");
                if (!type(id, json_type_string) || strncmp(s(id), "did:key:", 8) ||
                    !public_key(c, string(c, s(id) + 8)) || contains(ids, id))
                    fail(c, "invalid-parameter", n);
                push(ids, id);
            }
            J *t = get(w, "threshold");
            if (!integer(t) || num(t) < 1 || num(t) > len(ids))
                fail(c, "invalid-parameter", n);
            J *rule = object(c);
            set(rule, "threshold", t);
            set(rule, "witnesses", ws);
            set(p, "witness", rule);
        }
    }
    if (has(raw, "watchers")) {
        J *ws = get(raw, "watchers");
        if (!strings(ws))
            fail(c, "invalid-parameter", n);
        for (size_t i = 0; i < len(ws); i++) {
            const char *u = s(at(ws, i));
            const char *rest = !strncmp(u, "https://", 8)  ? u + 8
                               : !strncmp(u, "http://", 7) ? u + 7
                                                           : NULL;
            if (!rest || !*rest || strchr("/?#", *rest))
                fail(c, "invalid-parameter", n);
            for (size_t j = 0; j < slen(at(ws, i)); j++)
                if ((unsigned char)u[j] < 0x21 || (unsigned char)u[j] > 0x7e)
                    fail(c, "invalid-parameter", n);
        }
    }
    if (!type(get(p, "deactivated"), json_type_boolean) || !integer(get(p, "ttl")) ||
        num(get(p, "ttl")) < 0 || num(get(p, "ttl")) > 2147483648.0)
        fail(c, "invalid-parameter", n);
    if (previous && len(get(previous, "nextKeyHashes"))) {
        if (!has(raw, "updateKeys") || !has(raw, "nextKeyHashes"))
            fail(c, "prerotation-violation", n);
        J *keys2 = get(raw, "updateKeys");
        for (size_t i = 0; i < len(keys2); i++)
            if (!contains(get(previous, "nextKeyHashes"), string(c, hash(c, s(at(keys2, i))))))
                fail(c, "prerotation-violation", n);
    }
    return p;
}
static Entry verify_entry(vh_context *c, J *e, const Entry *previous, int64_t now) {
    int n = previous ? previous->number + 1 : 1;
    if (previous && json_object_get_boolean(get(previous->parameters, "deactivated")))
        fail(c, "entry-after-deactivation", n);
    if (json_object_object_length(e) != 5 || !type(get(e, "versionId"), json_type_string) ||
        !type(get(e, "versionTime"), json_type_string) ||
        !type(get(e, "parameters"), json_type_object) || !type(get(e, "state"), json_type_object) ||
        !type(get(e, "proof"), json_type_array))
        fail(c, "invalid-entry", n);
    J *p = parameters(c, get(e, "parameters"), previous ? previous->parameters : NULL, n);
    J *active = !previous || len(get(previous->parameters, "nextKeyHashes"))
                    ? get(p, "updateKeys")
                    : get(previous->parameters, "updateKeys");
    J *rule =
        !previous || (has(get(e, "parameters"), "witness") && !get(previous->parameters, "witness"))
            ? get(p, "witness")
            : get(previous->parameters, "witness");
    J *proofs = get(e, "proof");
    if (!len(proofs))
        fail(c, "invalid-proof", n);
    for (size_t i = 0; i < len(proofs); i++) {
        J *proof = at(proofs, i);
        char *mk = method_key(c, get(proof, "verificationMethod"));
        if (!mk)
            fail(c, "invalid-proof", n);
        if (!contains(active, string(c, mk)))
            fail(c, "unauthorized-key", n);
        if (!verify(c, without_proof(c, e), proof))
            fail(c, "invalid-proof", n);
    }
    const char *id = s(get(e, "versionId")), *dash = strchr(id, '-');
    char expected[40];
    snprintf(expected, sizeof expected, "%d", n);
    if (!dash || dash == id || (size_t)(dash - id) != strlen(expected) ||
        memcmp(id, expected, strlen(expected)) || !dash[1] || strchr(dash + 1, '-'))
        fail(c, "invalid-version-id", n);
    int check = check_hash(c, dash + 1);
    if (!check)
        fail(c, "invalid-version-id", n);
    if (check != 1)
        fail(c, "invalid-hash-algorithm", n);
    if (strcmp(entry_hash(c, e, s(previous ? get(previous->entry, "versionId") : get(p, "scid"))),
               dash + 1))
        fail(c, "entry-hash-mismatch", n);
    int64_t t = 0;
    if (!parse_time(get(e, "versionTime"), &t) || (previous && t <= previous->time))
        fail(c, "invalid-version-time", n);
    if (t > now + 300)
        fail(c, "future-version-time", n);
    if (!previous) {
        const char *sc = s(get(p, "scid"));
        check = check_hash(c, sc);
        if (check == 2)
            fail(c, "invalid-hash-algorithm", n);
        if (check != 1)
            fail(c, "scid-mismatch", n);
        J *rest = without_proof(c, e);
        set(rest, "versionId", string(c, "{SCID}"));
        int valid = 0;
        rest = parse(c, replace(c, jcs(c, rest), sc, "{SCID}"), &valid);
        if (!valid || strcmp(scid(c, rest), sc))
            fail(c, "scid-mismatch", n);
    }
    Entry out = {e, p, rule, n, t};
    return out;
}
static Verified *verify_log(vh_context *c, const char *log, J *witness, int has_witness,
                            int64_t now) {
    Verified *v = alloc(c, sizeof(*v));
    v->lines = lines(c, log);
    v->entries = alloc(c, len(v->lines) * sizeof(*v->entries));
    if (!len(v->lines)) {
        v->failure = report(c, "invalid-log", 0);
        return v;
    }
    jmp_buf trap;
    jmp_buf *outer = c->trap;
    c->trap = &trap;
    /* State is heap-resident so it remains defined across longjmp. */
    if (setjmp(trap) == 0) {
        while (v->count < len(v->lines)) {
            int valid = 0;
            J *raw = parse(c, s(at(v->lines, v->count)), &valid);
            if (!valid || !type(raw, json_type_object))
                fail(c, "invalid-log", (int)v->count + 1);
            Entry e = verify_entry(c, raw, v->count ? &v->entries[v->count - 1] : NULL, now);
            v->entries[v->count++] = e;
        }
    } else
        v->failure = c->error;
    c->trap = outer;
    for (size_t i = 0; i < v->count; i++) {
        J *rule = v->entries[i].rule;
        if (!rule)
            continue;
        J *file = has_witness ? witness : array(c);
        const char *code = NULL;
        int valid = type(file, json_type_array);
        for (size_t j = 0; valid && j < len(file); j++)
            if (!type(get(at(file, j), "versionId"), json_type_string) ||
                !type(get(at(file, j), "proof"), json_type_array))
                valid = 0;
        if (!valid)
            code = "invalid-witness-file";
        else {
            J *allowed = array(c), *approved = array(c), *ws = get(rule, "witnesses");
            for (size_t j = 0; j < len(ws); j++)
                push(allowed, get(at(ws, j), "id"));
            for (size_t j = 0; j < len(file); j++) {
                J *r = at(file, j);
                size_t index = v->count;
                for (size_t k = 0; k < v->count; k++)
                    if (equal(get(v->entries[k].entry, "versionId"), get(r, "versionId"))) {
                        index = k;
                        break;
                    }
                if (index == v->count || index < i)
                    continue;
                J *proofs = get(r, "proof");
                for (size_t k = 0; k < len(proofs); k++) {
                    J *proof = at(proofs, k);
                    char *mk = method_key(c, get(proof, "verificationMethod"));
                    if (!mk)
                        continue;
                    Buffer id = {0};
                    adds(c, &id, "did:key:");
                    adds(c, &id, mk);
                    J *identity = string(c, id.data), *doc = object(c);
                    set(doc, "versionId", get(r, "versionId"));
                    if (contains(allowed, identity) && !contains(approved, identity) &&
                        verify(c, doc, proof))
                        push(approved, identity);
                }
            }
            if (len(approved) < num(get(rule, "threshold")))
                code = "witness-threshold-not-met";
        }
        if (code) {
            v->failure = report(c, code, (int)i + 1);
            v->count = i;
            break;
        }
    }
    return v;
}
static J *line_value(vh_context *c, J *ls, size_t i) {
    if (i >= len(ls))
        return NULL;
    int valid = 0;
    J *v = parse(c, s(at(ls, i)), &valid);
    return valid ? v : NULL;
}
static J *line_id(vh_context *c, J *ls, size_t i) {
    J *id = get(line_value(c, ls, i), "versionId");
    return type(id, json_type_string) ? id : NULL;
}
static void warning(vh_context *c, J *warnings, const char *code, J *source) {
    J *w = object(c);
    set(w, "code", string(c, code));
    set(w, "message", string(c, code));
    if (source)
        set(w, "source", source);
    push(warnings, w);
}
static J *fork_copy(vh_context *c, J *source, J *id) {
    J *r = object(c);
    set(r, "source", source);
    set(r, "versionId", id ? id : string(c, ""));
    return r;
}
_Noreturn static void fork_error(vh_context *c, int n, J *copies) {
    J *r = report(c, "fork-detected", n), *fork = object(c);
    set(fork, "version", number(c, n));
    set(fork, "copies", copies);
    set(r, "fork", fork);
    throw_report(c, r);
}
static void retained(vh_context *c, Verified *v, J *source, J *id, J *warnings) {
    if (!type(id, json_type_string) || s(id)[0] < '1' || s(id)[0] > '9')
        fail(c, "invalid-option", 0);
    const char *p = s(id);
    while (*p >= '0' && *p <= '9')
        p++;
    if (*p != '-')
        fail(c, "invalid-option", 0);
    double big = strtod(s(id), NULL);
    if (big > v->count) {
        warning(c, warnings, "retained-version-not-found", NULL);
        return;
    }
    size_t n = (size_t)big;
    J *actual = get(v->entries[n - 1].entry, "versionId");
    if (!equal(actual, id)) {
        J *copies = array(c);
        push(copies, fork_copy(c, string(c, "retained"), id));
        push(copies, fork_copy(c, source, actual));
        fork_error(c, (int)n, copies);
    }
}
static J *result(vh_context *c, Verified *v, J *options, J *warnings, J *copies) {
    Entry *target = NULL;
    if (has(options, "versionId")) {
        for (size_t i = 0; i < v->count; i++)
            if (equal(get(v->entries[i].entry, "versionId"), get(options, "versionId"))) {
                target = &v->entries[i];
                break;
            }
        if (!target)
            for (size_t i = v->count; i < len(v->lines); i++)
                if (equal(line_id(c, v->lines, i), get(options, "versionId")))
                    throw_report(c, v->failure);
    } else if (has(options, "versionNumber")) {
        double n = num(get(options, "versionNumber"));
        if (n <= v->count)
            target = &v->entries[(size_t)n - 1];
        else if (n <= len(v->lines))
            throw_report(c, v->failure);
    } else if (has(options, "versionTime")) {
        int64_t t = 0;
        parse_time(get(options, "versionTime"), &t);
        if (v->failure) {
            int64_t invalid = 0;
            if (parse_time(get(line_value(c, v->lines, v->count), "versionTime"), &invalid) &&
                invalid <= t)
                throw_report(c, v->failure);
        }
        for (size_t i = v->count; i > 0; i--)
            if (v->entries[i - 1].time <= t) {
                target = &v->entries[i - 1];
                break;
            }
    } else
        target = &v->entries[v->count - 1];
    if (!target)
        fail(c, "not-found", 0);
    Entry *first = &v->entries[0], *last = &v->entries[v->count - 1];
    if (v->failure)
        warning(c, warnings, "invalid-entries", NULL);
    J *meta = object(c);
    set(meta, "versionId", get(target->entry, "versionId"));
    set(meta, "versionTime", get(target->entry, "versionTime"));
    set(meta, "versionNumber", number(c, target->number));
    set(meta, "created", get(first->entry, "versionTime"));
    set(meta, "updated", get(last->entry, "versionTime"));
    set(meta, "scid", get(first->parameters, "scid"));
    const char *keys[] = {"deactivated", "ttl", "witness", "watchers"};
    for (size_t i = 0; i < 4; i++)
        set(meta, keys[i], get(last->parameters, keys[i]));
    set(meta, "updateKeys", get(target->parameters, "updateKeys"));
    set(meta, "nextKeyHashes", get(target->parameters, "nextKeyHashes"));
    set(meta, "warnings", warnings);
    if (copies)
        set(meta, "copies", copies);
    J *out = object(c);
    set(out, "valid", boolean(c, 1));
    set(out, "state", get(target->entry, "state"));
    set(out, "metadata", meta);
    set(out, "firstInvalidVersion", v->failure ? number(c, (double)v->count + 1) : NULL);
    set(out, "error", v->failure);
    return out;
}
static Verified *copy_verify(vh_context *c, J *all, Verified **cache, size_t i, int64_t now) {
    if (!cache[i]) {
        J *v = at(all, i);
        cache[i] = verify_log(c, s(get(v, "log")), get(v, "witness"), has(v, "witness"), now);
    }
    return cache[i];
}
static void mark_invalid(vh_context *c, J *all, int *status, size_t i, J *warnings) {
    status[i] = 1;
    warning(c, warnings, "copy-invalid", get(at(all, i), "source"));
}
static J *resolve_copies(vh_context *c, J *input, int64_t now, J *options) {
    J *primary = object(c);
    set(primary, "source", string(c, "primary"));
    set(primary, "log", get(input, "log"));
    if (has(input, "witness"))
        set(primary, "witness", get(input, "witness"));
    J *all = array(c);
    push(all, primary);
    J *extra = get(input, "copies");
    for (size_t i = 0; i < len(extra); i++)
        push(all, at(extra, i));
    size_t count = len(all);
    int *status = alloc(c, count * sizeof(*status));
    int *matched = alloc(c, count * sizeof(*matched));
    Verified **cache = alloc(c, count * sizeof(*cache));
    J *warnings = array(c);
    for (size_t i = 0; i < count; i++)
        if (has(at(all, i), "unavailable")) {
            status[i] = 2;
            warning(c, warnings, "copy-unavailable", get(at(all, i), "source"));
        }
    size_t ref = count;
    for (size_t i = 0; i < count; i++) {
        if (status[i])
            continue;
        if (!copy_verify(c, all, cache, i, now)->failure) {
            ref = i;
            break;
        }
        mark_invalid(c, all, status, i, warnings);
    }
    if (ref == count) {
        J *out = object(c);
        set(out, "valid", boolean(c, 0));
        set(out, "error", copy_verify(c, all, cache, 0, now)->failure);
        return out;
    }
    matched[ref] = 1;
    for (size_t i = 0; i < count; i++) {
        if (status[i] || matched[i])
            continue;
        Verified *r = copy_verify(c, all, cache, ref, now), *v = copy_verify(c, all, cache, i, now);
        J *rl = r->lines, *cl = v->lines;
        if (!len(cl)) {
            mark_invalid(c, all, status, i, warnings);
            continue;
        }
        int same = len(cl) <= len(rl) && equal(line_id(c, cl, len(cl) - 1),
                                               get(r->entries[len(cl) - 1].entry, "versionId"));
        int extends = len(cl) > len(rl) && equal(line_id(c, cl, len(rl) - 1),
                                                 get(r->entries[r->count - 1].entry, "versionId"));
        if (same)
            matched[i] = 1;
        else if (extends && !v->failure) {
            matched[i] = 1;
            ref = i;
        } else if (v->failure)
            mark_invalid(c, all, status, i, warnings);
        else {
            size_t k = 0;
            while (k < len(rl) && k < len(cl) && equal(line_id(c, rl, k), line_id(c, cl, k)))
                k++;
            J *copies = array(c);
            push(copies, fork_copy(c, get(at(all, ref), "source"), line_id(c, rl, k)));
            push(copies, fork_copy(c, get(at(all, i), "source"), line_id(c, cl, k)));
            fork_error(c, (int)k + 1, copies);
        }
    }
    Verified *r = copy_verify(c, all, cache, ref, now);
    if (has(input, "retainedVersionId"))
        retained(c, r, get(at(all, ref), "source"), get(input, "retainedVersionId"), warnings);
    J *copies = array(c);
    size_t usable = 0;
    for (size_t i = 0; i < count; i++) {
        J *source = get(at(all, i), "source"), *record = object(c);
        set(record, "source", source);
        if (status[i]) {
            set(record, "status", string(c, status[i] == 2 ? "unavailable" : "invalid"));
            if (status[i] != 2) {
                J *ls = copy_verify(c, all, cache, i, now)->lines,
                  *id = line_id(c, ls, len(ls) - 1);
                if (id)
                    set(record, "versionId", id);
            }
        } else {
            J *ls = copy_verify(c, all, cache, i, now)->lines;
            int behind = len(ls) < len(r->lines);
            set(record, "status", string(c, behind ? "behind" : "current"));
            set(record, "versionId", line_id(c, ls, len(ls) - 1));
            usable++;
            if (behind)
                warning(c, warnings, "copy-behind", source);
        }
        push(copies, record);
    }
    if (usable < (has(options, "minCopies") ? num(get(options, "minCopies")) : 1))
        fail(c, "min-copies-not-met", 0);
    return result(c, r, options, warnings, copies);
}
static J *resolve_inner(vh_context *c, J *input) {
    int64_t now = 0;
    if (!parse_time(get(input, "now"), &now))
        fail(c, "invalid-option", 0);
    J *options = get(input, "options");
    if (!options)
        options = object(c);
    if (!type(options, json_type_object))
        fail(c, "invalid-option", 0);
    int selectors = 0;
    json_object_object_foreach(options, key, value) {
        (void)value;
        if (strcmp(key, "versionId") && strcmp(key, "versionTime") &&
            strcmp(key, "versionNumber") && strcmp(key, "minCopies"))
            fail(c, "invalid-option", 0);
        if (strcmp(key, "minCopies"))
            selectors++;
    }
    if (selectors > 1)
        fail(c, "invalid-option", 0);
    if (has(options, "versionId") && !type(get(options, "versionId"), json_type_string))
        fail(c, "invalid-option", 0);
    int64_t target_time = 0;
    if (has(options, "versionTime") && !parse_time(get(options, "versionTime"), &target_time))
        fail(c, "invalid-option", 0);
    const char *keys[] = {"versionNumber", "minCopies"};
    for (size_t i = 0; i < 2; i++)
        if (has(options, keys[i]) &&
            (!integer(get(options, keys[i])) || num(get(options, keys[i])) < 1))
            fail(c, "invalid-option", 0);
    if (has(input, "copies") || num(get(options, "minCopies")) > 1)
        return resolve_copies(c, input, now, options);
    Verified *v =
        verify_log(c, s(get(input, "log")), get(input, "witness"), has(input, "witness"), now);
    if (!v->count) {
        J *out = object(c);
        set(out, "valid", boolean(c, 0));
        set(out, "error", v->failure);
        return out;
    }
    J *warnings = array(c);
    if (has(input, "retainedVersionId"))
        retained(c, v, string(c, "primary"), get(input, "retainedVersionId"), warnings);
    return result(c, v, options, warnings, NULL);
}
static J *resolve(vh_context *c, J *input) {
    jmp_buf trap;
    jmp_buf *outer = c->trap;
    c->trap = &trap;
    J *out;
    if (setjmp(trap) == 0)
        out = resolve_inner(c, input);
    else {
        out = object(c);
        set(out, "valid", boolean(c, 0));
        set(out, "error", c->error);
    }
    c->trap = outer;
    return out;
}
static J *dispatch(vh_context *c, const char *op, J *input) {
    J *out = object(c);
    if (!strcmp(op, "jcs")) {
        int valid = 0;
        J *v = parse(c, s(get(input, "text")), &valid);
        if (!valid)
            fail(c, "invalid-json", 0);
        set(out, "output", string(c, jcs(c, v)));
    } else if (!strcmp(op, "hash")) {
        J *data = get(input, "data");
        set(out, "output", string(c, hash_n(c, s(data), slen(data))));
    } else if (!strcmp(op, "key-hash"))
        set(out, "output", string(c, hash(c, s(get(input, "multikey")))));
    else if (!strcmp(op, "multikey"))
        set(out, "multikey", string(c, multikey(c, s(get(input, "seed")))));
    else if (!strcmp(op, "scid"))
        set(out, "scid", string(c, scid(c, get(input, "entry"))));
    else if (!strcmp(op, "entry-hash"))
        set(out, "hash",
            string(c, entry_hash(c, get(input, "entry"), s(get(input, "previousVersionId")))));
    else if (!strcmp(op, "sign"))
        set(out, "proof", sign(c, get(input, "document"), s(get(input, "seed")), input));
    else if (!strcmp(op, "verify"))
        set(out, "valid", boolean(c, verify(c, get(input, "document"), get(input, "proof"))));
    else if (!strcmp(op, "witness")) {
        J *doc = object(c);
        set(doc, "versionId", get(input, "versionId"));
        set(out, "proof", sign(c, doc, s(get(input, "seed")), input));
    } else if (!strcmp(op, "create"))
        return create(c, input);
    else if (!strcmp(op, "update"))
        return update(c, input);
    else if (!strcmp(op, "resolve"))
        return resolve(c, input);
    else
        fail(c, "unknown-operation", 0);
    return out;
}
J *vh_request(vh_context *c, const char *request) {
    jmp_buf trap;
    c->trap = &trap;
    J *out = object(c);
    set(out, "id", NULL);
    if (setjmp(trap) == 0) {
        int valid = 0;
        J *r = parse(c, request, &valid);
        if (!valid || !type(r, json_type_object))
            fail(c, "invalid-request", 0);
        set(out, "id", get(r, "id"));
        if (!type(get(r, "op"), json_type_string) || !type(get(r, "input"), json_type_object))
            fail(c, "invalid-request", 0);
        J *result = dispatch(c, s(get(r, "op")), get(r, "input"));
        set(out, "ok", boolean(c, 1));
        set(out, "result", result);
    } else {
        set(out, "ok", boolean(c, 0));
        set(out, "error", get(c->error, "message"));
    }
    c->trap = NULL;
    return out;
}
