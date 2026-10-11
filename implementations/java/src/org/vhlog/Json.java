package org.vhlog;

import java.math.*;
import java.util.*;

/** Strict JSON with binary64 numbers, UTF-16 key order and RFC 8785 output. */
public final class Json {
    private final String text;
    private int pos;
    private Json(String text) { this.text = text; }
    public static Object parse(String text) {
        Json p = new Json(text);
        Object v = p.value();
        p.space();
        if (p.pos != text.length())
            throw new IllegalArgumentException("trailing JSON text");
        return v;
    }
    private void space() {
        while (pos < text.length() && " \t\r\n".indexOf(text.charAt(pos)) >= 0)
            pos++;
    }
    private char take() {
        if (pos == text.length())
            throw new IllegalArgumentException("unexpected EOF");
        return text.charAt(pos++);
    }
    private void expect(char c) {
        if (take() != c)
            throw new IllegalArgumentException("invalid JSON");
    }
    private Object value() {
        space();
        char c = take();
        if (c == '"')
            return string();
        if (c == '{') {
            Map<String, Object> out = new LinkedHashMap<>();
            space();
            if (pos < text.length() && text.charAt(pos) == '}') {
                pos++;
                return out;
            }
            while (true) {
                space();
                expect('"');
                String k = string();
                space();
                expect(':');
                out.put(k, value());
                space();
                c = take();
                if (c == '}')
                    return out;
                if (c != ',')
                    throw new IllegalArgumentException("object separator");
            }
        }
        if (c == '[') {
            List<Object> out = new ArrayList<>();
            space();
            if (pos < text.length() && text.charAt(pos) == ']') {
                pos++;
                return out;
            }
            while (true) {
                out.add(value());
                space();
                c = take();
                if (c == ']')
                    return out;
                if (c != ',')
                    throw new IllegalArgumentException("array separator");
            }
        }
        for (String word : List.of("true", "false", "null"))
            if (c == word.charAt(0) && text.startsWith(word, pos - 1)) {
                pos += word.length() - 1;
                return word.equals("null") ? null : word.equals("true");
            }
        int start = --pos;
        while (pos < text.length() && "0123456789.eE+-".indexOf(text.charAt(pos)) >= 0)
            pos++;
        String number = text.substring(start, pos);
        if (!number.matches("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?"))
            throw new IllegalArgumentException("invalid number");
        double d = Double.parseDouble(number);
        if (!Double.isFinite(d))
            throw new IllegalArgumentException("non-finite number");
        return d;
    }
    private String string() {
        StringBuilder out = new StringBuilder();
        while (true) {
            char c = take();
            if (c == '"')
                break;
            if (c < 32)
                throw new IllegalArgumentException("control character");
            if (c == '\\') {
                c = take();
                switch (c) {
                case '"', '\\', '/' -> out.append(c);
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'u' -> {
                    String h = text.substring(pos, Math.min(pos + 4, text.length()));
                    if (!h.matches("[0-9a-fA-F]{4}"))
                        throw new IllegalArgumentException("unicode escape");
                    out.append((char)Integer.parseInt(h, 16));
                    pos += 4;
                }
                default -> throw new IllegalArgumentException("string escape");
                }
            } else
                out.append(c);
        }
        String s = out.toString();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (++i >= s.length() || !Character.isLowSurrogate(s.charAt(i)))
                    throw new IllegalArgumentException("lone surrogate");
            } else if (Character.isLowSurrogate(c))
                throw new IllegalArgumentException("lone surrogate");
        }
        return s;
    }
    public static String number(double d) {
        if (!Double.isFinite(d))
            throw new IllegalArgumentException("non-finite number");
        if (d == 0)
            return "0";
        BigDecimal exact = new BigDecimal(Math.abs(d));
        String digits = "";
        int n = 0;
        for (int precision = 1; precision <= 17; precision++) {
            BigDecimal rounded = exact.round(new MathContext(precision, RoundingMode.HALF_EVEN));
            if (Double.parseDouble(rounded.toString()) == Math.abs(d)) {
                rounded = rounded.stripTrailingZeros();
                digits = rounded.unscaledValue().toString();
                n = digits.length() - rounded.scale();
                break;
            }
        }
        int k = digits.length();
        String body;
        if (n >= k && n <= 21)
            body = digits + "0".repeat(n - k);
        else if (n > 0 && n <= 21)
            body = digits.substring(0, n) + "." + digits.substring(n);
        else if (n <= 0 && n > -6)
            body = "0."
                   + "0".repeat(-n) + digits;
        else
            body = digits.charAt(0) + (k > 1 ? "." + digits.substring(1) : "") + "e" +
                   (n - 1 >= 0 ? "+" : "") + (n - 1);
        return (d < 0 ? "-" : "") + body;
    }
    public static String stringify(Object v) {
        if (v == null)
            return "null";
        if (v instanceof Boolean)
            return v.toString();
        if (v instanceof Number n)
            return number(n.doubleValue());
        if (v instanceof String s) {
            StringBuilder b = new StringBuilder("\"");
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\b' -> b.append("\\b");
                case '\f' -> b.append("\\f");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> {
                    if (c < 32)
                        b.append(String.format("\\u%04x", (int)c));
                    else
                        b.append(c);
                }
                }
            }
            return b.append('"').toString();
        }
        if (v instanceof List<?> a)
            return "[" + String.join(",", a.stream().map(Json::stringify).toList()) + "]";
        if(v instanceof Map<?,?> m) {
            List<String> items = new ArrayList<>();
            for (String k : new TreeSet<>(m.keySet().stream().map(Object::toString).toList()))
                items.add(stringify(k) + ":" + stringify(m.get(k)));
            return "{" + String.join(",", items) + "}";
        }
        throw new IllegalArgumentException("unsupported JSON value");
    }
}
