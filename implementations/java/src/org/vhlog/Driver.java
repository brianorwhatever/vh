package org.vhlog;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Map;
public final class Driver {
    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws IOException {
        Reader reader = new InputStreamReader(System.in, StandardCharsets.UTF_8);
        PrintWriter out = new PrintWriter(System.out, true, StandardCharsets.UTF_8);
        StringBuilder line = new StringBuilder();
        int c;
        while ((c = reader.read()) != -1) {
            if (c == '\n') {
                handle(line.toString(), out);
                line.setLength(0);
            } else
                line.append((char)c);
        }
        if (!line.isEmpty())
            handle(line.toString(), out);
    }
    @SuppressWarnings("unchecked")
    private static void handle(String line, PrintWriter out) {
        Object id = null;
        Map<String, Object> response;
        try {
            Map<String, Object> r = (Map<String, Object>)Json.parse(line);
            id = r.get("id");
            response =
                VHLog.obj("id", id, "ok", true, "result",
                          VHLog.dispatch((String)r.get("op"), (Map<String, Object>)r.get("input")));
        } catch (Exception e) {
            response = VHLog.obj("id", id, "ok", false, "error", e.toString());
        }
        out.println(Json.stringify(response));
    }
}
