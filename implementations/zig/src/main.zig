//! vh-log-driver: reads JSON Lines requests on stdin (split on "\n" only),
//! writes one response line per request to stdout, logs to stderr, and exits
//! 0 on EOF.

const std = @import("std");
const vhlog = @import("vhlog");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var in_buf: [64 * 1024]u8 = undefined;
    var in_reader = std.Io.File.stdin().readerStreaming(io, &in_buf);
    const in = &in_reader.interface;

    var out_buf: [64 * 1024]u8 = undefined;
    var out_writer = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const out = &out_writer.interface;

    var line: std.Io.Writer.Allocating = .init(gpa);
    defer line.deinit();

    while (true) {
        line.clearRetainingCapacity();
        _ = in.streamDelimiterEnding(&line.writer, '\n') catch |err| {
            std.log.err("reading stdin failed: {s}", .{@errorName(err)});
            return err;
        };
        // At end of stream the buffer is empty; otherwise it starts with '\n'.
        const at_eof = in.bufferedLen() == 0;
        if (!at_eof) in.toss(1); // the '\n'
        const text = line.written();
        if (text.len > 0) {
            const response = try vhlog.ops.handle(gpa, text);
            defer gpa.free(response);
            try out.writeAll(response);
            try out.writeByte('\n');
            try out.flush();
        }
        if (at_eof) break;
    }
}
