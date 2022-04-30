const std = @import("std");
const zigen = @import("zigen");

pub fn main() !void
{
    var out_buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&out_buf);
    const out = stream.writer();

    var w = zigen.writeStream(out);
    try w.beginEnum(.public, "Test", .{});
    try w.writeEnumConstant("test1", .{});
    try w.writeEnumConstant("test2", .{});
    try w.writeEnumConstant("test3", .{});
    try w.endEnum();
    
    const result = stream.getWritten();
    std.debug.print("{s}", .{result});
}