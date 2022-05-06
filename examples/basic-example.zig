const std = @import("std");
const zigen = @import("zigen");

pub fn main() !void
{
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    
    var generator = zigen.Generator.init(gpa.allocator());
    _ = generator;
    std.log.info("Basic Example", .{});
}
