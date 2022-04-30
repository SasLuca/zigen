const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

pub fn writeStream(out_stream: anytype) WriteStream(@TypeOf(out_stream)) 
{
    return WriteStream(@TypeOf(out_stream)).init(out_stream);
}

pub fn WriteStream(comptime OutStream: type) type 
{
    return struct 
    {
        const Self = @This();

        pub const Stream = OutStream;

        stream: OutStream,
        whitespace: Whitespace,

        pub fn init(stream: OutStream) Self 
        { 
            var self = Self {
                .stream = stream,
                .whitespace = .{},
            };
            return self;
        }

        pub fn writeCode(self: *Self, comptime code: []const u8, args: anytype) !void 
        {
            try self.writeIndent();
            try self.stream.print(code, args);
        }

        pub fn beginEnum(self: *Self, is_pub: bool, comptime name: []const u8, args: anytype) !void
        {
            try self.writeIndent();
            if (is_pub) try self.stream.print("pub ", .{});
            try self.stream.print("const " ++ name ++ " = enum {{\n", args);
            self.whitespace.indent_level += 1;
        }

        pub fn writeEnumConstant(self: *Self, comptime name: []const u8, args: anytype) !void
        {
            try self.writeIndent();
            try self.stream.print(name ++ ",\n", args);
        }

        pub fn endEnum(self: *Self) !void
        {
            self.whitespace.indent_level -= 1;
            try self.writeIndent();
            try self.stream.print("}};\n", .{});
        }

        fn writeIndent(self: *Self) !void 
        {
            try self.whitespace.outputIndent(self.stream);
        }
    };
}

pub const Whitespace = struct 
{
    /// How many indentation levels deep are we?
    indent_level: usize = 0,

    /// What character(s) should be used for indentation?
    indent: union(enum) 
    {
        Space: u8,
        Tab: void,
    } = .{ .Space = 4 },

    /// After a colon, should whitespace be inserted?
    separator: bool = true,

    pub fn outputIndent(whitespace: @This(), out_stream: anytype) @TypeOf(out_stream).Error!void 
    {
        var char: u8 = undefined;
        var n_chars: usize = undefined;
        switch (whitespace.indent) 
        {
            .Space => |n_spaces| 
            {
                char = ' ';
                n_chars = n_spaces;
            },
            .Tab => 
            {
                char = '\t';
                n_chars = 1;
            },
        }
        n_chars *= whitespace.indent_level;
        try out_stream.writeByteNTimes(char, n_chars);
    }
};

test "generate simple code"
{
    const expected = "const foo = 1;";

    var out_buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&out_buf);
    const out = stream.writer();

    var w = writeStream(out);
    try w.writeCode(expected, .{});
    const result = stream.getWritten();

    try std.testing.expect(std.mem.eql(u8, expected, result));
}

test "generate enum"
{
    var out_buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&out_buf);
    const out = stream.writer();

    var w = writeStream(out);
    try w.beginEnum(true, "Test", .{});
    try w.writeEnumConstant("test", .{});
    try w.endEnum();
    
    const result = stream.getWritten();

    const expected =
        \\pub const Test = enum {
        \\    test,
        \\};
        \\
    ;

    try std.testing.expect(std.mem.eql(u8, expected, result));
}

test "generate enum with multiple constants"
{
    var out_buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&out_buf);
    const out = stream.writer();

    var w = writeStream(out);
    try w.beginEnum(true, "Test", .{});
    try w.writeEnumConstant("test1", .{});
    try w.writeEnumConstant("test2", .{});
    try w.writeEnumConstant("test3", .{});
    try w.endEnum();
    
    const result = stream.getWritten();

    const expected =
        \\pub const Test = enum {
        \\    test1,
        \\    test2,
        \\    test3,
        \\};
        \\
    ;

    try std.testing.expect(std.mem.eql(u8, expected, result));
}