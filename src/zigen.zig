const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

pub fn writeStream(out_stream: anytype) WriteStream(@TypeOf(out_stream)) 
{
    return WriteStream(@TypeOf(out_stream)).init(out_stream);
}

pub const Visibility = enum {
    private,
    public,
};

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

        pub fn code(self: *Self, comptime text: []const u8, args: anytype) !void 
        {
            try self.indent();
            try self.stream.print(text, args);
        }

        pub fn codeNoIndent(self: *Self, comptime text: []const u8, args: anytype) !void
        {
            try self.stream.print(text, args);
        }

        pub fn beginScopePrefixed(self: *Self, comptime text: []const u8, args: anytype) !void
        {
            try self.indent();
            try self.stream.print(text, args);
            try self.stream.print(" {{\n", .{});
            self.whitespace.indent_level +|= 1;
        }
        
        pub fn beginScope(self: *Self) !void
        {
            try self.indent();
            try self.stream.print("{{\n", .{});
            self.whitespace.indent_level +|= 1;
        }

        pub fn endScope(self: *Self) !void
        {
            self.whitespace.indent_level -|= 1;
            try self.indent();
            try self.stream.print("}}", .{});
        }

        pub fn endStatementScope(self: *Self) !void
        {
            self.whitespace.indent_level -|= 1;
            try self.indent();
            try self.stream.print("}};\n", .{});
        }

        pub fn beginEnum(self: *Self, visibility: Visibility, comptime name: []const u8, args: anytype) !void
        {
            try self.indent();
            if (visibility == .public) try self.stream.print("pub ", .{});
            try self.stream.print("const " ++ name ++ " = enum {{\n", args);
            self.whitespace.indent_level +|= 1;
        }

        pub fn beginEnumWithTag(self: *Self, visibility: Visibility, comptime name: []const u8, name_args: anytype, comptime tag: []const u8, tag_args: anytype) !void
        {
            try self.indent();
            if (visibility == .public) try self.stream.print("pub ", .{});
            try self.stream.print("const " ++ name, name_args);
            try self.stream.print(" = enum(" ++ tag ++ ") {{\n", tag_args);
            self.whitespace.indent_level +|= 1;
        }

        pub fn enumConstant(self: *Self, comptime name: []const u8, args: anytype) !void
        {
            try self.indent();
            try self.stream.print(name ++ ",\n", args);
        }

        pub fn endEnum(self: *Self) !void
        {
            try self.endScope();
            try self.semicolon();
        }

        pub fn newline(self: *Self) !void
        {
            try self.codeNoIndent("\n", .{});
        }

        pub fn semicolon(self: *Self) !void
        {
            try self.codeNoIndent(";", .{});
        }

        fn indent(self: *Self) !void 
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
    var w = writeStream(stream.writer());

    try w.code(expected, .{});

    const result = stream.getWritten();
    try std.testing.expect(std.mem.eql(u8, expected, result));
}

test "generate enum"
{
    var out_buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&out_buf);
    const out = stream.writer();

    var w = writeStream(out);
    try w.beginEnum(.public, "Test", .{});
    try w.enumConstant("test", .{});
    try w.endEnum();
    
    const result = stream.getWritten();

    const expected =
        \\pub const Test = enum {
        \\    test,
        \\};
    ;

    try std.testing.expect(std.mem.eql(u8, expected, result));
}

test "generate private enum"
{
    var out_buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&out_buf);
    const out = stream.writer();

    var w = writeStream(out);
    try w.beginEnum(.private, "Test", .{});
    try w.enumConstant("test", .{});
    try w.endEnum();
    
    const result = stream.getWritten();

    const expected =
        \\const Test = enum {
        \\    test,
        \\};
    ;

    try std.testing.expect(std.mem.eql(u8, expected, result));
}

test "generate enum with multiple constants"
{
    var out_buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&out_buf);
    const out = stream.writer();

    var w = writeStream(out);
    try w.beginEnum(.public, "Test", .{});
    try w.enumConstant("test1", .{});
    try w.enumConstant("test2", .{});
    try w.enumConstant("test3", .{});
    try w.endEnum();
    
    const result = stream.getWritten();

    const expected =
        \\pub const Test = enum {
        \\    test1,
        \\    test2,
        \\    test3,
        \\};
    ;

    try std.testing.expect(std.mem.eql(u8, expected, result));
}

test "generate enum with tag"
{
    var out_buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&out_buf);
    const out = stream.writer();

    var w = writeStream(out);
    try w.beginEnumWithTag(.public, "Test", .{}, "c_int", .{});
    try w.enumConstant("test", .{});
    try w.endEnum();
    
    const result = stream.getWritten();

    const expected =
        \\pub const Test = enum(c_int) {
        \\    test,
        \\};
    ;

    try std.testing.expect(std.mem.eql(u8, expected, result));
}

test "generate enum with proc"
{
    var out_buf: [1024*4]u8 = undefined;
    var stream = std.io.fixedBufferStream(&out_buf);
    var w = writeStream(stream.writer());
    
    try w.beginEnumWithTag(.public, "Test", .{}, "c_int", .{});
        try w.enumConstant("test1", .{});
        try w.enumConstant("test2", .{});
        try w.enumConstant("test3", .{});
        try w.newline();
        try w.beginScopePrefixed("pub fn name(it: Test) []const u8", .{});
            try w.beginScopePrefixed("return switch(it)", .{});
                try w.code("Test.test1 => \"test1\",\n", .{});
                try w.code("Test.test2 => \"test2\",\n", .{});
                try w.code("Test.test3 => \"test3\",\n", .{});
            try w.endStatementScope();
        try w.endScope();
        try w.newline();
    try w.endEnum();
    
    const result = stream.getWritten();

    const expected =
        \\pub const Test = enum(c_int) {
        \\    test1,
        \\    test2,
        \\    test3,
        \\
        \\    pub fn name(it: Test) []const u8 {
        \\        return switch(it) {
        \\            Test.test1 => "test1",
        \\            Test.test2 => "test2",
        \\            Test.test3 => "test3",
        \\        };
        \\    }
        \\};
    ;

    try std.testing.expect(std.mem.eql(u8, expected, result));
}