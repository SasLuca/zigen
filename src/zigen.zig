const std = @import("std");

const Generator = @This();
arena: std.heap.ArenaAllocator,
/// indexes into `Generator.decls`
top_level_decl_indices: std.ArrayListUnmanaged(TopLevelNode) = .{},

raw_literals: std.StringArrayHashMapUnmanaged(void) = .{},
imports: std.StringArrayHashMapUnmanaged(void) = .{},
addrofs: std.ArrayListUnmanaged(Node) = .{},
pointers: std.MultiArrayList(Pointer) = .{},

pub const TopLevelNode = struct
{
    index: TopLevelNode.Index,
    tag: TopLevelNode.Tag,

    pub const Index = usize;
    pub const Tag = enum(usize)
    {
        const_decl,
    };
};

pub const Node = struct
{
    /// refers to the index of the value referred to by the declaration. Which array it indexes into is dependent on `Node.tag`.
    index: Node.Index,
    tag: Node.Tag,

    pub const Index = usize;
    pub const Tag = enum(usize)
    {
        /// index is the tag value of a `Generator.PrimitiveType`.
        primitive_type,
        /// index is the number of bits of the unsigned integer.
        unsigned_int,
        /// index is the number of bits of the signed integer.
        signed_int,
        /// index into field `Generator.raw_literals`.
        raw_literal,
        /// index into field `Generator.imports`.
        import,
        /// index into field `Generator.pointers`.
        pointer,
        /// index into field `Generator.addrofs`.
        addrof,
    };
};

pub const PrimitiveType = enum
{
    @"isize",
    @"usize",
    @"c_short",
    @"c_ushort",
    @"c_int",
    @"c_uint",
    @"c_long",
    @"c_ulong",
    @"c_longlong",
    @"c_ulonglong",
    @"c_longdouble",
    @"bool",
    @"anyopaque",
    @"void",
    @"noreturn",
    @"type",
    @"anyerror",
    @"comptime_int",
    @"comptime_float",
};

pub const Pointer = struct
{
    size: std.builtin.Type.Pointer.Size,
    alignment: ?u29,
    child: Node,
    sentinel: ?Node,
    flags: Flags,

    pub const Flags = packed struct {
        is_const: bool,
        is_volatile: bool,
        is_allowzero: bool,
    };
};

pub const Decl = struct
{
    /// refers to the index of the parent container declaration, with 'null' meaning file scope.
    parent_index: ?Node.Index,
    extern_lib_str: ?[]const u8,
    flags: Decl.Flags,
    name: []const u8,
    type_annotation: ?Node,
    value: Node,

    pub const Flags = extern struct
    {
        is_pub: bool,
        is_extern: bool,
        is_const: bool,
    };
};


pub fn init(child_allocator: std.mem.Allocator) Generator
{
    return .{
        .arena = std.heap.ArenaAllocator.init(child_allocator),
    };
}

pub fn deinit(self: *Generator) void
{
    self.arena.deinit();
}

pub fn format(self: Generator, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void
{
    _ = self;
    _ = fmt;
    _ = options;
    _ = writer;
}

fn fmtNode(self: *const Generator, node: Node) std.fmt.Formatter(formatNode)
{
    return std.fmt.Formatter(formatNode){
        .data = FormattableNode{
            .gen = self,
            .node = node,
        },
    };
}

const FormattableNode = struct { gen: *const Generator, node: Node };
fn formatNode(
    fmt_node: FormattableNode,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) @TypeOf(writer).Error!void
{
    _ = fmt;
    _ = options;

    const self = fmt_node.gen;
    const node = fmt_node.node;
    switch (node.tag)
    {
        .primitive_type => try writer.writeAll(@tagName(@intToEnum(PrimitiveType, node.index))),
        .unsigned_int => try writer.print("u{d}", .{@intCast(u16, node.index)}),
        .signed_int => try writer.print("i{d}", .{@intCast(u16, node.index)}),
        .raw_literal => try writer.writeAll(self.raw_literals.keys()[node.index]),
        .import => try writer.print("@import(\"{s}\")", .{self.imports.keys()[node.index]}),
        .addrof => try writer.print("&{}", .{self.fmtNode(self.addrofs.items[node.index])}),
        .pointer =>
        {
            const slice = self.pointers.slice();
            const sizes: []const std.builtin.Type.Pointer.Size = slice.items(.size);
            const sentinels: []const ?Node = slice.items(.sentinel);
            const alignments: []const ?u29 = slice.items(.alignment);
            const flags: []const Pointer.Flags = slice.items(.flags);
            const children: []const Node = slice.items(.child);

            var maybe_current_index: ?Node.Index = node.index;
            while (maybe_current_index) |idx|
            {
                switch (sizes[idx])
                {
                    .One => try writer.writeByte('*'),
                    .Many => {
                        try if (sentinels[idx]) |s|
                            writer.print("[*:{}]", .{self.fmtNode(s)})
                        else
                            writer.writeAll("[*]");
                    },
                    .Slice => {
                        try if (sentinels[idx]) |s|
                            writer.print("[:{}]", .{self.fmtNode(s)})
                        else
                            writer.writeAll("[]"); 
                    },
                    .C => try writer.writeAll("[*c]"),
                }
                if (flags[idx].is_allowzero) try writer.writeAll("allowzero ");
                if (alignments[idx]) |alignment| try writer.print("align({}) ", .{alignment});
                if (flags[idx].is_const) try writer.writeAll("const ");
                if (flags[idx].is_volatile) try writer.writeAll("volatile ");

                maybe_current_index = null;
                switch (children[idx].tag)
                {
                    .primitive_type,
                    .unsigned_int,
                    .signed_int,
                    .raw_literal,
                    .import,
                    => try writer.print("{}", .{self.fmtNode(children[idx])}),
                    .addrof => unreachable,
                    .pointer => maybe_current_index = children[idx].index,
                }
            }
        },
    }
}

fn allocator(self: *Generator) std.mem.Allocator
{
    return self.arena.allocator();
}

pub fn primitiveType(self: *Generator, tag: PrimitiveType) error{}!Node
{
    _ = self;
    return Node{
        .index = @enumToInt(tag),
        .tag = .primitive_type,
    };
}
pub fn primitiveTypeFrom(self: *Generator, comptime T: type) error{}!Node
{
    return self.primitiveType(@field(PrimitiveType, @typeName(T)));
}

pub fn intType(self: *Generator, sign: std.builtin.Signedness, bits: u16) error{}!Node
{
    _ = self;
    return Node{
        .index = bits,
        .tag = switch (sign) {
            .signed => .signed_int,
            .unsigned => .unsigned_int,
        },
    };
}
pub fn intTypeFrom(self: *Generator, comptime T: type) error{}!Node
{
    const info: std.builtin.Type.Int = @typeInfo(T).Int;
    return self.intType(info.signedness, info.bits);
}

pub fn createLiteral(self: *Generator, literal_str: []const u8) std.mem.Allocator.Error!Node
{
    const gop = try self.raw_literals.getOrPut(self.allocator(), literal_str);
    if (!gop.found_existing)
    {
        gop.key_ptr.* = try self.allocator().dupe(u8, literal_str);
    }

    return Node{
        .index = gop.index,
        .tag = .raw_literal,
    };
}

pub fn createImport(self: *Generator, import_str: []const u8) std.mem.Allocator.Error!Node
{
    const gop = try self.imports.getOrPut(self.allocator(), import_str);
    if (!gop.found_existing)
    {
        gop.key_ptr.* = try self.allocator().dupe(u8, import_str);
    }

    return Node{
        .index = gop.index,
        .tag = .import,
    };
}

pub fn addressOf(self: *Generator, node: Node) std.mem.Allocator.Error!Node
{
    const new_index = self.addrofs.items.len;
    try self.addrofs.append(self.allocator(), node);
    return Node{
        .index = new_index,
        .tag = .addrof,
    };
}

pub fn createPointerType(
    self: *Generator,
    size: std.builtin.Type.Pointer.Size,
    child: Node,
    extra: struct
    {
        sentinel: ?Node = null,
        alignment: ?u29 = null,
        flags: Pointer.Flags = .{ .is_allowzero = false, .is_const = false, .is_volatile = false },
    },
) std.mem.Allocator.Error!Node
{
    try self.pointers.ensureUnusedCapacity(self.allocator(), 1);
    const new_index = self.pointers.addOneAssumeCapacity();
    errdefer self.pointers.shrinkRetainingCapacity(new_index);

    self.pointers.set(new_index, Pointer{
        .size = size,
        .alignment = extra.alignment,
        .child = child,
        .sentinel = extra.sentinel,
        .flags = extra.flags,
    });

    return Node{
        .index = new_index,
        .tag = .pointer,
    };
}

fn expectNodeFmt(gen: *Generator, expected: []const u8, node: Node) !void
{
    return std.testing.expectFmt(expected, "{}", .{gen.fmtNode(node)});
}

test "fundamentals"
{
    var gen = Generator.init(std.testing.allocator);
    defer gen.deinit();

    try gen.expectNodeFmt("@import(\"foo.zig\")", try gen.createImport("foo.zig"));
    try gen.expectNodeFmt("type", try gen.primitiveTypeFrom(type));
    try gen.expectNodeFmt("u32", try gen.intTypeFrom(u32));
    try gen.expectNodeFmt("@as(u32, 43)",  try gen.createLiteral("@as(u32, 43)"));
    try gen.expectNodeFmt("&@as(u32, 43)", try gen.addressOf(try gen.createLiteral("@as(u32, 43)")));

    try gen.expectNodeFmt("*u32", try gen.createPointerType(.One, try gen.intTypeFrom(u32), .{}));
    try gen.expectNodeFmt("[*]u32", try gen.createPointerType(.Many, try gen.intTypeFrom(u32), .{}));
    try gen.expectNodeFmt("[]u32", try gen.createPointerType(.Slice, try gen.intTypeFrom(u32), .{}));

    // try std.testing.expectFmt(
    //     \\const Self = @This();
    //     \\const internal_foo = @import("foo.zig");
    //     \\pub const foo: type = internal_foo;
    //     \\extern var counter: u32;
    //     \\
    // , "{}", .{gen});
}
