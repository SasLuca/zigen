const std = @import("std");

const Generator = @This();
arena: std.heap.ArenaAllocator,
/// indexes into `Generator.decls`
top_level_decl_indices: std.ArrayListUnmanaged(usize) = .{},

raw_literals: std.StringArrayHashMapUnmanaged(void) = .{},
imports: std.StringArrayHashMapUnmanaged(void) = .{},
pointers: std.MultiArrayList(Pointer) = .{},
decls: std.MultiArrayList(Decl) = .{},

const _ = std.builtin.Type;

pub const Node = struct
{
    /// refers to the index of the value referred to by the declaration. Which array it indexes into is dependent on `Node.tag`.
    index: Node.Index,
    tag: Node.Tag,

    pub const Index = usize;
    pub const Tag = enum(usize)
    {
        /// index is a garbage value: do note use.
        extern_decl_value,
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
        /// index into field `Generator.decls`.
        decl,
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

    pub const Flags = packed struct
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
    _ = fmt;
    _ = options;

    for (self.top_level_decl_indices.items) |decl_index|
    {
        const decl: Decl = self.decls.get(decl_index);
        if (decl.flags.is_pub) try writer.writeAll("pub ");
        if (decl.flags.is_extern) try writer.writeAll("extern ");
        if (decl.extern_lib_str) |extern_lib_str| {
            std.debug.assert(decl.flags.is_extern);
            try writer.print("\"{s}\" ", .{extern_lib_str});
        }
        try writer.writeAll(if (decl.flags.is_const) "const " else "var ");

        try writer.print("{s}", .{std.zig.fmtId(decl.name)});
        if (decl.type_annotation) |type_annotation| try writer.print(": {}", .{self.fmtNode(type_annotation)});
        if (decl.flags.is_extern) {
            try writer.writeAll(";\n");
            return;
        }
        
        try writer.print(" = {};\n", .{self.fmtNode(decl.value)});
    }
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
        .extern_decl_value => {},
        .primitive_type => try writer.writeAll(@tagName(@intToEnum(PrimitiveType, node.index))),
        .unsigned_int => try writer.print("u{d}", .{@intCast(u16, node.index)}),
        .signed_int => try writer.print("i{d}", .{@intCast(u16, node.index)}),
        .raw_literal => try writer.writeAll(self.raw_literals.keys()[node.index]),
        .import => try writer.print("@import(\"{s}\")", .{self.imports.keys()[node.index]}),
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
                    .decl,
                    => try writer.print("{}", .{self.fmtNode(children[idx])}),
                    .extern_decl_value => unreachable,
                    .pointer => maybe_current_index = children[idx].index,
                }
            }
        },
        .decl =>
        {
            const slice = self.decls.slice();
            const names: []const []const u8 = slice.items(.name);

            const ParentIndexIterator = struct
            {
                const ParentIndexIterator = @This();
                parent_indices: []const ?Node.Index,
                current_parent_idx: ?usize,

                fn next(it: *ParentIndexIterator) ?Node.Index
                {
                    if (it.current_parent_idx) |idx|
                    {
                        it.current_parent_idx = it.parent_indices[idx];
                        return idx;
                    } else return null;
                }
            };
            const init_parent_index_iterator = ParentIndexIterator{
                .parent_indices = slice.items(.parent_index),
                .current_parent_idx = slice.items(.parent_index)[node.index],
            };

            const parent_count: usize = parent_count: {
                var parent_count: usize = 0;

                var iter = init_parent_index_iterator;
                while (iter.next()) |_| parent_count += 1;
                break :parent_count parent_count;
            };

            {
                var i_limit: usize = 0;
                while (i_limit < parent_count) : (i_limit += 1)
                {
                    var iter = init_parent_index_iterator;

                    var i: usize = parent_count;
                    while (true)
                    {
                        if (i == i_limit) break;
                        i -= 1;

                        const parent_idx = iter.next() orelse break;
                        try writer.print("{s}.", .{std.zig.fmtId(names[parent_idx])});
                    }
                }
            }
            try writer.print("{s}", .{std.zig.fmtId(names[node.index])});
        },
    }
}

fn allocator(self: *Generator) std.mem.Allocator
{
    return self.arena.allocator();
}

pub fn addDecl(
    self: *Generator,
    is_pub: bool,
    linkage: union(enum) { none, static, dyn: []const u8 },
    mutability: enum { @"var", @"const" },
    name: []const u8,
    type_annotation: ?Node,
    value: ?Node,
) std.mem.Allocator.Error!Node
{
    try self.decls.ensureUnusedCapacity(self.allocator(), 1);
    const index = self.decls.addOneAssumeCapacity();
    errdefer self.decls.shrinkRetainingCapacity(index);

    try self.top_level_decl_indices.append(self.allocator(), index);
    errdefer _ = self.top_level_decl_indices.pop();

    const duped_name = try self.allocator().dupe(u8, name);
    errdefer self.allocator().free(duped_name);

    const extern_lib_str: ?[]const u8 = switch (linkage)
    {
        .none, .static => null,
        .dyn => |str| try self.allocator().dupe(u8, str),
    };
    errdefer self.allocator().free(extern_lib_str orelse &.{});

    self.decls.set(index, Decl{
        .parent_index = null,
        .extern_lib_str = extern_lib_str,
        .flags = .{
            .is_pub = is_pub,
            .is_extern = linkage != .none,
            .is_const = mutability == .@"const",
        },
        .name = duped_name,
        .type_annotation = type_annotation,
        .value = if (linkage == .none) value.? else blk: {
            std.debug.assert(value == null);
            break :blk Node{
                .index = undefined,
                .tag = .extern_decl_value,
            };
        },
    });

    return Node{
        .index = index,
        .tag = .decl,
    };
}

pub fn primitiveType(self: *Generator, comptime T: type) error{}!Node
{
    _ = self;
    return Node{
        .index = @enumToInt(@field(PrimitiveType, @tagName(T))),
        .tag = .primitive_type,
    };
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

test "fundamentals"
{
    var gen = Generator.init(std.testing.allocator);
    defer gen.deinit();

    const this_literal = try gen.createLiteral("@This()");
    _ = try gen.addDecl(false, .none, .@"const", "Self", null, this_literal);

    const foo_import = try gen.createImport("foo.zig");
    const foo_import_decl = try gen.addDecl(false, .none, .@"const", "internal_foo", null, foo_import);
    _ = try gen.addDecl(true, .none, .@"const", "foo", try gen.createLiteral("type"), foo_import_decl);
    _ = try gen.addDecl(true, .static, .@"var", "counter", try gen.intType(.unsigned, 32), null);

    try std.testing.expectFmt(
        \\const Self = @This();
        \\const internal_foo = @import("foo.zig");
        \\pub const foo: type = internal_foo;
        \\pub extern var counter: u32;
        \\
    , "{}", .{gen});
}
