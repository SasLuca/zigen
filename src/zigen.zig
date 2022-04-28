const std = @import("std");

const Generator = @This();
arena: std.heap.ArenaAllocator,
top_level_nodes: std.ArrayListUnmanaged(Node) = .{},

raw_literals: std.StringArrayHashMapUnmanaged(void) = .{},
builtin_calls: std.ArrayListUnmanaged(BuiltinCall) = .{},
addrofs: std.ArrayListUnmanaged(Node) = .{},
pointers: std.MultiArrayList(Pointer) = .{},
decls: std.MultiArrayList(Decl) = .{},

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
        /// index into field `Generator.builtin_calls`.
        builtin_call,
        /// index into field `Generator.pointers`.
        pointer,
        /// index into field `Generator.addrofs`.
        addrof,
        /// index into field `Generator.decls`.
        decl,
        /// index into field `Generator.decls`.
        decl_alias,
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

pub const BuiltinCall = struct
{
    name: []const u8,
    params: []const Node,
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
    extern_mod: ExternMod,
    flags: Decl.Flags,
    name: []const u8,
    type_annotation: ?Node,
    value: ?Node,

    pub const ExternMod = union(enum)
    {
        none,
        static,
        dyn: []const u8,
    };

    pub const Flags = extern struct
    {
        is_pub: bool,
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

    for (self.top_level_nodes.items) |tln|
    {
        try writer.print("{}", .{self.fmtNode(tln)});
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
        .primitive_type => try writer.writeAll(@tagName(@intToEnum(PrimitiveType, node.index))),
        .unsigned_int => try writer.print("u{d}", .{@intCast(u16, node.index)}),
        .signed_int => try writer.print("i{d}", .{@intCast(u16, node.index)}),
        .raw_literal => try writer.writeAll(self.raw_literals.keys()[node.index]),
        .builtin_call =>
        {
            const builtin_call: BuiltinCall = self.builtin_calls.items[node.index];
            try writer.print("@{s}(", .{builtin_call.name});
            for (builtin_call.params[0..builtin_call.params.len - @boolToInt(builtin_call.params.len != 0)]) |param|
            {
                try writer.print("{}, ", .{self.fmtNode(param)});
            }
            if (builtin_call.params.len != 0)
            {
                try writer.print("{}", .{self.fmtNode(builtin_call.params[builtin_call.params.len - 1])});
            }
            try writer.writeByte(')');
        },
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
                const size: std.builtin.Type.Pointer.Size = sizes[idx];
                const sentinel: ?Node = sentinels[idx];
                const is_allowzero: bool = flags[idx].is_allowzero;
                const alignment: ?u29 = alignments[idx];
                const is_const: bool = flags[idx].is_const;
                const is_volatile: bool = flags[idx].is_volatile;

                switch (size)
                {
                    .C =>
                    {
                        std.debug.assert(sentinel == null);
                        std.debug.assert(!is_allowzero);
                    },
                    .One => std.debug.assert(sentinel == null),
                    .Many, .Slice => {},
                }
                switch (size)
                {
                    .One => try writer.writeByte('*'),
                    .Many =>
                    {
                        try if (sentinels[idx]) |s|
                            writer.print("[*:{}]", .{self.fmtNode(s)})
                        else
                            writer.writeAll("[*]");
                    },
                    .Slice =>
                    {
                        try if (sentinels[idx]) |s|
                            writer.print("[:{}]", .{self.fmtNode(s)})
                        else
                            writer.writeAll("[]"); 
                    },
                    .C => try writer.writeAll("[*c]"),
                }
                if (is_allowzero) try writer.writeAll("allowzero ");
                if (alignment) |a| try writer.print("align({}) ", .{a});
                if (is_const) try writer.writeAll("const ");
                if (is_volatile) try writer.writeAll("volatile ");

                maybe_current_index = null;
                switch (children[idx].tag)
                {
                    .primitive_type,
                    .unsigned_int,
                    .signed_int,
                    .raw_literal,
                    .builtin_call,
                    .decl,
                    .decl_alias,
                    => try writer.print("{}", .{self.fmtNode(children[idx])}),
                    .addrof => unreachable,
                    .pointer => maybe_current_index = children[idx].index,
                }
            }
        },
        .decl =>
        {
            const decl: Decl = self.decls.get(node.index);
            if (decl.flags.is_pub) try writer.writeAll("pub ");
            switch (decl.extern_mod) {
                .none =>
                {
                    try writer.writeAll(if (decl.flags.is_const) "const " else "var ");
                    try writer.print("{s}", .{std.zig.fmtId(decl.name)});
                    if (decl.type_annotation) |ta| try writer.print(": {}", .{self.fmtNode(ta)});
                    try writer.print(" = {};\n", .{self.fmtNode(decl.value.?)});
                },
                .static =>
                {
                    try writer.writeAll("extern ");
                    try writer.writeAll(if (decl.flags.is_const) "const " else "var ");
                    try writer.print("{s}", .{std.zig.fmtId(decl.name)});
                    try writer.print(": {};\n", .{self.fmtNode(decl.type_annotation.?)});
                    std.debug.assert(decl.value == null);
                },
                .dyn => |lib_str|
                {
                    try writer.print("extern \"{s}\" ", .{lib_str});
                    try writer.writeAll(if (decl.flags.is_const) "const " else "var ");
                    try writer.print("{s}", .{std.zig.fmtId(decl.name)});
                    try writer.print(": {};\n", .{self.fmtNode(decl.type_annotation.?)});
                    std.debug.assert(decl.value == null);
                },
            }
        },
        .decl_alias =>
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

pub fn createBuiltinCall(self: *Generator, builtin_name: []const u8, params: []const Node) std.mem.Allocator.Error!Node
{
    const new_index = self.builtin_calls.items.len;
    const new = try self.builtin_calls.addOne(self.allocator());
    errdefer _ = self.builtin_calls.pop();

    const duped_name = try self.allocator().dupe(u8, builtin_name);
    errdefer self.allocator().free(duped_name);

    const duped_params = try self.allocator().dupe(Node, params);
    errdefer self.allocator().free(duped_params);

    new.* = .{
        .name = duped_name,
        .params = duped_params,
    };

    return Node{
        .index = new_index,
        .tag = .builtin_call,
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

pub const Mutability = enum { Var, Const };

fn createDeclaration(
    self: *Generator,
    parent_index: ?Node.Index,
    is_pub: bool,
    extern_mod: Decl.ExternMod,
    mutability: Mutability,
    name: []const u8,
    type_annotation: ?Node,
    value: ?Node,
) std.mem.Allocator.Error!Node
{
    try self.decls.ensureUnusedCapacity(self.allocator(), 1);
    const new_index = self.decls.addOneAssumeCapacity();
    errdefer self.decls.shrinkRetainingCapacity(new_index);

    const duped_extern_mod: Decl.ExternMod = switch (extern_mod)
    {
        .none, .static => extern_mod,
        .dyn => |str| Decl.ExternMod{
            .dyn = try self.allocator().dupe(u8, str),
        },
    };
    errdefer {
        const str = switch (duped_extern_mod)
        {
            .none, .static => &[_]u8{},
            .dyn => |str| str,
        };
        self.allocator().free(str);
    }

    const duped_name = try self.allocator().dupe(u8, name);
    errdefer self.allocator().free(duped_name);

    self.decls.set(new_index, Decl{
        .parent_index = parent_index,
        .extern_mod = duped_extern_mod,
        .flags = .{ .is_pub = is_pub, .is_const = mutability == .Const },
        .name = duped_name,
        .type_annotation = type_annotation,
        .value = value,
    });
    
    return Node{
        .index = new_index,
        .tag = .decl,
    };
}

pub fn addDecl(
    self: *Generator,
    is_pub: bool,
    mutability: Mutability,
    name: []const u8,
    type_annotation: ?Node,
    value: Node,
) std.mem.Allocator.Error!Node
{
    const new_tldn = try self.top_level_nodes.addOne(self.allocator());
    errdefer _ = self.top_level_nodes.pop();

    new_tldn.* = try self.createDeclaration(null, is_pub, .none, mutability, name, type_annotation, value);
    return Node{
        .index = new_tldn.index,
        .tag = .decl_alias,
    };
}

fn expectNodeFmt(gen: *Generator, expected: []const u8, node: Node) !void
{
    return std.testing.expectFmt(expected, "{}", .{gen.fmtNode(node)});
}

test "node printing"
{
    var gen = Generator.init(std.testing.allocator);
    defer gen.deinit();

    try gen.expectNodeFmt("@This()", try gen.createBuiltinCall("This", &.{}));
    try gen.expectNodeFmt("type", try gen.primitiveTypeFrom(type));
    try gen.expectNodeFmt("u32", try gen.intTypeFrom(u32));
    try gen.expectNodeFmt("@as(u32, 43)",  try gen.createLiteral("@as(u32, 43)"));
    try gen.expectNodeFmt("&@as(u32, 43)", try gen.addressOf(try gen.createLiteral("@as(u32, 43)")));

    try gen.expectNodeFmt("*u32", try gen.createPointerType(.One, try gen.intTypeFrom(u32), .{}));
    try gen.expectNodeFmt("[*]u32", try gen.createPointerType(.Many, try gen.intTypeFrom(u32), .{}));
    try gen.expectNodeFmt("[]u32", try gen.createPointerType(.Slice, try gen.intTypeFrom(u32), .{}));
    try gen.expectNodeFmt("[:0]u32", try gen.createPointerType(.Slice, try gen.intTypeFrom(u32), .{
        .sentinel = try gen.createLiteral("0"),
    }));
    try gen.expectNodeFmt("[:0]align(16) u32", try gen.createPointerType(.Slice, try gen.intTypeFrom(u32), .{
        .sentinel = try gen.createLiteral("0"),
        .alignment = 16,
    }));
    try gen.expectNodeFmt("[:0]allowzero align(16) u32", try gen.createPointerType(.Slice, try gen.intTypeFrom(u32), .{
        .sentinel = try gen.createLiteral("0"),
        .alignment = 16,
        .flags = .{ .is_allowzero = true, .is_const = false, .is_volatile = false },
    }));
    try gen.expectNodeFmt("[:0]allowzero align(16) const u32", try gen.createPointerType(.Slice, try gen.intTypeFrom(u32), .{
        .sentinel = try gen.createLiteral("0"),
        .alignment = 16,
        .flags = .{ .is_allowzero = true, .is_const = true, .is_volatile = false },
    }));
    try gen.expectNodeFmt("[:0]allowzero align(16) const volatile u32", try gen.createPointerType(.Slice, try gen.intTypeFrom(u32), .{
        .sentinel = try gen.createLiteral("0"),
        .alignment = 16,
        .flags = .{ .is_allowzero = true, .is_const = true, .is_volatile = true },
    }));

    try gen.expectNodeFmt(
        "const foo = 3;\n",
        try gen.createDeclaration(null, false, .none, .Const, "foo", null, try gen.createLiteral("3")),
    );
    try gen.expectNodeFmt(
        "pub const foo = 3;\n",
        try gen.createDeclaration(null, true, .none, .Const, "foo", null, try gen.createLiteral("3")),
    );
    try gen.expectNodeFmt(
        "pub const foo = 3;\n",
        try gen.createDeclaration(null, true, .none, .Const, "foo", null, try gen.createLiteral("3")),
    );
    try gen.expectNodeFmt(
        "pub const foo: u32 = 3;\n",
        try gen.createDeclaration(null, true, .none, .Const, "foo", try gen.intTypeFrom(u32), try gen.createLiteral("3")),
    );
    try gen.expectNodeFmt(
        "pub var foo: u32 = 3;\n",
        try gen.createDeclaration(null, true, .none, .Var, "foo", try gen.intTypeFrom(u32), try gen.createLiteral("3")),
    );
    try gen.expectNodeFmt(
        "pub extern var foo: u32;\n",
        try gen.createDeclaration(null, true, .static, .Var, "foo", try gen.intTypeFrom(u32), null),
    );
    try gen.expectNodeFmt(
        "pub extern const foo: u32;\n",
        try gen.createDeclaration(null, true, .static, .Const, "foo", try gen.intTypeFrom(u32), null),
    );
}

test "top level decls"
{
    var gen = Generator.init(std.testing.allocator);
    defer gen.deinit();

    const foo_decl = try gen.addDecl(false, .Const, "foo", null, try gen.createLiteral("3"));
    const bar_decl = try gen.addDecl(false, .Var, "bar", try gen.intTypeFrom(u32), foo_decl);
    _ = try gen.addDecl(true, .Const, "p_bar", try gen.createPointerType(.One, try gen.intTypeFrom(u32), .{}), try gen.addressOf(bar_decl));

    try std.testing.expectFmt(
        \\const foo = 3;
        \\var bar: u32 = foo;
        \\pub const p_bar: *u32 = &bar;
        \\
    , "{}", .{gen});
}
