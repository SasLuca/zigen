const std = @import("std");

const Generator = @This();
arena: std.heap.ArenaAllocator,
/// indexes into `Generator.decls`
top_level_decl_indices: std.ArrayListUnmanaged(usize) = .{},

decls: std.MultiArrayList(Decl) = .{},
raw_literals: std.StringArrayHashMapUnmanaged(void) = .{},
imports: std.StringArrayHashMapUnmanaged(void) = .{},

pub const Node = struct
{
    /// refers to the index of the value referred to by the declaration. Which array it indexes into is dependent on `Node.tag`.
    index: Node.Index,
    tag: Node.Tag,

    pub const Index = usize;
    pub const Tag = enum(usize)
    {
        /// index into `Generator.decls`.
        decl,
        /// index into `Generator.raw_literals`.
        raw_literal,
        /// index into `Generator.imports`.
        import,
    };
};

pub const Decl = struct
{
    /// refers to the index of the parent container declaration, with 'null' meaning file scope.
    parent_index: ?Node.Index,
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
        try writer.writeAll(if (decl.flags.is_const) "const " else "var ");

        try writer.print("{s}", .{std.zig.fmtId(decl.name)});
        if (decl.type_annotation) |type_annotation| try writer.print(": {}", .{self.fmtNode(type_annotation)});
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
        .raw_literal => try writer.writeAll(self.raw_literals.keys()[node.index]),
        .import => try writer.print("@import(\"{s}\")", .{self.imports.keys()[node.index]}),
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

pub fn addConstDecl(
    self: *Generator,
    is_pub: bool,
    name: []const u8,
    type_annotation: ?Generator.Node,
    value: Generator.Node,
) std.mem.Allocator.Error!Generator.Node
{
    try self.decls.ensureUnusedCapacity(self.allocator(), 1);
    const index = self.decls.addOneAssumeCapacity();
    errdefer self.decls.shrinkRetainingCapacity(index);

    try self.top_level_decl_indices.append(self.allocator(), index);
    errdefer _ = self.top_level_decl_indices.pop();

    const duped_name = try self.allocator().dupe(u8, name);
    errdefer self.allocator().free(duped_name);

    self.decls.set(index, Decl{
        .name = duped_name,
        .parent_index = null,
        .type_annotation = type_annotation,
        .value = value,
        .flags = .{
            .is_pub = is_pub,
            .is_extern = false,
            .is_const = true,
        },
    });

    return Generator.Node{
        .index = index,
        .tag = .decl,
    };
}

pub fn createLiteral(self: *Generator, literal_str: []const u8) std.mem.Allocator.Error!Generator.Node
{
    const gop = try self.raw_literals.getOrPut(self.allocator(), literal_str);
    if (!gop.found_existing)
    {
        gop.key_ptr.* = try self.allocator().dupe(u8, literal_str);
    }

    return Generator.Node{
        .index = gop.index,
        .tag = .raw_literal,
    };
}

pub fn createImport(self: *Generator, import_str: []const u8) std.mem.Allocator.Error!Generator.Node
{
    const gop = try self.imports.getOrPut(self.allocator(), import_str);
    if (!gop.found_existing)
    {
        gop.key_ptr.* = try self.allocator().dupe(u8, import_str);
    }

    return Generator.Node{
        .index = gop.index,
        .tag = .import,
    };
}

pub const IntInfo = struct
{
    signedness: std.builtin.Signedness,
    bits: u16,

    pub fn init(signedness: std.builtin.Signedness, bits: u16) IntInfo
    {
        return .{
            .signedness = signedness,
            .bits = bits,
        };
    }

    pub fn from(comptime T: type) IntInfo
    {
        const info = @typeInfo(T).Int;
        return .{
            .signedness = info.signedness,
            .bits = info.bits,
        };
    }

    pub fn format(self: IntInfo, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void
    {
        _ = fmt;
        _ = options;
        try switch (self.signedness)
        {
            .signed => writer.print("i{d}", .{self.bits}),
            .unsigned => writer.print("u{d}", .{self.bits}),
        };
    }
};

test "create import"
{
    var gen = Generator.init(std.testing.allocator);
    defer gen.deinit();

    const this_literal = try gen.createLiteral("@This()");
    _ = try gen.addConstDecl(false, "Self", null, this_literal);

    const foo_import = try gen.createImport("foo.zig");
    const foo_import_decl = try gen.addConstDecl(false, "internal_foo", null, foo_import);
    _ = try gen.addConstDecl(true, "foo", try gen.createLiteral("type"), foo_import_decl);

    std.debug.print("\n\n```\n{}\n```\n", .{gen});
}
