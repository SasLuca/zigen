const std = @import("std");

const Generator = @This();
arena: std.heap.ArenaAllocator,
top_level_field_indices: std.ArrayListUnmanaged(usize) = .{},
/// indexes into `Arrays.decls`
top_level_decl_indices: std.ArrayListUnmanaged(usize) = .{},

arrays: Arrays = .{},

pub const Arrays = struct
{
    decls: std.MultiArrayList(Arrays.Decl) = .{},
    literals: std.StringArrayHashMapUnmanaged(void) = .{},
    imports: std.ArrayListUnmanaged([]const u8) = .{},

    pub const Decl = struct
    {
        name: []const u8,
        /// refers to the index of the parent container declaration, with 'null' meaning file scope.
        parent_index: ?Decl.Index,
        type_annotation: ?Decl.Value,
        value: Decl.Value,
        flags: Decl.Flags,

        pub const Flags = packed struct { is_pub: bool, is_const: bool };
        pub const Index = usize;
        pub const Value = struct
        {
            /// refers to the index of the value referred to by the declaration. Which array it indexes into is dependent on `Value.tag`.
            index: Value.Index,
            tag: Value.Tag,

            pub const Index = usize;
            pub const Tag = enum(usize)
            {
                /// index into `Arrays.literals`.
                literal,
                /// index into `Arrays.imports`.
                import,
                /// index into `Arrays.decls`.
                decl_alias,
                /// TODO:
                function,
            };
        };
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

pub fn write(self: Generator, writer: anytype) (@TypeOf(writer).Error || std.mem.Allocator.Error)!void
{
    for (self.top_level_field_indices.items) |field_index|
    {
        _ = field_index;
        std.debug.todo("");
    }
    for (self.top_level_decl_indices.items) |decl_index|
    {
        const decl: Arrays.Decl = self.arrays.decls.get(decl_index);
        if (decl.flags.is_pub) try writer.writeAll("pub ");
        if (decl.value.tag != .function)
        {
            try writer.writeAll(if (decl.flags.is_const) "const " else "var ");
            try writer.print("{s}", .{std.zig.fmtId(decl.name)});
            if (decl.type_annotation) |type_annotation|
            {
                try writer.writeAll(": ");
                switch (type_annotation.tag)
                {
                    .literal => try writer.print("{s}", .{self.arrays.literals.keys()[type_annotation.index]}),
                    .import => try writer.print("@import(\"{s}\")", .{self.arrays.imports.items[decl.value.index]}),
                    .decl_alias => try self.writeDeclReference(self.arrays.decls.get(type_annotation.index), writer),
                    .function => std.debug.todo(""),
                }
            }
            try writer.writeAll(" = ");
        }
        else
        {
            try writer.print("fn {s}", .{std.zig.fmtId(decl.name)});
            std.debug.todo("");
        }

        switch (decl.value.tag)
        {
            .literal => try writer.print("{s};\n", .{self.arrays.literals.keys()[decl.value.index]}),
            .import => try writer.print("@import(\"{s}\");\n", .{self.arrays.imports.items[decl.value.index]}),
            .decl_alias =>
            {
                try self.writeDeclReference(self.arrays.decls.get(decl.value.index), writer);
                try writer.writeAll(";\n");
            },
            .function => std.debug.todo(""),
        }
    }
}

fn writeDeclReference(self: Generator, decl: Arrays.Decl, writer: anytype) (@TypeOf(writer).Error || std.mem.Allocator.Error)!void
{
    const slice = self.arrays.decls.slice();

    const parent_indices: []const ?Arrays.Decl.Index = slice.items(.parent_index);
    const names: []const []const u8 = slice.items(.name);

    var access_chain = std.ArrayList([]const u8).init(self.arena.child_allocator);
    defer access_chain.deinit();

    var current_parent_idx = decl.parent_index;
    while (current_parent_idx) |idx|
    {
        try access_chain.insert(0, names[idx]);
        current_parent_idx = parent_indices[idx];
    }

    for (access_chain.items) |container_name|
    {
        try writer.print("{s}.", .{std.zig.fmtId(container_name)});
    }
    try writer.print("{s}", .{std.zig.fmtId(names[decl.value.index])});
}

fn allocator(self: *Generator) std.mem.Allocator
{
    return self.arena.allocator();
}

pub fn addDecl(
    self: *Generator,
    is_pub: bool,
    mutability: enum { @"const", @"var" },
    name: []const u8,
    type_annotation: ?Arrays.Decl.Value,
    value: Arrays.Decl.Value,
) std.mem.Allocator.Error!Arrays.Decl.Value
{
    const index = self.arrays.decls.len;

    try self.top_level_decl_indices.append(self.allocator(), index);
    errdefer self.top_level_decl_indices.shrinkRetainingCapacity(self.top_level_decl_indices.items.len - 1);

    const duped_name = try self.allocator().dupe(u8, name);
    errdefer self.allocator().free(duped_name);

    try self.arrays.decls.append(self.allocator(), Arrays.Decl{
        .name = duped_name,
        .parent_index = null,
        .type_annotation = type_annotation,
        .value = value,
        .flags = .{
            .is_pub = is_pub,
            .is_const = mutability == .@"const",
        },
    });

    return Arrays.Decl.Value{
        .index = index,
        .tag = .decl_alias,
    };
}

pub fn createLiteral(self: *Generator, literal_str: []const u8) std.mem.Allocator.Error!Arrays.Decl.Value
{
    const duped_literal_str = try self.allocator().dupe(u8, literal_str);
    errdefer self.allocator().free(duped_literal_str);

    var index = self.arrays.literals.entries.len;
    const gop = try self.arrays.literals.getOrPut(self.allocator(), duped_literal_str);
    if (gop.found_existing) {
        self.allocator().free(duped_literal_str);
        index = gop.index;
    }

    return Arrays.Decl.Value{
        .index = index,
        .tag = .literal,
    };
}

pub fn createImport(self: *Generator, import_str: []const u8) std.mem.Allocator.Error!Arrays.Decl.Value
{
    const duped_import_str = try self.allocator().dupe(u8, import_str);
    errdefer self.allocator().free(duped_import_str);

    const index = self.arrays.imports.items.len;
    try self.arrays.imports.append(self.allocator(), duped_import_str);

    return Arrays.Decl.Value{
        .index = index,
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

    const foo_import = try gen.addDecl(
        false,
        .@"const",
        "foo",
        null,
        try gen.createImport("foo.zig"),
    );

    _ = try gen.addDecl(
        true,
        .@"const",
        "bar",
        null,
        foo_import
    );

    _ = try gen.addDecl(
        true,
        .@"var",
        "baz",
        try gen.createLiteral("u32"),
        try gen.createLiteral("3"),
    );

    std.debug.print("\n\n", .{});
    try gen.write(std.io.getStdErr().writer());
    std.debug.print("\n", .{});
}
