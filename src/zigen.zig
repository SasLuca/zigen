const std = @import("std");

const Generator = @This();
arena: std.heap.ArenaAllocator,
decls: std.ArrayListUnmanaged(Decl) = .{},

enum_types: std.ArrayListUnmanaged(EnumType) = .{},
enum_fields: std.ArrayListUnmanaged(EnumField) = .{},

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

pub fn write(self: Generator, writer: anytype) @TypeOf(writer).Error!void
{
    for (self.decls.items) |decl|
    {
        if (decl.is_pub) try writer.writeAll("pub ");
        try if (decl.is_const)
            writer.writeAll("const ")
        else
            writer.writeAll("var ");
        try writer.print("{s} = ", .{decl.name});
        switch (decl.value.tag)
        {
            .@"enum" =>
            {
                const info: EnumType = self.enum_types.items[decl.value.index];
                try writer.writeAll("enum");
                if (info.tag) |tag| try writer.print("({})", .{tag});
                try writer.writeAll("{\n");
                for (info.field_indexes) |field_idx|
                {
                    const field: EnumField = self.enum_fields.items[field_idx];
                    try writer.print("    {s} = {s},\n", .{field.name, field.value});
                }
                if (!info.is_exhaustive) try writer.writeAll("    _,\n");
                try writer.writeAll("};\n");
            },
        }
    }
}

pub fn addDecl(self: *Generator, is_pub: bool, mutability: enum { Const, Var }, name: []const u8, value: Decl.Value) std.mem.Allocator.Error!void
{
    const new_decl = try self.decls.addOne(self.allocator());
    errdefer self.decls.shrinkRetainingCapacity(self.decls.items.len - 1);

    new_decl.name = try self.allocator().dupe(u8, name);
    errdefer self.allocator().free(new_decl.name);

    new_decl.value = value;
    new_decl.is_pub = is_pub;
    new_decl.is_const = mutability == .Const;
}

pub fn buildEnum(self: *Generator, tag: ?IntegerType, is_exhaustive: bool) EnumBuilder
{
    return .{
        .generator = self,
        .tag = tag,
        .is_exhaustive = is_exhaustive,
        .fields = .{},
    };
}

fn allocator(self: *Generator) std.mem.Allocator
{
    return self.arena.allocator();
}

const EnumBuilder = struct
{
    generator: *Generator,
    tag: ?IntegerType,
    is_exhaustive: bool,
    fields: std.ArrayListUnmanaged(EnumField) = .{},

    pub fn addField(self: *EnumBuilder, name: []const u8, value: anytype) std.mem.Allocator.Error!void
    {
        const new = try self.fields.addOne(self.generator.allocator());
        errdefer self.fields.shrinkRetainingCapacity(self.fields.items.len - 1);
        
        new.name = try self.generator.allocator().dupe(u8, name);
        errdefer self.generator.allocator().free(new.name);
        
        const Value = @TypeOf(value);
        const err_msg = "Expected an integer or a zig string, got " ++ @typeName(Value);
        new.value = switch (@typeInfo(Value))
        {
            .Int,
            .ComptimeInt,
            => try std.fmt.allocPrint(self.generator.allocator(), "{d}", .{value}),

            .Pointer => if (std.meta.trait.isZigString(Value))
                try self.generator.allocator().dupe(u8, value)
            else
                @compileError(err_msg),

            .Optional => |optional|
            if (std.meta.trait.isZigString(optional.child))
                if (value) |value_unwrapped| try self.generator.allocator().dupe(u8, value_unwrapped) else null
            else
                @compileError(err_msg),
            .Null => null,
            else => @compileError(err_msg),
        };
        errdefer self.generator.allocator().free(new.value orelse &[_]u8{});
    }

    pub fn commit(self: *EnumBuilder) std.mem.Allocator.Error!Decl.Value
    {
        const new_enum_type = try self.generator.enum_types.addOne(self.generator.allocator());
        errdefer self.generator.enum_types.shrinkRetainingCapacity(self.generator.enum_types.items.len - 1);

        const field_indexes = try self.generator.allocator().alloc(u32, self.fields.items.len);
        errdefer self.generator.allocator().free(field_indexes);

        for (field_indexes) |*index, i| index.* = @intCast(u32, self.generator.enum_fields.items.len + i);

        try self.generator.enum_fields.appendSlice(self.generator.allocator(), self.fields.items);
        errdefer self.generator.enum_fields.shrinkRetainingCapacity(self.generator.enum_fields.items.len - self.fields.items.len);

        new_enum_type.tag = self.tag;
        new_enum_type.is_exhaustive = self.is_exhaustive;
        new_enum_type.field_indexes = field_indexes;

        self.fields.deinit(self.generator.allocator());
        defer self.* = undefined;

        return Decl.Value{
            .tag = .@"enum",
            .index = @intCast(u32, self.generator.enum_types.items.len - 1),
        };
    }
};

const IntegerType = struct
{
    sign: std.builtin.Signedness,
    bits: u16,

    pub fn format(self: IntegerType, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void
    {
        _ = fmt;
        _ = options;
        try switch (self.sign)
        {
            .signed => writer.print("i{d}", .{self.bits}),
            .unsigned => writer.print("u{d}", .{self.bits}),
        };
    }
};

pub fn integerType(sign: std.builtin.Signedness, bits: u16) IntegerType
{
    return .{ .sign = sign, .bits = bits };
}

const Decl = struct
{
    is_pub: bool,
    is_const: bool,
    name: []const u8,
    value: Value,

    const Value = struct {
        tag: Value.Tag,
        /// usage is in accordance with `tag`:
        /// * `@"enum"`: index into `Generator.enum_types`.
        index: Value.Index,

        const Index = u32;
        const Tag = enum {
            @"enum",
        };
    };

};

const EnumType = struct
{
    tag: ?IntegerType,
    is_exhaustive: bool,
    field_indexes: []const u32,
};

const EnumField = struct
{
    name: []const u8,
    value: ?[]const u8,
};

test "create enum"
{
    var generator = Generator.init(std.testing.allocator);
    defer generator.deinit();

    {
        var ebuilder = generator.buildEnum(integerType(.signed, 16), false);
        try ebuilder.addField("foo", 0);
        try ebuilder.addField("bar", 1);
        try ebuilder.addField("baz", std.math.maxInt(u16));

        const value = try ebuilder.commit();
        try generator.addDecl(true, .Const, "FooBarBaz", value);
    }
    
    var buffer = std.ArrayList(u8).init(std.testing.allocator);
    defer buffer.deinit();
    
    try generator.write(buffer.writer());
    
    std.debug.print("\n{s}\n", .{buffer.items});
}
