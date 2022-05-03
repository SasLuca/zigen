const std = @import("std");

const Generator = @This();
arena: std.heap.ArenaAllocator,
top_level_nodes: ExternStructArraySet(StatementNode) = .{},
decls: std.MultiArrayList(Decl) = .{},

ordered_string_set: std.StringArrayHashMapUnmanaged(void) = .{},
ordered_node_set: ExternStructArraySet(ExprNode) = .{},

big_int_literals: ExternStructArraySet(BigIntLimbsRange) = .{},
list_inits: std.ArrayListUnmanaged(ListInit) = .{},
prefix_ops: ExternStructArraySet(PrefixOp) = .{},
bin_ops: std.ArrayListUnmanaged(BinOp) = .{},
postfix_ops: ExternStructArraySet(PostfixOp) = .{},
builtin_calls: std.ArrayListUnmanaged(BuiltinCall) = .{},
function_calls: std.ArrayListUnmanaged(FunctionCall) = .{},
pointers: std.MultiArrayList(Pointer) = .{},
dot_accesses: std.ArrayListUnmanaged(DotAccess) = .{},

/// string set to avoid duplicating the same string multiple times.
string_set: StringSet = .{},
/// referenced by `Generator.builtin_calls`, `Generator.function_calls`, and `Generator.list_inits`.
contiguous_node_list_store: std.ArrayListUnmanaged(ExprNode) = .{},
/// referenced by `Generator.big_int_literals`.
contiguous_big_int_limbs_store: std.ArrayListUnmanaged(std.math.big.Limb) = .{},
/// used during formatting for anything requring allocation,
/// grown during function calls that create things that would require
/// such scratch space.
scratch_space: std.ArrayListUnmanaged(u8) = .{},

const StringSet = std.StringHashMapUnmanaged(void);
fn dupeString(self: *Generator, str: []const u8) std.mem.Allocator.Error![]const u8
{
    const gop = try self.string_set.getOrPut(self.allocator(), str);
    if (!gop.found_existing) {
        gop.key_ptr.* = self.allocator().dupe(u8, str) catch |err| {
            std.debug.assert(self.string_set.remove(str));
            return err;
        };
    }
    return gop.key_ptr.*;
}

fn ExternStructArraySet(comptime T: type) type {
    const Context = struct
    {
        pub fn hash(self: @This(), prefix_op: T) u32 {
            _ = self;
            return @truncate(u32, std.hash.Wyhash.hash(0, std.mem.asBytes(&prefix_op)));
        }
        pub fn eql(self: @This(), a: T, b: T, b_index: usize) bool {
            _ = self;
            _ = b_index;
            return std.meta.eql(a, b);
        }
    };
    return std.ArrayHashMapUnmanaged(T, void, Context, false);
}

pub const StatementNode = extern struct
{
    /// meaning is dicated by `StatementNode.tag`.
    index: StatementNode.Index,
    tag: StatementNode.Tag,

    pub const Index = usize;
    pub const Tag = enum(u8)
    {
        /// index into field `Generator.decls`.
        decl,
        /// index into field `Generator.ordered_node_set`.
        usingnamespace_statement,
    };
};
pub const ExprNode = extern struct
{
    /// meaning is dicated by `ExprNode.tag`.
    index: ExprNode.Index,
    tag: ExprNode.Tag,

    pub const Index = usize;
    pub const Tag = enum(u8)
    {
        /// contextual sentinel node.
        invalid,
        /// index is the tag value of a `Generator.PrimitiveType`.
        primitive_type,
        /// index is the number of bits of the unsigned integer.
        unsigned_int_type,
        /// index is the number of bits of the signed integer.
        signed_int_type,
        /// index is the tag value of a `Generator.PrimitiveValue`.
        primitive_value,

        /// index is the value of a decimal integer literal.
        addr_sized_int_decimal,
        /// index is the value of a hex integer literal.
        addr_sized_int_hex,
        /// index is the value of an octal integer literal.
        addr_sized_int_octal,
        /// index is the value of a binrary integer literal.
        addr_sized_int_binary,

        /// index into field `Generator.big_int_literals`.
        big_int_literal_decimal,
        /// index into field `Generator.big_int_literals`.
        big_int_literal_hex,
        /// index into field `Generator.big_int_literals`.
        big_int_literal_octal,
        /// index into field `Generator.big_int_literals`.
        big_int_literal_binary,

        /// index into field `Generator.ordered_string_set`.
        raw_code_literal,
        /// index into field `Generator.ordered_string_set`.
        char_literal,
        /// index into field `Generator.ordered_string_set`.
        string_literal,
        /// index into field `Generator.list_inits`.
        list_init,
        /// index into field `Generator.prefix_ops`.
        prefix_op,
        /// index into field `Generator.bin_ops`.
        bin_op,
        /// index into field `Generator.postfix_ops`.
        postfix_op,
        /// index into field `Generator.builtin_calls`.
        builtin_call,
        /// index into field `Generator.function_calls`.
        function_call,
        /// index into field `Generator.ordered_node_set`.
        optional,
        /// index into field `Generator.pointers`.
        pointer,
        /// index into field `Generator.ordered_node_set`.
        parentheses_expression,
        /// index into field `Generator.dot_accesses`.
        dot_access,
        /// index into field `Generator.decls`.
        decl_ref,
    };

    fn nullIfInvalid(self: ExprNode) ?ExprNode
    {
        return if (self.tag != .invalid) self else null;
    }
};

const PrimitiveType = enum(ExprNode.Index)
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

const PrimitiveValue = enum(ExprNode.Index)
{
    @"true",
    @"false",
    @"null",
    @"undefined",
};

const BigIntLimbsRange = extern struct
{
    /// start of range in field `Generator.contiguous_big_int_limbs_store`.
    limbs_start: usize,
    /// end of range in field `Generator.contiguous_big_int_limbs_store`.
    limbs_end: usize,
};

const ListInit = struct
{
    annotations: ListInit.Annotations,
    /// start of range in field `Generator.contiguous_node_list_store`.
    elems_start: usize,
    /// end of range in field `Generator.contiguous_node_list_store`.
    elems_end: usize,

    const Annotations = union(enum)
    {
        /// full inference (`.{...}`).
        none,
        /// partial or no inference (`[_]T`, `[n]T`, `[_:s]T`, `[n:s]T`).
        some: ListInit.Annotations.Some,

        const Some = struct
        {
            type: ExprNode,
            sentinel: ExprNode = invalidExprNode(undefined),
            len: ExprNode = invalidExprNode(undefined),
        };
    };
};

const PrefixOp = extern struct
{
    tag: PrefixOp.Tag,
    target: ExprNode,

    const Tag = enum(u8)
    {
        @"-",
        @"-%",
        @"~",
        @"!",
        @"&",
    };
};
const BinOp = extern struct
{
    lhs: ExprNode,
    tag: BinOp.Tag,
    rhs: ExprNode,

    const Tag = enum(u8)
    {
        @"+",
        @"+%",
        @"+|",

        @"-",
        @"-%",
        @"-|",

        @"*",
        @"*%",
        @"*|",

        @"/",
        @"%",

        @"<<",
        @"<<|",
        @">>",
        @"&",
        @"|",
        @"^",

        @"orelse",
        @"catch",

        @"and",
        @"or",

        @"==",
        @"!=",
        @">",
        @">=",
        @"<",
        @"<=",

        @"++",
        @"**",
        @"||",
    };
};
const PostfixOp = extern struct
{
    tag: PostfixOp.Tag,
    target: ExprNode,

    const Tag = enum(u8) { @".?", @".*" };
};

const BuiltinCall = struct
{
    /// name of the builtin function.
    name: []const u8,
    /// start of range in field `Generator.contiguous_node_list_store`.
    params_start: usize,
    /// end of range in field `Generator.contiguous_node_list_store`.
    params_end: usize,
};

const FunctionCall = extern struct
{
    callable: ExprNode,
    params_start: usize,
    params_end: usize,
};

pub const Pointer = struct
{
    size: std.builtin.Type.Pointer.Size,
    alignment: ExprNode,
    child: ExprNode,
    sentinel: ExprNode,
    flags: Flags,

    pub const Flags = packed struct
    {
        is_const: bool = false,
        is_volatile: bool = false,
        is_allowzero: bool = false,
    };
};

const DotAccess = struct
{
    lhs: ExprNode,
    rhs: []const []const u8,
};

const Decl = struct
{
    /// refers to the index of the parent container declaration, with 'null' meaning file scope.
    parent_index: ?ExprNode.Index,
    extern_mod: ExternMod,
    flags: Decl.Flags,
    name: []const u8,
    type_annotation: ExprNode,
    value: ExprNode,

    const ExternMod = union(enum)
    {
        none,
        static,
        dyn: []const u8,
    };

    const Flags = extern struct
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

    for (self.top_level_nodes.keys()) |tln|
    {
        switch (tln.tag)
        {
            .decl,
            .usingnamespace_statement,
            => try writer.print("{}", .{self.fmtStatementNode(tln)}),
        }
    }
}

fn fmtExprNode(self: *const Generator, node: ExprNode) std.fmt.Formatter(formatExprNode)
{
    return .{
        .data = FormattableExprNode{
            .gen = self,
            .node = node,
        },
    };
}

const FormattableExprNode = struct { gen: *const Generator, node: ExprNode };
fn formatExprNode(
    fmt_node: FormattableExprNode,
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
        .invalid => unreachable,
        .primitive_type => try writer.writeAll(@tagName(@intToEnum(PrimitiveType, node.index))),
        .unsigned_int_type => try writer.print("u{d}", .{@intCast(u16, node.index)}),
        .signed_int_type => try writer.print("i{d}", .{@intCast(u16, node.index)}),
        .primitive_value => try writer.writeAll(@tagName(@intToEnum(PrimitiveValue, node.index))),

        .addr_sized_int_decimal => try writer.print("{d}", .{node.index}),
        .addr_sized_int_hex => try writer.print("{x}", .{node.index}),
        .addr_sized_int_octal => try writer.print("{o}", .{node.index}),
        .addr_sized_int_binary => try writer.print("{b}", .{node.index}),

        .big_int_literal_decimal,
        .big_int_literal_hex,
        .big_int_literal_octal,
        .big_int_literal_binary,
        =>
        {
            const range: BigIntLimbsRange = self.big_int_literals.keys()[node.index];
            const limbs = self.contiguous_big_int_limbs_store.items[range.limbs_start..range.limbs_end];
            const big_int = std.math.big.int.Const{
                .limbs = limbs,
                .positive = true,
            };

            var fba = std.heap.FixedBufferAllocator.init(self.scratch_space.items);
            const str = big_int.toStringAlloc(
                fba.allocator(),
                switch (node.tag)
                {
                    .big_int_literal_decimal => 10,
                    .big_int_literal_hex => 16,
                    .big_int_literal_octal => 8,
                    .big_int_literal_binary => 2,
                    else => unreachable,
                },
                .lower,
            ) catch unreachable;
            try writer.print("{s}", .{str});
        },

        .raw_code_literal => try writer.writeAll(self.ordered_string_set.keys()[node.index]),
        .char_literal => try writer.print("'{s}'", .{self.ordered_string_set.keys()[node.index]}),
        .string_literal => try writer.print("\"{s}\"", .{self.ordered_string_set.keys()[node.index]}),
        .list_init =>
        {
            const list_init: ListInit = self.list_inits.items[node.index];
            switch (list_init.annotations)
            {
                .none => try writer.writeByte('.'),
                .some => |annotations|
                {
                    std.debug.assert(annotations.type.tag != .invalid);
                    try writer.writeByte('[');
                    if (annotations.len.nullIfInvalid()) |len|
                    {
                        try writer.print("{}", .{self.fmtExprNode(len)});
                    }
                    else
                    {
                        try writer.writeByte('_');
                    }
                    if (annotations.sentinel.nullIfInvalid()) |s|
                    {
                        try writer.print(":{}]", .{self.fmtExprNode(s)});
                    }
                    else
                    {
                        try writer.writeByte(']');
                    }
                    try writer.print("{}", .{self.fmtExprNode(annotations.type)});
                },
            }

            const elements: []const ExprNode = self.contiguous_node_list_store.items[list_init.elems_start..list_init.elems_end];
            try writer.writeByte('{');
            switch (elements.len)
            {
                0 => {},
                1 => try writer.print("{}", .{self.fmtExprNode(elements[0])}),
                2 => try writer.print(" {}, {} ", .{self.fmtExprNode(elements[0]), self.fmtExprNode(elements[1])}),
                3 => try writer.print(" {}, {}, {} ", .{self.fmtExprNode(elements[0]), self.fmtExprNode(elements[1]), self.fmtExprNode(elements[2])}),
                else =>
                {
                    try writer.writeByte('\n');
                    for (elements) |elem|
                    {
                        try writer.print("    {},\n", .{self.fmtExprNode(elem)});
                    }
                },
            }
            try writer.writeByte('}');
        },
        .prefix_op => try writer.print("{s}{}", .{
            @tagName(self.prefix_ops.keys()[node.index].tag),
            self.fmtExprNode(self.prefix_ops.keys()[node.index].target),
        }),
        .bin_op => try writer.print("{} {s} {}", .{
            self.fmtExprNode(self.bin_ops.items[node.index].lhs),
            @tagName(self.bin_ops.items[node.index].tag),
            self.fmtExprNode(self.bin_ops.items[node.index].rhs),
        }),
        .postfix_op => try writer.print("{}{s}", .{
            self.fmtExprNode(self.postfix_ops.keys()[node.index].target),
            @tagName(self.postfix_ops.keys()[node.index].tag),
        }),
        .builtin_call =>
        {
            const builtin_call: BuiltinCall = self.builtin_calls.items[node.index];
            const params: []const ExprNode = self.contiguous_node_list_store.items[builtin_call.params_start..builtin_call.params_end];

            try writer.print("@{s}(", .{builtin_call.name});
            for (params[0..params.len - @boolToInt(params.len != 0)]) |param|
            {
                try writer.print("{}, ", .{self.fmtExprNode(param)});
            }
            if (params.len != 0)
            {
                try writer.print("{}", .{self.fmtExprNode(params[params.len - 1])});
            }
            try writer.writeByte(')');
        },
        .function_call =>
        {
            const function_call: FunctionCall = self.function_calls.items[node.index];
            const params: []const ExprNode = self.contiguous_node_list_store.items[function_call.params_start..function_call.params_end];

            try writer.print("{}(", .{self.fmtExprNode(function_call.callable)});
            for (params[0..params.len - @boolToInt(params.len != 0)]) |param|
            {
                try writer.print("{}, ", .{self.fmtExprNode(param)});
            }
            if (params.len != 0)
            {
                try writer.print("{}", .{self.fmtExprNode(params[params.len - 1])});
            }
            try writer.writeByte(')');
        },
        .optional => try writer.print("?{}", .{self.fmtExprNode(self.ordered_node_set.keys()[node.index])}),
        .pointer =>
        {
            const slice = self.pointers.slice();

            const pointer = Pointer{
                .size = slice.items(.size)[node.index],
                .sentinel = slice.items(.sentinel)[node.index],
                .alignment = slice.items(.alignment)[node.index],
                .flags = slice.items(.flags)[node.index],
                .child = slice.items(.child)[node.index],
            };

            switch (pointer.size)
            {
                .C =>
                {
                    std.debug.assert(pointer.sentinel.tag == .invalid);
                    std.debug.assert(!pointer.flags.is_allowzero);
                },
                .One => std.debug.assert(pointer.sentinel.tag == .invalid),
                .Many, .Slice => {},
            }
            switch (pointer.size)
            {
                .One => try writer.writeByte('*'),
                .Many =>
                {
                    try if (pointer.sentinel.nullIfInvalid()) |s|
                        writer.print("[*:{}]", .{self.fmtExprNode(s)})
                    else
                        writer.writeAll("[*]");
                },
                .Slice =>
                {
                    try if (pointer.sentinel.nullIfInvalid()) |s|
                        writer.print("[:{}]", .{self.fmtExprNode(s)})
                    else
                        writer.writeAll("[]"); 
                },
                .C => try writer.writeAll("[*c]"),
            }
            if (pointer.flags.is_allowzero) try writer.writeAll("allowzero ");
            if (pointer.alignment.nullIfInvalid()) |a| try writer.print("align({}) ", .{self.fmtExprNode(a)});
            if (pointer.flags.is_const) try writer.writeAll("const ");
            if (pointer.flags.is_volatile) try writer.writeAll("volatile ");

            switch (pointer.child.tag)
            {
                .primitive_type,
                .unsigned_int_type,
                .signed_int_type,
                .raw_code_literal,
                .bin_op,
                .postfix_op,
                .builtin_call,
                .function_call,
                .optional,
                .parentheses_expression,
                .dot_access,
                .decl_ref,
                .pointer,
                => try writer.print("{}", .{self.fmtExprNode(pointer.child)}),
                .invalid => unreachable,

                .addr_sized_int_decimal => unreachable,
                .addr_sized_int_hex => unreachable,
                .addr_sized_int_octal => unreachable,
                .addr_sized_int_binary => unreachable,

                .big_int_literal_decimal => unreachable,
                .big_int_literal_hex => unreachable,
                .big_int_literal_octal => unreachable,
                .big_int_literal_binary => unreachable,

                .primitive_value => unreachable,
                .char_literal => unreachable,
                .string_literal => unreachable,
                .list_init => unreachable,
                .prefix_op => unreachable,
            }
        },
        .parentheses_expression => try writer.print("({})", .{self.fmtExprNode(self.ordered_node_set.keys()[node.index])}),
        .dot_access =>
        {
            const dot_access: DotAccess = self.dot_accesses.items[node.index];
            try writer.print("{}", .{self.fmtExprNode(dot_access.lhs)});
            for (dot_access.rhs) |rhs|
            {
                try writer.print(".{s}", .{std.zig.fmtId(rhs)});
            }
        },
        .decl_ref =>
        {
            const slice = self.decls.slice();
            const names: []const []const u8 = slice.items(.name);

            const ParentIndexIterator = struct
            {
                const ParentIndexIterator = @This();
                parent_indices: []const ?ExprNode.Index,
                current_parent_idx: ?usize,

                fn next(it: *ParentIndexIterator) ?ExprNode.Index
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

fn fmtStatementNode(self: *const Generator, node: StatementNode) std.fmt.Formatter(formatStatementNode)
{
    return .{
        .data = FormattableStatementNode{
            .gen = self,
            .node = node,
        },
    };
}

const FormattableStatementNode = struct { gen: *const Generator, node: StatementNode };
fn formatStatementNode(
    fmt_decl: FormattableStatementNode,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) @TypeOf(writer).Error!void
{
    _ = fmt;
    _ = options;

    const self = fmt_decl.gen;
    const node = fmt_decl.node;
    switch (node.tag)
    {
        .decl =>
        {
            const decl: Decl = self.decls.get(node.index);
            if (decl.flags.is_pub) try writer.writeAll("pub ");
            switch (decl.extern_mod) {
                .none =>
                {
                    try writer.writeAll(if (decl.flags.is_const) "const " else "var ");
                    try writer.print("{s}", .{std.zig.fmtId(decl.name)});
                    if (decl.type_annotation.nullIfInvalid()) |ta| try writer.print(": {}", .{self.fmtExprNode(ta)});
                    try writer.print(" = {};\n", .{self.fmtExprNode(decl.value.nullIfInvalid().?)});
                },
                .static =>
                {
                    try writer.writeAll("extern ");
                    try writer.writeAll(if (decl.flags.is_const) "const " else "var ");
                    try writer.print("{s}", .{std.zig.fmtId(decl.name)});
                    try writer.print(": {};\n", .{self.fmtExprNode(decl.type_annotation.nullIfInvalid().?)});
                    std.debug.assert(decl.value.tag == .invalid);
                },
                .dyn => |lib_str|
                {
                    try writer.print("extern \"{s}\" ", .{lib_str});
                    try writer.writeAll(if (decl.flags.is_const) "const " else "var ");
                    try writer.print("{s}", .{std.zig.fmtId(decl.name)});
                    try writer.print(": {};\n", .{self.fmtExprNode(decl.type_annotation.nullIfInvalid().?)});
                    std.debug.assert(decl.value.tag == .invalid);
                },
            }
        },
        .usingnamespace_statement => try writer.print("usingnamespace {};\n", .{self.fmtExprNode(self.ordered_node_set.keys()[node.index])}),
    }
}

usingnamespace struct
{
    pub fn allocator(self: *Generator) std.mem.Allocator
    {
        return self.arena.allocator();
    }
};

fn invalidExprNode(index_value: ExprNode.Index) ExprNode
{
    return ExprNode{
        .index = index_value,
        .tag = .invalid,
    };
}

pub fn createPrimitiveType(tag: PrimitiveType) ExprNode
{
    return ExprNode{
        .index = @enumToInt(tag),
        .tag = .primitive_type,
    };
}
pub fn primType(comptime T: type) ExprNode
{
    return createPrimitiveType(@field(PrimitiveType, @typeName(T)));
}

pub fn createPrimitiveValue(tag: PrimitiveValue) ExprNode
{
    return ExprNode{
        .index = @enumToInt(tag),
        .tag = .primitive_value,
    };
}
pub fn trueValue() ExprNode
{
    return createPrimitiveValue(.@"true");
}
pub fn falseValue() ExprNode
{
    return createPrimitiveValue(.@"false");
}
pub fn nullValue() ExprNode
{
    return createPrimitiveValue(.@"null");
}
pub fn undefinedValue() ExprNode
{
    return createPrimitiveValue(.@"undefined");
}

pub fn createIntType(sign: std.builtin.Signedness, bits: u16) ExprNode
{
    return ExprNode{
        .index = bits,
        .tag = switch (sign) {
            .signed => .signed_int_type,
            .unsigned => .unsigned_int_type,
        },
    };
}
pub fn intType(comptime T: type) ExprNode
{
    const info: std.builtin.Type.Int = @typeInfo(T).Int;
    return createIntType(info.signedness, info.bits);
}

const IntLiteralRadix = enum
{
    decimal,
    hex,
    octal,
    binary,
};
pub fn createAddrSizedIntLiteral(radix: IntLiteralRadix, value: ExprNode.Index) ExprNode
{
    return ExprNode{
        .index = value,
        .tag = switch (radix)
        {
            .decimal => .addr_sized_int_decimal,
            .hex => .addr_sized_int_hex,
            .octal => .addr_sized_int_octal,
            .binary => .addr_sized_int_binary,
        },
    };
}
pub fn createBigIntLiteral(self: *Generator, radix: IntLiteralRadix, big_int: std.math.big.int.Const) std.mem.Allocator.Error!ExprNode
{
    std.debug.assert(big_int.positive);
    const tag: ExprNode.Tag = switch (radix)
    {
        .decimal => .big_int_literal_decimal,
        .hex => .big_int_literal_hex,
        .octal => .big_int_literal_octal,
        .binary => .big_int_literal_binary,
    };
    const base: u8 = switch (radix)
    {
        .decimal => 10,
        .hex => 16,
        .octal => 8,
        .binary => 2,
    };

    if (std.mem.indexOf(std.math.big.Limb, self.contiguous_big_int_limbs_store.items, big_int.limbs)) |limbs_start|
    {
        return ExprNode{
            .index = self.big_int_literals.getIndex(BigIntLimbsRange{
                .limbs_start = limbs_start,
                .limbs_end = limbs_start + big_int.limbs.len,
            }).?,
            .tag = tag,
        };
    }

    try self.scratch_space.ensureUnusedCapacity(
        self.allocator(),
        big_int.sizeInBaseUpperBound(base) +
            std.math.big.int.calcToStringLimbsBufferLen(big_int.limbs.len, base) * @sizeOf(std.math.big.Limb),
    );
    self.scratch_space.expandToCapacity();

    const limbs_start = self.contiguous_big_int_limbs_store.items.len;
    try self.contiguous_big_int_limbs_store.appendSlice(self.allocator(), big_int.limbs);
    const limbs_end = self.contiguous_big_int_limbs_store.items.len;
    errdefer self.contiguous_big_int_limbs_store.shrinkRetainingCapacity(limbs_start);

    const gop = try self.big_int_literals.getOrPut(self.allocator(), BigIntLimbsRange{
        .limbs_start = limbs_start,
        .limbs_end = limbs_end,
    });
    errdefer _ = self.big_int_literals.pop();
    std.debug.assert(!gop.found_existing);

    return ExprNode{
        .index = gop.index,
        .tag = tag,
    };
}
fn removeLatestBigIntLiteral(self: *Generator) void
{
    const range = self.big_int_literals.pop();
    std.debug.assert(range.limbs_end == self.contiguous_big_int_limbs_store.items.len);
    std.debug.assert(range.limbs_start < range.limbs_end);
    self.contiguous_big_int_limbs_store.shrinkRetainingCapacity(range.limbs_start);
}
pub fn createIntLiteral(self: *Generator, radix: IntLiteralRadix, value: anytype) std.mem.Allocator.Error!ExprNode
{
    switch (@typeInfo(@TypeOf(value)))
    {
        .Int => |info|
        {
            if (info.bits <= @bitSizeOf(ExprNode.Index))
            {
                const literal = Generator.createAddrSizedIntLiteral(radix, std.math.absCast(value));
                return if (value < 0) try self.createPrefixOp(.@"-", literal) else literal;
            }
            var big_int = try std.math.big.int.Managed.initSet(self.arena.child_allocator, value);
            defer big_int.deinit();

            const literal = try self.createBigIntLiteral(radix, big_int.toConst());
            errdefer self.removeLatestBigIntLiteral();

            return if (value < 0) try self.createPrefixOp(.@"-", literal) else literal;
        },
        .ComptimeInt => return self.createIntLiteral(radix, @as(std.math.IntFittingRange(value, value), value)),
        else => @compileError(std.fmt.comptimePrint("Expected a {s} or an integer type, got {s}.", .{@typeName(comptime_int), @typeName(@TypeOf(value))})),
    }
}

pub fn createListInit(
    self: *Generator,
    annotations: ListInit.Annotations,
    nodes: []const ExprNode,
) std.mem.Allocator.Error!ExprNode
{
    const new_index = self.list_inits.items.len;
    const new = try self.list_inits.addOne(self.allocator());
    errdefer _ = self.list_inits.pop();

    const elems_start = self.contiguous_node_list_store.items.len;
    try self.contiguous_node_list_store.appendSlice(self.allocator(), nodes);
    const elems_end = self.contiguous_node_list_store.items.len;
    errdefer self.contiguous_node_list_store.shrinkRetainingCapacity(elems_start);

    new.* = .{
        .annotations = annotations,
        .elems_start = elems_start,
        .elems_end = elems_end,
    };

    return ExprNode{
        .index = new_index,
        .tag = .list_init,
    };
}

pub fn createRawCode(self: *Generator, literal_str: []const u8) std.mem.Allocator.Error!ExprNode
{
    const gop = try self.ordered_string_set.getOrPut(self.allocator(), literal_str);
    if (!gop.found_existing)
    {
        gop.key_ptr.* = self.dupeString(literal_str) catch |err|
        {
            const popped_str = self.ordered_string_set.pop().key;
            if (@import("builtin").mode == .Debug)
            {
                std.debug.assert(std.mem.eql(u8, popped_str, literal_str));
            }
            return err;
        };
    }

    return ExprNode{
        .index = gop.index,
        .tag = .raw_code_literal,
    };
}
pub fn createRawCodeFmt(self: *Generator, comptime fmt: []const u8, args: anytype) std.mem.Allocator.Error!ExprNode
{
    const formatted_str = try std.fmt.allocPrint(self.arena.child_allocator, fmt, args);
    defer self.arena.child_allocator.free(formatted_str);
    return self.createRawCode(formatted_str);
}

pub const CreateCharLiteralError = error{
    InvalidEscapeCharacter,
    ExpectedHexDigit,
    EmptyUnicodeEscapeSequence,
    ExpectedHexDigitOrRbrace,
    InvalidUnicodeCodepoint,
    ExpectedLBrace,
    ExpectedRBrace,
    ExpectedSingleQuote,
    InvalidCharacter,
};
pub fn createCharLiteral(self: *Generator, char_literal_content: []const u8) (std.mem.Allocator.Error || CreateCharLiteralError)!ExprNode
{
    std.debug.assert(char_literal_content.len >= 1);
    { // validate char literal content.
        const with_single_quotes = try std.fmt.allocPrint(self.arena.child_allocator, "'{s}'", .{char_literal_content});
        defer self.arena.child_allocator.free(with_single_quotes);

        try switch (std.zig.parseCharLiteral(with_single_quotes))
        {
            .success => {},
            .failure => |err| switch (err)
            {
                .invalid_escape_character => error.InvalidEscapeCharacter,
                .expected_hex_digit => error.ExpectedHexDigit,
                .empty_unicode_escape_sequence => error.EmptyUnicodeEscapeSequence,
                .expected_hex_digit_or_rbrace => error.ExpectedHexDigitOrRbrace,
                .invalid_unicode_codepoint => error.InvalidUnicodeCodepoint,
                .expected_lbrace => error.ExpectedLBrace,
                .expected_rbrace => error.ExpectedRBrace,
                .expected_single_quote => error.ExpectedSingleQuote,
                .invalid_character => error.InvalidCharacter,
            },
        };
    }

    const duped_char_literal_content = try self.dupeString(char_literal_content);
    const gop = try self.ordered_string_set.getOrPut(self.allocator(), duped_char_literal_content);
    return ExprNode{
        .index = gop.index,
        .tag = .char_literal,
    };
}

pub fn createStringLiteral(self: *Generator, content: []const u8) std.mem.Allocator.Error!ExprNode
{
    const duped_content = try self.dupeString(content);
    const gop = try self.ordered_string_set.getOrPut(self.allocator(), duped_content);
    return ExprNode{
        .index = gop.index,
        .tag = .string_literal,
    };
}

pub fn createPrefixOp(self: *Generator, op: PrefixOp.Tag, target: ExprNode) std.mem.Allocator.Error!ExprNode
{
    const gop = try self.prefix_ops.getOrPut(self.allocator(), PrefixOp{
        .tag = op,
        .target = target,
    });
    return ExprNode{
        .index = gop.index,
        .tag = .prefix_op,
    };
}

pub fn createBinOp(self: *Generator, lhs: ExprNode, op: BinOp.Tag, rhs: ExprNode) std.mem.Allocator.Error!ExprNode
{
    const new_index = self.bin_ops.items.len;
    const new = try self.bin_ops.addOne(self.allocator());
    errdefer _ = self.bin_ops.pop();

    new.* = .{
        .lhs = lhs,
        .tag = op,
        .rhs = rhs,
    };

    return ExprNode{
        .index = new_index,
        .tag = .bin_op,
    };
}

pub fn createPostfixOp(self: *Generator, target: ExprNode, op: PostfixOp.Tag) std.mem.Allocator.Error!ExprNode
{
    const gop = try self.postfix_ops.getOrPut(self.allocator(), PostfixOp{
        .tag = op,
        .target = target,
    });
    return ExprNode{
        .index = gop.index,
        .tag = .postfix_op,
    };
}

pub fn createBuiltinCall(self: *Generator, builtin_name: []const u8, params: []const ExprNode) std.mem.Allocator.Error!ExprNode
{
    const duped_name = try self.dupeString(builtin_name);

    const new_index = self.builtin_calls.items.len;
    const new = try self.builtin_calls.addOne(self.allocator());
    errdefer _ = self.builtin_calls.pop();

    const params_start = self.contiguous_node_list_store.items.len;
    try self.contiguous_node_list_store.appendSlice(self.allocator(), params);
    const params_end = self.contiguous_node_list_store.items.len;
    errdefer self.contiguous_node_list_store.shrinkRetainingCapacity(params_start);

    new.* = .{
        .name = duped_name,
        .params_start = params_start,
        .params_end = params_end,
    };

    return ExprNode{
        .index = new_index,
        .tag = .builtin_call,
    };
}

pub fn createFunctionCall(self: *Generator, callable: ExprNode, params: []const ExprNode) std.mem.Allocator.Error!ExprNode
{
    const new_index = self.function_calls.items.len;
    const new = try self.function_calls.addOne(self.allocator());
    errdefer _ = self.function_calls.pop();

    const params_start = self.contiguous_node_list_store.items.len;
    try self.contiguous_node_list_store.appendSlice(self.allocator(), params);
    const params_end = self.contiguous_node_list_store.items.len;
    errdefer self.contiguous_node_list_store.shrinkRetainingCapacity(params_start);

    new.* = .{
        .callable = callable,
        .params_start = params_start,
        .params_end = params_end,
    };

    return ExprNode{
        .index = new_index,
        .tag = .function_call,
    };
}

pub fn createOptionalType(self: *Generator, node: ExprNode) std.mem.Allocator.Error!ExprNode
{
    const gop = try self.ordered_node_set.getOrPut(self.allocator(), node);
    return ExprNode{
        .index = gop.index,
        .tag = .optional,
    };
}

pub fn createPointerType(
    self: *Generator,
    size: std.builtin.Type.Pointer.Size,
    child: ExprNode,
    extra: struct
    {
        sentinel: ?ExprNode = null,
        alignment: ?ExprNode = null,
        flags: Pointer.Flags = .{ .is_allowzero = false, .is_const = false, .is_volatile = false },
    },
) std.mem.Allocator.Error!ExprNode
{
    const new_index = try self.pointers.addOne(self.allocator());
    errdefer self.pointers.shrinkRetainingCapacity(new_index);

    self.pointers.set(new_index, Pointer{
        .size = size,
        .alignment = extra.alignment orelse invalidExprNode(undefined),
        .child = child,
        .sentinel = extra.sentinel orelse invalidExprNode(undefined),
        .flags = extra.flags,
    });

    return ExprNode{
        .index = new_index,
        .tag = .pointer,
    };
}

pub fn createParenthesesExpression(self: *Generator, node: ExprNode) std.mem.Allocator.Error!ExprNode
{
    const gop = try self.ordered_node_set.getOrPut(self.allocator(), node);
    return ExprNode{
        .index = gop.index,
        .tag = .parentheses_expression,
    };
}

pub fn createDotAccess(self: *Generator, lhs: ExprNode, rhs: []const []const u8) std.mem.Allocator.Error!ExprNode
{
    const new_index = self.dot_accesses.items.len;
    const new_dot_access = try self.dot_accesses.addOne(self.allocator());
    errdefer _ = self.dot_accesses.pop();

    var ordered_string_set = try std.ArrayList([]const u8).initCapacity(self.allocator(), rhs.len);
    errdefer ordered_string_set.deinit();

    var linear_str = std.ArrayList(u8).init(self.allocator());
    errdefer linear_str.deinit();
    try linear_str.ensureUnusedCapacity(capacity: {
        var capacity: usize = 0;
        for (rhs) |str| capacity += str.len;
        break :capacity capacity;
    });

    for (rhs) |str|
    {
        const start = linear_str.items.len;
        linear_str.appendSliceAssumeCapacity(str);
        const end = linear_str.items.len;
        ordered_string_set.appendAssumeCapacity(linear_str.items[start..end]);
    }

    new_dot_access.* = .{
        .lhs = lhs,
        .rhs = ordered_string_set.toOwnedSlice(),
    };
    return ExprNode{
        .index = new_index,
        .tag = .dot_access,
    };
}

pub const Mutability = enum { Var, Const };
pub fn addDecl(
    self: *Generator,
    is_pub: bool,
    mutability: Mutability,
    name: []const u8,
    type_annotation: ?ExprNode,
    value: ExprNode,
) std.mem.Allocator.Error!ExprNode
{
    if (type_annotation) |ta| {
        std.debug.assert(ta.tag != .invalid);
    }
    const decl_node = try self.createDeclaration(null,
        is_pub,
        .none,
        mutability,
        name,
        type_annotation orelse Generator.invalidExprNode(undefined),
        value,
    );
    errdefer {
        self.decls.shrinkRetainingCapacity(self.decls.len - 1);
        std.debug.assert(self.decls.len == decl_node.index);
    }

    try self.top_level_nodes.putNoClobber(self.allocator(), decl_node, {});
    return ExprNode{
        .index = decl_node.index,
        .tag = .decl_ref,
    };
}

pub fn addUsingnamespace(self: *Generator, target: ExprNode) std.mem.Allocator.Error!void
{
    const usingnamespace_node = try self.createUsingnamespace(target);
    try self.top_level_nodes.putNoClobber(self.allocator(), usingnamespace_node, {});
}

pub fn createUsingnamespace(self: *Generator, target: ExprNode) std.mem.Allocator.Error!StatementNode
{
    const gop = try self.ordered_node_set.getOrPut(self.allocator(), target);
    return StatementNode{
        .index = gop.index,
        .tag = .usingnamespace_statement,
    };
}

fn createDeclaration(
    self: *Generator,
    parent_index: ?ExprNode.Index,
    is_pub: bool,
    extern_mod: Decl.ExternMod,
    mutability: Mutability,
    name: []const u8,
    type_annotation: ExprNode,
    value: ExprNode,
) std.mem.Allocator.Error!StatementNode
{
    const duped_name = try self.dupeString(name);

    const duped_extern_mod: Decl.ExternMod = switch (extern_mod)
    {
        .none, .static => extern_mod,
        .dyn => |str| Decl.ExternMod{
            .dyn = try self.dupeString(str),
        },
    };

    const new_index = try self.decls.addOne(self.allocator());
    errdefer self.decls.shrinkRetainingCapacity(new_index);

    errdefer {
        const str = switch (duped_extern_mod)
        {
            .none, .static => &[_]u8{},
            .dyn => |str| str,
        };
        self.allocator().free(str);
    }

    self.decls.set(new_index, Decl{
        .parent_index = parent_index,
        .extern_mod = duped_extern_mod,
        .flags = .{ .is_pub = is_pub, .is_const = mutability == .Const },
        .name = duped_name,
        .type_annotation = type_annotation,
        .value = value,
    });

    return StatementNode{
        .index = new_index,
        .tag = .decl,
    };
}

fn expectNodeFmt(gen: *Generator, expected: []const u8, node: anytype) !void
{
    const node_types = [_]type
    {
        ExprNode,
        StatementNode,
    };
    comptime
    {
        var msg: []const u8 = "Expected one of ";
        for (node_types) |NodeType|
        {
            if (@TypeOf(node) == NodeType) break;
            msg = msg ++ "'" ++ @typeName(NodeType) ++ "', ";
        }
        else
        {
            msg = msg ++ ", found " ++ @typeName(@TypeOf(node)) ++ ".\n";
            @compileError(msg);
        }
    }
    return switch (@TypeOf(node))
    {
        ExprNode => std.testing.expectFmt(expected, "{}", .{gen.fmtExprNode(node)}),
        StatementNode => std.testing.expectFmt(expected, "{}", .{gen.fmtStatementNode(node)}),
        else => unreachable,
    };
}

test "node printing behavior"
{
    _ = createBigIntLiteral;
    const allocator = std.testing.allocator;

    var gen = Generator.init(allocator);
    defer gen.deinit();

    const u32_type = Generator.intType(u32);
    const literal_43 = Generator.createAddrSizedIntLiteral(.decimal, 43);
    const p_u32_type = try gen.createPointerType(.One, u32_type, .{});

    try gen.expectNodeFmt("u32", u32_type);
    try gen.expectNodeFmt("43",  literal_43);
    try gen.expectNodeFmt("@as(*u32, undefined).*", try gen.createPostfixOp(try gen.createBuiltinCall("as", &.{ p_u32_type, Generator.undefinedValue() }), .@".*"));
    try gen.expectNodeFmt("@This()", try gen.createBuiltinCall("This", &.{}));
    try gen.expectNodeFmt("type", Generator.primType(type));
    try gen.expectNodeFmt("(43)", try gen.createParenthesesExpression(literal_43));
    try gen.expectNodeFmt("(43 + 43)", try gen.createParenthesesExpression(try gen.createBinOp(literal_43, .@"+", literal_43)));
    try gen.expectNodeFmt(std.fmt.comptimePrint("{d}", .{std.math.maxInt(usize) + 1}), try gen.createIntLiteral(.decimal, std.math.maxInt(usize) + 1));

    try gen.expectNodeFmt(".{}", try gen.createListInit(.none, &.{}));
    try gen.expectNodeFmt(".{43}", try gen.createListInit(.none, &.{literal_43}));
    try gen.expectNodeFmt(".{ 43, 43 }", try gen.createListInit(.none, &.{ literal_43, literal_43 }));
    try gen.expectNodeFmt(".{ 43, 43, 42 }", try gen.createListInit(.none, &.{ literal_43, literal_43, Generator.createAddrSizedIntLiteral(.decimal, 42) }));
    try gen.expectNodeFmt(
        \\.{
        \\    'a',
        \\    'b',
        \\    'c',
        \\    'd',
        \\}
    , try gen.createListInit(.none, &.{
        try gen.createCharLiteral("a"),
        try gen.createCharLiteral("b"),
        try gen.createCharLiteral("c"),
        try gen.createCharLiteral("d"),
    }));
    try gen.expectNodeFmt("[_]u32{}", try gen.createListInit(@unionInit(ListInit.Annotations, "some", .{ .type = u32_type }), &.{}));
    try gen.expectNodeFmt("[0]u32{}", try gen.createListInit(@unionInit(ListInit.Annotations, "some", .{
        .type = u32_type,
        .len = Generator.createAddrSizedIntLiteral(.decimal, 0),
    }), &.{}));
    try gen.expectNodeFmt("[_:0]u32{}", try gen.createListInit(@unionInit(ListInit.Annotations, "some", .{
        .type = u32_type,
        .sentinel = Generator.createAddrSizedIntLiteral(.decimal, 0),
    }), &.{}));
    try gen.expectNodeFmt("[0:0]u32{}", try gen.createListInit(@unionInit(ListInit.Annotations, "some", .{
        .type = u32_type,
        .len = Generator.createAddrSizedIntLiteral(.decimal, 0),
        .sentinel = Generator.createAddrSizedIntLiteral(.decimal, 0),
    }), &.{}));

    try gen.expectNodeFmt("*u32", p_u32_type);
    try gen.expectNodeFmt("?*u32", try gen.createOptionalType(p_u32_type));
    try gen.expectNodeFmt("**u32", try gen.createPointerType(.One, p_u32_type, .{}));

    try gen.expectNodeFmt("[*]u32", try gen.createPointerType(.Many, u32_type, .{}));
    try gen.expectNodeFmt("[]u32", try gen.createPointerType(.Slice, u32_type, .{}));
    try gen.expectNodeFmt("[:0]u32", try gen.createPointerType(.Slice, u32_type, .{
        .sentinel = Generator.createAddrSizedIntLiteral(.decimal, 0),
    }));
    try gen.expectNodeFmt("[:0]align(16) u32", try gen.createPointerType(.Slice, u32_type, .{
        .sentinel = Generator.createAddrSizedIntLiteral(.decimal, 0),
        .alignment = try gen.createIntLiteral(.decimal, 16),
    }));
    try gen.expectNodeFmt("[:0]allowzero align(16) u32", try gen.createPointerType(.Slice, u32_type, .{
        .sentinel = Generator.createAddrSizedIntLiteral(.decimal, 0),
        .alignment = try gen.createIntLiteral(.decimal, 16),
        .flags = .{ .is_allowzero = true },
    }));
    try gen.expectNodeFmt("[:0]allowzero align(16) const u32", try gen.createPointerType(.Slice, u32_type, .{
        .sentinel = Generator.createAddrSizedIntLiteral(.decimal, 0),
        .alignment = try gen.createIntLiteral(.decimal, 16),
        .flags = .{ .is_allowzero = true, .is_const = true },
    }));
    try gen.expectNodeFmt("[:0]allowzero align(16) const volatile u32", try gen.createPointerType(.Slice, u32_type, .{
        .sentinel = Generator.createAddrSizedIntLiteral(.decimal, 0),
        .alignment = try gen.createIntLiteral(.decimal, 16),
        .flags = .{ .is_allowzero = true, .is_const = true, .is_volatile = true },
    }));

    try gen.expectNodeFmt(
        "const foo = 3;\n",
        try gen.createDeclaration(null, false, .none, .Const, "foo", Generator.invalidExprNode(undefined), try gen.createIntLiteral(.decimal, 3)),
    );
    try gen.expectNodeFmt(
        "pub const foo = 3;\n",
        try gen.createDeclaration(null, true, .none, .Const, "foo", Generator.invalidExprNode(undefined), try gen.createIntLiteral(.decimal, 3)),
    );
    try gen.expectNodeFmt(
        "pub const foo = 3;\n",
        try gen.createDeclaration(null, true, .none, .Const, "foo", Generator.invalidExprNode(undefined), try gen.createIntLiteral(.decimal, 3)),
    );
    try gen.expectNodeFmt(
        "pub const foo: u32 = 3;\n",
        try gen.createDeclaration(null, true, .none, .Const, "foo", u32_type, try gen.createIntLiteral(.decimal, 3)),
    );
    try gen.expectNodeFmt(
        "pub var foo: u32 = 3;\n",
        try gen.createDeclaration(null, true, .none, .Var, "foo", u32_type, try gen.createIntLiteral(.decimal, 3)),
    );
    try gen.expectNodeFmt(
        "pub extern var foo: u32;\n",
        try gen.createDeclaration(null, true, .static, .Var, "foo", u32_type, Generator.invalidExprNode(undefined)),
    );
    try gen.expectNodeFmt(
        "pub extern \"fbb\" const foo: u32;\n",
        try gen.createDeclaration(null, true, .{ .dyn = "fbb" }, .Const, "foo", u32_type, Generator.invalidExprNode(undefined)),
    );

    try gen.expectNodeFmt(
        "usingnamespace @import(\"std\");\n",
        try gen.createUsingnamespace(try gen.createBuiltinCall("import", &.{ try gen.createStringLiteral("std") })),
    );
}

test "top level decls"
{
    const allocator = std.testing.allocator;

    var gen = Generator.init(allocator);
    defer gen.deinit();

    const std_import = try gen.addDecl(false, .Const, "std", null, try gen.createBuiltinCall("import", &.{ try gen.createStringLiteral("std") }));
    const array_list_ref_decl = try gen.addDecl(false, .Const, "ArrayListUnmanaged", null, try gen.createDotAccess(std_import, &.{ "ArrayListUnmanaged" }));
    const string_type_decl = try gen.addDecl(true, .Const, "String", null, try gen.createFunctionCall(array_list_ref_decl, &.{ Generator.intType(u8) }));

    const foo_decl = try gen.addDecl(false, .Const, "foo", null, try gen.createIntLiteral(.decimal, 3));
    const bar_decl = try gen.addDecl(false, .Var, "bar", Generator.intType(u32), foo_decl);
    _ = try gen.addDecl(true, .Const, "p_bar", try gen.createPointerType(.One, Generator.intType(u32), .{}), try gen.createPrefixOp(.@"&", bar_decl));
    _ = try gen.addDecl(true, .Const, "empty_str", string_type_decl, try gen.createListInit(.none, &.{}));

    try std.testing.expectFmt(
        \\const std = @import("std");
        \\const ArrayListUnmanaged = std.ArrayListUnmanaged;
        \\pub const String = ArrayListUnmanaged(u8);
        \\const foo = 3;
        \\var bar: u32 = foo;
        \\pub const p_bar: *u32 = &bar;
        \\pub const empty_str: String = .{};
        \\
    , "{}", .{gen});
}
