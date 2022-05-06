const std = @import("std");

// zig fmt: off
const Generator = @This();
arena: std.heap.ArenaAllocator,
top_level_nodes: ExternStructArraySet(StatementNode) = .{},
decls: std.MultiArrayList(Decl) = .{},

ordered_string_set: std.StringArrayHashMapUnmanaged(void) = .{},
ordered_node_set: ExternStructArraySet(ExprNode) = .{},

big_int_literals: BigIntSet = .{},
list_inits: std.ArrayListUnmanaged(ListInit) = .{},
bin_expr_operands: ExternStructArraySet(BinaryExprOperands) = .{},
builtin_calls: BuiltinCallSet = .{},
function_calls: FunctionCallSet = .{},
pointer_types: std.MultiArrayList(PointerType) = .{},
dot_accesses: std.ArrayListUnmanaged(DotAccess) = .{},

error_sets_set: ErrorSetsSet = .{},

/// string set to avoid duplicating the same string multiple times.
string_set: StringSet = .{},
/// referenced by `Generator.builtin_calls`, `Generator.function_calls`, and `Generator.list_inits`.
node_list_set: ExprNodeListSet = .{},
/// used during formatting for anything requring allocation,
/// grown during function calls that create things that would require
/// such scratch space.
scratch_space: std.ArrayListUnmanaged(u8) = .{},

fn dupeString(self: *Generator, str: []const u8) std.mem.Allocator.Error![]const u8
{
    const gop = try self.string_set.getOrPut(self.allocator(), str);
    if (!gop.found_existing)
    {
        gop.key_ptr.* = self.allocator().dupe(u8, str) catch |err| {
            std.debug.assert(self.string_set.remove(str));
            return err;
        };
    }
    return gop.key_ptr.*;
}
fn dupeExprNodeList(self: *Generator, node_list: []const ExprNode) std.mem.Allocator.Error![]const ExprNode
{
    const gop = try self.node_list_set.getOrPut(self.allocator(), node_list);
    if (!gop.found_existing)
    {
        gop.key_ptr.* = self.allocator().dupe(ExprNode, node_list) catch |err| {
            std.debug.assert(self.node_list_set.remove(node_list));
            return err;
        };
    }
    return gop.key_ptr.*;
}

const StringSet = std.StringHashMapUnmanaged(void);
const BigIntSet = std.ArrayHashMapUnmanaged(
    []const std.math.big.Limb,
    void,
    struct
    {
        pub fn hash(ctx: @This(), limbs: []const std.math.big.Limb) u32
        {
            _ = ctx;
            var hasher = std.hash.Wyhash.init(0);
            for (limbs) |*limb|
            {
                hasher.update(std.mem.asBytes(limb));
            }
            return @truncate(u32, hasher.final());
        }
        pub fn eql(ctx: @This(), a: []const std.math.big.Limb, b: []const std.math.big.Limb, b_index: usize) bool
        {
            _ = ctx;
            _ = b_index;
            return std.mem.eql(std.math.big.Limb, a, b);
        }
    },
    true,
);
const ExprNodeListSet = std.HashMapUnmanaged(
    []const ExprNode,
    void,
    struct
    {
        pub fn hash(ctx: @This(), list: []const ExprNode) u64
        {
            _ = ctx;
            var hasher = std.hash.Wyhash.init(0);
            for (list) |node|
            {
                std.hash.autoHash(&hasher, node);
            }
            return hasher.final();
        }
        pub fn eql(ctx: @This(), a: []const ExprNode, b: []const ExprNode) bool
        {
            _ = ctx;
            for (a) |node_a, i|
            {
                const node_b = b[i];
                if (!std.meta.eql(node_a, node_b)) return false;
            }
            return true;
        }
    },
    std.hash_map.default_max_load_percentage,
);
const BuiltinCallSet = std.ArrayHashMapUnmanaged(
    BuiltinCall,
    void,
    struct
    {
        pub fn hash(ctx: @This(), bcall: BuiltinCall) u32
        {
            _ = ctx;
            var hasher = std.hash.Wyhash.init(0);
            std.hash.autoHash(&hasher, bcall.name);
            for (bcall.params) |param|
            {
                std.hash.autoHash(&hasher, param);
            }
            return @truncate(u32, hasher.final());
        }
        pub fn eql(ctx: @This(), a: BuiltinCall, b: BuiltinCall, b_index: usize) bool
        {
            _ = ctx;
            _ = b_index;
            return a.name == b.name and for (a.params) |param_a, i|
            {
                const param_b = b.params[i];
                if (!std.meta.eql(param_a, param_b)) break false;
            } else true;
        }
    },
    true,
);
const FunctionCallSet = std.ArrayHashMapUnmanaged(
    FunctionCall,
    void,
    struct
    {
        pub fn hash(ctx: @This(), fcall: FunctionCall) u32
        {
            _ = ctx;
            var hasher = std.hash.Wyhash.init(0);
            std.hash.autoHash(&hasher, fcall.callable);
            for (fcall.params) |param|
            {
                std.hash.autoHash(&hasher, param);
            }
            return @truncate(u32, hasher.final());
        }
        pub fn eql(ctx: @This(), a: FunctionCall, b: FunctionCall, b_index: usize) bool
        {
            _ = ctx;
            _ = b_index;
            return std.meta.eql(a.callable, b.callable) and for (a.params) |param_a, i|
            {
                const param_b = b.params[i];
                if (!std.meta.eql(param_a, param_b)) break false;
            } else true;
        }
    },
    true,
);
const ErrorSetsSet = std.ArrayHashMapUnmanaged(
    []const []const u8,
    void,
    struct
    {
        pub fn hash(ctx: @This(), names: []const []const u8) u32
        {
            _ = ctx;
            var hasher = std.hash.Wyhash.init(0);
            for (names) |name|
            {
                hasher.update(std.mem.asBytes(&name.len));
                hasher.update(std.mem.asBytes(&name.ptr));
            }
            return @truncate(u32, hasher.final());
        }
        pub fn eql(ctx: @This(), a: []const []const u8, b: []const []const u8, b_index: usize) bool
        {
            _ = ctx;
            _ = b_index;
            for (a) |name_a, i|
            {
                const name_b = b[i];
                if (name_a.len != name_b.len or name_a.ptr != name_b.ptr) return false;
            }
            return true;
        }
    },
    true,
);
fn ExternStructArraySet(comptime T: type) type {
    const Context = struct
    {
        pub fn hash(self: @This(), k: T) u32 {
            _ = self;
            return @truncate(u32, std.hash.Wyhash.hash(0, std.mem.asBytes(&k)));
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
        /// contextual sentinel node.
        sentinel,
        /// index into field `Generator.decls`.
        decl_const,
        /// index into field `Generator.decls`.
        decl_var,
        /// index into field `Generator.decls`.
        decl_pub_const,
        /// index into field `Generator.decls`.
        decl_pub_var,
        /// index into field `Generator.ordered_node_set`.
        usingnamespace_statement,
        /// index into field `Generator.ordered_node_set`.
        pub_usingnamespace_statement,
    };

    fn unwrap(self: StatementNode) ?StatementNode
    {
        return if (self.tag != .sentinel) self else null;
    }
    const sentinel = StatementNode{
        .index = std.math.maxInt(StatementNode.Index),
        .tag = .sentinel,
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
        sentinel,
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
        /// index into field `Generator.ordered_string_set`.
        enum_literal,
        /// index into field `Generator.list_inits`.
        list_init,

        /// index into field `Generator.builtin_calls`.
        builtin_call,
        /// index into field `Generator.function_calls`.
        function_call,
        /// index into field `Generator.ordered_node_set`.
        optional,

        /// index into field `Generator.pointer_types`.
        pointer_one,
        /// index into field `Generator.pointer_types`.
        pointer_many,
        /// index into field `Generator.pointer_types`.
        pointer_slice,
        /// index into field `Generator.pointer_types`.
        pointer_c,

        /// index into field `Generator.ordered_node_set`.
        parentheses_expression,
        /// index into field `Generator.dot_accesses`.
        dot_access,
        /// index into field `Generator.decls`.
        decl_ref,

        /// index into field `Generator.ordered_node_set`.
        error_union_inferred,
        /// index into field `Generator.bin_expr_operands`.
        error_union,
        /// index into field `Generator.error_sets_set`.
        error_set,

        /// index into field `Generator.ordered_node_set`.
        @"prefix_op -",
        /// index into field `Generator.ordered_node_set`.
        @"prefix_op -%",
        /// index into field `Generator.ordered_node_set`.
        @"prefix_op ~",
        /// index into field `Generator.ordered_node_set`.
        @"prefix_op !",
        /// index into field `Generator.ordered_node_set`.
        @"prefix_op &",

        /// index into field `Generator.bin_expr_operands`.
        @"bin_op +",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op +%",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op +|",

        /// index into field `Generator.bin_expr_operands`.
        @"bin_op -",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op -%",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op -|",

        /// index into field `Generator.bin_expr_operands`.
        @"bin_op *",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op *%",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op *|",

        /// index into field `Generator.bin_expr_operands`.
        @"bin_op /",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op %",

        /// index into field `Generator.bin_expr_operands`.
        @"bin_op <<",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op <<|",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op >>",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op &",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op |",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op ^",

        /// index into field `Generator.bin_expr_operands`.
        @"bin_op orelse",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op catch",

        /// index into field `Generator.bin_expr_operands`.
        @"bin_op and",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op or",

        /// index into field `Generator.bin_expr_operands`.
        @"bin_op ==",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op !=",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op >",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op >=",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op <",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op <=",

        /// index into field `Generator.bin_expr_operands`.
        @"bin_op ++",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op **",
        /// index into field `Generator.bin_expr_operands`.
        @"bin_op ||",

        /// index into field `Generator.ordered_node_set`.
        @"postfix_op .?",
        /// index into field `Generator.ordered_node_set`.
        @"postfix_op .*",
    };

    fn unwrap(self: ExprNode) ?ExprNode
    {
        return if (self.tag != .sentinel) self else null;
    }
    const sentinel = ExprNode{
        .index = std.math.maxInt(ExprNode.Index),
        .tag = .sentinel,
    };
};

pub const PrimitiveType = enum(ExprNode.Index)
{
    f16,
    f32,
    f64,
    f80,
    f128,
    isize,
    usize,
    c_short,
    c_ushort,
    c_int,
    c_uint,
    c_long,
    c_ulong,
    c_longlong,
    c_ulonglong,
    c_longdouble,
    bool,
    anyopaque,
    void,
    noreturn,
    type,
    anyerror,
    comptime_int,
    comptime_float,
};

pub const PrimitiveValue = enum(ExprNode.Index)
{
    @"true",
    @"false",
    @"null",
    @"undefined",
};

const ListInit = struct
{
    annotations: ListInit.Annotations,
    elems: []const ExprNode,

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

const BinaryExprOperands = extern struct
{
    lhs: ExprNode,
    rhs: ExprNode,
};

const BuiltinFnName = enum
{
    addWithOverflow,
    alignCast,
    alignOf,
    as,
    asyncCall,
    atomicLoad,
    atomicRmw,
    atomicStore,
    bitCast,
    bitOffsetOf,
    boolToInt,
    bitSizeOf,
    breakpoint,
    mulAdd,
    byteSwap,
    bitReverse,
    offsetOf,
    call,
    cDefine,
    cImport,
    cInclude,
    clz,
    cmpxchgStrong,
    cmpxchgWeak,
    compileError,
    compileLog,
    ctz,
    cUndef,
    divExact,
    divFloor,
    divTrunc,
    embedFile,
    enumToInt,
    errorName,
    errorReturnTrace,
    errorToInt,
    errSetCast,
    @"export",
    @"extern",
    fence,
    field,
    fieldParentPtr,
    floatCast,
    floatToInt,
    frame,
    Frame,
    frameAddress,
    frameSize,
    hasDecl,
    hasField,
    import,
    intCast,
    intToEnum,
    intToError,
    intToFloat,
    intToPtr,
    maximum,
    memcpy,
    memset,
    minimum,
    wasmMemorySize,
    wasmMemoryGrow,
    mod,
    mulWithOverflow,
    panic,
    popCount,
    prefetch,
    ptrCast,
    ptrToInt,
    rem,
    returnAddress,
    select,
    setAlignStack,
    setCold,
    setEvalBranchQuota,
    setFloatMode,
    setRuntimeSafety,
    shlExact,
    shlWithOverflow,
    shrExact,
    shuffle,
    sizeOf,
    splat,
    reduce,
    src,
    sqrt,
    sin,
    cos,
    tan,
    exp,
    exp2,
    log,
    log2,
    log10,
    fabs,
    floor,
    ceil,
    trunc,
    round,
    subWithOverflow,
    tagName,
    This,
    truncate,
    Type,
    typeInfo,
    typeName,
    TypeOf,
    unionInit,
    Vector,
};

const BuiltinCall = struct
{
    name: BuiltinFnName,
    params: []const ExprNode,
};

const FunctionCall = struct
{
    callable: ExprNode,
    params: []const ExprNode,
};

pub const PointerType = extern struct
{
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

const ArrayType = extern struct
{
    len: ExprNode,
    sentinel: ExprNode,
    child: ExprNode,
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
    name: []const u8,
    type_annotation: ExprNode,
    alignment: ExprNode,
    @"linksection": ExprNode,
    value: ExprNode,

    const ExternMod = union(enum)
    {
        none,
        static,
        dyn: []const u8,
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

pub fn render(self: *const Generator, writer: anytype) @TypeOf(writer).Error!void
{
    for (self.top_level_nodes.keys()) |tln|
    {
        switch (tln.tag)
        {
            .sentinel => unreachable,
            .decl_const,
            .decl_var,
            .decl_pub_const,
            .decl_pub_var,
            .usingnamespace_statement,
            .pub_usingnamespace_statement,
            => try writer.print("{}", .{self.fmtStatementNode(tln)}),
        }
    }
}

pub fn renderFmt(self: *const Generator) std.fmt.Formatter(Generator.renderFormat)
{
    return .{ .data = self };
}
fn renderFormat(self: *const Generator, comptime fmt_str: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void
{
    _ = fmt_str;
    _ = options;
    return self.render(writer);
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
fn fmtStatementNode(self: *const Generator, node: StatementNode) std.fmt.Formatter(formatStatementNode)
{
    return .{
        .data = FormattableStatementNode{
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
        .sentinel => unreachable,
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
            const limbs: []const std.math.big.Limb = self.big_int_literals.keys()[node.index];
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
        .enum_literal => try writer.print(".{s}", .{std.zig.fmtId(self.ordered_string_set.keys()[node.index])}),
        .list_init =>
        {
            const list_init: ListInit = self.list_inits.items[node.index];
            switch (list_init.annotations)
            {
                .none => try writer.writeByte('.'),
                .some => |annotations|
                {
                    std.debug.assert(annotations.type.tag != .sentinel);
                    try writer.writeByte('[');
                    try if (annotations.len.unwrap()) |len| writer.print("{}", .{self.fmtExprNode(len)}) else writer.writeByte('_');
                    try if (annotations.sentinel.unwrap()) |s| writer.print(":{}]", .{self.fmtExprNode(s)}) else writer.writeByte(']');
                    try writer.print("{}", .{self.fmtExprNode(annotations.type)});
                },
            }

            const elements: []const ExprNode = list_init.elems;
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

        .builtin_call =>
        {
            const builtin_call: BuiltinCall = self.builtin_calls.keys()[node.index];
            const params: []const ExprNode = builtin_call.params;

            try writer.print("@{s}(", .{@tagName(builtin_call.name)});
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
            const function_call: FunctionCall = self.function_calls.keys()[node.index];
            const params: []const ExprNode = function_call.params;

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
        .pointer_one,
        .pointer_many,
        .pointer_slice,
        .pointer_c,
        =>
        {
            const slice = self.pointer_types.slice();

            const pointer = PointerType{
                .sentinel = slice.items(.sentinel)[node.index],
                .alignment = slice.items(.alignment)[node.index],
                .flags = slice.items(.flags)[node.index],
                .child = slice.items(.child)[node.index],
            };
            const size: std.builtin.Type.Pointer.Size = switch (node.tag)
            {
                .pointer_one => .One,
                .pointer_many => .Many,
                .pointer_slice => .Slice,
                .pointer_c => .C,
                else => unreachable,
            };

            switch (size)
            {
                .C =>
                {
                    std.debug.assert(pointer.sentinel.tag == .sentinel);
                    std.debug.assert(!pointer.flags.is_allowzero);
                },
                .One => std.debug.assert(pointer.sentinel.tag == .sentinel),
                .Many, .Slice => {},
            }
            switch (size)
            {
                .One => try writer.writeByte('*'),
                .Many =>
                {
                    try if (pointer.sentinel.unwrap()) |s|
                        writer.print("[*:{}]", .{self.fmtExprNode(s)})
                    else
                        writer.writeAll("[*]");
                },
                .Slice =>
                {
                    try if (pointer.sentinel.unwrap()) |s|
                        writer.print("[:{}]", .{self.fmtExprNode(s)})
                    else
                        writer.writeAll("[]"); 
                },
                .C => try writer.writeAll("[*c]"),
            }
            if (pointer.flags.is_allowzero) try writer.writeAll("allowzero ");
            if (pointer.alignment.unwrap()) |a| try writer.print("align({}) ", .{self.fmtExprNode(a)});
            if (pointer.flags.is_const) try writer.writeAll("const ");
            if (pointer.flags.is_volatile) try writer.writeAll("volatile ");

            switch (pointer.child.tag)
            {
                .primitive_type,
                .unsigned_int_type,
                .signed_int_type,
                .raw_code_literal,

                .builtin_call,
                .function_call,
                .optional,
                .parentheses_expression,
                .dot_access,
                .decl_ref,

                .pointer_one,
                .pointer_many,
                .pointer_slice,
                .pointer_c,

                .error_union,
                .error_set,

                .@"bin_op orelse",
                .@"bin_op catch",

                .@"postfix_op .?",
                .@"postfix_op .*",
                => try writer.print("{}", .{self.fmtExprNode(pointer.child)}),

                .sentinel => unreachable,

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
                .enum_literal => unreachable,
                .list_init => unreachable,

                .error_union_inferred => unreachable,

                .@"prefix_op -" => unreachable,
                .@"prefix_op -%" => unreachable,
                .@"prefix_op ~" => unreachable,
                .@"prefix_op !" => unreachable,
                .@"prefix_op &" => unreachable,

                .@"bin_op +" => unreachable,
                .@"bin_op +%" => unreachable,
                .@"bin_op +|" => unreachable,
                .@"bin_op -" => unreachable,
                .@"bin_op -%" => unreachable,
                .@"bin_op -|" => unreachable,
                .@"bin_op *" => unreachable,
                .@"bin_op *%" => unreachable,
                .@"bin_op *|" => unreachable,
                .@"bin_op /" => unreachable,
                .@"bin_op %" => unreachable,
                .@"bin_op <<" => unreachable,
                .@"bin_op <<|" => unreachable,
                .@"bin_op >>" => unreachable,
                .@"bin_op &" => unreachable,
                .@"bin_op |" => unreachable,
                .@"bin_op ^" => unreachable,

                .@"bin_op and" => unreachable,
                .@"bin_op or" => unreachable,
                .@"bin_op ==" => unreachable,
                .@"bin_op !=" => unreachable,
                .@"bin_op >" => unreachable,
                .@"bin_op >=" => unreachable,
                .@"bin_op <" => unreachable,
                .@"bin_op <=" => unreachable,
                .@"bin_op ++" => unreachable,
                .@"bin_op **" => unreachable,
                .@"bin_op ||" => unreachable, // you should surround the error set union operation with parentheses.
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

        .error_union_inferred => try writer.print("!{}", .{self.fmtExprNode(self.ordered_node_set.keys()[node.index])}),
        .error_union =>
        {
            const operands = self.bin_expr_operands.keys()[node.index];
            const error_set = operands.lhs;
            const payload = operands.rhs;
            try writer.print("{}!{}", .{self.fmtExprNode(error_set), self.fmtExprNode(payload)});
        },
        .error_set =>
        {
            const set: []const []const u8 = self.error_sets_set.keys()[node.index];
            try writer.writeAll("error{");
            switch (set.len)
            {
                0 => {},
                1 => try writer.print("{s}", .{std.zig.fmtId(set[0])}),
                2 => try writer.print(" {s}, {s} ", .{ std.zig.fmtId(set[0]), std.zig.fmtId(set[1]) }),
                3 => try writer.print(" {s}, {s}, {s} ", .{ std.zig.fmtId(set[0]), std.zig.fmtId(set[1]), std.zig.fmtId(set[2]) }),
                else =>
                {
                    try writer.writeByte('\n');
                    for (set) |name|
                    {
                        try writer.print("    {s},", .{std.zig.fmtId(name)});
                    }
                },
            }
            try writer.writeAll("}");
        },

        .@"prefix_op -",
        .@"prefix_op -%",
        .@"prefix_op ~",
        .@"prefix_op !",
        .@"prefix_op &",
        =>
        {
            const op_str = @tagName(node.tag)["prefix_op ".len..];
            const target = self.ordered_node_set.keys()[node.index];
            try writer.print("{s}{}", .{op_str, self.fmtExprNode(target)});
        },

        .@"bin_op +",
        .@"bin_op +%",
        .@"bin_op +|",
        .@"bin_op -",
        .@"bin_op -%",
        .@"bin_op -|",
        .@"bin_op *",
        .@"bin_op *%",
        .@"bin_op *|",
        .@"bin_op /",
        .@"bin_op %",
        .@"bin_op <<",
        .@"bin_op <<|",
        .@"bin_op >>",
        .@"bin_op &",
        .@"bin_op |",
        .@"bin_op ^",
        .@"bin_op orelse",
        .@"bin_op catch",
        .@"bin_op and",
        .@"bin_op or",
        .@"bin_op ==",
        .@"bin_op !=",
        .@"bin_op >",
        .@"bin_op >=",
        .@"bin_op <",
        .@"bin_op <=",
        .@"bin_op ++",
        .@"bin_op **",
        .@"bin_op ||",
        =>
        {
            const op_str = @tagName(node.tag)["bin_op ".len..];
            const operands = self.bin_expr_operands.keys()[node.index];
            const lhs = operands.lhs;
            const rhs = operands.rhs;
            try writer.print("{} {s} {}", .{self.fmtExprNode(lhs), op_str, self.fmtExprNode(rhs)});
        },

        .@"postfix_op .?",
        .@"postfix_op .*",
        =>
        {
            const op_str = @tagName(node.tag)["postfix_op ".len..];
            const target = self.ordered_node_set.keys()[node.index];
            try writer.print("{}{s}", .{self.fmtExprNode(target), op_str});
        },
    }
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
        .sentinel => unreachable,
        .decl_const,
        .decl_var,
        .decl_pub_const,
        .decl_pub_var,
        =>
        {
            const decl: Decl = self.decls.get(node.index);
            switch (node.tag)
            {
                .decl_pub_const,
                .decl_pub_var,
                => try writer.writeAll("pub "),
                .decl_const,
                .decl_var,
                => {},
                else => unreachable,
            }
            switch (decl.extern_mod)
            {
                .none => {},
                .static => try writer.writeAll("extern "),
                .dyn => |lib_str| try writer.print("extern \"{s}\" ", .{lib_str})
            }
            switch (node.tag)
            {
                .decl_const,
                .decl_pub_const,
                => try writer.writeAll("const "),
                .decl_var,
                .decl_pub_var,
                => try writer.writeAll("var "),
                else => unreachable,
            }
            try writer.print("{s}", .{std.zig.fmtId(decl.name)});
            if (decl.type_annotation.unwrap())  |ta | try writer.print(": {}",              .{self.fmtExprNode(ta)});
            if (decl.alignment.unwrap())        |a  | try writer.print(" align({})",        .{self.fmtExprNode(a)});
            if (decl.@"linksection".unwrap())   |ls | try writer.print(" linksection({})",  .{self.fmtExprNode(ls)});
            if (decl.value.unwrap())            |val| try writer.print(" = {}",             .{self.fmtExprNode(val)});
            try writer.writeAll(";\n");
        },
        .usingnamespace_statement => try writer.print("usingnamespace {};\n", .{self.fmtExprNode(self.ordered_node_set.keys()[node.index])}),
        .pub_usingnamespace_statement => try writer.print("pub usingnamespace {};\n", .{self.fmtExprNode(self.ordered_node_set.keys()[node.index])}),
    }
}

fn allocator(self: *Generator) std.mem.Allocator
{
    return self.arena.allocator();
}

fn invalidExprNode(index_value: ExprNode.Index) ExprNode
{
    return ExprNode{
        .index = index_value,
        .tag = .sentinel,
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

    const gop = try self.big_int_literals.getOrPut(self.allocator(), big_int.limbs);
    errdefer {
        if (!gop.found_existing)
        {
            const popped = self.big_int_literals.pop();
            if (comptime std.debug.runtime_safety)
            {
                std.debug.assert(std.mem.eql(std.math.big.Limb, gop.key_ptr.*, popped.key));
            }
        }
    }
    if (gop.found_existing)
    {
        return ExprNode{
            .index = gop.index,
            .tag = tag,
        };
    }

    try self.scratch_space.ensureTotalCapacityPrecise(
        self.allocator(),
        big_int.sizeInBaseUpperBound(base) +
            (std.math.big.int.calcToStringLimbsBufferLen(big_int.limbs.len, base) * @sizeOf(std.math.big.Limb)) + 1,
    );
    self.scratch_space.expandToCapacity();

    gop.key_ptr.* = try self.allocator().dupe(std.math.big.Limb, big_int.limbs);
    errdefer unreachable; // please don't error after this point, I can't figure out how to structure this without wasting/leaking memory other than this.

    return ExprNode{
        .index = gop.index,
        .tag = tag,
    };
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
            var big_int = try std.math.big.int.Managed.initSet(self.arena.child_allocator, std.math.absCast(value));
            defer big_int.deinit();

            const literal = try self.createBigIntLiteral(radix, big_int.toConst());
            return if (value < 0) try self.createPrefixOp(.@"-", literal) else literal;
        },
        .ComptimeInt => return self.createIntLiteral(radix, @as(std.math.IntFittingRange(value, value), value)),
        else => @compileError(std.fmt.comptimePrint("Expected a {s} or an integer type, got {s}.", .{@typeName(comptime_int), @typeName(@TypeOf(value))})),
    }
}

pub fn createEnumLiteral(self: *Generator, tag_name: []const u8) std.mem.Allocator.Error!ExprNode
{
    const duped_tag_name = try self.dupeString(tag_name);
    const gop = try self.ordered_string_set.getOrPut(self.allocator(), duped_tag_name);
    return ExprNode{
        .index = gop.index,
        .tag = .enum_literal,
    };
}
pub fn createEnumLiteralFrom(self: *Generator, comptime literal: @Type(.EnumLiteral)) std.mem.Allocator.Error!ExprNode
{
    return self.createEnumLiteral(@tagName(literal));
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

    new.* = .{
        .annotations = annotations,
        .elems = try self.dupeExprNodeList(nodes),
    };

    return ExprNode{
        .index = new_index,
        .tag = .list_init,
    };
}

pub fn createRawCode(self: *Generator, literal_str: []const u8) std.mem.Allocator.Error!ExprNode
{
    const duped_str = try self.dupeString(literal_str);
    const gop = try self.ordered_string_set.getOrPut(self.allocator(), duped_str);
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

pub const PrefixOp = enum
{
    @"-",
    @"-%",
    @"~",
    @"!",
    @"&",
};
pub fn createPrefixOp(self: *Generator, op: PrefixOp, target: ExprNode) std.mem.Allocator.Error!ExprNode
{
    const gop = try self.ordered_node_set.getOrPut(self.allocator(), target);
    return ExprNode{
        .index = gop.index,
        .tag = switch (op)
        {
            .@"-" => .@"prefix_op -",
            .@"-%" => .@"prefix_op -%",
            .@"~" => .@"prefix_op ~",
            .@"!" => .@"prefix_op !",
            .@"&" => .@"prefix_op &",
        },
    };
}

pub const BinOp = enum(u8)
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
pub fn createBinOp(self: *Generator, lhs: ExprNode, op: BinOp, rhs: ExprNode) std.mem.Allocator.Error!ExprNode
{
    const gop = try self.bin_expr_operands.getOrPut(self.allocator(), BinaryExprOperands{
        .lhs = lhs,
        .rhs = rhs,
    });
    return ExprNode{
        .index = gop.index,
        .tag = switch (op)
        {
            .@"+" => .@"bin_op +",
            .@"+%" => .@"bin_op +%",
            .@"+|" => .@"bin_op +|",

            .@"-" => .@"bin_op -",
            .@"-%" => .@"bin_op -%",
            .@"-|" => .@"bin_op -|",

            .@"*" => .@"bin_op *",
            .@"*%" => .@"bin_op *%",
            .@"*|" => .@"bin_op *|",

            .@"/" => .@"bin_op /",
            .@"%" => .@"bin_op %",

            .@"<<" => .@"bin_op <<",
            .@"<<|" => .@"bin_op <<|",
            .@">>" => .@"bin_op >>",
            .@"&" => .@"bin_op &",
            .@"|" => .@"bin_op |",
            .@"^" => .@"bin_op ^",

            .@"orelse" => .@"bin_op orelse",
            .@"catch" => .@"bin_op catch",

            .@"and" => .@"bin_op and",
            .@"or" => .@"bin_op or",

            .@"==" => .@"bin_op ==",
            .@"!=" => .@"bin_op !=",
            .@">" => .@"bin_op >",
            .@">=" => .@"bin_op >=",
            .@"<" => .@"bin_op <",
            .@"<=" => .@"bin_op <=",

            .@"++" => .@"bin_op ++",
            .@"**" => .@"bin_op **",
            .@"||" => .@"bin_op ||",
        },
    };
}

pub const PostfixOp = enum {
    @".?",
    @".*",
};
pub fn createPostfixOp(self: *Generator, target: ExprNode, op: PostfixOp) std.mem.Allocator.Error!ExprNode
{
    const gop = try self.ordered_node_set.getOrPut(self.allocator(), target);
    return ExprNode{
        .index = gop.index,
        .tag = switch (op)
        {
            .@".?" => .@"postfix_op .?",
            .@".*" => .@"postfix_op .*",
        },
    };
}

pub fn createBuiltinCall(self: *Generator, builtin_name: BuiltinFnName, params: []const ExprNode) std.mem.Allocator.Error!ExprNode
{
    const gop = try self.builtin_calls.getOrPut(self.allocator(), BuiltinCall{
        .name = builtin_name,
        .params = params,
    });
    if (!gop.found_existing)
    {
        gop.key_ptr.params = self.dupeExprNodeList(params) catch |err| {
            const popped = self.builtin_calls.pop();
            if (comptime @import("builtin").mode == .Debug)
            {
                std.debug.assert(popped.key.name == builtin_name and for (popped.key.params) |param, i|
                {
                    if (!std.meta.eql(param, params[i])) break false;
                } else true);
            }
            return err;
        };
    }

    return ExprNode{
        .index = gop.index,
        .tag = .builtin_call,
    };
}

pub fn createFunctionCall(self: *Generator, callable: ExprNode, params: []const ExprNode) std.mem.Allocator.Error!ExprNode
{
    // const new_index = self.function_calls.items.len;
    // const new = try self.function_calls.addOne(self.allocator());
    // errdefer _ = self.function_calls.pop();

    // new.* = .{
    //     .callable = callable,
    //     .params = try self.dupeExprNodeList(params),
    // };

    const gop = try self.function_calls.getOrPut(self.allocator(), FunctionCall{
        .callable = callable,
        .params = params,
    });
    if (!gop.found_existing)
    {
        gop.key_ptr.params = self.dupeExprNodeList(params) catch |err| {
            const popped = self.function_calls.pop();
            if (comptime @import("builtin").mode == .Debug)
            {
                std.debug.assert(std.meta.eql(popped.key.callable, callable) and for (popped.key.params) |param, i|
                {
                    if (!std.meta.eql(param, params[i])) break false;
                } else true);
            }
            return err;
        };
    }

    return ExprNode{
        .index = gop.index,
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
        flags: PointerType.Flags = .{ .is_allowzero = false, .is_const = false, .is_volatile = false },
    },
) std.mem.Allocator.Error!ExprNode
{
    const new_index = try self.pointer_types.addOne(self.allocator());
    errdefer self.pointer_types.shrinkRetainingCapacity(new_index);

    self.pointer_types.set(new_index, PointerType{
        .alignment = extra.alignment orelse invalidExprNode(undefined),
        .child = child,
        .sentinel = extra.sentinel orelse invalidExprNode(undefined),
        .flags = extra.flags,
    });

    return ExprNode{
        .index = new_index,
        .tag = switch (size)
        {
            .One => .pointer_one,
            .Many => .pointer_many,
            .Slice => .pointer_slice,
            .C => .pointer_c,
        },
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
    try self.dot_accesses.ensureUnusedCapacity(self.allocator(), 1);

    var strings = try std.ArrayList([]const u8).initCapacity(self.allocator(), rhs.len);
    errdefer strings.deinit();

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
        strings.appendAssumeCapacity(linear_str.items[start..end]);
    }

    const new_index = self.dot_accesses.items.len;
    self.dot_accesses.appendAssumeCapacity(DotAccess{
        .lhs = lhs,
        .rhs = strings.toOwnedSlice(),
    });
    errdefer _ = self.dot_accesses.pop();

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
    const decl_node = try self.createDeclaration(mutability, name, type_annotation, value, .{ .is_pub = is_pub });
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

pub fn createErrorUnionTypeInferred(self: *Generator, payload: ExprNode) std.mem.Allocator.Error!ExprNode
{
    const gop = try self.ordered_node_set.getOrPut(self.allocator(), payload);
    return ExprNode{
        .index = gop.index,
        .tag = .error_union_inferred,
    };
}
pub fn createErrorUnionType(self: *Generator, error_set: ExprNode, payload: ExprNode) std.mem.Allocator.Error!ExprNode
{
    const gop = try self.bin_expr_operands.getOrPut(self.allocator(), BinaryExprOperands{
        .lhs = error_set,
        .rhs = payload,
    });
    return ExprNode{
        .index = gop.index,
        .tag = .error_union,
    };
}

pub fn createErrorSetType(self: *Generator, names: []const []const u8) std.mem.Allocator.Error!ExprNode
{
    const names_duped = try self.allocator().alloc([]const u8, names.len);
    errdefer self.allocator().free(names_duped);
    
    for (names_duped) |*name, i| name.* = try self.dupeString(names[i]);
    const gop = try self.error_sets_set.getOrPut(self.allocator(), names_duped);
    return ExprNode{
        .index = gop.index,
        .tag = .error_set,
    };
}
pub fn createErrorSetTypeFrom(self: *Generator, comptime ErrorSet: type) std.mem.Allocator.Error!ExprNode
{
    comptime std.debug.assert(@typeInfo(ErrorSet) == .ErrorSet);
    return self.createErrorSetType(std.meta.fieldNames(ErrorSet));
}

fn createUsingnamespace(self: *Generator, is_pub: bool, target: ExprNode) std.mem.Allocator.Error!StatementNode
{
    const gop = try self.ordered_node_set.getOrPut(self.allocator(), target);
    return StatementNode{
        .index = gop.index,
        .tag = if (is_pub)
            .pub_usingnamespace_statement
        else
            .usingnamespace_statement,
    };
}

fn createDeclaration(
    self: *Generator,
    mutability: Mutability,
    name: []const u8,
    type_annotation: ?ExprNode,
    value: ?ExprNode,
    extra: struct {
        parent_index: ?ExprNode.Index = null,
        is_pub: bool = false,
        extern_mod: Decl.ExternMod = .none,
        alignment: ?ExprNode = null,
        @"linksection": ?ExprNode = null,
    },
) std.mem.Allocator.Error!StatementNode
{
    const duped_name = try self.dupeString(name);

    const duped_extern_mod: Decl.ExternMod = switch (extra.extern_mod)
    {
        .none, .static => extra.extern_mod,
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
        .parent_index = extra.parent_index,
        .extern_mod = duped_extern_mod,
        .name = duped_name,
        .type_annotation = if (type_annotation) |ta| ta.unwrap().? else ExprNode.sentinel,
        .alignment = if (extra.alignment) |a| a.unwrap().? else ExprNode.sentinel,
        .@"linksection" = if (extra.@"linksection") |ls| ls.unwrap().? else ExprNode.sentinel,
        .value = if (value) |val| val.unwrap().? else ExprNode.sentinel,
    });

    return StatementNode{
        .index = new_index,
        .tag = switch (mutability)
        {
            .Var => @as(StatementNode.Tag, if (extra.is_pub) .decl_pub_var else .decl_var),
            .Const => @as(StatementNode.Tag, if (extra.is_pub) .decl_pub_const else .decl_const),
        },
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

test "basic types"
{
    var gen = Generator.init(std.testing.allocator);
    defer gen.deinit();

    try gen.expectNodeFmt("u32", Generator.intType(u32));
    try gen.expectNodeFmt("type", Generator.primType(type));

    try gen.expectNodeFmt("error{}", try gen.createErrorSetType(&.{}));
    try gen.expectNodeFmt("error{Foo}", try gen.createErrorSetType(&.{"Foo"}));
    try gen.expectNodeFmt("error{ Foo, Bar }", try gen.createErrorSetType(&.{ "Foo", "Bar" }));
    try gen.expectNodeFmt("error{ Foo, Bar, Baz }", try gen.createErrorSetType(&.{ "Foo", "Bar", "Baz" }));

    try gen.expectNodeFmt("!void", try gen.createErrorUnionTypeInferred(Generator.primType(void)));
    try gen.expectNodeFmt("error{Foo}!void", try gen.createErrorUnionType(try gen.createErrorSetTypeFrom(error{Foo}), Generator.primType(void)));
    try gen.expectNodeFmt("?i15", try gen.createOptionalType(Generator.intType(i15)));

    try gen.expectNodeFmt("[*c]i8", try gen.createPointerType(.C, Generator.intType(i8), .{}));
    try gen.expectNodeFmt("*u64", try gen.createPointerType(.One, Generator.intType(u64), .{}));
    try gen.expectNodeFmt("[*]i32", try gen.createPointerType(.Many, Generator.intType(i32), .{}));
    try gen.expectNodeFmt("[*:0]i8", try gen.createPointerType(.Many, Generator.intType(i8), .{ .sentinel = try gen.createIntLiteral(.decimal, 0) }));
    try gen.expectNodeFmt("[]i8", try gen.createPointerType(.Slice, Generator.intType(i8), .{}));
    try gen.expectNodeFmt("[]align(4) u16", try gen.createPointerType(.Slice, Generator.intType(u16), .{ .alignment = try gen.createIntLiteral(.decimal, 4) }));
    try gen.expectNodeFmt("*allowzero f80", try gen.createPointerType(.One, Generator.primType(f80), .{ .flags = .{ .is_allowzero = true } }));
    try gen.expectNodeFmt("[]const u8", try gen.createPointerType(.Slice, Generator.intType(u8), .{ .flags = .{ .is_const = true } }));
    try gen.expectNodeFmt("[*]volatile c_int", try gen.createPointerType(.Many, Generator.primType(c_int), .{ .flags = .{ .is_volatile = true } }));
    try gen.expectNodeFmt("[*:0]allowzero align(2) const volatile c_uint", try gen.createPointerType(.Many, Generator.primType(c_uint), .{
        .sentinel = try gen.createIntLiteral(.decimal, 0),
        .alignment = try gen.createIntLiteral(.decimal, 2),
        .flags = .{ .is_allowzero = true, .is_const = true, .is_volatile = true },
    }));
}

test "value expressions and statements"
{
    var gen = Generator.init(std.testing.allocator);
    defer gen.deinit();

    const u32_type = Generator.intType(u32);
    const literal_43 = Generator.createAddrSizedIntLiteral(.decimal, 43);
    const p_u32_type = try gen.createPointerType(.One, u32_type, .{});

    try gen.expectNodeFmt("u32", u32_type);
    try gen.expectNodeFmt("43",  literal_43);
    try gen.expectNodeFmt("@as(*u32, undefined).*", try gen.createPostfixOp(try gen.createBuiltinCall(.as, &.{ p_u32_type, Generator.undefinedValue() }), .@".*"));
    try gen.expectNodeFmt("@This()", try gen.createBuiltinCall(.This, &.{}));
    try gen.expectNodeFmt("(43)", try gen.createParenthesesExpression(literal_43));
    try gen.expectNodeFmt("(43 + 43)", try gen.createParenthesesExpression(try gen.createBinOp(literal_43, .@"+", literal_43)));
    try gen.expectNodeFmt(std.fmt.comptimePrint("{d}", .{std.math.maxInt(usize) + 1}), try gen.createIntLiteral(.decimal, std.math.maxInt(usize) + 1));
    try gen.expectNodeFmt(".fizzbuzz", try gen.createEnumLiteralFrom(.fizzbuzz));
    try gen.expectNodeFmt(".@\"continue\"", try gen.createEnumLiteral("continue"));

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

    try gen.expectNodeFmt("const foo = 3;\n", try gen.createDeclaration(.Const, "foo", null, try gen.createIntLiteral(.decimal, 3), .{}));
    try gen.expectNodeFmt("pub const foo = 3;\n", try gen.createDeclaration(.Const, "foo", null, try gen.createIntLiteral(.decimal, 3), .{
        .is_pub = true,
    }));
    try gen.expectNodeFmt("pub const foo: u32 = 3;\n", try gen.createDeclaration(.Const, "foo", u32_type, try gen.createIntLiteral(.decimal, 3), .{
        .is_pub = true,
    }));
    try gen.expectNodeFmt("pub var foo: u32 = 3;\n", try gen.createDeclaration(.Var, "foo", u32_type, try gen.createIntLiteral(.decimal, 3), .{
        .is_pub = true,
    }));
    try gen.expectNodeFmt("pub extern var foo: u32;\n", try gen.createDeclaration(.Var, "foo", u32_type, null, .{
        .is_pub = true,
        .extern_mod = .static,
    }));
    try gen.expectNodeFmt("pub extern \"fbb\" const foo: u32;\n", try gen.createDeclaration(.Const, "foo", u32_type, null, .{
        .is_pub = true,
        .extern_mod = .{ .dyn = "fbb" },
    }));
    try gen.expectNodeFmt("pub extern \"fbb\" const foo: u32 align(64);\n", try gen.createDeclaration(.Const, "foo", u32_type, null, .{
        .is_pub = true,
        .extern_mod = .{ .dyn = "fbb" },
        .alignment = try gen.createIntLiteral(.decimal, 64),
    }));
    try gen.expectNodeFmt("pub extern \"fbb\" const foo: u32 align(64) linksection(\"bar\");\n", try gen.createDeclaration(.Const, "foo", u32_type, null, .{
        .is_pub = true,
        .extern_mod = .{ .dyn = "fbb" },
        .alignment = try gen.createIntLiteral(.decimal, 64),
        .@"linksection" = try gen.createStringLiteral("bar"),
    }));

    try gen.expectNodeFmt(
        "usingnamespace @import(\"std\");\n",
        try gen.createUsingnamespace(false, try gen.createBuiltinCall(.import, &.{try gen.createStringLiteral("std")})),
    );
    try gen.expectNodeFmt(
        "pub usingnamespace @import(\"std\");\n",
        try gen.createUsingnamespace(true, try gen.createBuiltinCall(.import, &.{try gen.createStringLiteral("std")})),
    );
}

test "thorough check for prefix/bin/postfix ops"
{
    var gen = Generator.init(std.testing.allocator);
    defer gen.deinit();

    const operand_a = try gen.addDecl(false, .Const, "a", null, try gen.createIntLiteral(.decimal, 1));
    const operand_b = try gen.addDecl(false, .Const, "b", null, try gen.createIntLiteral(.decimal, 2));
    _ = operand_b;

    for (std.enums.values(PrefixOp)) |op_tag|
    {
        var buff = [_]u8{0} ** std.fmt.count("{s}a", .{"####" ** 10});
        const expected = try std.fmt.bufPrint(&buff, "{s}a", .{@tagName(op_tag)});
        try gen.expectNodeFmt(expected, try gen.createPrefixOp(op_tag, operand_a));
    }

    for (std.enums.values(PostfixOp)) |op_tag|
    {
        var buff = [_]u8{0} ** std.fmt.count("a{s}", .{"####" ** 10});
        const expected = try std.fmt.bufPrint(&buff, "a{s}", .{@tagName(op_tag)});
        try gen.expectNodeFmt(expected, try gen.createPostfixOp(operand_a, op_tag));
    }

    for (std.enums.values(BinOp)) |op_tag|
    {
        var buff = [_]u8{0} ** std.fmt.count("a {s} b", .{"####" ** 10});
        const expected = try std.fmt.bufPrint(&buff, "a {s} b", .{@tagName(op_tag)});
        try gen.expectNodeFmt(expected, try gen.createBinOp(operand_a, op_tag, operand_b));
    }
}

test "top level decls"
{
    var gen = Generator.init(std.testing.allocator);
    defer gen.deinit();

    const std_import = try gen.addDecl(false, .Const, "std", null, try gen.createBuiltinCall(.import, &.{ try gen.createStringLiteral("std") }));
    const array_list_ref_decl = try gen.addDecl(false, .Const, "ArrayListUnmanaged", null, try gen.createDotAccess(std_import, &.{ "ArrayListUnmanaged" }));
    const string_type_decl = try gen.addDecl(true, .Const, "String", null, try gen.createFunctionCall(array_list_ref_decl, &.{ Generator.intType(u8) }));

    const foo_decl = try gen.addDecl(false, .Const, "foo", null, try gen.createIntLiteral(.decimal, 3));
    const bar_decl = try gen.addDecl(false, .Var, "bar", Generator.intType(u32), foo_decl);
    _ = try gen.addDecl(true, .Const, "p_bar", try gen.createPointerType(.One, Generator.intType(u32), .{}), try gen.createPrefixOp(.@"&", bar_decl));
    _ = try gen.addDecl(true, .Const, "empty_str", string_type_decl, try gen.createListInit(.none, &.{}));
    _ = try gen.addDecl(true, .Const, "Error", Generator.primType(type), try gen.createErrorSetType(&.{ "OutOfMemory" }));

    try std.testing.expectFmt(
        \\const std = @import("std");
        \\const ArrayListUnmanaged = std.ArrayListUnmanaged;
        \\pub const String = ArrayListUnmanaged(u8);
        \\const foo = 3;
        \\var bar: u32 = foo;
        \\pub const p_bar: *u32 = &bar;
        \\pub const empty_str: String = .{};
        \\pub const Error: type = error{OutOfMemory};
        \\
    , "{}", .{gen.renderFmt()});
}
