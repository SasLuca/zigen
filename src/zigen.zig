const std = @import("std");

const Generator = @This();
arena: std.heap.ArenaAllocator,
top_level_nodes: NodeSet = .{},

raw_literals: StringSet = .{},
prefix_ops: PrefixOpSet = .{},
bin_ops: std.ArrayListUnmanaged(BinOp) = .{},
postfix_ops: PostfixOpSet = .{},
builtin_calls: std.ArrayListUnmanaged(BuiltinCall) = .{},
function_calls: std.ArrayListUnmanaged(FunctionCall) = .{},
optionals: NodeSet = .{},
derefs: NodeSet = .{},
pointers: std.MultiArrayList(Pointer) = .{},
parentheses_expressions: NodeSet = .{},
dot_accesses: std.ArrayListUnmanaged(DotAccess) = .{},
decls: std.MultiArrayList(Decl) = .{},
usingnamespace_statements: NodeSet = .{},

/// referenced by `Generator.builtin_calls` and `Generator.function_calls`.
contiguous_param_lists: std.ArrayListUnmanaged(Node) = .{},
/// string set to avoid duplicating the same string multiple times.
string_set: StringSet = .{},

fn getString(self: *Generator, str: []const u8) std.mem.Allocator.Error![]const u8
{
    const gop = try self.string_set.getOrPut(self.allocator(), str);
    if (!gop.found_existing) {
        gop.key_ptr.* = self.allocator().dupe(u8, str) catch |err| {
            _ = self.string_set.pop();
            return err;
        };
    }
    return gop.key_ptr.*;
}

const StringSet = std.StringArrayHashMapUnmanaged(void);
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
const PrefixOpSet = ExternStructArraySet(PrefixOp);
const PostfixOpSet = ExternStructArraySet(PostfixOp);
const NodeSet = ExternStructArraySet(Node);

const Node = extern struct
{
    /// refers to the index of the value referred to by the declaration. Which array it indexes into is dependent on `Node.tag`.
    index: Node.Index,
    tag: Node.Tag,

    const Index = usize;
    const Tag = enum(u8)
    {
        /// index is the tag value of a `Generator.PrimitiveType`.
        primitive_type,
        /// index is the number of bits of the unsigned integer.
        unsigned_int,
        /// index is the number of bits of the signed integer.
        signed_int,
        /// index is the tag value of a `Generator.PrimitiveValue`.
        primitive_value,
        /// index into field `Generator.raw_literals`.
        raw_literal,
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
        /// index into field `Generator.optionals`.
        optional,
        /// index into field `Generator.pointers`.
        pointer,
        /// index into field `Generator.parentheses_expressions`.
        parentheses_expression,
        /// index into field `Generator.dot_accesses`.
        dot_access,
        /// index into field `Generator.decls`.
        decl,
        /// index into field `Generator.decls`.
        decl_ref,
        /// index into field `Generator.usingnamespace_statements`.
        usingnamespace_statement,
    };
};

const PrimitiveType = enum(u8)
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

const PrimitiveValue = enum(u8)
{
    @"true",
    @"false",
    @"null",
    @"undefined",
};

const PrefixOp = extern struct
{
    tag: PrefixOp.Tag,
    target: Node,

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
    lhs: Node,
    tag: BinOp.Tag,
    rhs: Node,

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
    target: Node,

    const Tag = enum(u8) { @".?", @".*" };
};

const BuiltinCall = struct
{
    name: []const u8,
    params_start: usize,
    params_end: usize,
};

const FunctionCall = extern struct
{
    callable: Node,
    params_start: usize,
    params_end: usize,
};

const Pointer = struct
{
    size: std.builtin.Type.Pointer.Size,
    alignment: ?u29,
    child: Node,
    sentinel: ?Node,
    flags: Flags,

    const Flags = packed struct {
        is_const: bool,
        is_volatile: bool,
        is_allowzero: bool,
    };
};

const DotAccess = struct
{
    lhs: Node,
    rhs: []const []const u8,
};

const Decl = struct
{
    /// refers to the index of the parent container declaration, with 'null' meaning file scope.
    parent_index: ?Node.Index,
    extern_mod: ExternMod,
    flags: Decl.Flags,
    name: []const u8,
    type_annotation: ?Node,
    value: ?Node,

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
            else => unreachable,
        }
    }
}

fn fmtExprNode(self: *const Generator, node: Node) std.fmt.Formatter(formatExprNode)
{
    std.debug.assert(node.tag != .decl);
    std.debug.assert(node.tag != .usingnamespace_statement);
    return .{
        .data = FormattableExprNode{
            .gen = self,
            .node = node,
        },
    };
}

const FormattableExprNode = struct { gen: *const Generator, node: Node };
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
        .primitive_type => try writer.writeAll(@tagName(@intToEnum(PrimitiveType, node.index))),
        .unsigned_int => try writer.print("u{d}", .{@intCast(u16, node.index)}),
        .signed_int => try writer.print("i{d}", .{@intCast(u16, node.index)}),
        .primitive_value => try writer.writeAll(@tagName(@intToEnum(PrimitiveValue, node.index))),
        .raw_literal => try writer.writeAll(self.raw_literals.keys()[node.index]),
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
            const params: []const Node = self.contiguous_param_lists.items[builtin_call.params_start..builtin_call.params_end];

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
            const params: []const Node = self.contiguous_param_lists.items[function_call.params_start..function_call.params_end];

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
        .optional => try writer.print("?{}", .{self.fmtExprNode(self.optionals.keys()[node.index])}),
        .pointer =>
        {
            const slice = self.pointers.slice();
            const flags: []const Pointer.Flags = slice.items(.flags);
            const children: []const Node = slice.items(.child);

            const pointer = Pointer{
                .size = slice.items(.size)[node.index],
                .sentinel = slice.items(.sentinel)[node.index],
                .alignment = slice.items(.alignment)[node.index],
                .flags = .{
                    .is_allowzero = flags[node.index].is_allowzero,
                    .is_const = flags[node.index].is_const,
                    .is_volatile = flags[node.index].is_volatile,
                },
                .child = children[node.index],
            };

            switch (pointer.size)
            {
                .C =>
                {
                    std.debug.assert(pointer.sentinel == null);
                    std.debug.assert(!pointer.flags.is_allowzero);
                },
                .One => std.debug.assert(pointer.sentinel == null),
                .Many, .Slice => {},
            }
            switch (pointer.size)
            {
                .One => try writer.writeByte('*'),
                .Many =>
                {
                    try if (pointer.sentinel) |s|
                        writer.print("[*:{}]", .{self.fmtExprNode(s)})
                    else
                        writer.writeAll("[*]");
                },
                .Slice =>
                {
                    try if (pointer.sentinel) |s|
                        writer.print("[:{}]", .{self.fmtExprNode(s)})
                    else
                        writer.writeAll("[]"); 
                },
                .C => try writer.writeAll("[*c]"),
            }
            if (pointer.flags.is_allowzero) try writer.writeAll("allowzero ");
            if (pointer.alignment) |a| try writer.print("align({}) ", .{a});
            if (pointer.flags.is_const) try writer.writeAll("const ");
            if (pointer.flags.is_volatile) try writer.writeAll("volatile ");

            switch (pointer.child.tag)
            {
                .primitive_type,
                .unsigned_int,
                .signed_int,
                .raw_literal,
                .bin_op,
                .postfix_op,
                .builtin_call,
                .function_call,
                .optional,
                .parentheses_expression,
                .dot_access,
                .decl_ref,
                .pointer,
                => try writer.print("{}", .{self.fmtExprNode(children[node.index])}),
                .primitive_value => unreachable,
                .prefix_op => unreachable,
                .decl => unreachable,
                .usingnamespace_statement => unreachable,
            }
        },
        .parentheses_expression => try writer.print("({})", .{self.fmtExprNode(self.parentheses_expressions.keys()[node.index])}),
        .dot_access =>
        {
            const dot_access: DotAccess = self.dot_accesses.items[node.index];
            try writer.print("{}", .{self.fmtExprNode(dot_access.lhs)});
            for (dot_access.rhs) |rhs|
            {
                try writer.print(".{s}", .{std.zig.fmtId(rhs)});
            }
        },
        .decl => unreachable,
        .decl_ref =>
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
        .usingnamespace_statement => unreachable,
    }
}

fn fmtStatementNode(self: *const Generator, node: Node) std.fmt.Formatter(formatDeclNode)
{
    return .{
        .data = FormattableStatementNode{
            .gen = self,
            .node = node,
        },
    };
}

const FormattableStatementNode = struct { gen: *const Generator, node: Node };
fn formatDeclNode(
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
                    if (decl.type_annotation) |ta| try writer.print(": {}", .{self.fmtExprNode(ta)});
                    try writer.print(" = {};\n", .{self.fmtExprNode(decl.value.?)});
                },
                .static =>
                {
                    try writer.writeAll("extern ");
                    try writer.writeAll(if (decl.flags.is_const) "const " else "var ");
                    try writer.print("{s}", .{std.zig.fmtId(decl.name)});
                    try writer.print(": {};\n", .{self.fmtExprNode(decl.type_annotation.?)});
                    std.debug.assert(decl.value == null);
                },
                .dyn => |lib_str|
                {
                    try writer.print("extern \"{s}\" ", .{lib_str});
                    try writer.writeAll(if (decl.flags.is_const) "const " else "var ");
                    try writer.print("{s}", .{std.zig.fmtId(decl.name)});
                    try writer.print(": {};\n", .{self.fmtExprNode(decl.type_annotation.?)});
                    std.debug.assert(decl.value == null);
                },
            }
        },
        .usingnamespace_statement => try writer.print("usingnamespace {};\n", .{self.fmtExprNode(self.usingnamespace_statements.keys()[node.index])}),
        else => unreachable,
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
pub fn primType(self: *Generator, comptime T: type) error{}!Node
{
    return self.primitiveType(@field(PrimitiveType, @typeName(T)));
}

pub fn createPrimitiveValue(self: *Generator, tag: PrimitiveValue) error{}!Node
{
    _ = self;
    return Node{
        .index = @enumToInt(tag),
        .tag = .primitive_value,
    };
}
pub fn trueVale(self: *Generator) error{}!Node
{
    return self.createPrimitiveValue(.@"true");
}
pub fn falseVale(self: *Generator) error{}!Node
{
    return self.createPrimitiveValue(.@"false");
}
pub fn nullValue(self: *Generator) error{}!Node
{
    return self.createPrimitiveValue(.@"null");
}
pub fn undefinedValue(self: *Generator) error{}!Node
{
    return self.createPrimitiveValue(.@"undefined");
}

pub fn createIntType(self: *Generator, sign: std.builtin.Signedness, bits: u16) error{}!Node
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
pub fn intType(self: *Generator, comptime T: type) error{}!Node
{
    const info: std.builtin.Type.Int = @typeInfo(T).Int;
    return self.createIntType(info.signedness, info.bits);
}

pub fn createLiteral(self: *Generator, literal_str: []const u8) std.mem.Allocator.Error!Node
{
    const gop = try self.raw_literals.getOrPut(self.allocator(), literal_str);
    errdefer {
        if (!gop.found_existing)
        {
            _ = self.string_set.pop();
        }
    }

    if (!gop.found_existing)
    {
        gop.key_ptr.* = try self.getString(literal_str);
    }

    return Node{
        .index = gop.index,
        .tag = .raw_literal,
    };
}
pub fn createStringLiteral(self: *Generator, content: []const u8) std.mem.Allocator.Error!Node
{
    return self.createLiteral(try std.fmt.allocPrint(self.allocator(), "\"{s}\"", .{content}));
}

pub fn createPrefixOp(self: *Generator, op: PrefixOp.Tag, target: Node) std.mem.Allocator.Error!Node
{
    const gop = try self.prefix_ops.getOrPut(self.allocator(), PrefixOp{
        .tag = op,
        .target = target,
    });
    return Node{
        .index = gop.index,
        .tag = .prefix_op,
    };
}

pub fn createBinOp(self: *Generator, lhs: Node, op: BinOp.Tag, rhs: Node) std.mem.Allocator.Error!Node
{
    const new_index = self.bin_ops.items.len;
    const new = try self.bin_ops.addOne(self.allocator());
    errdefer _ = self.bin_ops.pop();

    new.* = .{
        .lhs = lhs,
        .tag = op,
        .rhs = rhs,
    };

    return Node{
        .index = new_index,
        .tag = .bin_op,
    };
}

pub fn createPostfixOp(self: *Generator, target: Node, op: PostfixOp.Tag) std.mem.Allocator.Error!Node
{
    const gop = try self.postfix_ops.getOrPut(self.allocator(), PostfixOp{
        .tag = op,
        .target = target,
    });
    return Node{
        .index = gop.index,
        .tag = .postfix_op,
    };
}

pub fn createBuiltinCall(self: *Generator, builtin_name: []const u8, params: []const Node) std.mem.Allocator.Error!Node
{
    const new_index = self.builtin_calls.items.len;
    const new = try self.builtin_calls.addOne(self.allocator());
    errdefer _ = self.builtin_calls.pop();

    const duped_name = try self.getString(builtin_name);

    const params_start = self.contiguous_param_lists.items.len;
    try self.contiguous_param_lists.appendSlice(self.allocator(), params);
    const params_end = self.contiguous_param_lists.items.len;

    new.* = .{
        .name = duped_name,
        .params_start = params_start,
        .params_end = params_end,
    };

    return Node{
        .index = new_index,
        .tag = .builtin_call,
    };
}

pub fn createFunctionCall(self: *Generator, callable: Node, params: []const Node) std.mem.Allocator.Error!Node
{
    const new_index = self.function_calls.items.len;
    const new = try self.function_calls.addOne(self.allocator());
    errdefer _ = self.function_calls.pop();

    const params_start = self.contiguous_param_lists.items.len;
    try self.contiguous_param_lists.appendSlice(self.allocator(), params);
    const params_end = self.contiguous_param_lists.items.len;

    new.* = .{
        .callable = callable,
        .params_start = params_start,
        .params_end = params_end,
    };

    return Node{
        .index = new_index,
        .tag = .function_call,
    };
}

pub fn createOptionalType(self: *Generator, node: Node) std.mem.Allocator.Error!Node
{
    const gop = try self.optionals.getOrPut(self.allocator(), node);
    return Node{
        .index = gop.index,
        .tag = .optional,
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

pub fn createParenthesesExpression(self: *Generator, node: Node) std.mem.Allocator.Error!Node
{
    const gop = try self.parentheses_expressions.getOrPut(self.allocator(), node);
    return Node{
        .index = gop.index,
        .tag = .parentheses_expression,
    };
}

pub fn createDotAccess(self: *Generator, lhs: Node, rhs: []const []const u8) std.mem.Allocator.Error!Node
{
    const new_index = self.dot_accesses.items.len;
    const new_dot_access = try self.dot_accesses.addOne(self.allocator());
    errdefer _ = self.dot_accesses.pop();

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

    new_dot_access.* = .{
        .lhs = lhs,
        .rhs = strings.toOwnedSlice(),
    };
    return Node{
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
    type_annotation: ?Node,
    value: Node,
) std.mem.Allocator.Error!Node
{
    const decl_node = try self.createDeclaration(null, is_pub, .none, mutability, name, type_annotation, value);
    errdefer {
        self.decls.shrinkRetainingCapacity(self.decls.len - 1);
        std.debug.assert(self.decls.len == decl_node.index);
    }

    try self.top_level_nodes.putNoClobber(self.allocator(), decl_node, {});
    return Node{
        .index = decl_node.index,
        .tag = .decl_ref,
    };
}

pub fn addUsingnamespace(self: *Generator, target: Node) std.mem.Allocator.Error!void
{
    const usingnamespace_node = try self.createUsingnamespace(target);
    errdefer _ = self.usingnamespace_statements.pop();
    try self.top_level_nodes.putNoClobber(self.allocator(), usingnamespace_node, {});
}

pub fn createUsingnamespace(self: *Generator, target: Node) std.mem.Allocator.Error!Node
{
    const gop = try self.usingnamespace_statements.getOrPut(self.allocator(), target);
    return Node{
        .index = gop.index,
        .tag = .usingnamespace_statement,
    };
}

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
            .dyn = try self.getString(str),
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

    const duped_name = try self.getString(name);

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

fn expectNodeFmt(gen: *Generator, expected: []const u8, node: Node) !void
{
    return switch (node.tag) {
        .decl, .usingnamespace_statement => std.testing.expectFmt(expected, "{}", .{gen.fmtStatementNode(node)}),
        else => std.testing.expectFmt(expected, "{}", .{gen.fmtExprNode(node)}),
    };
}

test "basic node printing"
{
    var gen = Generator.init(std.testing.allocator);
    defer gen.deinit();

    const u32_type = try gen.intType(u32);
    const literal_43 = try gen.createLiteral("43");
    const p_u32_type = try gen.createPointerType(.One, u32_type, .{});

    try gen.expectNodeFmt("u32", u32_type);
    try gen.expectNodeFmt("43",  literal_43);
    try gen.expectNodeFmt("@as(*u32, undefined).*", try gen.createPostfixOp(try gen.createBuiltinCall("as", &.{ p_u32_type, try gen.undefinedValue() }), .@".*"));
    try gen.expectNodeFmt("@This()", try gen.createBuiltinCall("This", &.{}));
    try gen.expectNodeFmt("type", try gen.primType(type));
    try gen.expectNodeFmt("(43)", try gen.createParenthesesExpression(literal_43));
    try gen.expectNodeFmt("(43 + 43)", try gen.createParenthesesExpression(try gen.createBinOp(literal_43, .@"+", literal_43)));

    try gen.expectNodeFmt("*u32", p_u32_type);
    try gen.expectNodeFmt("?*u32", try gen.createOptionalType(p_u32_type));
    try gen.expectNodeFmt("**u32", try gen.createPointerType(.One, p_u32_type, .{}));

    try gen.expectNodeFmt("[*]u32", try gen.createPointerType(.Many, u32_type, .{}));
    try gen.expectNodeFmt("[]u32", try gen.createPointerType(.Slice, u32_type, .{}));
    try gen.expectNodeFmt("[:0]u32", try gen.createPointerType(.Slice, u32_type, .{
        .sentinel = try gen.createLiteral("0"),
    }));
    try gen.expectNodeFmt("[:0]align(16) u32", try gen.createPointerType(.Slice, u32_type, .{
        .sentinel = try gen.createLiteral("0"),
        .alignment = 16,
    }));
    try gen.expectNodeFmt("[:0]allowzero align(16) u32", try gen.createPointerType(.Slice, u32_type, .{
        .sentinel = try gen.createLiteral("0"),
        .alignment = 16,
        .flags = .{ .is_allowzero = true, .is_const = false, .is_volatile = false },
    }));
    try gen.expectNodeFmt("[:0]allowzero align(16) const u32", try gen.createPointerType(.Slice, u32_type, .{
        .sentinel = try gen.createLiteral("0"),
        .alignment = 16,
        .flags = .{ .is_allowzero = true, .is_const = true, .is_volatile = false },
    }));
    try gen.expectNodeFmt("[:0]allowzero align(16) const volatile u32", try gen.createPointerType(.Slice, u32_type, .{
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
        try gen.createDeclaration(null, true, .none, .Const, "foo", u32_type, try gen.createLiteral("3")),
    );
    try gen.expectNodeFmt(
        "pub var foo: u32 = 3;\n",
        try gen.createDeclaration(null, true, .none, .Var, "foo", u32_type, try gen.createLiteral("3")),
    );
    try gen.expectNodeFmt(
        "pub extern var foo: u32;\n",
        try gen.createDeclaration(null, true, .static, .Var, "foo", u32_type, null),
    );
    try gen.expectNodeFmt(
        "pub extern \"fbb\" const foo: u32;\n",
        try gen.createDeclaration(null, true, .{ .dyn = "fbb" }, .Const, "foo", u32_type, null),
    );

    try gen.expectNodeFmt(
        "usingnamespace @import(\"std\");\n",
        try gen.createUsingnamespace(try gen.createBuiltinCall("import", &.{ try gen.createStringLiteral("std") })),
    );
}

test "top level decls"
{
    var gen = Generator.init(std.testing.allocator);
    defer gen.deinit();

    const std_import = try gen.addDecl(false, .Const, "std", null, try gen.createBuiltinCall("import", &.{ try gen.createStringLiteral("std") }));
    const array_list_ref_decl = try gen.addDecl(false, .Const, "ArrayListUnmanaged", null, try gen.createDotAccess(std_import, &.{ "ArrayListUnmanaged" }));
    const string_type_decl = try gen.addDecl(true, .Const, "String", null, try gen.createFunctionCall(array_list_ref_decl, &.{ try gen.intType(u8) }));

    const foo_decl = try gen.addDecl(false, .Const, "foo", null, try gen.createLiteral("3"));
    const bar_decl = try gen.addDecl(false, .Var, "bar", try gen.intType(u32), foo_decl);
    _ = try gen.addDecl(true, .Const, "p_bar", try gen.createPointerType(.One, try gen.intType(u32), .{}), try gen.createPrefixOp(.@"&", bar_decl));
    _ = try gen.addDecl(true, .Const, "empty_str", string_type_decl, try gen.createLiteral(".{}"));

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
