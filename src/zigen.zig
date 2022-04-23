const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

pub const Generator = struct 
{
    const Self = @This();

    allocator: Allocator,
    top_level_nodes: ArrayList(Node),
    
    pub fn init(allocator: Allocator) Generator
    {
        return .{ 
            .allocator = allocator,
            .top_level_nodes = ArrayList(Node).init(allocator)
        };
    }

    pub fn addRawCode(self: *Self) !RawCodeNode
    {
        const raw_code: Node = .{ .raw_code = .{ .base = NodeBase { .generator = self } } };
        try self.top_level_nodes.add(raw_code);
        return raw_code;
    }
};

pub const NodeTag = enum 
{
    raw_code,
};

pub const Node = union(NodeTag) 
{
    raw_code: RawCodeNode,
};

pub const NodeBase = struct 
{
    generator: *Generator
};

pub const RawCodeNode = struct
{
    base: NodeBase,
    code: []const u8,
};

test "create generator"
{
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    
    var generator = Generator.init(gpa.allocator());
    _ = generator;
}