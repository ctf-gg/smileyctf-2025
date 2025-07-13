const std = @import("std");
const print = std.debug.print;
const ArrayList = std.ArrayList;

const Number = struct {
    inner: usize,
};

var alloc = std.heap.smp_allocator;

pub fn main() !void {
    var list = ArrayList(Number).init(alloc);
    var next = ArrayList(Number).init(alloc);

    for (0..16) |_| {
        try list.append(Number{ .inner = 1 });
        print("cap = {}\n", .{list.capacity});
    }

    for (0..17) |_| {
        try next.append(Number{ .inner = 2 });
    }

    try list.append(list.items[0]);
    print("last = {x}\n", .{list.getLast().inner});
}
