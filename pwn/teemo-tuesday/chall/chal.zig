// zig fmt: off
const std = @import("std");
const print = std.debug.print;
const linux = std.os.linux;
const ArrayList = std.ArrayList;

const Item = struct {
    const Id = enum(usize) {
        @"Sorcerer's Shoes",
        @"Malignance",
        @"Nashor's Tooth",
        @"Zhonya's Hourglass",
        @"Blackfire Torch",
        @"Liandry's Torment",
        @"Shadowflame",
        @"Void Staff",
        @"Rabadon's Deathcap",
        @"Fiendish Codex",
        @"Cosmic Drive",
        @"Stormsurge",
        @"Luden's Companion",
        None,
    };

    id: Id,
};

const Consumable = struct {
    const Id = enum(usize) {
        @"Cappa Juice",
        @"Elixir Of Sorcery",
        @"Elixir Of Iron",
        @"Elixir Of Wrath",
        @"Pickle Juice",
    };

    id: Id,
};

const Trinket = struct {
    const Id = enum(usize) {
        @"Farsight",
        @"Oracle",
        @"Stealth Ward",
        None,
    };

    id: Id,
};

fn set_cpu_count() !void {
    const orig = try std.posix.sched_getaffinity(0);
    var set: linux.cpu_set_t = @splat(0);
    set[0] = 1;
    try linux.sched_setaffinity(0, &set);
    _ = try alloc.alloc(u8, 1);
    try linux.sched_setaffinity(0, &orig);
}

fn displayId(Id: type, id: Id) void {
    const value = @intFromEnum(id);
    if (std.meta.intToEnum(Id, value)) |valid| {
        print("{s}", .{ @tagName(valid) });
    } else |_| {
        print("(Unknown id: {})", .{ value });
    }
}

const MAX_ITEMS = 6;
const Build = struct {
    name: ?[]const u8 = null,
    items: [MAX_ITEMS]Item = @splat(.{ .id = .None }),
    consumables: ArrayList(Consumable),
    trinket: Trinket = .{ .id = .None },
};

const banner =
\\                       .-'~~~-.
\\                     .'o  oOOOo`.
\\                    :~~~-.oOo   o`.
\\                     `. \ ~-.  oOOo.
\\        Top Diff       `.; / ~.  OO:
\\                       .'  ;-- `.o.'
\\                      ,'  ; ~~--'~
\\                      ;  ;
\\_______\|/__________\\;_\\//___\|/________
\\
\\Welcome to the Teemo build menu, where you are tasked with creating the most optimal Teemo build.
\\
\\Build options:
\\  1. Add an item to the build
\\  2. Add a consumable to the build
\\  3. Duplicate a consumable
\\  4. Choose a trinket
\\  5. Name build
\\  6. Show build
\\  7. Quit
\\
;

var alloc = std.heap.smp_allocator;
var stdin = std.io.getStdIn();
var builds: [3]Build = undefined;

fn parseInt(T: type, base: u8) !T {
    var buf: [0x100]u8 = @splat(0);

    const bytes = try stdin.reader().readUntilDelimiter(&buf, '\n');
    return try std.fmt.parseInt(T, bytes, base);
} 

pub fn main() !void {
    try set_cpu_count();

    var buf: [0x100]u8 = @splat(0);
    builds = @splat(.{
        .consumables = .init(alloc),
    });

    print(banner, .{});

    while (true) {
        print("Choose build: ", .{});
        const build_idx = parseInt(u32, 10) catch continue;
        if (build_idx >= builds.len) {
            print("invalid build!\n", .{});
            continue;
        }

        const build = &builds[build_idx];
        print("Choose an option: ", .{});
        const choice = parseInt(u32, 10) catch continue;

        switch (choice) {
            1 => {
                print("Choose item slot: ", .{});
                const slot = parseInt(u32, 10) catch continue;
                if (slot >= MAX_ITEMS) {
                    print("invalid item slot!\n", .{});
                    continue;
                }

                print("Choose item: ", .{});
                const name = try stdin.reader().readUntilDelimiter(&buf, '\n');

                inline for (@typeInfo(Item.Id).@"enum".fields) |field| {
                    if (std.mem.eql(u8, field.name, name)) {
                        build.items[slot] = .{ .id = @enumFromInt(field.value) };
                        break;
                    }
                } else {
                    print("invalid item!\n", .{});
                    continue;
                }

                print("Added {s} to slot {}\n", .{ @tagName(build.items[slot].id), slot });
            },
            2 => {
                print("Choose consumable: ", .{});
                const name = try stdin.reader().readUntilDelimiter(&buf, '\n');

                inline for (@typeInfo(Consumable.Id).@"enum".fields) |field| {
                    if (std.mem.eql(u8, field.name, name)) {
                        try build.consumables.append(.{ .id = @enumFromInt(field.value) });
                        break;
                    }
                } else {
                    print("invalid consumable!\n", .{});
                    continue;
                }

                print("Added {s}\n", .{ @tagName(build.consumables.getLast().id) });
            },
            3 => {
                print("Choose slot to duplicate: ", .{});
                const slot = parseInt(u32, 10) catch continue;

                if (slot >= build.consumables.items.len) {
                    print("invalid slot!\n", .{});
                    continue;
                }

                try build.consumables.append(build.consumables.items[slot]);
            },
            4 => {
                print("Choose trinket: ", .{});
                const name = try stdin.reader().readUntilDelimiter(&buf, '\n');

                inline for (@typeInfo(Trinket.Id).@"enum".fields) |field| {
                    if (std.mem.eql(u8, field.name, name)) {
                        build.trinket = .{ .id = @enumFromInt(field.value) };
                        break;
                    }
                } else {
                    print("invalid trinket!\n", .{});
                    continue;
                }

                print("Chose {s}\n", .{ @tagName(build.trinket.id) });
            },
            5 => {
                print("Name your build: ", .{});

                if (build.name) |name| {
                    alloc.free(name);
                    build.name = null;
                }
                var name: []const u8 = try stdin.reader().readUntilDelimiterAlloc(alloc, '\n', 0x1000);
                defer alloc.free(name);

                name = std.mem.trim(u8, name, &std.ascii.whitespace);
                build.name = try alloc.dupe(u8, name);
            },
            6 => {
                print("Current build:\n", .{});

                const name = val: for (build.name orelse "\xff") |ch| {
                    if (!std.ascii.isAlphanumeric(ch) and !std.ascii.isWhitespace(ch))
                        break :val "(Garbled yordle noises)";
                } else {
                    break :val build.name.?;
                };
                print("  == {s}\n", .{ name });

                print("  == Items\n", .{});
                for (&build.items, 0..) |x, idx| {
                    print("    [{}] ", .{ idx });
                    displayId(Item.Id, x.id);
                    print("\n", .{});
                }
                print("  == Consumables\n", .{});
                for (build.consumables.items, 0..) |x, idx| {
                    print("    ({}) ", .{ idx });
                    displayId(Consumable.Id, x.id);
                    print("\n", .{});
                }
                print("  == Trinket\n", .{});
                print("    ", .{});
                displayId(Trinket.Id, build.trinket.id);
                print("\n", .{});
            },
            7 => break,
            else => print("invalid choice!\n", .{}),
        }
    }
}
