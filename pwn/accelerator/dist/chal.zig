const std = @import("std");

export fn bootstrap() linksection(".entry") callconv(.Naked) void {
    asm volatile (
        \\.rept 5
        \\  nop
        \\.endr
        \\lui sp, 0x20
        \\call _start
    );
}

fn hcall(sysno: u32, arg1: u32, arg2: u32, arg3: u32) callconv(.C) u32 {
    var ret: u32 = undefined;
    asm volatile (
        \\mv a0, %[sysno]
        \\mv a1, %[arg1]
        \\mv a2, %[arg2]
        \\mv a3, %[arg3]
        \\.rept 5
        \\  nop
        \\.endr
        \\lui t0, 0x2000
        \\lw  a0, 0x14(t0)
        \\mv  %[ret], a0
        : [ret] "=r" (ret),
        : [sysno] "r" (sysno),
          [arg1] "r" (arg1),
          [arg2] "r" (arg2),
          [arg3] "r" (arg3),
        : "memory", "a0", "a1", "a2", "a3"
    );
    return ret;
}

noinline fn coproc_fail() void {
    _ = hcall(1, 0, 0, 0);
}

noinline fn coproc_pass() void {
    _ = hcall(2, 0, 0, 0);
}

noinline fn exit(code: u8) noreturn {
    _ = hcall(3, code, 0, 0);
    unreachable;
}

noinline fn log(ctx: void, msg: []const u8) !usize {
    _ = ctx;
    _ = hcall(4, @intFromPtr(msg.ptr), msg.len, 0);
    return msg.len;
}

const Writer = std.io.Writer(void, error{}, log);
var writer: Writer linksection(".data") = .{ .context = {} };
noinline fn print(comptime msg: []const u8, args: anytype) void {
    _ = writer.print(msg, args) catch unreachable;
}

export fn _start(c: *allowzero Config) callconv(.C) noreturn {
    exit(main(c));
}

const SHARPEN = 3;
const EDGE = 4;
const COPY = 5;
const PATCH = 6;

const Packet = extern struct {
    kind: u32,
    bounds: extern struct { x: u32, y: u32, width: u32, height: u32 },
};

const Config = extern struct {
    width: u32,
    height: u32,
    packet_base: u32,
    packet_len: u32,
    input: u32,
    output: u32,
};

const Pixel = extern struct { r: u8, g: u8, b: u8, a: u8 };

var config: Config align(4) linksection(".data") = .{
    .width = 0,
    .height = 0,
    .packet_base = undefined,
    .packet_len = 0,
    .input = undefined,
    .output = undefined,
};
var tmp: Config align(4) linksection(".data") = undefined;

noinline fn validate_config() u32 {
    const packets: [*]Packet = @ptrFromInt(tmp.packet_base);

    if (tmp.width < 3) return 0;
    if (tmp.height < 3) return 0;

    for (0..tmp.packet_len) |i| {
        if (packets[i].bounds.x > tmp.width) return 0;
        if (packets[i].bounds.y > tmp.height) return 0;
        if (packets[i].bounds.width > tmp.width) return 0;
        if (packets[i].bounds.height > tmp.height) return 0;
        if (@addWithOverflow(packets[i].bounds.x, packets[i].bounds.width)[1] == 1) return 0;
        if (@addWithOverflow(packets[i].bounds.y, packets[i].bounds.height)[1] == 1) return 0;
        if (packets[i].bounds.x + packets[i].bounds.width > tmp.width) return 0;
        if (packets[i].bounds.y + packets[i].bounds.height > tmp.height) return 0;
    }

    return 1;
}

var zero: Pixel linksection(".data") = .{ .r = 0, .g = 0, .b = 0, .a = 0 };
noinline fn get_pixel(x: u32, y: u32) *const Pixel {
    if (x == 0xffffffff or y == 0xffffffff) return &zero;
    if (x >= config.width or y >= config.height) return &zero;

    const input: [*]Pixel = @ptrFromInt(config.input);
    const idx = y * config.width + x;
    return &input[idx];
}

noinline fn apply_kernel(xbegin: u32, xend: u32, ybegin: u32, yend: u32, kernel: []const u8) void {
    const output: [*]Pixel = @ptrFromInt(config.output);
    for (xbegin..xend) |x| {
        for (ybegin..yend) |y| {
            var sum: Pixel = .{ .r = 0, .g = 0, .b = 0, .a = 0 };
            for (0..3) |ky| {
                for (0..3) |kx| {
                    const px = get_pixel(x + kx, y + ky);
                    sum.r += px.r * kernel[kx + 3 * ky];
                    sum.g += px.g * kernel[kx + 3 * ky];
                    sum.b += px.b * kernel[kx + 3 * ky];
                }
            }
            const idx = y * config.width + x;
            output[idx].r = sum.r;
            output[idx].g = sum.g;
            output[idx].b = sum.b;
        }
    }
}

var kernels: [2][]const u8 = .{
    &.{ 0, 0xff, 0, 0xff, 5, 0xff, 0, 0xff, 0 },
    &.{ 0xff, 0xff, 0xff, 0xff, 8, 0xff, 0xff, 0xff, 0xff },
};

noinline fn process_pipeline() void {
    const packets: [*]Packet = @ptrFromInt(config.packet_base);
    const input: [*]Pixel = @ptrFromInt(config.input);
    const output: [*]Pixel = @ptrFromInt(config.output);

    for (0..config.packet_len) |i| {
        const xbegin = packets[i].bounds.x;
        const xend = xbegin + packets[i].bounds.width;
        const ybegin = packets[i].bounds.y;
        const yend = ybegin + packets[i].bounds.height;

        switch (packets[i].kind) {
            SHARPEN => {
                apply_kernel(xbegin, xend, ybegin, yend, kernels[0]);
            },

            EDGE => {
                apply_kernel(xbegin, xend, ybegin, yend, kernels[1]);
            },

            COPY => {
                for (xbegin..xend) |x| {
                    for (ybegin..yend) |y| {
                        const i_idx = y * config.width + x;
                        const o_idx = (y - ybegin) * config.width + (x - xbegin);
                        output[o_idx] = input[i_idx];
                    }
                }
            },

            PATCH => {
                for (xbegin..xend) |x| {
                    for (ybegin..yend) |y| {
                        const i_idx = (y - ybegin) * config.width + (x - xbegin);
                        const o_idx = y * config.width + x;
                        output[o_idx] = input[i_idx];
                    }
                }
            },

            else => {},
        }
    }
}

fn main(c: *allowzero Config) u8 {
    if (@intFromPtr(c) == 0) {
        process_pipeline();
        coproc_pass();
        return 0;
    } else {
        tmp = c.*;
        if (validate_config() == 1) {
            config = tmp;
            coproc_pass();
            return 0;
        } else {
            coproc_fail();
            return 1;
        }
    }
}
