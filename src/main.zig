const std = @import("std");
const libelf = @cImport(@cInclude("libelf.h"));

fn kind_string(kind: c_uint) []const u8 {
    return switch (kind) {
        libelf.ELF_K_AR => return "ELF_K_AR",
        libelf.ELF_K_ELF => return "ELF_K_ELF",
        libelf.ELF_K_NONE => return "ELF_K_NONE",
        else => unreachable,
    };
}

fn libelf_error(msg_out: std.io.Writer) !c_uint {
    const err = libelf.elf_errno();
    try msg_out.print("{s}", .{libelf.elf_errmsg(err)});
    return err;
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    // try stdout.print("libelf.ELF_C_NULL = {}", .{libelf.ELF_C_NULL});

    var args = std.process.args();
    _ = args.next().?;
    const arg = args.next() orelse {
        try stdout.print("must provide a file\n", .{});
        return;
    };
    var f = try std.fs.cwd().openFile(arg, .{ .mode = .read_only });
    defer f.close();
    try stdout.print("the fd is {}\n", .{f.handle});

    if (libelf.elf_version(libelf.EV_CURRENT) == libelf.EV_NONE) {
        try stdout.print("version mismatch between header and library\nheader version = {}, library version = {}", .{ libelf.EV_CURRENT, libelf.elf_version(libelf.EV_NONE) });
    }
    const elf = libelf.elf_begin(f.handle, libelf.ELF_C_READ, null) orelse return libelf_error(stderr);
    defer if (libelf.elf_end(elf) != 0) {
        unreachable;
    };
    const kind = libelf.elf_kind(elf);
    try stdout.print("{s} is of kind {s}\n", .{ arg, kind_string(kind) });
    switch (kind) {
        libelf.ELF_K_ELF => {
            var dst: usize = undefined;
            const c_ident: [*]const u8 = libelf.elf_getident(elf, &dst) orelse return libelf_error(stderr);
            const ident: []const u8 = c_ident[0..dst];
            std.debug.print("the elfs ident is {s}\n", .{ident});
        },
        else => unreachable,
    }
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
