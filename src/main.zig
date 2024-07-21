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

fn libelf_error(msg_out: std.io.AnyWriter) !u8 {
    const err: u8 = @intCast(libelf.elf_errno());
    try msg_out.print("{s}", .{libelf.elf_errmsg(err)});
    return err;
}

const EI_CLASS: type = enum(u2) {
    ELFCLASS32 = libelf.ELFCLASS32,
    ELFCLASS64 = libelf.ELFCLASS64,
};

fn ElfOffset(comptime ei_class: EI_CLASS) type {
    return switch (ei_class) {
        .ELFCLASS32 => libelf.Elf32_Off,
        .ELFCLASS64 => libelf.Elf64_Off,
    };
}

fn ElfPhdr(comptime ei_class: EI_CLASS) type {
    return switch (ei_class) {
        .ELFCLASS32 => libelf.Elf32_Phdr,
        .ELFCLASS64 => libelf.Elf64_Phdr,
    };
}

const Error: type = error{
    SegmentNotFound,
};

fn get_phdr(comptime ei_class: EI_CLASS, elf: *libelf.Elf, off: ElfOffset(ei_class)) Error!*ElfPhdr(ei_class) {
    const temp: [*]ElfPhdr(ei_class) = switch (ei_class) {
        .ELFCLASS32 => libelf.elf32_getphdr(elf),
        .ELFCLASS64 => libelf.elf64_getphdr(elf),
    };
    var phdr_num = undefined;
    if (libelf.elf_getphdrnum(elf, &phdr_num) == -1) {
        unreachable;
    }
    const phdr_table: []ElfPhdr(ei_class) = temp[0..phdr_num];
    for (phdr_table) |*phdr| {
        if (off < (phdr.p_offset + phdr.p_filesz)) {
            return phdr;
        }
    }
    return Error.SegmentNotFound;
}

fn insert_patch(comptime ei_class: EI_CLASS, elf: *libelf.Elf, off: ElfOffset(ei_class), patch: []u8) !void {
    _ = patch;
    const phdr: *ElfPhdr(ei_class) = get_phdr(ei_class, elf, off);
    std.debug.print("phdr = {}\n", .{phdr});
}

pub fn main() !u8 {
    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    // try stdout.print("libelf.ELF_C_NULL = {}", .{libelf.ELF_C_NULL});

    var args = std.process.args();
    _ = args.next().?;
    const arg = args.next() orelse {
        try stdout.print("must provide a file\n", .{});
        return 0;
    };
    var f = try std.fs.cwd().openFile(arg, .{ .mode = .read_only });
    defer f.close();
    try stdout.print("the fd is {}\n", .{f.handle});

    if (libelf.elf_version(libelf.EV_CURRENT) == libelf.EV_NONE) {
        try stdout.print("version mismatch between header and library\nheader version = {}, library version = {}", .{ libelf.EV_CURRENT, libelf.elf_version(libelf.EV_NONE) });
    }
    const elf = libelf.elf_begin(f.handle, libelf.ELF_C_READ, null) orelse return libelf_error(stderr.any());
    defer if (libelf.elf_end(elf) != 0) {
        unreachable;
    };
    const kind = libelf.elf_kind(elf);
    try stdout.print("{s} is of kind {s}\n", .{ arg, kind_string(kind) });
    switch (kind) {
        libelf.ELF_K_ELF => {
            var dst: usize = undefined;
            const c_ident: [*]const u8 = libelf.elf_getident(elf, &dst) orelse return libelf_error(stderr.any());
            const ident: []const u8 = c_ident[0..dst];
            std.debug.print("the elfs ident is {s}\n", .{ident});
            std.debug.print("EI_CLASS = {}\n", .{ident[5]});
            std.debug.print("ELFCLASS32 = {}\n", .{libelf.ELFCLASS32});
            std.debug.print("ELFCLASS64 = {}\n", .{libelf.ELFCLASS64});
        },
        else => unreachable,
    }
    return 1;
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
