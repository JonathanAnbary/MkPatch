const std = @import("std");

const ElfModder = @import("elf/Modder.zig");
const CoffModder = @import("coff/Modder.zig");
const ElfParsed = @import("elf/Parsed.zig");
const CoffParsed = @import("coff/Parsed.zig");
const arch = @import("arch.zig");
const patch = @import("patch.zig");

const capstone = @import("capstone.zig");

fn arg_err(out: *std.Io.Writer) !void {
    try out.print("binmodify <file-to-patch> <patch-addr> <patch>", .{});
}

fn find_cave_err(out: *std.Io.Writer) !void {
    try out.print("No Code cave found that fits request", .{});
}

const MZ = "MZ";
const ELF = [_]u8{0x7F} ++ "ELF";

pub const Error = error{
    FileTypeNotSupported,
};

pub fn main(init: std.process.Init) !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer if (gpa.deinit() != .ok) std.debug.panic("Program leaked", .{});
    const alloc = gpa.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(init.io, &stdout_buffer);
    const stdout = &stdout_writer.interface;
    defer stdout.flush() catch {};

    var stderr_buffer: [4096]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(init.io, &stderr_buffer);
    const stderr = &stderr_writer.interface;

    var args = init.minimal.args.iterate();
    _ = args.next() orelse return arg_err(stderr);

    const to_patch = args.next() orelse return arg_err(stderr);
    const patch_addr_str = args.next() orelse return arg_err(stderr);
    const patch_addr = std.fmt.parseUnsigned(u64, patch_addr_str, 0) catch |err| {
        return stderr.print("failed to parse {s} as u32 (err - {})\n", .{ patch_addr_str, err });
    };
    const wanted_patch_hex = args.next() orelse return arg_err(stderr);
    if (wanted_patch_hex.len == 0) return stderr.print("<patch> must be hex bytes", .{});
    const patch_buf = try alloc.alloc(u8, @divFloor(wanted_patch_hex.len, 2));
    defer alloc.free(patch_buf);
    const wanted_patch = try std.fmt.hexToBytes(patch_buf, wanted_patch_hex);
    const cwd = std.Io.Dir.cwd();
    var f = try cwd.openFile(init.io, to_patch, .{ .mode = .read_write });
    defer f.close(init.io);

    var buf: [4]u8 = undefined;
    var read_buffer: [1024]u8 = undefined;
    var reader = f.reader(init.io, &read_buffer);
    var mz_vec = [_][]u8{buf[0..MZ.len]};
    if ((try reader.interface.readVec(&mz_vec)) != MZ.len) return Error.FileTypeNotSupported;
    if (std.mem.eql(u8, buf[0..MZ.len], MZ)) {
        const stat = try f.stat(init.io);
        const data = try alloc.alloc(u8, stat.size);
        defer alloc.free(data);
        const buffers = [_][]u8{data};
        std.debug.assert((try f.readPositional(init.io, &buffers, 0)) == data.len);
        const coff = try std.coff.Coff.init(data, false);
        const parsed = CoffParsed.init(coff);
        var patcher = try patch.Patcher(CoffModder, capstone.Disasm).init(alloc, &f, &parsed, init.io);
        defer patcher.deinit(alloc);
        try stdout.print("Performing pure patch at addr {X}, patch {X}\n", .{ patch_addr, wanted_patch });
        _ = try patcher.try_patch(alloc, patch_addr, wanted_patch, &f, init.io);
        try stdout.print("Patch done\n", .{});
    } else {
        var elf_vec = [_][]u8{buf[MZ.len..ELF.len]};
        if ((try reader.interface.readVec(&elf_vec)) != (ELF.len - MZ.len)) return Error.FileTypeNotSupported;
        if (std.mem.eql(u8, buf[0..ELF.len], ELF)) {
            const parsed = try ElfParsed.init(&f, init.io);
            var patcher = try patch.Patcher(ElfModder, capstone.Disasm).init(alloc, &f, &parsed, init.io);
            defer patcher.deinit(alloc);
            try stdout.print("Performing pure patch at addr {X}, patch {X}\n", .{ patch_addr, wanted_patch });
            _ = try patcher.try_patch(alloc, patch_addr, wanted_patch, &f, init.io);
            try stdout.print("Patch done\n", .{});
        }
    }
}
