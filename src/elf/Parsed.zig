//! Used for creating an `elf/Modder` structure.

const std = @import("std");
const elf = std.elf;

const arch = @import("../arch.zig");

header: elf.Header,

const Self = @This();

pub fn init(file: *std.Io.File, io: std.Io) !Self {
    var buffer: [8192]u8 = undefined;
    var reader = file.reader(io, &buffer);
    return .{
        .header = try elf.Header.read(&reader.interface),
    };
}

pub fn get_arch(self: *const Self) !arch.Arch {
    return switch (self.header.machine) {
        .X86_64, .@"386" => .X86,
        .ARM => .ARM,
        .AARCH64 => .ARM64,
        else => arch.Error.ArchNotSupported,
    };
}

pub fn get_mode(self: *const Self) !arch.Mode {
    return switch (self.header.machine) {
        .X86_64 => if (self.header.is_64) .MODE_64 else arch.Error.ArchModeMismatch,
        .@"386" => if (self.header.is_64) arch.Error.ArchModeMismatch else .MODE_32,
        .ARM => .ARM,
        .AARCH64 => .ARM64,
        else => arch.Error.ArchNotSupported,
    };
}

pub fn get_endian(self: *const Self) !arch.Endian {
    return self.header.endian;
}
