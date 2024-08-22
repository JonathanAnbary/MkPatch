const std = @import("std");
const keystone = @import("../translated-include/keystone/keystone.zig");
// const keystone = @cImport(@cInclude("keystone.h"));
//

const ARM: type = enum(u8) {
    ARM = keystone.KS_MODE_ARM,
    THUMB = keystone.KS_MODE_THUMB,
    ARMV8 = keystone.KS_MODE_ARM + keystone.KS_MODE_V8,
};

const ARM64: type = enum(u8) {
    ARM64 = 0,
};

const MIPS: type = enum(u8) {
    MIPS32 = keystone.KS_MODE_MIPS32,
    MIPS64 = keystone.KS_MODE_MIPS64,
    MICRO = keystone.KS_MODE_MICRO,
    MIPS3 = keystone.KS_MODE_MIPS3,
    MIPS32R6 = keystone.KS_MODE_MIPS32R6,
};

const MODE: type = enum(u8) {
    MODE_16 = keystone.KS_MODE_16,
    MODE_32 = keystone.KS_MODE_32,
    MODE_64 = keystone.KS_MODE_64,
};

const PPC: type = enum(u8) {
    PPC32 = keystone.KS_MODE_PPC32,
    PPC64 = keystone.KS_MODE_PPC64,
    QPX = keystone.KS_MODE_QPX,
};

const SPARC: type = enum(u8) {
    SPARC32 = keystone.KS_MODE_SPARC32,
    SPARC64 = keystone.KS_MODE_SPARC64,
    V9 = keystone.KS_MODE_V9,
};

const SYSTEMZ: type = enum(u8) {
    BIG_ENDIAN = keystone.KS_MODE_BIG_ENDIAN,
};

const HEXAGON: type = enum(u8) {
    LITTLE_ENDIAN = keystone.KS_MODE_LITTLE_ENDIAN,
};

const EVM: type = enum(u8) {
    LITTLE_ENDIAN = keystone.KS_MODE_LITTLE_ENDIAN,
};

const ENDIAN: type = enum(u8) {
    LITTLE_ENDIAN = keystone.KS_MODE_LITTLE_ENDIAN,
    BIG_ENDIAN = keystone.KS_MODE_BIG_ENDIAN,
};

const ARCH: type = enum(u4) {
    ARM = keystone.KS_ARCH_ARM,
    ARM64 = keystone.KS_ARCH_ARM64,
    MIPS = keystone.KS_ARCH_MIPS,
    X86 = keystone.KS_ARCH_X86,
    PPC = keystone.KS_ARCH_PPC,
    SPARC = keystone.KS_ARCH_SPARC,
    SYSTEMZ = keystone.KS_ARCH_SYSTEMZ,
    HEXAGON = keystone.KS_ARCH_HEXAGON,
    EVM = keystone.KS_ARCH_EVM,
    MAX = keystone.KS_ARCH_MAX,
};

const IS_ENDIANABLE = std.EnumSet(ARCH).init(std.enums.EnumFieldStruct(ARCH, type, null){
    .ARM = true,
    .ARM64 = true,
    .MIPS = true,
    .X86 = true,
    .PPC = true,
    .SPARC = true,
    .SYSTEMZ = false,
    .HEXAGON = false,
    .EVM = false,
});

const ARCH_MODE_MAP = std.EnumArray(ARCH, type).init(std.enums.EnumFieldStruct(ARCH, type, null){
    .ARM = ARM,
    .ARM64 = ARM64,
    .MIPS = MIPS,
    .X86 = MODE,
    .PPC = PPC,
    .SPARC = SPARC,
    .SYSTEMZ = SYSTEMZ,
    .HEXAGON = HEXAGON,
    .EVM = EVM,
});

fn assemble_max_jmp(arch: ARCH, mode: MODE) ![]u8 {
    var temp_ksh: ?*keystone.ks_engine = null;
    if ((keystone.ks_open(@intFromEnum(arch), @intFromEnum(mode), &temp_ksh) != keystone.KS_ERR_OK) or (temp_ksh == null)) {
        unreachable;
    }
    const ksh: *keystone.ks_engine = temp_ksh.?;
    defer std.debug.assert(keystone.ks_close(ksh) == 0);

    var encode: ?[*]u8 = null;
    var siz: usize = undefined;
    var enc_count: usize = undefined;
    const max_jmp_asm_size: comptime_int = comptime blk: {
        break :blk "jmp ".len + std.fmt.count("{}", .{std.math.minInt(i128)}) + 1;
    };
    var jmp_insn_asm_buf: [max_jmp_asm_size]u8 = undefined;
    // this assumes that the following will always generate the max size jmp.
    const jmp_asm = try std.fmt.bufPrintZ(&jmp_insn_asm_buf, "jmp {};", .{0xFFFF});
    if (keystone.ks_asm(ksh, @as(?[*]const u8, @ptrCast(jmp_asm)), 0, &encode, &siz, &enc_count) != keystone.KS_ERR_OK) {
        // std.debug.print("ERROR: ks_asm() failed & count = {}, error = {}\n", .{ enc_count, keystone.ks_errno(ksh) });
        unreachable;
    }
    // the caller is responsible for calling keystone.ks_free.
    // defer keystone.ks_free(encode);
    return encode.?[0..siz];
}

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try std.process.argsAlloc(arena);

    if (args.len != 2) fatal("wrong number of arguments", .{});

    const output_file_path = args[1];

    var output_file = std.fs.cwd().createFile(output_file_path, .{}) catch |err| {
        fatal("unable to open '{s}': {s}", .{ output_file_path, @errorName(err) });
    };
    defer output_file.close();
    for (ARCH.values()) |arch| {
        for (ARCH_MODE_MAP.get(arch)) |mode| {
            if (IS_ENDIANABLE.contains(arch)) {
                assemble_max_jmp(arch, mode + );
        }
    }

    try output_file.writeAll(
        \\pub const Person = struct {
        \\   age: usize = 18,
        \\   name: []const u8 = "foo"        
        \\};
    );
    return std.process.cleanExit();
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    std.debug.print(format, args);
    std.process.exit(1);
}
