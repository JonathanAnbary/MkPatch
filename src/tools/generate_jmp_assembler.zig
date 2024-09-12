const std = @import("std");
const capstone = @cImport(@cInclude("capstone.h"));
const keystone = @cImport(@cInclude("keystone.h"));

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

const SYSTEMZ: type = enum(u32) {
    BIG_ENDIAN = keystone.KS_MODE_BIG_ENDIAN,
};

const HEXAGON: type = enum(u8) {
    LITTLE_ENDIAN = keystone.KS_MODE_LITTLE_ENDIAN,
};

const EVM: type = enum(u8) {
    LITTLE_ENDIAN = keystone.KS_MODE_LITTLE_ENDIAN,
};

const ENDIAN: type = enum(u32) {
    LITTLE_ENDIAN = keystone.KS_MODE_LITTLE_ENDIAN,
    BIG_ENDIAN = keystone.KS_MODE_BIG_ENDIAN,
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

const ARCH_MODE_MAP = std.EnumMap(ARCH, type).init(std.enums.EnumFieldStruct(ARCH, type, null){
    .X86 = MODE,
    .ARM = ARM,
    .ARM64 = ARM64,
    .MIPS = MIPS,
    .PPC = PPC,
    .SPARC = SPARC,
    .SYSTEMZ = SYSTEMZ,
    .HEXAGON = HEXAGON,
    .EVM = EVM,
    .MAX = undefined,
});

fn to_ks_mode(arch: ARCH, mode: ARCH_MODE_MAP.get(arch)) c_int {
    return @intFromEnum(mode);
}

fn to_cs_mode(arch: ARCH, mode: ARCH_MODE_MAP.get(arch)) capstone.cs_mode {
    return switch (arch) {
        .X86 => switch (mode) {
            .MODE_16 => capstone.CS_MODE_16,
            .MODE_32 => capstone.CS_MODE_32,
            .MODE_64 => capstone.CS_MODE_64,
        },
        .ARM => switch (mode) {
            .ARM => capstone.CS_MODE_ARM,
            .THUMB => capstone.CS_MODE_THUMB,
            .ARMV8 => capstone.CS_MODE_ARM + capstone.CS_MODE_V8,
        },
        .ARM64 => switch (mode) {
            .ARM64 => 0,
        },
        .MIPS => switch (mode) {
            .MIPS32 => capstone.CS_MODE_MIPS32,
            .MIPS64 => capstone.CS_MODE_MIPS64,
            .MICRO => capstone.CS_MODE_MICRO,
            .MIPS3 => capstone.CS_MODE_MIPS3,
            .MIPS32R6 => capstone.CS_MODE_MIPS32R6,
        },
        .PPC => switch (mode) {
            .PPC32 => capstone.CS_MODE_PPC32,
            .PPC64 => capstone.CS_MODE_PPC64,
            .QPX => capstone.CS_MODE_QPX,
        },
        .SPARC => switch (mode) {
            .SPARC32 => capstone.CS_MODE_SPARC32,
            .SPARC64 => capstone.CS_MODE_SPARC64,
            .V9 => capstone.CS_MODE_V9,
        },
        .SYSTEMZ => switch (mode) {
            .BIG_ENDIAN => capstone.CS_MODE_BIG_ENDIAN,
        },
        .HEXAGON => switch (mode) {
            .LITTLE_ENDIAN => capstone.CS_MODE_LITTLE_ENDIAN,
        },
        .EVM => switch (mode) {
            .LITTLE_ENDIAN => capstone.CS_MODE_LITTLE_ENDIAN,
        },
        .MAX => @compileError("MAX is not an architecture and thus has no modes."),
    };
}

fn to_ks_arch(arch: ARCH) keystone.ks_arch {
    return @intFromEnum(arch);
}
fn to_cs_arch(arch: ARCH) capstone.cs_arch {
    return switch (arch) {
        inline .ARM => capstone.CS_ARCH_ARM,
        inline .ARM64 => capstone.CS_ARCH_AARCH64,
        inline .MIPS => capstone.CS_ARCH_MIPS,
        inline .X86 => capstone.CS_ARCH_X86,
        inline .PPC => capstone.CS_ARCH_PPC,
        inline .SPARC => capstone.CS_ARCH_SPARC,
        inline .SYSTEMZ => capstone.CS_ARCH_SYSZ,
        inline .HEXAGON => capstone.CS_ARCH_XCORE, // TODO: make sure that HEXAGON == XCORE
        inline .EVM => capstone.CS_ARCH_EVM,
        inline .MAX => capstone.CS_ARCH_MAX,
    };
}

fn assemble(arch: keystone.ks_arch, mode: c_int, assembly: []const u8, addr: u64) ![]u8 {
    var temp_ksh: ?*keystone.ks_engine = null;
    const err: keystone.ks_err = keystone.ks_open(arch, mode, &temp_ksh);
    if ((err != keystone.KS_ERR_OK) or (temp_ksh == null)) {
        std.debug.print("err = {x}\n", .{err});
        unreachable;
    }
    const ksh: *keystone.ks_engine = temp_ksh.?;
    defer std.debug.assert(keystone.ks_close(ksh) == 0);

    var encode: ?[*]u8 = null;
    var siz: usize = undefined;
    var enc_count: usize = undefined;
    if (keystone.ks_asm(ksh, @as(?[*]const u8, @ptrCast(assembly)), addr, &encode, &siz, &enc_count) != keystone.KS_ERR_OK) {
        std.debug.print("ERROR: ks_asm() failed & count = {}, error = {}\n", .{ enc_count, keystone.ks_errno(ksh) });
        unreachable;
    }
    // the caller is responsible for calling keystone.ks_free.
    // defer keystone.ks_free(encode);
    return encode.?[0..siz];
}

const ARCH_CTL_FLOW_MAP = std.EnumMap(ARCH, []const u8).init(std.enums.EnumFieldStruct(ARCH, []const u8, null){
    .X86 = "jmp ",
    .ARM = "bal #",
    .ARM64 = "b #",
    .MIPS = "j ",
    .PPC = "b ",
    .SPARC = SPARC,
    .SYSTEMZ = SYSTEMZ,
    .HEXAGON = HEXAGON,
    .EVM = EVM,
    .MAX = undefined,
});

test "test assemble max jmp" {
    const pos = 0x400000;
    const target = "0x401000";
    // if the instruction starts at pos, you want to get to target.
    // the bytes that will make such jump = (target - (pos + 0x8)) >> 0x2. (there are 3 bytes available for the jmp)
    // for example:
    // pos = 0x400000
    // target = 0x401000
    // jmp bytes = (0x401000 - (0x400000 + 0x8)) >> 0x2 = 0x3fe
    const assembled2 = try assemble(to_ks_arch(ARCH.ARM), to_ks_mode(ARCH.ARM, ARM.ARM), ARCH_CTL_FLOW_MAP.get(ARCH.ARM) ++ target, pos); // 0x48d160 = 0x123456 * 4 + 0x8.
    defer keystone.ks_free(assembled2.ptr);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xfe, 0x03, 0x00, 0xea }, assembled2); // the 0xea is the bal instruction, it comes at the end for some reason.
    // bytes that will make such jump = (target - pos) >> 0x2. (there are 26 bits available for the jmp).
    // for example:
    // pos = 0x400000
    // target = 0x401000
    // jmp bytes = 0x400
    const assembled5 = try assemble(to_ks_arch(ARCH.ARM64), to_ks_mode(ARCH.ARM64, ARM64.ARM64), ARCH_CTL_FLOW_MAP.get(ARCH.ARM64) ++ target, pos); // 0x491158 = (0x123456 + 0x1000) << 2.
    defer keystone.ks_free(assembled5.ptr);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x04, 0x00, 0x14 }, assembled5);
    // bytes that will make such jump = target >> 0x2. (there are 26 bits available for the jmp).
    // for example:
    // pos = 0x400000
    // target = 0x401000
    // jmp bytes = 0x401000 >> 0x2 = 0x100400
    const assembled3 = try assemble(to_ks_arch(ARCH.MIPS), to_ks_mode(ARCH.MIPS, MIPS.MIPS64), ARCH_CTL_FLOW_MAP.get(ARCH.MIPS) ++ target, pos); // the jmp target is absolute.
    defer keystone.ks_free(assembled3.ptr);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x04, 0x10, 0x08, 0, 0, 0, 0 }, assembled3);
    // bytes that will make such jump = target - (pos + 0x5). (there are 4 bytes available for this jmp).
    // for example:
    // pos = 0x400000
    // target = 0x401000
    // jmp bytes = 0x401000 - (0x400000 + 0x5) = 0xffb
    const assembled = try assemble(to_ks_arch(ARCH.X86), to_ks_mode(ARCH.X86, MODE.MODE_64), ARCH_CTL_FLOW_MAP.get(ARCH.X86) ++ target, pos); // the offset is from the end of the instruction 0x1234567d = 0x12345678 + 0x5.
    defer keystone.ks_free(assembled.ptr);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xe9, 0xfb, 0x0f, 0x00, 0x00 }, assembled);
    // bytes that will make such jump = target - pos. (there are 26 bits available for this jmp).
    // for example:
    // pos = 0x400000
    // target = 0x401000
    // jmp bytes = 0x401000 - 0x400000 = 0x1000
    const assembled4 = try assemble(to_ks_arch(ARCH.PPC), to_ks_mode(ARCH.PPC, PPC.PPC64), ARCH_CTL_FLOW_MAP.get(ARCH.PPC) ++ target, pos); // the jmp target is absolute.
    defer keystone.ks_free(assembled4.ptr);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x10, 0x00, 0x48 }, assembled4);

    //const assembled6 = try assemble(to_ks_arch(ARCH.SPARC), to_ks_mode(ARCH.SPARC, SPARC.SPARC32), "b " ++ target, pos); // the jmp target is absolute.
    //defer keystone.ks_free(assembled6.ptr);
    //try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x10, 0x00, 0x48 }, assembled6);
}

const OpDesc: type = struct {
    off: u8,
    size: u8,
    signedness: bool,
};

// cant manage to autogenerate these Ranges so for now Ill do them hardcoded.
fn far_call_target_op_range(arch: ARCH, mode: u64) OpDesc {
    return switch (arch) {
        .X86 => switch (@as(MODE, @enumFromInt(mode))) {
            .MODE_64 => OpDesc{ .off = 1, .size = 4, .signedness = true },
            else => unreachable,
        },
        .ARM => switch (@as(ARM, @enumFromInt(mode))) {
            .ARM => OpDesc{ .off = 0, .size = 3, .signedness = true },
            else => unreachable,
        },
        .ARM64 => switch (@as(ARM64, @enumFromInt(mode))) {
            .ARM64 => OpDesc{ .off = 0, .size = 3, .signedness = true },
        },
        else => unreachable,
    };
}

fn calc_jmp_op(arch: ARCH, mode: u64, target: u64, addr: u64) u64 {
    return switch (arch) {
        .X86 => switch (@as(MODE, @enumFromInt(mode))) {
            .MODE_64 => target - (addr + 0x5),
            else => unreachable,
        },
        .ARM => switch (@as(MODE, @enumFromInt(mode))) {
            .ARM => (target - (addr + 0x8)) >> 0x2,
            else => unreachable,
        },
        .ARM64 => switch (@as(MODE, @enumFromInt(mode))) {
            .ARM64 => (target - addr) >> 0x2,
        },
        else => unreachable,
    };
}

fn assemble_ctl_flow_transfer(arch: ARCH, mode: u64, endian: ENDIAN, target: u64, addr: u64, buf: []u8) ![]u8 {
    const assembled2 = try assemble(to_ks_arch(arch), to_ks_mode(arch, mode), ARCH_CTL_FLOW_MAP.get(arch) ++ target, addr); // 0x48d160 = 0x123456 * 4 + 0x8.
    defer keystone.ks_free(assembled2.ptr);
    std.mem.copyForwards(u8, buf[0..assembled2.len], assembled2);
    const target_op_desc = far_call_target_op_range(arch, mode);
    const op_type: type = @Type(std.builtin.Type.Int{ .bits = target_op_desc.size * 8, .signedness = target_op_desc.signedness });
    std.mem.writeInt(op_type, buf[target_op_desc.off..][0..target_op_desc.size], calc_jmp_op(arch, mode, target, addr), endian);
    return buf;
}

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try std.process.argsAlloc(arena);

    if (args.len != 2) fatal("wrong number of arguments", .{});

    const output_file_path = args[1];

    const output_file: std.fs.File = try std.fs.cwd().createFile(output_file_path, .{});

    const w = std.io.bufferedWriter(output_file.writer()).writer();
    // values which generate the ctl flow instruction with the maximum size.
    const pos = 0x400000;
    const target = "0x401000";

    w.write(
        \\fn get_ctl_flow_transfer_asm(arch: ARCH, mode: u64, endian: Endian, buf: []u8) []u8 {
        \\return switch (arch) {
    );
    for (ARCH.values()) |arch| {
        w.write(".");
        w.write(@tagName(arch));
        w.write(" => switch (@as(");
        w.write(@tagName(arch));
        w.write(", @enumFromInt(mode))) {\n");
        for (ARCH_MODE_MAP.get(arch)) |mode| {
            w.write(".");
            w.write(@tagName(mode));
            w.write(" => ");
            if (IS_ENDIANABLE.contains(arch)) {
                const be_max_jmp = assemble(arch, mode + ENDIAN.BIG_ENDIAN, ARCH_CTL_FLOW_MAP(arch) ++ target, pos);
                defer keystone.ks_free(be_max_jmp);

                const le_max_jmp = assemble(arch, mode + ENDIAN.LITTLE_ENDIAN, ARCH_CTL_FLOW_MAP(arch) ++ target, pos);
                defer keystone.ks_free(le_max_jmp);
            } else {
                const max_jmp = assemble(arch, mode, ARCH_CTL_FLOW_MAP(arch) ++ target, pos);
                defer keystone.ks_free(max_jmp);
            }
        }
    }

    var output_file = std.fs.cwd().createFile(output_file_path, .{}) catch |err| {
        fatal("unable to open '{s}': {s}", .{ output_file_path, @errorName(err) });
    };
    defer output_file.close();
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
