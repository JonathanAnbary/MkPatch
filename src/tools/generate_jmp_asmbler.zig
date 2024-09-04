const std = @import("std");
const capstone = @cImport(@cInclude("capstone.h"));
const keystone = @cImport(@cInclude("keystone.h"));
// const capstone = @import("../../translated-include/capstone-5.0/capstone/capstone.zig");
// const keystone = @import("../../translated-include/keystone/keystone.zig");

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

const ARCH_MODE_MAP = std.EnumArray(ARCH, type).init(std.enums.EnumFieldStruct(ARCH, type, null){
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

fn to_ks_mode(comptime arch: ARCH, comptime mode: ARCH_MODE_MAP.get(arch)) c_int {
    return @intFromEnum(mode);
}
fn to_cs_mode(comptime arch: ARCH, comptime mode: ARCH_MODE_MAP.get(arch)) capstone.cs_mode {
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

fn to_ks_arch(comptime arch: ARCH) keystone.ks_arch {
    return @intFromEnum(arch);
}
fn to_cs_arch(comptime arch: ARCH) capstone.cs_arch {
    return switch (arch) {
        inline .ARM => capstone.CS_ARCH_ARM,
        inline .ARM64 => capstone.CS_ARCH_ARM64,
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

test "test assemble max jmp" {
    const pos = 0x400000;
    const target = "0x401000";
    // if the instruction starts at pos, you want to get to target.
    // the bytes that will make such jump = (target - (pos + 0x8)) >> 0x2. (there are 3 bytes available for the jmp)
    // for example:
    // pos = 0x400000
    // target = 0x401000
    // jmp bytes = (0x401000 - (0x400000 + 0x8)) >> 0x2 = 0x400
    const assembled2 = try assemble(to_ks_arch(ARCH.ARM), to_ks_mode(ARCH.ARM, ARM.ARM), "bal #" ++ target, pos); // 0x48d160 = 0x123456 * 4 + 0x8.
    defer keystone.ks_free(assembled2.ptr);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xfe, 0x03, 0x00, 0xea }, assembled2); // the 0xea is the bal instruction, it comes at the end for some reason.
    // bytes that will make such jump = (target - pos) >> 0x2. (there are 26 bits available for the jmp).
    // for example:
    // pos = 0x400000
    // target = 0x401000
    // jmp bytes = 0x400
    const assembled5 = try assemble(to_ks_arch(ARCH.ARM64), to_ks_mode(ARCH.ARM64, ARM64.ARM64), "b #" ++ target, pos); // 0x491158 = (0x123456 + 0x1000) << 2.
    defer keystone.ks_free(assembled5.ptr);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x04, 0x00, 0x14 }, assembled5);
    // bytes that will make such jump = target >> 0x2. (there are 26 bits available for the jmp).
    // for example:
    // pos = 0x400000
    // target = 0x401000
    // jmp bytes = 0x401000 >> 0x2 = 0x100400
    const assembled3 = try assemble(to_ks_arch(ARCH.MIPS), to_ks_mode(ARCH.MIPS, MIPS.MIPS64), "j " ++ target, pos); // the jmp target is absolute.
    defer keystone.ks_free(assembled3.ptr);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x04, 0x10, 0x08, 0, 0, 0, 0 }, assembled3);
    // bytes that will make such jump = target - (pos + 0x5). (there are 4 bytes available for this jmp).
    // for example:
    // pos = 0x400000
    // target = 0x401000
    // jmp bytes = 0x401000 - (0x400000 + 0x5) = 0xffb
    const assembled = try assemble(to_ks_arch(ARCH.X86), to_ks_mode(ARCH.X86, MODE.MODE_64), "jmp " ++ target, pos); // the offset is from the end of the instruction 0x1234567d = 0x12345678 + 0x5.
    defer keystone.ks_free(assembled.ptr);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xe9, 0xfb, 0x0f, 0x00, 0x00 }, assembled);
    // bytes that will make such jump = target - pos. (there are 26 bits available for this jmp).
    // for example:
    // pos = 0x400000
    // target = 0x401000
    // jmp bytes = 0x401000 - 0x400000 = 0x1000
    const assembled4 = try assemble(to_ks_arch(ARCH.PPC), to_ks_mode(ARCH.PPC, PPC.PPC64), "b " ++ target, pos); // the jmp target is absolute.
    defer keystone.ks_free(assembled4.ptr);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x10, 0x00, 0x48 }, assembled4);

    //const assembled6 = try assemble(to_ks_arch(ARCH.SPARC), to_ks_mode(ARCH.SPARC, SPARC.SPARC32), "b " ++ target, pos); // the jmp target is absolute.
    //defer keystone.ks_free(assembled6.ptr);
    //try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x10, 0x00, 0x48 }, assembled6);
}

const Range: type = struct {
    off: u8,
    size: u8,
};

fn get_operand_range(arch: capstone.cs_arch, mode: capstone.cs_mode, asmb: []const u8, op_idx: u8) ?Range {
    var csh: capstone.csh = undefined;
    if (capstone.cs_open(arch, mode, &csh) != capstone.CS_ERR_OK) {
        unreachable;
    }
    if (capstone.cs_option(csh, capstone.CS_OPT_DETAIL, capstone.CS_OPT_ON) != capstone.CS_ERR_OK) {
        unreachable;
    }
    std.debug.print("\n{}\n", .{csh});
    const insn: *capstone.cs_insn = capstone.cs_malloc(csh);
    defer capstone.cs_free(insn, 1);
    defer _ = capstone.cs_close(&csh);
    var curr_code = asmb;
    var curr_size = asmb.len;
    const start: u64 = 0;
    var end: u64 = start;
    if (!capstone.cs_disasm_iter(
        csh,
        @as([*c][*c]const u8, @ptrCast(&curr_code)),
        &curr_size,
        &end,
        insn,
    )) {
        unreachable;
    }
    switch (arch) {
        capstone.CS_ARCH_ARM => std.debug.print("{}\n", .{insn.detail.*.unnamed_0.arm}),
        capstone.CS_ARCH_ARM64 => std.debug.print("{}\n", .{insn.detail.*.unnamed_0.arm64}),
        capstone.CS_ARCH_MIPS => std.debug.print("{}\n", .{insn.detail.*.unnamed_0.mips}),
        capstone.CS_ARCH_X86 => {
            if (op_idx >= insn.detail.*.unnamed_0.x86.op_count) return null;
            var off: u8 = @intCast(std.mem.indexOf(u8, &insn.detail.*.unnamed_0.x86.opcode, &[_]u8{0}) orelse 4);
            std.debug.print("0off = {}\n", .{off});
            for (insn.detail.*.unnamed_0.x86.operands[0..op_idx]) |op| {
                off += op.size;
            }
            std.debug.print("{}\n", .{insn.detail.*.unnamed_0.x86.operands[op_idx]});

            return Range{ .off = off, .size = insn.detail.*.unnamed_0.x86.operands[op_idx].size };
        },
        capstone.CS_ARCH_PPC => std.debug.print("{}\n", .{insn.detail.*.unnamed_0.ppc}),
        // not currently implementing since I dont even assemble a max jmp for these arches.
        //.SPARC => std.debug.print("{}\n", .{insn.detail.*.unnamed_0.sparc}),
        //.SYSTEMZ => std.debug.print("{}\n", .{insn.detail.*.unnamed_0.sysz}),
        //.HEXAGON => std.debug.print("{}\n", .{insn.detail.*.unnamed_0.xcore}), // TODO: make sure HEXAGON == XCORE
        //.EVM => std.debug.print("{}\n", .{insn.detail.*.unnamed_0.evm}),
        else => unreachable,
    }
    return null;
}

test "op idx gettings" {
    const pos = 0x400000;
    const target = "0x401000";
    const assembled = try assemble(to_ks_arch(ARCH.X86), to_ks_mode(ARCH.X86, MODE.MODE_64), "jmp " ++ target, pos);
    defer keystone.ks_free(assembled.ptr);
    const op_range = get_operand_range(to_cs_arch(ARCH.X86), to_cs_mode(ARCH.X86, MODE.MODE_64), assembled, 0).?;
    std.debug.print("\n{}\n", .{op_range});
    try std.testing.expect(op_range.off == 1 and op_range.size == 4);
}

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try std.process.argsAlloc(arena);

    if (args.len != 2) fatal("wrong number of arguments", .{});

    const output_file_path = args[1];

    for (ARCH.values()) |arch| {
        for (ARCH_MODE_MAP.get(arch)) |mode| {
            if (IS_ENDIANABLE.contains(arch)) {
                const be_max_jmp = assemble(arch, mode + ENDIAN.BIG_ENDIAN);
                defer keystone.ks_free(be_max_jmp);

                const le_max_jmp = assemble(arch, mode + ENDIAN.LITTLE_ENDIAN);
                defer keystone.ks_free(le_max_jmp);
            } else {
                const max_jmp = assemble(arch, mode);
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
