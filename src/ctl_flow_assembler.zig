const std = @import("std");
const keystone = @cImport(@cInclude("keystone.h"));

const ARCH: type = enum(u4) {
    ARM,
    ARM64,
    MIPS,
    X86,
    PPC,
    SPARC,
    SYSTEMZ,
    HEXAGON,
    EVM,
};

const ARM: type = enum(u8) {
    ARM,
    THUMB,
    ARMV8,
};

const ARM64: type = enum(u8) {
    ARM64 = 0,
};

const MIPS: type = enum(u8) {
    MIPS32,
    MIPS64,
    MICRO,
    MIPS3,
    MIPS32R6,
};

const MODE: type = enum(u8) {
    MODE_16,
    MODE_32,
    MODE_64,
};

const PPC: type = enum(u8) {
    PPC32,
    PPC64,
    QPX,
};

const SPARC: type = enum(u8) {
    SPARC32,
    SPARC64,
    V9,
};

const SYSTEMZ: type = enum(u32) {
    big,
};

const HEXAGON: type = enum(u8) {
    little,
};

const EVM: type = enum(u8) {
    little,
};

const Endian: type = enum(u1) {
    little,
    big,
};

const IS_EndianABLE = std.EnumSet(ARCH).init(std.enums.EnumFieldStruct(ARCH, type, null){
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

const ARCH_MODE_MAP = std.EnumMap(ARCH, type).init(std.enums.EnumFieldStruct(ARCH, ?type, null){
    .X86 = MODE,
    .ARM = ARM,
    .ARM64 = ARM64,
    .MIPS = MIPS,
    .PPC = PPC,
    .SPARC = SPARC,
    .SYSTEMZ = SYSTEMZ,
    .HEXAGON = HEXAGON,
    .EVM = EVM,
});

const ARCH_TO_CTL_FLOW = std.EnumMap(ARCH, []const u8).init(std.enums.EnumFieldStruct(ARCH, ?[]const u8, null){
    .ARM = &[_]u8{ 0x00, 0x00, 0x00, 0xea },
    .ARM64 = &[_]u8{ 0x00, 0x00, 0x00, 0x14 },
    .MIPS = &[_]u8{ 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00 },
    .X86 = &[_]u8{ 0xe9, 0x00, 0x00, 0x00, 0x00 },
    .PPC = &[_]u8{ 0x00, 0x00, 0x00, 0x48 },
    .SPARC = null,
    .SYSTEMZ = null,
    .HEXAGON = null,
    .EVM = null,
});

const OpDesc: type = struct {
    off: u8,
    size: u8,
    signedness: std.builtin.Signedness,
};

// cant manage to autogenerate these Ranges so for now Ill do them hardcoded.
fn far_call_target_op_range(arch: ARCH, mode: u64, endian: Endian) OpDesc {
    _ = endian;
    return switch (arch) {
        .X86 => switch (@as(MODE, @enumFromInt(mode))) {
            .MODE_64 => OpDesc{ .off = 1, .size = 4 * 8, .signedness = .signed },
            else => unreachable,
        },
        .ARM => switch (@as(ARM, @enumFromInt(mode))) {
            .ARM => OpDesc{ .off = 0, .size = 3 * 8, .signedness = .signed },
            else => unreachable,
        },
        .ARM64 => switch (@as(ARM64, @enumFromInt(mode))) {
            .ARM64 => OpDesc{ .off = 0, .size = 3 * 8, .signedness = .signed },
        },
        .MIPS => switch (@as(MIPS, @enumFromInt(mode))) {
            .MIPS64 => OpDesc{ .off = 0, .size = 26, .signedness = .unsigned },
            else => unreachable,
        },
        else => unreachable,
    };
}

fn calc_jmp_op(arch: ARCH, mode: u64, target: i128, addr: i128) i128 {
    return switch (arch) {
        .X86 => switch (@as(MODE, @enumFromInt(mode))) {
            .MODE_64 => target - (addr + 0x5),
            else => unreachable,
        },
        .ARM => switch (@as(ARM, @enumFromInt(mode))) {
            .ARM => (target - (addr + 0x8)) >> 0x2,
            else => unreachable,
        },
        .ARM64 => switch (@as(ARM64, @enumFromInt(mode))) {
            .ARM64 => (target - addr) >> 0x2,
        },
        .MIPS => switch (@as(MIPS, @enumFromInt(mode))) {
            .MIPS64 => target >> 0x2,
            else => unreachable,
        },
        else => unreachable,
    };
}

// TODO: check if all architectures use twos complement.
fn twos_complement(comptime T: type, buffer: []u8, value: T, endian: Endian) void {
    const bits = @typeInfo(T).Int.bits;
    const bytes = (bits + 7) / 8;
    var temp = blk: {
        if (value < 0) {
            var temp2 = @abs(value);
            temp2 = ~temp2;
            temp2 += 1;
            break :blk temp2;
        } else {
            break :blk @abs(value);
        }
    };
    const save_buf: u8 = if (endian == .big) buffer[0] else buffer[bytes - 1];
    for (0..bytes) |i| {
        buffer[if (endian == .big) bytes - i - 1 else i] = @intCast(temp & 0xff);
        temp = @intCast(@as(@Type(.{ .Int = .{ .bits = @max(bits, 64), .signedness = .unsigned } }), @intCast(temp)) >> 8);
    }
    const one: u8 = 1;
    if (bits % 8 != 0) {
        for (bits % 8..8) |i| {
            buffer[if (endian == .big) 0 else bytes - 1] |= save_buf & one << @intCast(i);
        }
    }
}

test "twos complement" {
    const types = [_]type{ u8, i8, u16, i16, u32, i32, u64, i64 };
    const neg = -123;
    const pos = 123;
    var expected: [100]u8 = undefined;
    var got: [100]u8 = undefined;
    inline for (types) |T| {
        const temp_expected = expected[0..@divExact(@typeInfo(T).Int.bits, 8)];
        const temp_got = got[0..@divExact(@typeInfo(T).Int.bits, 8)];
        std.mem.writeInt(T, temp_expected, std.math.minInt(T), .little);
        twos_complement(T, temp_got, std.math.minInt(T), .little);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        std.mem.writeInt(T, temp_expected, std.math.maxInt(T), .little);
        twos_complement(T, temp_got, std.math.maxInt(T), .little);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        std.mem.writeInt(T, temp_expected, std.math.minInt(T), .big);
        twos_complement(T, temp_got, std.math.minInt(T), .big);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        std.mem.writeInt(T, temp_expected, std.math.maxInt(T), .big);
        twos_complement(T, temp_got, std.math.maxInt(T), .big);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        if (@typeInfo(T).Int.signedness == .signed) {
            std.mem.writeInt(T, temp_expected, neg, .big);
            twos_complement(T, temp_got, neg, .big);
            try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
            std.mem.writeInt(T, temp_expected, neg, .little);
            twos_complement(T, temp_got, neg, .little);
            try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        }
        std.mem.writeInt(T, temp_expected, pos, .big);
        twos_complement(T, temp_got, pos, .big);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        std.mem.writeInt(T, temp_expected, pos, .little);
        twos_complement(T, temp_got, pos, .little);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
    }
}

fn assemble_ctl_flow_transfer(comptime arch: ARCH, comptime mode: u64, comptime endian: Endian, target: u64, addr: u64, buf: []u8) ![]u8 {
    const ctl_flow_insn = ARCH_TO_CTL_FLOW.get(arch).?;
    std.mem.copyForwards(u8, buf[0..ctl_flow_insn.len], ctl_flow_insn);
    const target_op_desc = comptime far_call_target_op_range(arch, mode, endian);
    const op_type: type = @Type(.{ .Int = .{ .bits = target_op_desc.size, .signedness = target_op_desc.signedness } });
    twos_complement(op_type, buf[target_op_desc.off..][0 .. (target_op_desc.size + 7) / 8], @intCast(calc_jmp_op(arch, mode, target, addr)), endian);
    return buf[0..ctl_flow_insn.len];
}

test "assemble control flow transfer" {
    const addr = 0x400000;
    const target = "0x401000";
    var buf: [100]u8 = undefined;
    // if the instruction starts at addr, you want to get to target.
    // the bytes that will make such jump = (target - (addr + 0x8)) >> 0x2. (there are 3 bytes available for the jmp)
    // for example:
    // addr = 0x400000
    // target = 0x401000
    // jmp bytes = (0x401000 - (0x400000 + 0x8)) >> 0x2 = 0x3fe
    const assembled2 = try assemble(to_ks_arch(ARCH.ARM), to_ks_mode(ARCH.ARM, ARM.ARM), "bal #" ++ target, addr); // 0x48d160 = 0x123456 * 4 + 0x8.
    defer keystone.ks_free(assembled2.ptr);
    try std.testing.expectEqualSlices(u8, assembled2, try assemble_ctl_flow_transfer(
        ARCH.ARM,
        @intFromEnum(ARM.ARM),
        Endian.little,
        try std.fmt.parseInt(u64, target, 0),
        addr,
        &buf,
    )); // the 0xea is the bal instruction, it comes at the end for some reason.
    // bytes that will make such jump = (target - addr) >> 0x2. (there are 26 bits available for the jmp).
    // for example:
    // addr = 0x400000
    // target = 0x401000
    // jmp bytes = 0x400
    const assembled5 = try assemble(to_ks_arch(ARCH.ARM64), to_ks_mode(ARCH.ARM64, ARM64.ARM64), "b #" ++ target, addr); // 0x491158 = (0x123456 + 0x1000) << 2.
    defer keystone.ks_free(assembled5.ptr);
    try std.testing.expectEqualSlices(u8, assembled5, try assemble_ctl_flow_transfer(
        ARCH.ARM64,
        @intFromEnum(ARM64.ARM64),
        Endian.little,
        try std.fmt.parseInt(u64, target, 0),
        addr,
        &buf,
    ));
    // bytes that will make such jump = target >> 0x2. (there are 26 bits available for the jmp).
    // for example:
    // addr = 0x400000
    // target = 0x401000
    // jmp bytes = 0x401000 >> 0x2 = 0x100400
    const assembled3 = try assemble(to_ks_arch(ARCH.MIPS), to_ks_mode(ARCH.MIPS, MIPS.MIPS64), "j " ++ target, addr); // the jmp target is absolute.
    defer keystone.ks_free(assembled3.ptr);
    try std.testing.expectEqualSlices(u8, assembled3, try assemble_ctl_flow_transfer(
        ARCH.MIPS,
        @intFromEnum(MIPS.MIPS64),
        Endian.little,
        try std.fmt.parseInt(u64, target, 0),
        addr,
        &buf,
    ));

    // bytes that will make such jump = target - (addr + 0x5). (there are 4 bytes available for this jmp).
    // for example:
    // addr = 0x400000
    // target = 0x401000
    // jmp bytes = 0x401000 - (0x400000 + 0x5) = 0xffb
    const assembled = try assemble(to_ks_arch(ARCH.X86), to_ks_mode(ARCH.X86, MODE.MODE_64), "jmp " ++ target, addr); // the offset is from the end of the instruction 0x1234567d = 0x12345678 + 0x5.
    defer keystone.ks_free(assembled.ptr);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xe9, 0xfb, 0x0f, 0x00, 0x00 }, assembled);
    // bytes that will make such jump = target - addr. (there are 26 bits available for this jmp).
    // for example:
    // addr = 0x400000
    // target = 0x401000
    // jmp bytes = 0x401000 - 0x400000 = 0x1000
    const assembled4 = try assemble(to_ks_arch(ARCH.PPC), to_ks_mode(ARCH.PPC, PPC.PPC64), "b " ++ target, addr); // the jmp target is absolute.
    defer keystone.ks_free(assembled4.ptr);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x10, 0x00, 0x48 }, assembled4);

    //const assembled6 = try assemble(to_ks_arch(ARCH.SPARC), to_ks_mode(ARCH.SPARC, SPARC.SPARC32), "b " ++ target, addr); // the jmp target is absolute.
    //defer keystone.ks_free(assembled6.ptr);
    //try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x10, 0x00, 0x48 }, assembled6);
}

fn to_ks_arch(arch: ARCH) keystone.ks_arch {
    return switch (arch) {
        .X86 => keystone.KS_ARCH_X86,
        .ARM => keystone.KS_ARCH_ARM,
        .ARM64 => keystone.KS_ARCH_ARM64,
        .MIPS => keystone.KS_ARCH_MIPS,
        .PPC => keystone.KS_ARCH_PPC,
        .SPARC => keystone.KS_ARCH_SPARC,
        .SYSTEMZ => keystone.KS_ARCH_SYSTEMZ,
        .HEXAGON => keystone.KS_ARCH_HEXAGON,
        .EVM => keystone.KS_ARCH_EVM,
    };
}

fn to_ks_mode(comptime arch: ARCH, mode: ARCH_MODE_MAP.get(arch).?) c_int {
    return switch (arch) {
        .X86 => switch (mode) {
            .MODE_64 => keystone.KS_MODE_64,
            .MODE_32 => keystone.KS_MODE_32,
            .MODE_16 => keystone.KS_MODE_16,
        },
        .ARM => switch (mode) {
            .ARM => keystone.KS_MODE_ARM,
            .THUMB => keystone.KS_MODE_THUMB,
            .ARMV8 => keystone.KS_MODE_ARM + keystone.KS_MODE_V8,
        },
        .ARM64 => switch (mode) {
            .ARM64 => keystone.KS_MODE_LITTLE_ENDIAN,
        },
        .MIPS => switch (mode) {
            .MIPS32 => keystone.KS_MODE_MIPS32,
            .MIPS64 => keystone.KS_MODE_MIPS64,
            .MICRO => keystone.KS_MODE_MICRO,
            .MIPS3 => keystone.KS_MODE_MIPS3,
            .MIPS32R6 => keystone.KS_MODE_MIPS32R6,
        },
        .PPC => switch (mode) {
            .PPC32 => keystone.KS_MODE_PPC32,
            .PPC64 => keystone.KS_MODE_PPC64,
            .QPX => keystone.KS_MODE_QPX,
        },
        .SPARC => switch (mode) {
            .SPARC32 => keystone.KS_MODE_SPARC32,
            .SPARC64 => keystone.KS_MODE_SPARC64,
            .V9 => keystone.KS_MODE_V9,
        },
        .SYSTEMZ => switch (mode) {
            .big => keystone.KS_MODE_BIG_ENDIAN,
        },
        .HEXAGON => switch (mode) {
            .little => keystone.KS_MODE_LITTLE_Endian,
        },
        .EVM => switch (mode) {
            .little => keystone.KS_MODE_LITTLE_Endian,
        },
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
