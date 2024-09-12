const std = @import("std");
const keystone = @cImport(@cInclude("keystone.h"));

pub const Arch: type = enum(u4) {
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

pub const ARM: type = enum(u8) {
    ARM,
    THUMB,
    ARMV8,
};

pub const ARM64: type = enum(u8) {
    ARM64 = 0,
};

pub const MIPS: type = enum(u8) {
    MIPS32,
    MIPS64,
    MICRO,
    MIPS3,
    MIPS32R6,
};

pub const MODE: type = enum(u8) {
    MODE_16,
    MODE_32,
    MODE_64,
};

pub const PPC: type = enum(u8) {
    PPC32,
    PPC64,
    QPX,
};

pub const SPARC: type = enum(u8) {
    SPARC32,
    SPARC64,
    V9,
};

pub const SYSTEMZ: type = enum(u32) {
    big,
};

pub const HEXAGON: type = enum(u8) {
    little,
};

pub const EVM: type = enum(u8) {
    little,
};

pub const Endian: type = enum(u1) {
    little,
    big,
};

pub const IS_ENDIANABLE = std.EnumSet(Arch).init(std.enums.EnumFieldStruct(Arch, bool, false){
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

pub const ARCH_MODE_MAP = std.EnumMap(Arch, type).init(std.enums.EnumFieldStruct(Arch, ?type, null){
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

// TODO: check if all architectures use twos complement.
fn twos_complement(value: i128, bits: u16, endian: Endian, buffer: []u8) void {
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
        temp >>= 8;
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
        const bits = @typeInfo(T).Int.bits;
        const temp_expected = expected[0..@divExact(@typeInfo(T).Int.bits, 8)];
        const temp_got = got[0..@divExact(@typeInfo(T).Int.bits, 8)];
        std.mem.writeInt(T, temp_expected, std.math.minInt(T), .little);
        twos_complement(std.math.minInt(T), bits, .little, temp_got);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        std.mem.writeInt(T, temp_expected, std.math.maxInt(T), .little);
        twos_complement(std.math.maxInt(T), bits, .little, temp_got);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        std.mem.writeInt(T, temp_expected, std.math.minInt(T), .big);
        twos_complement(std.math.minInt(T), bits, .big, temp_got);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        std.mem.writeInt(T, temp_expected, std.math.maxInt(T), .big);
        twos_complement(std.math.maxInt(T), bits, .big, temp_got);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        if (@typeInfo(T).Int.signedness == .signed) {
            std.mem.writeInt(T, temp_expected, neg, .big);
            twos_complement(neg, bits, .big, temp_got);
            try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
            std.mem.writeInt(T, temp_expected, neg, .little);
            twos_complement(neg, bits, .little, temp_got);
            try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        }
        std.mem.writeInt(T, temp_expected, pos, .big);
        twos_complement(pos, bits, .big, temp_got);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        std.mem.writeInt(T, temp_expected, pos, .little);
        twos_complement(pos, bits, .little, temp_got);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
    }
}

pub const CtlFlowAssembler: type = struct {
    arch: Arch,
    mode: u64,
    endian: ?Endian,

    pub const Error: type = error{
        ArchNotEndianable,
    };

    const Self = @This();

    pub fn init(arch: Arch, mode: u64, endian: ?Endian) Error!Self {
        if (IS_ENDIANABLE.contains(arch) and endian != null) return Error.ArchNotEndianable;
        // TODO: check that the mode matches the arch.
        // try @as(ARCH_MODE_MAP.get(arch), @enumFromInt(mode));
        return .{
            .arch = arch,
            .mode = mode,
            .endian = endian,
        };
    }

    pub fn assemble_ctl_flow_transfer(self: *const Self, target: u64, addr: u64, buf: []u8) ![]u8 {
        const ctl_flow_insn = ARCH_TO_CTL_FLOW.get(self.arch).?;
        std.mem.copyForwards(u8, buf[0..ctl_flow_insn.len], ctl_flow_insn);
        const target_op_desc = self.transfer_target_operand_range();
        twos_complement(
            self.calc_ctl_tranfer_op(target, addr),
            target_op_desc.size,
            self.endian orelse .little,
            buf[target_op_desc.off..][0 .. (target_op_desc.size + 7) / 8],
        );
        return buf[0..ctl_flow_insn.len];
    }

    fn transfer_target_operand_range(self: *const Self) OpDesc {
        _ = self.endian;
        return switch (self.arch) {
            .X86 => switch (@as(MODE, @enumFromInt(self.mode))) {
                .MODE_64 => OpDesc{ .off = 1, .size = 4 * 8, .signedness = .signed },
                else => unreachable,
            },
            .ARM => switch (@as(ARM, @enumFromInt(self.mode))) {
                .ARM => OpDesc{ .off = 0, .size = 3 * 8, .signedness = .signed },
                else => unreachable,
            },
            .ARM64 => switch (@as(ARM64, @enumFromInt(self.mode))) {
                .ARM64 => OpDesc{ .off = 0, .size = 3 * 8, .signedness = .signed },
            },
            .MIPS => switch (@as(MIPS, @enumFromInt(self.mode))) {
                .MIPS64 => OpDesc{ .off = 0, .size = 26, .signedness = .unsigned },
                else => unreachable,
            },
            else => unreachable,
        };
    }

    fn calc_ctl_tranfer_op(self: *const Self, target: i128, addr: i128) i128 {
        return switch (self.arch) {
            .X86 => switch (@as(MODE, @enumFromInt(self.mode))) {
                .MODE_64 => target - (addr + 0x5),
                else => unreachable,
            },
            .ARM => switch (@as(ARM, @enumFromInt(self.mode))) {
                .ARM => (target - (addr + 0x8)) >> 0x2,
                else => unreachable,
            },
            .ARM64 => switch (@as(ARM64, @enumFromInt(self.mode))) {
                .ARM64 => (target - addr) >> 0x2,
            },
            .MIPS => switch (@as(MIPS, @enumFromInt(self.mode))) {
                .MIPS64 => target >> 0x2,
                else => unreachable,
            },
            else => unreachable,
        };
    }

    const ARCH_TO_CTL_FLOW = std.EnumMap(Arch, []const u8).init(std.enums.EnumFieldStruct(Arch, ?[]const u8, null){
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
};

fn assemble_ctl_flow_transfer(arch: Arch, mode: u64, endian: Endian, target: u64, addr: u64, buf: []u8) []u8 {
    const ctl_flow_engine: CtlFlowAssembler = CtlFlowAssembler.init(arch, mode, endian);
    return ctl_flow_engine.assemble_ctl_flow_transfer(target, addr, buf);
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
    const assembled2 = try assemble(to_ks_arch(Arch.ARM), to_ks_mode(Arch.ARM, ARM.ARM), "bal #" ++ target, addr); // 0x48d160 = 0x123456 * 4 + 0x8.
    defer keystone.ks_free(assembled2.ptr);
    try std.testing.expectEqualSlices(u8, assembled2, try assemble_ctl_flow_transfer(
        Arch.ARM,
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
    const assembled5 = try assemble(to_ks_arch(Arch.ARM64), to_ks_mode(Arch.ARM64, ARM64.ARM64), "b #" ++ target, addr); // 0x491158 = (0x123456 + 0x1000) << 2.
    defer keystone.ks_free(assembled5.ptr);
    try std.testing.expectEqualSlices(u8, assembled5, try assemble_ctl_flow_transfer(
        Arch.ARM64,
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
    const assembled3 = try assemble(to_ks_arch(Arch.MIPS), to_ks_mode(Arch.MIPS, MIPS.MIPS64), "j " ++ target, addr); // the jmp target is absolute.
    defer keystone.ks_free(assembled3.ptr);
    try std.testing.expectEqualSlices(u8, assembled3, try assemble_ctl_flow_transfer(
        Arch.MIPS,
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
    const assembled = try assemble(to_ks_arch(Arch.X86), to_ks_mode(Arch.X86, MODE.MODE_64), "jmp " ++ target, addr); // the offset is from the end of the instruction 0x1234567d = 0x12345678 + 0x5.
    defer keystone.ks_free(assembled.ptr);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xe9, 0xfb, 0x0f, 0x00, 0x00 }, assembled);
    // bytes that will make such jump = target - addr. (there are 26 bits available for this jmp).
    // for example:
    // addr = 0x400000
    // target = 0x401000
    // jmp bytes = 0x401000 - 0x400000 = 0x1000
    const assembled4 = try assemble(to_ks_arch(Arch.PPC), to_ks_mode(Arch.PPC, PPC.PPC64), "b " ++ target, addr); // the jmp target is absolute.
    defer keystone.ks_free(assembled4.ptr);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x10, 0x00, 0x48 }, assembled4);

    //const assembled6 = try assemble(to_ks_arch(ARCH.SPARC), to_ks_mode(ARCH.SPARC, SPARC.SPARC32), "b " ++ target, addr); // the jmp target is absolute.
    //defer keystone.ks_free(assembled6.ptr);
    //try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x10, 0x00, 0x48 }, assembled6);
}

fn to_ks_arch(arch: Arch) keystone.ks_arch {
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

fn to_ks_mode(comptime arch: Arch, mode: ARCH_MODE_MAP.get(arch).?) c_int {
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
