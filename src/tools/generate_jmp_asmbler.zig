const std = @import("std");
const capstone = @cImport(@cInclude("capstone.h"));
const keystone = @cImport(@cInclude("keystone.h"));
// const capstone = @import("../translated-include/capstone-5.0/capstone/capstone.zig");
// const keystone = @import("../translated-include/keystone/keystone.zig");

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

const SYSTEMZ: type = enum(u8) {
    BIG_ENDIAN = keystone.KS_MODE_BIG_ENDIAN,
};

const HEXAGON: type = enum(u8) {
    LITTLE_ENDIAN = keystone.KS_MODE_LITTLE_ENDIAN,
};

const EVM: type = enum(u8) {
    LITTLE_ENDIAN = keystone.KS_MODE_LITTLE_ENDIAN,
};

const KS_ENDIAN: type = enum(u8) {
    LITTLE_ENDIAN = keystone.KS_MODE_LITTLE_ENDIAN,
    BIG_ENDIAN = keystone.KS_MODE_BIG_ENDIAN,
};

const CS_ENDIAN: type = enum(u8) {
    LITTLE_ENDIAN = keystone.CS_MODE_LITTLE_ENDIAN,
    BIG_ENDIAN = keystone.CS_MODE_BIG_ENDIAN,
};

fn ks2cs_mode(comptime ks_const: keystone.ks_mode) capstone.cs_mode {
    return switch (ks_const) {
        // 1
        inline keystone.KS_MODE_ARM => capstone.CS_MODE_ARM,
        // 2
        inline keystone.KS_MODE_16 => capstone.CS_MODE_16,
        // 4
        inline keystone.KS_MODE_32 => capstone.CS_MODE_32,
        inline keystone.KS_MODE_MIPS32 => capstone.CS_MODE_MIPS32,
        // inline keystone.KS_MODE_SPARC32 => capstone.CS_MODE_SPARC32,
        // inline keystone.KS_MODE_PPC32 => capstone.CS_MODE_PPC32,
        // 8
        inline keystone.KS_MODE_MIPS64 => capstone.CS_MODE_MIPS64,
        inline keystone.KS_MODE_64 => capstone.CS_MODE_64,
        // inline keystone.KS_MODE_PPC64 => capstone.CS_MODE_PPC64,
        // inline keystone.KS_MODE_SPARC64 => capstone.CS_MODE_SPARC64,
        // 16
        inline keystone.KS_MODE_THUMB => capstone.CS_MODE_THUMB,
        inline keystone.KS_MODE_MICRO => capstone.CS_MODE_MICRO,
        inline keystone.KS_MODE_QPX => capstone.CS_MODE_QPX,
        inline keystone.KS_MODE_V9 => capstone.CS_MODE_V9,
        // 32
        inline keystone.KS_MODE_MIPS3 => capstone.CS_MODE_MIPS3,
        // 64
        inline keystone.KS_MODE_MIPS32R6 => capstone.CS_MODE_MIPS32R6,
        // 65
        inline keystone.KS_MODE_ARM + capstone.CS_MODE_V8 => capstone.CS_MODE_ARM + capstone.CS_MODE_V8,
    };
}

fn ks2cs_arch(comptime ks_const: keystone.ks_arch) capstone.cs_arch {
    return switch (ks_const) {
        inline keystone.KS_ARCH_ARM => capstone.CS_ARCH_ARM,
        inline keystone.KS_ARCH_ARM64 => capstone.CS_ARCH_ARM64,
        inline keystone.KS_ARCH_MIPS => capstone.CS_ARCH_MIPS,
        inline keystone.KS_ARCH_X86 => capstone.CS_ARCH_X86,
        inline keystone.KS_ARCH_PPC => capstone.CS_ARCH_PPC,
        inline keystone.KS_ARCH_SPARC => capstone.CS_ARCH_SPARC,
        inline keystone.KS_ARCH_SYSTEMZ => capstone.CS_ARCH_SYSZ,
        inline keystone.KS_ARCH_HEXAGON => capstone.CS_ARCH_XCORE, // TODO: make sure that HEXAGON == XCORE
        inline keystone.KS_ARCH_EVM => capstone.CS_ARCH_EVM,
        inline keystone.KS_ARCH_MAX => capstone.CS_ARCH_MAX,
    };
}

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

fn assemble(arch: ARCH, mode: MODE, assembly: []const u8) ![]u8 {
    var temp_ksh: ?*keystone.ks_engine = null;
    if ((keystone.ks_open(@intFromEnum(arch), @intFromEnum(mode), &temp_ksh) != keystone.KS_ERR_OK) or (temp_ksh == null)) {
        unreachable;
    }
    const ksh: *keystone.ks_engine = temp_ksh.?;
    defer std.debug.assert(keystone.ks_close(ksh) == 0);

    var encode: ?[*]u8 = null;
    var siz: usize = undefined;
    var enc_count: usize = undefined;
    if (keystone.ks_asm(ksh, @as(?[*]const u8, @ptrCast(assembly)), 0, &encode, &siz, &enc_count) != keystone.KS_ERR_OK) {
        // std.debug.print("ERROR: ks_asm() failed & count = {}, error = {}\n", .{ enc_count, keystone.ks_errno(ksh) });
        unreachable;
    }
    // the caller is responsible for calling keystone.ks_free.
    // defer keystone.ks_free(encode);
    return encode.?[0..siz];
}

test "test assemble max jmp" {
    const assembled = try assemble(ARCH.X86, MODE.MODE_64, "jmp 0xffff");
    defer keystone.ks_free(assembled.ptr);
    std.debug.print("\n{x}\n", .{assembled});
}

fn get_operand_offset(arch: capstone.cs_arch, mode: capstone.cs_mode, asmb: []const u8, op_idx: u8) void {
    _ = op_idx;
    var csh: capstone.csh = undefined;
    if (capstone.cs_open(arch, mode + CS_ENDIAN.BIG_ENDIAN, &csh) != capstone.CS_ERR_OK) {
        unreachable;
    }
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
        .ARM => std.debug.print("{}\n", .{insn.detail.*.unnamed_0.arm}),
        .ARM64 => std.debug.print("{}\n", .{insn.detail.*.unnamed_0.arm64}),
        .MIPS => std.debug.print("{}\n", .{insn.detail.*.unnamed_0.mips}),
        .X86 => std.debug.print("{}\n", .{insn.detail.*.unnamed_0.x86}),
        .PPC => std.debug.print("{}\n", .{insn.detail.*.unnamed_0.ppc}),
        .SPARC => std.debug.print("{}\n", .{insn.detail.*.unnamed_0.sparc}),
        .SYSTEMZ => std.debug.print("{}\n", .{insn.detail.*.unnamed_0.sysz}),
        .HEXAGON => std.debug.print("{}\n", .{insn.detail.*.unnamed_0.xcore}), // TODO: make sure HEXAGON == XCORE
        .EVM => std.debug.print("{}\n", .{insn.detail.*.unnamed_0.evm}),
        else => unreachable,
    }
}

test "op idx gettings" {}

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
                const be_max_jmp = assemble(arch, mode + KS_ENDIAN.BIG_ENDIAN);
                defer keystone.ks_free(be_max_jmp);

                const le_max_jmp = assemble(arch, mode + KS_ENDIAN.LITTLE_ENDIAN);
                defer keystone.ks_free(le_max_jmp);
            } else {
                const max_jmp = assemble(arch, mode);
                defer keystone.ks_free(max_jmp);
            }
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
