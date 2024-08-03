const std = @import("std");
const libelf = @cImport(@cInclude("libelf.h"));
const capstone = @cImport(@cInclude("capstone/capstone.h"));
const keystone = @cImport(@cInclude("keystone.h"));

fn kind_string(kind: c_uint) []const u8 {
    return switch (kind) {
        libelf.ELF_K_AR => return "ELF_K_AR",
        libelf.ELF_K_ELF => return "ELF_K_ELF",
        libelf.ELF_K_NONE => return "ELF_K_NONE",
        else => unreachable,
    };
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
        inline .ELFCLASS32 => libelf.Elf32_Phdr,
        inline .ELFCLASS64 => libelf.Elf64_Phdr,
    };
}

fn ElfShdr(comptime ei_class: EI_CLASS) type {
    return switch (ei_class) {
        inline .ELFCLASS32 => libelf.Elf32_Shdr,
        inline .ELFCLASS64 => libelf.Elf64_Shdr,
    };
}

const Error: type = error{
    SegmentNotFound,
    SectionNotFound,
    PhdrNotGot,
    BeginFailed,
    NoSections,
    NotPatchingNotBytes,
};

fn elf_getphdr(comptime ei_class: EI_CLASS, elf: *libelf.Elf) ?[*]ElfPhdr(ei_class) {
    return switch (ei_class) {
        inline .ELFCLASS32 => libelf.elf32_getphdr(elf),
        inline .ELFCLASS64 => libelf.elf64_getphdr(elf),
    };
}

fn elf_getshdr(comptime ei_class: EI_CLASS, scn: *libelf.Elf_Scn) ?*ElfShdr(ei_class) {
    return switch (ei_class) {
        inline .ELFCLASS32 => libelf.elf32_getshdr(scn),
        inline .ELFCLASS64 => libelf.elf64_getshdr(scn),
    };
}

fn get_offset_phdr(comptime ei_class: EI_CLASS, elf: *libelf.Elf, off: ElfOffset(ei_class)) Error!*ElfPhdr(ei_class) {
    std.debug.print("here {}\n", .{ei_class});
    const temp: [*]ElfPhdr(ei_class) = elf_getphdr(ei_class, elf) orelse {
        std.debug.print("{s}\n", .{libelf.elf_errmsg(libelf.elf_errno())});
        return Error.PhdrNotGot;
    };

    var phdr_num: usize = undefined;
    if (libelf.elf_getphdrnum(elf, &phdr_num) == -1) {
        unreachable;
    }
    const phdr_table: []ElfPhdr(ei_class) = temp[0..phdr_num];
    std.debug.print("{}\n", .{phdr_num});
    for (phdr_table) |*phdr| {
        std.debug.print(
            \\off - {}
            \\phdr.p_offset - {}
            \\phdr.p_filesz - {}
            \\(phdr.p_offset + phdr.p_filesz) - {}
            \\
        , .{ off, phdr.p_offset, phdr.p_filesz, (phdr.p_offset + phdr.p_filesz) });
        if (off < (phdr.p_offset + phdr.p_filesz)) {
            return phdr;
        }
    }
    return Error.SegmentNotFound;
}

fn get_off_scn(comptime ei_class: EI_CLASS, elf: *libelf.Elf, off: ElfOffset(ei_class)) ?*libelf.Elf_Scn {
    var curr_scn: ?*libelf.Elf_Scn = null;
    while (libelf.elf_nextscn(elf, curr_scn)) |scn| : (curr_scn = scn) {
        const parsed_shdr = elf_getshdr(ei_class, scn) orelse {
            return Error.SectionNotFound;
        };
        if ((off > parsed_shdr.sh_offset) and (off < (parsed_shdr.sh_offset + parsed_shdr.sh_size))) {
            return scn;
        }
    }
    return null;
}

fn make_off_scn(comptime ei_class: EI_CLASS, elf: *libelf.Elf, off: ElfOffset(ei_class)) *libelf.Elf_Scn {
    const scn: *libelf.Elf_Scn = libelf.elf_newscn(elf) orelse {
        std.debug.print("{s}\n", .{libelf.elf_errmsg(libelf.elf_errno)});
        unreachable;
    };
    const shdr: *ElfShdr(ei_class) = elf_getshdr(ei_class, scn) orelse {
        std.debug.print("{s}\n", .{libelf.elf_errmsg(libelf.elf_errno)});
        unreachable;
    };

    shdr.sh_name = 0;
    shdr.sh_type = libelf.SHT_PROGBITS;
    shdr.sh_flags = libelf.SHF_EXECINSTR | libelf.SHF_ALLOC;
    shdr.sh_offset = off;
    shdr.sh_size = 0x100;

    return scn;
}

fn get_scn_off_data(comptime ei_class: EI_CLASS, scn: *libelf.Elf_Scn, off: ElfOffset(ei_class)) ?*libelf.Elf_Data {
    const shdr: *ElfShdr(ei_class) = elf_getshdr(ei_class, scn) orelse {
        std.debug.print("{s}\n", .{libelf.elf_errmsg(libelf.elf_errno)});
        unreachable;
    };
    var curr_data: ?*libelf.Elf_Data = null;
    while (libelf.elf_getdata(scn, curr_data)) |data| : (curr_data = data) {
        if ((off > data.d_off + shdr.sh_addr) and (off < (data.d_off + shdr.sh_addr + data.d_size))) {
            return data;
        }
    }
    return null;
}

fn insert_patch(
    comptime ei_class: EI_CLASS,
    elf: *libelf.Elf,
    cs_handle: capstone.csh,
    ksh: ?*keystone.ks_engine,
    off: ElfOffset(ei_class),
    patch_data: []const u8,
    patch_block: []u8,
) !void {
    if (patch_data.len + JMP_BACK_SIZE + EXTRA_INSN_MAX_SIZE > patch_block.len) {
        unreachable;
    }
    // const phdr: *ElfPhdr(ei_class) = try get_offset_phdr(ei_class, elf, off);
    // std.debug.print("phdr = {*}\n", .{phdr});
    const scn: *libelf.Elf_Scn = get_off_scn(ei_class, elf, off) orelse make_off_scn(ei_class, elf, off);
    const off_data: *libelf.Elf_Data = get_scn_off_data(ei_class, scn, off).?;
    if (off_data.d_type != libelf.ELF_T_BYTE) {
        return Error.NotPatchingNotBytes;
    }
    const patch_target_data: []const u8 = @as([*]const u8, @ptrCast(off_data.d_buf.?))[0..off_data.d_size];
    const shdr = elf_getshdr(ei_class, scn).?;
    var insn: *capstone.cs_insn = undefined;
    var moved_size = 0; // the number of bytes to move to the jmp target.
    while (moved_size < JMP_PATCH_SIZE) {
        const curr_data = patch_target_data[off + moved_size - shdr.sh_offset - off_data.d_off ..];
        if (!capstone.cs_disasm_iter(
            cs_handle,
            @as([*]const u8, @ptrCast(curr_data)),
            &curr_data.len,
            0, // dont know the address, not sure it matters.
            &insn,
        )) {
            unreachable;
        }
        @memcpy(patch_block[patch_data.len + moved_size ..], curr_data[0..insn.size]);
        moved_size += insn.size;
    }
    @memcpy(patch_block, patch_data);
    const target: *libelf.Elf_Data = libelf.elf_newdata(scn).?;

    // const count = capstone.cs_disasm(
    //     cs_handle,
    //     @as([*]const u8, @ptrCast(curr_data[off - shdr.sh_offset ..])),
    //     off_data.d_size - (off - shdr.sh_offset),
    //     0,
    //     1,
    //     @as([*c][*c]capstone.cs_insn, @ptrCast(&insn)),
    // );
    // if (count > 0) {
    //     for (0..count) |j| {
    //         // std.debug.print("{}\n", .{insn[j]});
    //         std.debug.print("{} - {s} - {s}\n", .{ insn[j].address, insn[j].mnemonic[0..std.mem.indexOf(u8, &insn[j].mnemonic, &[1]u8{0}).?], insn[j].op_str[0..std.mem.indexOf(u8, &insn[j].op_str, &[1]u8{0}).?] });
    //     }
    //     capstone.cs_free(insn, count);
    // } else std.debug.print("ERROR: Failed to disassemble given code!\n", .{});

    const code = "jmp 5";
    var encode: ?[*]u8 = null;
    var siz: usize = undefined;
    var enc_count: usize = undefined;
    if (keystone.ks_asm(ksh, code, 0, &encode, &siz, &enc_count) != keystone.KS_ERR_OK) {
        std.debug.print("ERROR: ks_asm() failed & count = {}, error = {}\n", .{ enc_count, keystone.ks_errno(ksh) });
    }
    defer keystone.ks_free(encode);
    std.debug.print("{s} = {x}\n", .{ code, encode.?[0..siz] });
}

pub fn main() !u8 {
    var csh: capstone.csh = undefined;
    if (capstone.cs_open(capstone.CS_ARCH_X86, capstone.CS_MODE_64, &csh) != capstone.CS_ERR_OK) {
        return 1;
    }
    defer _ = capstone.cs_close(&csh);
    var ksh: ?*keystone.ks_engine = null;
    if (keystone.ks_open(keystone.KS_ARCH_X86, keystone.KS_MODE_32, &ksh) != keystone.KS_ERR_OK) {
        return 1;
    }
    defer _ = keystone.ks_close(ksh);
    const stdout = std.io.getStdOut().writer();
    var args = std.process.args();
    _ = args.next().?;
    const arg = args.next() orelse {
        try stdout.print("must provide a file\n", .{});
        return 1;
    };
    var f = try std.fs.cwd().openFile(arg, .{ .mode = .read_only });
    defer f.close();

    if (libelf.elf_version(libelf.EV_CURRENT) == libelf.EV_NONE) {
        try stdout.print("version mismatch between header and library\nheader version = {}, library version = {}", .{ libelf.EV_CURRENT, libelf.elf_version(libelf.EV_NONE) });
    }
    const elf = libelf.elf_begin(f.handle, libelf.ELF_C_READ, null) orelse {
        std.debug.print("{s}\n", .{libelf.elf_errmsg(libelf.elf_errno())});
        return Error.BeginFailed;
    };
    defer if (libelf.elf_end(elf) != 0) {
        unreachable;
    };
    const kind = libelf.elf_kind(elf);
    if (kind != libelf.ELF_K_ELF) {
        return 1;
    }
    const test_patch = "test";
    var dst: usize = undefined;
    const c_ident: [*]const u8 = libelf.elf_getident(elf, &dst) orelse {
        std.debug.print("{s}\n", .{libelf.elf_errmsg(libelf.elf_errno())});
        return Error.BeginFailed;
    };
    const ident: []const u8 = c_ident[0..dst];
    const ei_class: EI_CLASS = @enumFromInt(ident[4]);
    try switch (ei_class) {
        .ELFCLASS32 => insert_patch(EI_CLASS.ELFCLASS32, elf, csh, ksh, 0x37e0b, test_patch),
        .ELFCLASS64 => insert_patch(EI_CLASS.ELFCLASS64, elf, csh, ksh, 0x37e0b, test_patch),
    };
    return 0;
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
