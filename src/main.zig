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
            unreachable;
        };
        if ((off > parsed_shdr.sh_offset) and (off < (parsed_shdr.sh_offset + parsed_shdr.sh_size))) {
            return scn;
        }
    }
    return null;
}

fn make_off_scn(comptime ei_class: EI_CLASS, elf: *libelf.Elf, off: ElfOffset(ei_class)) *libelf.Elf_Scn {
    const scn: *libelf.Elf_Scn = libelf.elf_newscn(elf) orelse {
        std.debug.print("{s}\n", .{libelf.elf_errmsg(libelf.elf_errno())});
        unreachable;
    };
    const shdr: *ElfShdr(ei_class) = elf_getshdr(ei_class, scn) orelse {
        std.debug.print("{s}\n", .{libelf.elf_errmsg(libelf.elf_errno())});
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
        std.debug.print("{s}\n", .{libelf.elf_errmsg(libelf.elf_errno())});
        unreachable;
    };
    var curr_data: ?*libelf.Elf_Data = null;
    while (@as(?*libelf.Elf_Data, @ptrCast(libelf.elf_getdata(scn, curr_data)))) |data| : (curr_data = data) {
        if ((off > data.d_off + @as(isize, @intCast(shdr.sh_offset))) and
            (off < (data.d_off + @as(isize, @intCast(shdr.sh_offset)) + @as(isize, @intCast(data.d_size)))))
        {
            return data;
        }
    }
    return null;
}

const JMP_BACK_SIZE = 10;
const EXTRA_INSN_MAX_SIZE = 10;
const JMP_PATCH_SIZE = 10;
const JMP_FAR_ASM_SIZE = 20;

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
    const phdr: *ElfPhdr(ei_class) = try get_offset_phdr(ei_class, elf, off);
    std.debug.print("phdr = {}\n", .{phdr});
    phdr.p_filesz += @as(u32, @intCast(patch_block.len));
    phdr.p_memsz += @as(u32, @intCast(patch_block.len));

    const scn: *libelf.Elf_Scn = get_off_scn(ei_class, elf, off) orelse make_off_scn(ei_class, elf, off);
    const off_data: *libelf.Elf_Data = get_scn_off_data(ei_class, scn, off).?;
    if (off_data.d_type != libelf.ELF_T_BYTE) {
        unreachable;
    }
    const shdr = elf_getshdr(ei_class, scn).?;
    const patch_sec_off: usize = off - shdr.sh_offset;
    var patch_target_data: []u8 = @as([*]u8, @ptrCast(off_data.d_buf.?))[patch_sec_off - @as(u64, @intCast(off_data.d_off)) .. off_data.d_size];
    const insn: *capstone.cs_insn = capstone.cs_malloc(cs_handle);
    defer capstone.cs_free(insn, 1);
    var curr_code = patch_target_data;
    var curr_size = patch_target_data[off - shdr.sh_offset - @as(u64, @intCast(off_data.d_off)) ..].len;
    var patch_end_off = patch_sec_off;
    while ((patch_end_off - patch_sec_off) < JMP_PATCH_SIZE) {
        if (!capstone.cs_disasm_iter(
            cs_handle,
            @as([*c][*c]const u8, @ptrCast(&curr_code)),
            &curr_size,
            &patch_end_off,
            insn,
        )) {
            unreachable;
        }
    }
    const moved_insn_size = patch_end_off - patch_sec_off;
    @memcpy(patch_block[0..patch_data.len], patch_data);
    @memcpy(patch_block[patch_data.len .. patch_data.len + moved_insn_size], patch_target_data[0..moved_insn_size]);
    const target_elf_data: *libelf.Elf_Data = libelf.elf_newdata(scn).?;
    var prev_elf_data: *libelf.Elf_Data = off_data;
    while (libelf.elf_getdata(scn, prev_elf_data)) |next_data| {
        if (next_data == target_elf_data) {
            break;
        }
        prev_elf_data = next_data;
    }
    target_elf_data.d_buf = @ptrCast(patch_block);
    target_elf_data.d_size = patch_block.len;
    target_elf_data.d_off = prev_elf_data.d_off + @as(isize, @intCast(prev_elf_data.d_size));
    std.debug.print("new section loc = {x}\n", .{target_elf_data.d_off + @as(isize, @intCast(shdr.sh_offset))});
    std.debug.print("new section size = {}\n", .{target_elf_data.d_size});

    var encode: ?[*]u8 = null;
    var siz: usize = undefined;
    var enc_count: usize = undefined;
    var jmp_far_buf: [JMP_FAR_ASM_SIZE]u8 = undefined;
    const jmp_to_patch = try std.fmt.bufPrintZ(&jmp_far_buf, "jmp {};", .{target_elf_data.d_off - @as(isize, @intCast(patch_sec_off))});

    {
        if (keystone.ks_asm(ksh, @as(?[*]const u8, @ptrCast(jmp_to_patch)), 0, &encode, &siz, &enc_count) != keystone.KS_ERR_OK) {
            std.debug.print("ERROR: ks_asm() failed & count = {}, error = {}\n", .{ enc_count, keystone.ks_errno(ksh) });
            unreachable;
        }
        defer keystone.ks_free(encode);
        std.debug.print("jmp_to_patch ({s}) = {x}\n", .{ jmp_to_patch, encode.?[0..siz] });
        @memcpy(patch_target_data[0..siz], encode.?[0..siz]);
    }

    const patch_block_end_off = target_elf_data.d_off + @as(isize, @intCast(patch_data.len)) + @as(isize, @intCast(moved_insn_size));

    const jmp_back = try std.fmt.bufPrintZ(&jmp_far_buf, "jmp {};", .{@as(isize, @intCast(patch_sec_off)) + @as(isize, @intCast(moved_insn_size)) - patch_block_end_off});
    std.debug.print("code_jmp_back = {s}\n", .{jmp_back});
    // const temp = "jmp -763279;";
    if (keystone.ks_asm(ksh, @as(?[*]const u8, @ptrCast(jmp_back)), 0, &encode, &siz, &enc_count) != keystone.KS_ERR_OK) {
        std.debug.print("ERROR: ks_asm() failed & count = {}, error = {}\n", .{ enc_count, keystone.ks_errno(ksh) });
        unreachable;
    }
    defer keystone.ks_free(encode);
    std.debug.print("jmp_to_patch ({s}) = {x}\n", .{ jmp_back, encode.?[0..siz] });
    @memcpy(patch_block[patch_data.len + moved_insn_size .. patch_data.len + moved_insn_size + siz], encode.?[0..siz]);
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
    var f = try std.fs.cwd().openFile(arg, .{ .mode = .read_write });
    defer f.close();

    if (libelf.elf_version(libelf.EV_CURRENT) == libelf.EV_NONE) {
        try stdout.print("version mismatch between header and library\nheader version = {}, library version = {}", .{ libelf.EV_CURRENT, libelf.elf_version(libelf.EV_NONE) });
    }
    const elf = libelf.elf_begin(f.handle, libelf.ELF_C_RDWR, null) orelse {
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
    const test_patch = "test" ** 1000;
    var dst: usize = undefined;
    const c_ident: [*]const u8 = libelf.elf_getident(elf, &dst) orelse {
        std.debug.print("{s}\n", .{libelf.elf_errmsg(libelf.elf_errno())});
        return Error.BeginFailed;
    };
    const ident: []const u8 = c_ident[0..dst];
    const ei_class: EI_CLASS = @enumFromInt(ident[4]);
    var patch_buff: [test_patch.len + 50]u8 = undefined;
    try switch (ei_class) {
        .ELFCLASS32 => insert_patch(EI_CLASS.ELFCLASS32, elf, csh, ksh, 0x37e0b, test_patch, &patch_buff),
        .ELFCLASS64 => insert_patch(EI_CLASS.ELFCLASS64, elf, csh, ksh, 0x37e0b, test_patch, &patch_buff),
    };
    const temp = libelf.elf_update(elf, libelf.ELF_C_WRITE);
    std.debug.print("image size = {}\n", .{temp});
    return 0;
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
