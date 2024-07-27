const std = @import("std");
const libelf = @cImport(@cInclude("libelf.h"));
const capstone = @cImport(@cInclude("capstone/capstone.h"));

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
fn get_offset_scn(comptime ei_class: EI_CLASS, elf: *libelf.Elf, off: ElfOffset(ei_class)) ?*libelf.Elf_Scn {
    var curr_scn: ?*libelf.Elf_Scn = null;
    while (libelf.elf_nextscn(elf, curr_scn)) |scn| : (curr_scn = scn) {
        const parsed_shdr = elf_getshdr(ei_class, scn).?;
        if ((off > parsed_shdr.sh_offset) and (off < (parsed_shdr.sh_offset + parsed_shdr.sh_size))) {
            std.debug.print("parsed_shdr = {}", .{parsed_shdr});
            return scn;
        }
    }
    return null;
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

fn insert_patch(comptime ei_class: EI_CLASS, elf: *libelf.Elf, cs_handle: capstone.csh, off: ElfOffset(ei_class), patch: []const u8) !void {
    _ = patch;
    // const phdr: *ElfPhdr(ei_class) = try get_offset_phdr(ei_class, elf, off);
    // std.debug.print("phdr = {*}\n", .{phdr});
    const scn: *libelf.Elf_Scn = get_offset_scn(ei_class, elf, off).?;
    std.debug.print("scn = {}\n", .{scn});
    std.debug.print("index = {}\n", .{libelf.elf_ndxscn(scn)});
    const elf_data: *libelf.Elf_Data = libelf.elf_getdata(scn, null).?;
    std.debug.print("{}\n", .{elf_data});
    std.debug.print("ELF_T_BYTE = {}\n", .{libelf.ELF_T_BYTE});
    if (elf_data.d_type != libelf.ELF_T_BYTE) {
        return Error.NotPatchingNotBytes;
    }
    // std.debug.print("d_buf = {}\n", .{elf_data.d_buf.?});
    const sec_data: []const u8 = @as([*]const u8, @ptrCast(elf_data.d_buf.?))[0..elf_data.d_size];
    std.debug.print("{x}\n", .{sec_data[0..10]});
    const parsed_shdr = elf_getshdr(ei_class, scn).?;
    std.debug.print("parsed_shdr.sh_offset - {x}\n", .{parsed_shdr.sh_offset});
    std.debug.print("off - {x}\n", .{off});
    std.debug.print("{x}\n", .{off - parsed_shdr.sh_offset});
    std.debug.print("{x}\n", .{sec_data[off - parsed_shdr.sh_offset .. 10 + off - parsed_shdr.sh_offset]});
    std.debug.print("", .{});
    const insn: [*][*]capstone.cs_insn = undefined;
    const count = capstone.cs_disasm(cs_handle, @as([*]const u8, @ptrCast(sec_data)), elf_data.d_size, 0x1000, 10, insn);

    if (count > 0) {
        for (0..count) |j| {
            std.debug.print("{} - {} - {}\n", .{ insn[j].address, insn[j].mnemonic, insn[j].op_str });
        }
        capstone.cs_free(insn, count);
    } else std.debug.print("ERROR: Failed to disassemble given code!\n");
}

pub fn main() !u8 {
    var handle: capstone.csh = undefined;
    if (capstone.cs_open(capstone.CS_ARCH_X86, capstone.CS_MODE_64, &handle) != capstone.CS_ERR_OK) {
        return 1;
    }
    defer _ = capstone.cs_close(&handle);
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
        .ELFCLASS32 => insert_patch(EI_CLASS.ELFCLASS32, elf, handle, 0x37db0, test_patch),
        .ELFCLASS64 => insert_patch(EI_CLASS.ELFCLASS64, elf, handle, 0x37db0, test_patch),
    };
    return 0;
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
