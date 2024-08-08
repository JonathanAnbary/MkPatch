const std = @import("std");
// const libelf = @import("../translated-include/libelf/libelf.zig");
// const capstone = @import("../translated-include/capstone-5.0/capstone/capstone.zig");
// const keystone = @import("../translated-include/keystone/keystone.zig");
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
fn ElfAddr(comptime ei_class: EI_CLASS) type {
    return switch (ei_class) {
        .ELFCLASS32 => libelf.Elf32_Addr,
        .ELFCLASS64 => libelf.Elf64_Addr,
    };
}

fn ElfOff(comptime ei_class: EI_CLASS) type {
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

fn get_off_phdr(comptime ei_class: EI_CLASS, elf: *libelf.Elf, off: ElfOff(ei_class)) ?*ElfPhdr(ei_class) {
    const temp: [*]ElfPhdr(ei_class) = elf_getphdr(ei_class, elf).?;
    var phdr_num: usize = undefined;
    if (libelf.elf_getphdrnum(elf, &phdr_num) == -1) {
        unreachable;
    }
    const phdr_table: []ElfPhdr(ei_class) = temp[0..phdr_num];
    for (phdr_table) |*phdr| {
        if (off < (phdr.p_offset + phdr.p_filesz)) {
            return phdr;
        }
    }
    return null;
}

fn get_off_scn(comptime ei_class: EI_CLASS, elf: *libelf.Elf, off: ElfOff(ei_class)) ?*libelf.Elf_Scn {
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

fn make_off_scn(comptime ei_class: EI_CLASS, elf: *libelf.Elf, off: ElfOff(ei_class)) *libelf.Elf_Scn {
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

fn get_scn_off_data(comptime ei_class: EI_CLASS, scn: *libelf.Elf_Scn, off: ElfOff(ei_class)) ?*libelf.Elf_Data {
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

const SegProximity: type = struct {
    seg_idx: u16,
    is_end: bool,
};

fn get_addr(seg_idx: u32, is_end: bool, ei_class: EI_CLASS, phdr_table: []ElfPhdr(ei_class)) u64 {
    if (is_end) {
        return phdr_table[seg_idx].p_offset + phdr_table[seg_idx].p_filesz;
    }
    return phdr_table[seg_idx].p_offset;
}

fn get_off(seg_idx: u32, is_end: bool, ei_class: EI_CLASS, phdr_table: []ElfPhdr(ei_class)) u64 {
    if (is_end) {
        return phdr_table[seg_idx].p_offset + phdr_table[seg_idx].p_filesz;
    }
    return phdr_table[seg_idx].p_offset;
}

fn get_gap_size(seg_prox: SegProximity, ei_class: EI_CLASS, phdr_table: []ElfPhdr(ei_class)) u64 {
    const start: u64 = blk: {
        if (seg_prox.is_end) {
            break :blk get_off(seg_prox, ei_class, phdr_table);
        } else if (seg_prox.seg_idx != 0) {
            break :blk get_off(SegProximity{ .seg_idx = seg_prox.seg_idx - 1, .is_end = true }, ei_class, phdr_table);
        } else {
            break :blk 0;
        }
    };
    const end: u64 = blk: {
        if (!seg_prox.is_end) {
            break :blk get_off(seg_prox, ei_class, phdr_table);
        } else if (seg_prox.seg_idx != (phdr_table.len - 1)) {
            break :blk get_off(SegProximity{ .seg_idx = seg_prox.seg_idx + 1, .is_end = false }, ei_class, phdr_table);
        } else {
            break :blk std.math.maxInt(u64);
        }
    };
    return end - start;
}

fn find(start: u32, end: u32, jump: i32, comptime ei_class: EI_CLASS, phdr_table: []ElfPhdr(ei_class), comptime cond: fn (phdr: ElfPhdr(ei_class)) bool) ?u32 {
    std.debug.assert(jump != 0);
    std.debug.assert((start < end) == (jump > 0));
    var i: u32 = start;
    while (i != end) : (i = @as(u32, @intCast(@as(i64, @intCast(i)) + jump))) {
        if (cond(phdr_table[i])) {
            return i;
        }
    }
    return null;
}

fn gen_is_load(comptime ei_class: EI_CLASS) fn (phdr: ElfPhdr(ei_class)) bool {
    return struct {
        fn is_load(phdr: ElfPhdr(ei_class)) bool {
            std.debug.print("(phdr.p_type == libelf.PT_LOAD) = {}\n(phdr.p_flags & (libelf.pf_r | libelf.pf_x) != 0) = {}\n", .{ (phdr.p_type == libelf.PT_LOAD), (phdr.p_type == libelf.PT_LOAD) });
            return ((phdr.p_type == libelf.PT_LOAD) and (phdr.p_flags & (libelf.PF_R | libelf.PF_X) != 0));
        }
    }.is_load;
}

// fn get_proximity_seg(ei_class: EI_CLASS, phdr_table: []ElfPhdr(ei_class), wanted_addr_prox: u64) SegProximity {
//     var curr: u32 = find(0, phdr_table.len - 1, 1, ei_class, phdr_table, is_load).?;
//     if (curr == phdr_table.len - 1) {
//         return SegProximity{.seg_idx = curr, .is_end = (wanted_addr_prox > (phdr_table[curr].p_vaddr + (phdr_table[curr].p_memsz >> 2))),};
//     }
//     var maybe_next: ?u32 = find(seg_idx + 1, phdr_table.len - 1, 1, ei_class,phdr_table, is_load);
//     while (maybe_next) |next| : (maybe_next = find(curr.seg_idx + 1, phdr_table.len - 1, 1, ei_class,phdr_table, is_load)) {
//         if (wanted_addr_prox < ((get_addr(curr, true) + get_addr(next, false) ) >> 2)) {
//             return SegProximity{.seg_idx = curr, .is_end = (wanted_addr_prox > (phdr_table[curr].p_vaddr + (phdr_table[curr].p_memsz >> 2))),};
//         }
//         curr = next;
//     }
//     return SegProximity{.seg_idx = curr, .is_end = true,};
// }
//
// fn get_lower(seg_prox: SegProximity) ?SegProximity {
//     if (seg_prox.is_end) {
//         return SegProximity{ .seg_idx = seg_prox.seg_idx, .is_end = false };
//     } else if (seg_prox.seg_idx == 0) {
//         return null;
//     }
//     return SegProximity{ .seg_idx = seg_prox.seg_idx - 1, .is_end = true };
// }
//
// fn get_higher(seg_prox: SegProximity, lim: u16) ?SegProximity {
//     if (!seg_prox.is_end) {
//         return SegProximity{ .seg_idx = seg_prox.seg_idx, .is_end = true };
//     } else if (seg_prox.seg_idx == lim) {
//         return null;
//     }
//     return SegProximity{ .seg_idx = seg_prox.seg_idx + 1, .is_end = false };
// }

// fn get_closest_gap(ei_class: EI_CLASS, phdr_table: []ElfPhdr, wanted_proximity: u64) SegProximity{
//     const prox_seg: SegProximity = get_proximity_seg(ei_class, phdr_table, wanted_proximity);
//     var high_seg: SegProximity = prox_seg;
//     var low_seg: SegProximity = prox_seg;
//     var close_seg: SegProximity = prox_seg;
//     while (wanted_size > get_gap_size(close_seg, ei_class, phdr_table)) {
//         const lower_seg = get_lower(low_seg);
//         const higher_seg = get_higher(high_seg, phdr_table.len - 1);
//         if (!lower_seg and !higher_seg) {
//             return null;
//         } else if (!lower_seg) {
//             close_seg = higher_seg;
//             high_seg = higher_seg;
//         } else if (!higher_seg) {
//             close_seg = lower_seg;
//             low_seg = lower_seg;
//         } else {
//             const low_vaddr = get_addr(lower_seg, ei_class, phdr_table);
//             const high_vaddr = get_addr(high_seg, ei_class, phdr_table);
//             if (wanted_proximity < ((low_vaddr + high_vaddr) >> 2)) {
//                 close_seg = lower_seg;
//                 low_seg = lower_seg;
//             } else {
//                 close_seg = higher_seg;
//                 high_seg = higher_seg;
//             }
//         }
//     }
// }

const BlockInfo: type = struct {
    block: *libelf.Elf_Data,
    addr: u64,
};

fn adjust_segs(comptime ei_class: EI_CLASS, phdr_table: []ElfPhdr(ei_class), amount: ElfOff(ei_class)) void {
    for (phdr_table) |*phdr| {
        phdr.p_offset += amount;
    }
}

fn adjust_secs_after(comptime ei_class: EI_CLASS, elf: *libelf.Elf, after: u64, amount: ElfOff(ei_class)) void {
    var shdrnum: usize = undefined;
    if (libelf.elf_getshdrnum(elf, &shdrnum) == -1) {
        unreachable;
    }
    for (0..shdrnum) |i| {
        const scn: *libelf.Elf_Scn = libelf.elf_getscn(elf, i).?;
        var shdr: *ElfShdr(ei_class) = elf_getshdr(ei_class, scn).?;
        if (shdr.sh_offset > after) {
            shdr.sh_offset += amount;
        }
    }
}

fn get_last_mem_seg(comptime ei_class: EI_CLASS, phdr_table: []ElfPhdr(ei_class)) ?u16 {
    var max: u16 = @intCast(find(0, @as(u32, @intCast(phdr_table.len - 1)), 1, ei_class, phdr_table, gen_is_load(ei_class)) orelse return null);
    if (max == phdr_table.len - 1) return max;
    for (max + 1..phdr_table.len) |i| {
        if ((gen_is_load(ei_class)(phdr_table[i])) and (phdr_table[i].p_vaddr > phdr_table[max].p_vaddr)) {
            max = @intCast(i);
        }
    }
    return max;
}

fn elf_newphdr(comptime ei_class: EI_CLASS, elf: *libelf.Elf, count: u16) ?[*]ElfPhdr(ei_class) {
    return switch (ei_class) {
        inline .ELFCLASS32 => libelf.elf32_newphdr(elf, count),
        inline .ELFCLASS64 => libelf.elf64_newphdr(elf, count),
    };
}

fn get_patch_block_buffer(comptime ei_class: EI_CLASS, elf: *libelf.Elf, wanted_size: ElfOff(ei_class)) ?BlockInfo {
    var phdr_num: usize = undefined;
    if (libelf.elf_getphdrnum(elf, &phdr_num) == -1) {
        unreachable;
    }
    const prev_phdr_table: []ElfPhdr(ei_class) = elf_getphdr(ei_class, elf).?[0..phdr_num];
    const first_phdr = prev_phdr_table[0];
    std.debug.print("prev_phdr_table[0] = {}\n", .{prev_phdr_table[0]});
    const last_mem_seg_idx: u16 = get_last_mem_seg(ei_class, prev_phdr_table).?;
    const phdr_table: []ElfPhdr(ei_class) = elf_newphdr(ei_class, elf, @intCast(phdr_num + 1)).?[0 .. phdr_num + 1];
    std.mem.copyBackwards(ElfPhdr(ei_class), phdr_table[1..], prev_phdr_table[1..]);
    phdr_table[0] = first_phdr;
    std.debug.print("phdr_table[0] = {}\n", .{phdr_table[0]});
    const new_mem_seg_idx: u16 = @intCast(phdr_num);

    std.debug.print("last_mem_seg_idx = {}\n", .{last_mem_seg_idx});
    std.debug.print("phdr = {}\n", .{phdr_table[last_mem_seg_idx]});

    phdr_table[new_mem_seg_idx].p_type = libelf.PT_LOAD;
    phdr_table[new_mem_seg_idx].p_flags = libelf.PF_X | libelf.PF_R;
    phdr_table[new_mem_seg_idx].p_align = 0x1000;
    phdr_table[new_mem_seg_idx].p_filesz = wanted_size;
    phdr_table[new_mem_seg_idx].p_offset = phdr_table[phdr_num - 1].p_offset + phdr_table[phdr_num - 1].p_filesz;
    phdr_table[new_mem_seg_idx].p_vaddr = phdr_table[last_mem_seg_idx].p_vaddr + phdr_table[last_mem_seg_idx].p_memsz;
    phdr_table[new_mem_seg_idx].p_paddr = phdr_table[last_mem_seg_idx].p_paddr + phdr_table[last_mem_seg_idx].p_memsz;
    phdr_table[new_mem_seg_idx].p_memsz = phdr_table[new_mem_seg_idx].p_filesz + phdr_table[new_mem_seg_idx].p_align - (phdr_table[new_mem_seg_idx].p_filesz % phdr_table[new_mem_seg_idx].p_align);

    const new_data_off = phdr_table[new_mem_seg_idx].p_offset;
    const new_data_addr = phdr_table[last_mem_seg_idx].p_vaddr;

    std.debug.print("new_data_off = {x}\nnew_data_addr = {x}\n", .{ new_data_off, new_data_addr });

    // again I am assuming that segments are sequential.
    // adjust_segs(ei_class, phdr_table[last_mem_seg_idx + 1 ..], wanted_size);
    // adjust_secs_after(ei_class, elf, new_data_off, wanted_size);

    const scn = libelf.elf_newscn(elf).?;

    var d: *libelf.Elf_Data = libelf.elf_newdata(scn).?;
    d.d_align = 8;
    d.d_off = 0;
    d.d_buf = null;
    d.d_type = libelf.ELF_T_BYTE;
    d.d_size = wanted_size;
    d.d_version = libelf.EV_CURRENT;

    var shdr: *ElfShdr(ei_class) = elf_getshdr(ei_class, scn).?;
    shdr.sh_name = 0;
    shdr.sh_type = libelf.SHT_PROGBITS;
    shdr.sh_addr = new_data_addr;
    shdr.sh_offset = new_data_off;
    shdr.sh_flags = libelf.SHF_ALLOC;
    shdr.sh_size = 0;

    std.debug.print("new section loc = {x}\n", .{new_data_off});
    std.debug.print("new section size = {}\n", .{wanted_size});

    return BlockInfo{ .block = d, .addr = new_data_addr };
}

fn off_to_addr(comptime ei_class: EI_CLASS, elf: *libelf.Elf, off: ElfOff(ei_class)) ?ElfAddr(ei_class) {
    const phdr = get_off_phdr(ei_class, elf, off) orelse return null;
    return off - phdr.p_offset + phdr.p_vaddr;
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
    off: ElfOff(ei_class),
    patch_data: []const u8,
    patch_block: []u8,
) !void {
    if (patch_data.len + JMP_BACK_SIZE + EXTRA_INSN_MAX_SIZE > patch_block.len) {
        unreachable;
    }
    const addr: ElfAddr(ei_class) = off_to_addr(ei_class, elf, off).?;
    const scn: *libelf.Elf_Scn = get_off_scn(ei_class, elf, off) orelse make_off_scn(ei_class, elf, off);
    const off_data: *libelf.Elf_Data = get_scn_off_data(ei_class, scn, off).?;
    if (off_data.d_type != libelf.ELF_T_BYTE) {
        unreachable;
    }
    const shdr = elf_getshdr(ei_class, scn).?;
    const patch_sec_off: ElfOff(ei_class) = off - shdr.sh_offset;
    var patch_loc_data: []u8 = @as([*]u8, @ptrCast(off_data.d_buf.?))[patch_sec_off - @as(u64, @intCast(off_data.d_off)) .. off_data.d_size];
    const insn: *capstone.cs_insn = capstone.cs_malloc(cs_handle);
    defer capstone.cs_free(insn, 1);
    var curr_code = patch_loc_data;
    var curr_size = patch_loc_data.len - (off - shdr.sh_offset - @as(u64, @intCast(off_data.d_off)));
    var patch_end_off: u64 = patch_sec_off;
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
    const moved_insn_size: ElfOff(ei_class) = @as(u32, @intCast(patch_end_off)) - patch_sec_off;
    var elf_patch_block_data = get_patch_block_buffer(ei_class, elf, @as(u32, @intCast(patch_data.len)) + moved_insn_size + JMP_BACK_SIZE).?;
    elf_patch_block_data.block.d_buf = @ptrCast(patch_block);
    @memcpy(patch_block[0..patch_data.len], patch_data);
    @memcpy(patch_block[patch_data.len .. patch_data.len + moved_insn_size], patch_loc_data[0..moved_insn_size]);

    var encode: ?[*]u8 = null;
    var siz: usize = undefined;
    var enc_count: usize = undefined;
    var jmp_far_buf: [JMP_FAR_ASM_SIZE]u8 = undefined;
    const jmp_to_patch = try std.fmt.bufPrintZ(&jmp_far_buf, "jmp {};", .{elf_patch_block_data.addr - addr});
    {
        if (keystone.ks_asm(ksh, @as(?[*]const u8, @ptrCast(jmp_to_patch)), 0, &encode, &siz, &enc_count) != keystone.KS_ERR_OK) {
            std.debug.print("ERROR: ks_asm() failed & count = {}, error = {}\n", .{ enc_count, keystone.ks_errno(ksh) });
            unreachable;
        }
        defer keystone.ks_free(encode);
        std.debug.print("jmp_to_patch ({s}) = {x}\n", .{ jmp_to_patch, encode.?[0..siz] });
        @memcpy(patch_loc_data[0..siz], encode.?[0..siz]);
    }

    const jmp_back_insn_addr = elf_patch_block_data.addr + patch_data.len + moved_insn_size;
    const jmp_back_target_addr = addr + moved_insn_size;

    std.debug.print("jmp_back_addr = {x}\naddr = {x}\nmoved_insn_size = {x}\n", .{ jmp_back_insn_addr, addr, moved_insn_size });
    const jmp_back = try std.fmt.bufPrintZ(&jmp_far_buf, "jmp {};", .{@as(i128, @intCast(jmp_back_target_addr)) - jmp_back_insn_addr});
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
    const test_patch = "\x90" ** 10;
    var dst: usize = undefined;
    const c_ident: [*]const u8 = libelf.elf_getident(elf, &dst) orelse {
        std.debug.print("{s}\n", .{libelf.elf_errmsg(libelf.elf_errno())});
        return Error.BeginFailed;
    };
    const ident: []const u8 = c_ident[0..dst];
    const ei_class: EI_CLASS = @enumFromInt(ident[4]);
    var patch_buff: [test_patch.len + 50]u8 = undefined;
    try switch (ei_class) {
        .ELFCLASS32 => insert_patch(EI_CLASS.ELFCLASS32, elf, csh, ksh, 0x6c1f9a, test_patch, &patch_buff),
        .ELFCLASS64 => insert_patch(EI_CLASS.ELFCLASS64, elf, csh, ksh, 0x6c1f9a, test_patch, &patch_buff),
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
