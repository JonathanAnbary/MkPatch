const std = @import("std");

const config = @import("config");

pub fn should_add_test(gen_test_name: []const u8) bool {
    if (config.test_filters.len == 0) return true;
    @setEvalBranchQuota(5000);
    var add = false;
    for (config.test_filters) |filter| {
        if (std.mem.indexOf(u8, gen_test_name, filter) != null) {
            add = true;
            break;
        }
    }
    return add;
}

pub fn Index(T: type) type {
    return enum(u16) {
        _,

        const Self = @This();

        pub fn get(self: Self, items: [*]T) *T {
            return &items[@intFromEnum(self)];
        }

        pub fn next(self: Self) Self {
            return @enumFromInt(@intFromEnum(self) + 1);
        }

        pub fn prev(self: Self) Self {
            return @enumFromInt(@intFromEnum(self) - 1);
        }
    };
}

// The permissions that exist on a range of data in a file.
pub const FileRangeFlags: type = packed struct {
    read: bool = false,
    write: bool = false,
    execute: bool = false,
};

pub const ShiftError = error{
    StartAfterEnd,
    UnexpectedEof,
};

pub fn shift_forward(stream: anytype, io: std.Io, start: u64, end: u64, amt: u64) !void {
    if ((start == end) or (amt == 0)) return;
    if (start > end) return ShiftError.StartAfterEnd;
    var buff: [1024]u8 = undefined;
    var rw_buffer: [4096]u8 = undefined;

    const shift_start: u64 = blk: {
        if (end < (start + amt)) {
            const stat = try stream.stat(io);
            const temp = stat.size;
            if ((start + amt) > temp) {
                var writer = stream.writer(io, &rw_buffer);
                try writer.seekTo(temp);
                // Write zeros to extend the file
                const zeros_to_write = start + amt - temp;
                var remaining = zeros_to_write;
                const zero_buff = [_]u8{0} ** 128;
                while (remaining > 0) {
                    const to_write = @min(remaining, zero_buff.len);
                    const zero_vec = [_][]const u8{zero_buff[0..to_write]};
                    _ = try writer.interface.writeVec(&zero_vec);
                    remaining -= to_write;
                }
            }
            break :blk start;
        } else break :blk end - amt;
    };

    var pos = shift_start;
    while ((pos + buff.len) < end) : (pos += buff.len) {
        {
            var reader = stream.reader(io, &rw_buffer);
            try reader.seekTo(pos);
            var buff_vec = [_][]u8{&buff};
            if (try reader.interface.readVec(&buff_vec) != buff.len) return ShiftError.UnexpectedEof;
        }
        {
            var writer = stream.writer(io, &rw_buffer);
            try writer.seekTo(pos + amt);
            const buff_vec = [_][]const u8{&buff};
            if (try writer.interface.writeVec(&buff_vec) != buff.len) return ShiftError.UnexpectedEof;
        }
    }

    {
        var reader = stream.reader(io, &rw_buffer);
        try reader.seekTo(pos);
        var buff_vec = [_][]u8{buff[0 .. end - pos]};
        if (try reader.interface.readVec(&buff_vec) != end - pos) return ShiftError.UnexpectedEof;
    }
    {
        var writer = stream.writer(io, &rw_buffer);
        try writer.seekTo(pos + amt);
        const buff_vec = [_][]const u8{buff[0 .. end - pos]};
        if (try writer.interface.writeVec(&buff_vec) != end - pos) return ShiftError.UnexpectedEof;
    }

    pos = shift_start;
    while (pos > (start + buff.len)) : (pos -= buff.len) {
        {
            var reader = stream.reader(io, &rw_buffer);
            try reader.seekTo(pos - buff.len);
            var buff_vec = [_][]u8{&buff};
            if (try reader.interface.readVec(&buff_vec) != buff.len) return ShiftError.UnexpectedEof;
        }
        {
            var writer = stream.writer(io, &rw_buffer);
            try writer.seekTo(pos - buff.len + amt);
            const buff_vec = [_][]const u8{&buff};
            if (try writer.interface.writeVec(&buff_vec) != buff.len) return ShiftError.UnexpectedEof;
        }
    }

    {
        var reader = stream.reader(io, &rw_buffer);
        try reader.seekTo(start);
        var buff_vec = [_][]u8{buff[0 .. pos - start]};
        if (try reader.interface.readVec(&buff_vec) != pos - start) return ShiftError.UnexpectedEof;
    }
    {
        var writer = stream.writer(io, &rw_buffer);
        try writer.seekTo(start + amt);
        const buff_vec = [_][]const u8{buff[0 .. pos - start]};
        if (try writer.interface.writeVec(&buff_vec) != pos - start) return ShiftError.UnexpectedEof;
    }
}

test "test shift stream" {
    const start = 0;
    const end = 10;
    const shift = 3;
    var buf = "abcdefghijklmnopqrstuvwxyz".*;
    var expected = "abcabcdefghijnopqrstuvwxyz".*;
    @memcpy(expected[start + shift .. end + shift], buf[start..end]);
    var stream = std.io.fixedBufferStream(&buf);
    try shift_forward(&stream, start, end, shift);
    try std.testing.expectEqualStrings(&expected, &buf);
    const start2 = 0;
    const end2 = 4432;
    const shift2 = 1543;
    var buf2 = [1]u8{'A'} ** 1024 ++ "\n".* ++ [1]u8{'B'} ** 1024 ++ "\n".* ++ [1]u8{'C'} ** 1024 ++ "\n".* ++ [1]u8{'D'} ** 1024 ++ "\n".* ++ [1]u8{'E'} ** 1024 ++ "\n".* ++ [1]u8{'F'} ** 1024 ++ "\n".*;
    var expected2 = [1]u8{'A'} ** 1024 ++ "\n".* ++ [1]u8{'B'} ** 1024 ++ "\n".* ++ [1]u8{'C'} ** 1024 ++ "\n".* ++ [1]u8{'D'} ** 1024 ++ "\n".* ++ [1]u8{'E'} ** 1024 ++ "\n".* ++ [1]u8{'F'} ** 1024 ++ "\n".*;
    @memcpy(expected2[start2 + shift2 .. end2 + shift2], buf2[start2..end2]);
    var stream2 = std.io.fixedBufferStream(&buf2);
    try shift_forward(&stream2, start2, end2, shift2);
    try std.testing.expectEqualStrings(&expected2, &buf2);
}

pub fn align_ceil(T: type, num: T, alignm: T) T {
    return if ((num % alignm) != 0) num - (num % alignm) + alignm else num;
}
