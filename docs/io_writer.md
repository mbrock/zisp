# Introducing `std.Io.Writer`

Zig's new `std.Io.Writer` interface replaces the old generic writers. The buffer now lives
in the interface, providing a concrete, optimizer‑friendly stream abstraction with
precisely defined error sets.

## Creating a writer

A writer is created by giving a buffer to an implementation. The buffer size controls
how much data can be staged before a flush. For example, to write to stdout:

```zig
var stdout_buffer: [1024]u8 = undefined;
var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
const stdout: *std.Io.Writer = &stdout_writer.interface;

try stdout.print("hello world\n", .{});
try stdout.flush();
```

For file I/O the pattern is similar:

```zig
var buffer: [4096]u8 = undefined;
var file_writer = file.writer(&buffer);
try file_writer.interface.print("some data\n", .{});
try file_writer.interface.flush();
```

## Writing bytes

`std.Io.Writer` provides several ways to send data:

* `writeAll` writes a slice of bytes.
* `print` performs formatted output.
* `splatBytesAll` repeats a pattern without copying each byte. In
  `src/trace.zig` this draws the call stack:

```zig
try writer.splatBytesAll("│", machine.calls.items.len + 1);
```

## Advanced features

Writers can propagate high level operations:

* *Splatting* writes repeated patterns without allocating.
* *sendFile* transfers data directly between file descriptors when available.
* The buffer can be rebased to preserve unread bytes.
* `fixed` constructs a writer that fails once the buffer is full, useful for
  writing into a fixed array.

## Don't forget to flush

Buffered writers require an explicit `flush` to ensure all data reaches the
underlying sink. This repository uses `flush` after dumping bytecode to files and
on stdout to guarantee complete output.

```zig
try stdout.flush();
```

The concrete `std.Io.Writer` API encourages reusable stream code without
leaking implementation details, while providing convenient methods and
precise error reporting.
