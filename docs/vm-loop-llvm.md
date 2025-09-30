# Inspecting the `demoGrammar` VM Loop in LLVM IR

This note shows how to force Zig to emit LLVM IR for the `VM(.Loop)` interpreter that `src/vm.zig` builds around the `demoGrammar` rules, and what the optimized lowering looks like once LLVM sees the fully monomorphized code. The snapshots below are abridged for readability, but every symbol referenced comes straight out of the real IR generated in `ReleaseFast` mode.

## Build the sample once

1. Keep the standalone driver that instantiates the VM with the demo grammar (`vm_loop_demo.zig`):
   ```zig
   const std = @import("std");
   const peg = @import("src/peg.zig");
   const vm_mod = @import("src/vm.zig");

   pub fn main() !void {
       const VM = vm_mod.VM(peg.demoGrammar);
       var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
       defer arena.deinit();
       const allocator = arena.allocator();

       var parser = try VM.initAlloc("[[1] [2]]", allocator, 64, 64, 512);
       defer parser.deinit(allocator);
       try parser.run();
   }
   ```

2. Compile with LLVM output enabled:
   ```bash
   zig build-exe vm_loop_demo.zig \
       -O ReleaseFast \
       -fllvm \
       -femit-llvm-ir=zig-out/vm_loop_demo.ll \
       -femit-asm=zig-out/vm_loop_demo.s
   ```

   The `.ll` file is optimized IR. `ReleaseFast` keeps the tight loop, but runs the usual instcombine/vectorize passes, so you are looking at realistic codegen rather than SSA straight from the front end.

## Monomorphized VM state

The first few lines already show that the interpreter has been fully specialized to the grammar. There are no generics left—every type is spelling out `src.vm.VM(src.peg.demoGrammar)` and the layout matches the fields in `src/vm.zig`:

```llvm
%"src.vm.VM(src.peg.demoGrammar)" = type {
    { ptr, i64 },                          ; text slice
    %"array_list.Aligned(src.vm.VM(src.peg.demoGrammar).SaveFrame,null)",
    %"array_list.Aligned(src.vm.VM(src.peg.demoGrammar).CallFrame,null)",
    %"array_list.Aligned(src.ast.NodeType,null)",
    %"array_list.Aligned(u32,null)",      ; child stack
    %"array_list.Aligned(src.vm.VM(src.peg.demoGrammar).StructuralFrame,null)",
    ptr,                                   ; optional memo table
    i32, { i32, i8, [3 x i8] }, [4 x i8]
}
```

Every support type follows suit. `SaveFrame`, `CallFrame`, `StructuralFrame`, and all helper `ArrayList` instantiations are concrete, so LLVM optimizes under fixed offsets and sizes instead of opaque pointers.

## Dispatch becomes a computed goto

The VM loop body (`VM.next`) lowers to a single state-machine function with a dense jump table. The real symbol name is `"src.vm.VM(src.peg.demoGrammar).next__anon_3053"`, and the entry block pulls the next opcode by indexing into a static array of blockaddresses:

```llvm
@__jmptab_4670 = internal unnamed_addr constant [35 x ptr] [
    ptr blockaddress(@"...next__anon_3053", %Case),
    ptr blockaddress(@"...next__anon_3053", %Case1),
    ...
]

Entry:
    %ip_ok   = icmp ult i32 %ip, 35
    br i1 %ip_ok, label %dispatch, label %parse_fail

dispatch:
    %slot = getelementptr inbounds [35 x ptr], ptr @__jmptab_4670, i64 %ip
    %dest = load ptr, ptr %slot
    indirectbr ptr %dest,
        [label %Case, label %Case1, label %Case2, ... label %Case34]
```

What used to be a giant Zig `switch (OP)` is now LLVM’s `indirectbr`. Each `CaseN` recipe implements an opcode from `src/vm.zig:234` with loop-mode rewrites (no returning IP, just `continue :vm`).

## Character sets collapse to bit masks

`demoGrammar` only uses four character classes: `[1-9]`, `[0-9]`, `'['`, `']'`, and whitespace. LLVM turns those into constant bitsets (four 64-bit words) that live next to the jump table:

```llvm
@1 = private unnamed_addr constant [4 x i64] [  ; "1".."9"
    287667426198290432, 0, 0, 0
]
@2 = private unnamed_addr constant [4 x i64] [  ; "0".."9"
    287948901175001088, 0, 0, 0
]
@3 = private unnamed_addr constant [4 x i64] [  ; '[['
    0, 134217728, 0, 0
]
@4 = private unnamed_addr constant [4 x i64] [  ; "]"
    0, 536870912, 0, 0
]
@5 = private unnamed_addr constant [4 x i64] [  ; whitespace set
    4294977024, 0, 0, 0
]
```

A typical opcode, the `CharRange('1','9', .one)` check inside `Integer`, expands to a mask lookup and branch:

```llvm
Case6: ; read digit 1-9
    %byte       = load i8, ptr %text_ptr
    %word_idx   = lshr i64 %byte, 6
    %mask_word  = load i64, ptr getelementptr([4 x i64], ptr @1, i64 0, i64 %word_idx)
    %bit_idx    = and i64 %byte, 63
    %probe_bit  = shl nuw i64 1, %bit_idx
    %is_match   = icmp ne i64 (and i64 %probe_bit, %mask_word), 0
    br i1 %is_match, label %consume_digit, label %fail_digit
```

No helper calls needed—the compile-time predicates became raw bitmath.

## Rule calls and AST nodes write constant payloads

When an opcode finishes a rule (`.done` in Zig), LLVM emits direct stores into the call-frame arrays. The value `3` below is the enum tag for `.Skip`, and all offsets line up with the `StructFrame`/`SaveFrame` layouts from the VM definition:

```llvm
Case: ; OP.done
    %save_len   = load i64, ptr %saves.len_ptr
    %save_slot  = getelementptr %"...SaveFrame", ptr %saves.buffer, i64 %save_len
    store i64 %start_sp,   ptr %save_slot          ; frame.start_sp
    store i64 %return_ip,  ptr (%save_slot + 8)
    store i64 %node_len,   ptr (%save_slot + 16)
    store i32 3,           ptr (%save_slot + 24)    ; rule enum (Skip)
    store i32 %struct_lo,  ptr (%save_slot + 28)
    store i32 %child_lo,   ptr (%save_slot + 32)
    br label %Case1        ; continue with next opcode
```

The structural helpers (`open`, `next`, `shut`) similarly spill child slices into preallocated arrays, with their field tags baked in (`store i8 5` corresponds to `.field` nodes for struct fields). Because all of these numbers originate from `demoGrammar`, nothing is indirect.

## Memoization path is concrete too

Even optional features like memo tables collapse to concrete hash-map calls:

```llvm
Case17: ; memo lookup
    %memo_ptr = load ptr, ptr (%self + memo_offset)
    br i1 (icmp eq ptr %memo_ptr, null), label %skip_lookup, label %lookup

lookup:
    %key_hash = tail call i64 @llvm.fshl.i64(i64 5, i64 %key_ip, i64 32)
    %tbl_slot = getelementptr [80 x %MemoEntry], ptr %memo_ptr, i64 %key_hash
    %entry    = load %MemoEntry, ptr %tbl_slot
    ...
```

All the helper symbols (`hash_map.HashMapUnmanaged(src.vm.VM(src.peg.demoGrammar).MemoKey, ...)`) are grammar-qualified, so you can drop into them with `llvm-objdump` and correlate the fast path vs miss path exactly.

## Where to look next

* `zig-out/vm_loop_demo.ll` — full optimized IR. Search for `next__anon` to jump straight into the VM loop, and use `CaseN` labels to navigate opcodes.
* `zig-out/vm_loop_demo.s` — target-assembly view. On AArch64 the indirect jump turns into a `br xN` against the jump table, and the character-set probes become a couple of shifts and `tst`s.
* `zig-out/vm_loop_demo` — the executable. `llvm-objdump -d zig-out/vm_loop_demo` mirrors what you see in `.s` but keeps symbol references intact if you prefer working from the binary.

Because we compiled with `-fllvm`, any other LLVM tooling (e.g. `opt -analyze`, `llvm-mca`) can be aimed at the `.ll` file without replaying the Zig build. That makes it practical to iterate on VM changes while confirming what the interpreter looks like under real release builds.
