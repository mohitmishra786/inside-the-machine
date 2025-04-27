---
layout: chapter
title: "Chapter 5: Assembly Language Basics"
part: "Part 2: Disassembly and Analysis"
order: 5
---


*Part 2: Disassembly and Analysis*

In this chapter, we'll build a foundation for understanding assembly language across different architectures. Rather than attempting to be a comprehensive reference, we'll focus on the core concepts and patterns that will help you make sense of disassembled code in real-world reverse engineering scenarios.

## Understanding the CPU Architecture Model

Before diving into assembly language itself, we need to understand the computational model that underlies it. Modern CPUs, despite their differences, share common architectural elements that assembly language directly manipulates.

### Registers

Registers are small, high-speed storage locations built directly into the CPU. They serve as the primary working space for the processor, holding operands for calculations, memory addresses, program counters, and other critical values.

The number, size, and purpose of registers vary by architecture, but most CPUs include:

- **General-purpose registers**: Used for arithmetic, data movement, and addressing
- **Program counter/instruction pointer**: Points to the next instruction to execute
- **Stack pointer**: Manages the program stack
- **Status/flags register**: Contains bits that reflect the results of operations (zero, negative, overflow, etc.)
- **Specialized registers**: May include base pointers, segment registers, vector registers, etc.

Registers are the most frequently referenced elements in assembly code, so understanding their roles in a particular architecture is essential.

### Memory Model

Assembly language operates within the CPU's memory model, which typically includes:

- **Flat memory space**: Modern architectures generally use a single, continuous address space
- **Stack**: A region of memory that grows and shrinks in a last-in, first-out manner, used for local variables, function parameters, return addresses, and register preservation
- **Heap**: Dynamically allocated memory
- **Code/data segments**: Regions containing program instructions and data

Assembly instructions frequently reference memory locations, either directly by address or indirectly through registers and offsets.

### Instruction Set

The instruction set defines the operations a CPU can perform. While instruction sets vary between architectures, they typically include:

- **Data movement**: Transferring data between registers and memory
- **Arithmetic**: Addition, subtraction, multiplication, division
- **Logical operations**: AND, OR, XOR, NOT
- **Comparison**: Testing values against each other
- **Control flow**: Conditional and unconditional jumps, calls, and returns
- **Stack manipulation**: Push and pop operations
- **Special instructions**: System calls, interrupts, privileged operations

Each instruction in the set has a mnemonic (a short, symbolic name) that assembly language uses to represent it.

## x86 and x86-64 Architecture

The x86 architecture (and its 64-bit extension, x86-64) is one of the most common targets for reverse engineering due to its prevalence in desktop and server computing. Let's explore its key characteristics.

### Register Set

#### 32-bit x86 Registers

The 32-bit x86 architecture includes eight general-purpose registers:

- **EAX**: Accumulator, often used for arithmetic operations and function return values
- **EBX**: Base register, sometimes used for memory addressing
- **ECX**: Counter register, used for loop counters and shifts
- **EDX**: Data register, used for I/O and some arithmetic operations
- **ESI**: Source index for string operations
- **EDI**: Destination index for string operations
- **ESP**: Stack pointer, points to the top of the stack
- **EBP**: Base pointer, typically points to the stack frame

Special registers include:

- **EIP**: Instruction pointer, points to the next instruction
- **EFLAGS**: Status flags register

Segment registers (CS, DS, SS, ES, FS, GS) are also available but less commonly used in modern code.

#### 64-bit x86-64 Registers

The x86-64 architecture extends the register set to 16 general-purpose 64-bit registers:

- **RAX, RBX, RCX, RDX**: 64-bit extensions of the original registers
- **RSI, RDI**: 64-bit extensions of the index registers
- **RSP, RBP**: 64-bit extensions of the stack and base pointers
- **R8-R15**: Eight additional general-purpose registers

The instruction pointer becomes RIP, and the flags register becomes RFLAGS.

Importantly, portions of these registers can be accessed separately:

- **RAX** (64-bit full register)
  - **EAX** (lower 32 bits)
    - **AX** (lower 16 bits)
      - **AL** (lower 8 bits)
      - **AH** (upper 8 bits of AX)

This register overlap is a common source of confusion but also provides flexibility in handling data of different sizes.

### Memory Addressing

x86 and x86-64 use several addressing modes to access memory:

- **Immediate**: Direct value (e.g., `mov eax, 42`)
- **Register**: Value in a register (e.g., `mov eax, ebx`)
- **Direct**: Value at a specific memory address (e.g., `mov eax, [0x12345678]`)
- **Register indirect**: Value at the address contained in a register (e.g., `mov eax, [ebx]`)
- **Base + displacement**: Value at the address calculated as register + offset (e.g., `mov eax, [ebx+20]`)
- **Scaled index**: Value at the address calculated using multiple components (e.g., `mov eax, [ebx+ecx*4+20]`)

This flexible addressing system allows efficient access to arrays, structures, and other complex data organizations.

### Common Instructions

Let's examine some of the most frequently encountered x86/x86-64 instructions in reverse engineering:

#### Data Movement

```assembly
mov dest, src      ; Copy src to dest
push src           ; Push src onto the stack
pop dest           ; Pop value from stack into dest
lea dest, [addr]   ; Load effective address (calculate address without accessing memory)
xchg a, b          ; Exchange values between a and b
```

`mov` is likely the most common instruction you'll see. It simply copies data from the source to the destination. The source and destination can be registers, memory locations, or immediate values (with restrictions).

`lea` (Load Effective Address) is particularly interesting as it calculates an address but doesn't access memory. It's often used for pointer arithmetic or quick calculations.

#### Arithmetic

```assembly
add dest, src      ; dest = dest + src
sub dest, src      ; dest = dest - src
inc dest           ; Increment dest by 1
dec dest           ; Decrement dest by 1
mul src            ; Unsigned multiply (EAX * src)
imul src           ; Signed multiply
div src            ; Unsigned divide (EDX:EAX / src)
idiv src           ; Signed divide
neg dest           ; Negate (two's complement)
```

Arithmetic instructions typically modify the flags register based on their result, which can then be used by conditional jumps.

#### Logical Operations

```assembly
and dest, src      ; Bitwise AND
or dest, src       ; Bitwise OR
xor dest, src      ; Bitwise XOR
not dest           ; Bitwise NOT
shl dest, count    ; Shift left
shr dest, count    ; Shift right (unsigned)
sar dest, count    ; Shift right (signed)
rol dest, count    ; Rotate left
ror dest, count    ; Rotate right
```

`xor reg, reg` (e.g., `xor eax, eax`) is commonly used to zero a register, as it's more compact than `mov reg, 0`.

#### Comparison and Testing

```assembly
cmp a, b           ; Compare a and b (compute a - b and set flags)
test a, b          ; Bitwise AND for testing (compute a & b and set flags)
```

These instructions don't store their result; they only set flags that can be used by subsequent conditional jumps.

#### Control Flow

```assembly
jmp target         ; Unconditional jump
je/jz target       ; Jump if equal/zero
jne/jnz target     ; Jump if not equal/not zero
jg/jnle target     ; Jump if greater (signed)
ja/jnbe target     ; Jump if above (unsigned)
jl/jnge target     ; Jump if less (signed)
jb/jnae target     ; Jump if below (unsigned)
call target        ; Call subroutine
ret                ; Return from subroutine
```

Conditional jumps test the flags set by previous instructions (often `cmp` or `test`). The signed/unsigned distinction is important when comparing values that could be interpreted as either signed or unsigned integers.

### Calling Conventions

Calling conventions define how functions receive parameters and return values. They're crucial for understanding function interactions in disassembled code.

#### 32-bit Calling Conventions

Common 32-bit x86 calling conventions include:

- **cdecl**: Parameters pushed right-to-left, caller cleans the stack, return value in EAX
- **stdcall**: Parameters pushed right-to-left, callee cleans the stack, return value in EAX
- **fastcall**: First two parameters in ECX and EDX, others pushed right-to-left, callee cleans the stack

A typical cdecl function call might look like:

```assembly
; Calling func(1, 2, 3)
push 3          ; Push parameters right-to-left
push 2
push 1
call func       ; Call the function
add esp, 12     ; Clean up stack (3 parameters * 4 bytes)
```

#### 64-bit Calling Conventions

The x86-64 architecture primarily uses:

- **Microsoft x64**: First four parameters in RCX, RDX, R8, R9; others pushed on stack; 32 bytes of "shadow space" reserved on stack
- **System V AMD64 ABI** (Linux, macOS): First six parameters in RDI, RSI, RDX, RCX, R8, R9; others pushed on stack

Both conventions return values in RAX and preserve certain registers across calls.

A System V AMD64 function call might look like:

```assembly
; Calling func(1, 2, 3, 4, 5, 6, 7)
mov rdi, 1      ; First six parameters in registers
mov rsi, 2
mov rdx, 3
mov rcx, 4
mov r8, 5
mov r9, 6
push 7          ; Seventh parameter on stack
call func
add rsp, 8      ; Clean up stack
```

### Stack Frame Management

Functions typically establish a stack frame for local variables and saved registers. The standard prologue and epilogue patterns are important to recognize:

#### 32-bit Stack Frame

```assembly
; Function prologue
push ebp         ; Save old base pointer
mov ebp, esp     ; Set new base pointer
sub esp, X       ; Allocate X bytes for local variables

; Function body
; Local variables accessed as [ebp-X]
; Parameters accessed as [ebp+X]

; Function epilogue
mov esp, ebp     ; Restore stack pointer
pop ebp          ; Restore base pointer
ret              ; Return to caller
```

#### 64-bit Stack Frame

64-bit code often uses a more streamlined approach, especially for leaf functions (those that don't call other functions):

```assembly
; Minimal function prologue
push rbp         ; Save base pointer (optional)
sub rsp, X       ; Allocate stack space (typically aligned to 16 bytes)

; Function body

; Minimal function epilogue
add rsp, X       ; Free stack space
pop rbp          ; Restore base pointer (if pushed)
ret              ; Return to caller
```

More complex functions may save additional registers or use frame pointers similarly to 32-bit code.

## ARM Architecture

The ARM architecture is dominant in mobile devices and increasingly important in other domains. Its instruction set differs significantly from x86, making it important to understand for comprehensive reverse engineering capabilities.

### Register Set

ARM processors use a load-store architecture, where operations are performed on registers, with separate instructions to load from or store to memory.

#### 32-bit ARM Registers

The 32-bit ARM architecture provides 16 general-purpose registers:

- **R0-R3**: Function arguments and return values
- **R4-R11**: Local variables (preserved across function calls)
- **R12**: Intra-procedure call scratch register (IP)
- **R13**: Stack pointer (SP)
- **R14**: Link register (LR), holds return address
- **R15**: Program counter (PC)

Additionally, the Current Program Status Register (CPSR) contains condition flags and processor state information.

#### 64-bit ARM64/AArch64 Registers

The 64-bit ARM architecture expands to 31 general-purpose registers:

- **X0-X7**: Function arguments and return values
- **X8**: Indirect result location register
- **X9-X15**: Temporary registers
- **X16-X17**: Intra-procedure call registers
- **X18**: Platform register (reserved in some ABIs)
- **X19-X28**: Callee-saved registers
- **X29**: Frame pointer (FP)
- **X30**: Link register (LR)
- **SP**: Stack pointer (not numbered)

The lower 32 bits of each X register can be accessed as W0-W30.

### Instruction Sets

ARM supports multiple instruction sets:

- **ARM**: 32-bit fixed-length instructions
- **Thumb**: 16-bit compressed instructions for better code density
- **Thumb-2**: Extension of Thumb with both 16-bit and 32-bit instructions
- **A64**: 64-bit instructions for AArch64

When reverse engineering ARM binaries, you may encounter any of these instruction sets, sometimes mixed within the same program.

### Common Instructions

Let's examine some common ARM instructions you'll encounter in reverse engineering:

#### Data Movement

```assembly
MOV Rd, Operand    ; Move value to register
LDR Rd, [Rn, #off] ; Load from memory
STR Rd, [Rn, #off] ; Store to memory
PUSH {reg list}    ; Push registers onto stack
POP {reg list}     ; Pop registers from stack
```

ARM's load-store architecture means that operations can only be performed on registers, not directly on memory.

#### Arithmetic

```assembly
ADD Rd, Rn, Operand ; Rd = Rn + Operand
SUB Rd, Rn, Operand ; Rd = Rn - Operand
MUL Rd, Rn, Rm      ; Rd = Rn * Rm
DIV Rd, Rn, Rm      ; Rd = Rn / Rm
```

Many ARM instructions can optionally update the condition flags by adding an 'S' suffix (e.g., `ADDS`, `SUBS`).

#### Logical Operations

```assembly
AND Rd, Rn, Operand ; Bitwise AND
ORR Rd, Rn, Operand ; Bitwise OR
EOR Rd, Rn, Operand ; Bitwise XOR (exclusive OR)
BIC Rd, Rn, Operand ; Bit clear (AND with complement)
LSL Rd, Rn, #shift  ; Logical shift left
LSR Rd, Rn, #shift  ; Logical shift right
```

#### Comparison

```assembly
CMP Rn, Operand     ; Compare (set flags based on Rn - Operand)
TST Rn, Operand     ; Test bits (set flags based on Rn & Operand)
```

#### Control Flow

```assembly
B label             ; Branch (jump)
BL label            ; Branch with link (call subroutine)
BX Rn               ; Branch and exchange (can switch instruction sets)
BLX Rn              ; Branch with link and exchange
BEQ label           ; Branch if equal
BNE label           ; Branch if not equal
BGT label           ; Branch if greater than
BLT label           ; Branch if less than
```

Conditional execution is a distinctive feature of ARM. Many instructions can be conditionally executed based on the flags, using suffixes like EQ (equal), NE (not equal), GT (greater than), etc.

### ARM Calling Conventions

ARM uses register-based parameter passing:

#### 32-bit ARM

- First four parameters in R0-R3
- Additional parameters on stack
- Return value in R0 (or R0:R1 for 64-bit values)
- Callee must preserve R4-R11 and SP

#### 64-bit ARM (AArch64)

- First eight parameters in X0-X7
- Additional parameters on stack
- Return value in X0 (or X0:X1 for 128-bit values)
- Callee must preserve X19-X28, FP, and SP

### ARM Function Prologues and Epilogues

ARM functions typically save registers and establish a frame using patterns like:

#### 32-bit ARM

```assembly
; Prologue
PUSH {R4-R11, LR}   ; Save registers and return address
SUB SP, SP, #X      ; Allocate local variables

; Function body

; Epilogue
ADD SP, SP, #X      ; Deallocate local variables
POP {R4-R11, PC}    ; Restore registers and return (PC = popped LR)
```

#### 64-bit ARM (AArch64)

```assembly
; Prologue
STP X29, X30, [SP, #-16]!  ; Save FP and LR, update SP
MOV X29, SP                ; Set frame pointer
STP X19, X20, [SP, #-16]!  ; Save preserved registers

; Function body

; Epilogue
LDP X19, X20, [SP], #16    ; Restore preserved registers
LDP X29, X30, [SP], #16    ; Restore FP and LR
RET                        ; Return (using LR)
```

The `STP` (Store Pair) and `LDP` (Load Pair) instructions are commonly used in AArch64 for efficient register saving and restoring.

## MIPS Architecture

While less common than x86 or ARM, the MIPS architecture is important in embedded systems, networking equipment, and some gaming consoles. Its clean, RISC-based design makes it an interesting study in assembly language principles.

### Register Set

MIPS provides 32 general-purpose registers, conventionally used as follows:

- **$0**: Always contains zero
- **$1** ($at): Assembler temporary
- **$2-$3** ($v0-$v1): Function return values
- **$4-$7** ($a0-$a3): Function arguments
- **$8-$15** ($t0-$t7): Temporary registers
- **$16-$23** ($s0-$s7): Saved registers (preserved across calls)
- **$24-$25** ($t8-$t9): More temporary registers
- **$26-$27** ($k0-$k1): Reserved for kernel use
- **$28** ($gp): Global pointer
- **$29** ($sp): Stack pointer
- **$30** ($fp): Frame pointer
- **$31** ($ra): Return address

Additionally, MIPS has a program counter (PC) and a status register containing condition flags.

### Common Instructions

MIPS instructions follow a consistent format, typically with three operands.

#### Data Movement

```assembly
move $t0, $t1      ; Copy value (pseudoinstruction for addu $t0, $t1, $zero)
lw $t0, offset($t1) ; Load word from memory
sw $t0, offset($t1) ; Store word to memory
li $t0, imm        ; Load immediate value (pseudoinstruction)
```

#### Arithmetic

```assembly
addu $t0, $t1, $t2 ; $t0 = $t1 + $t2 (unsigned)
subu $t0, $t1, $t2 ; $t0 = $t1 - $t2 (unsigned)
mul $t0, $t1, $t2  ; $t0 = $t1 * $t2
div $t0, $t1       ; Lo = $t0 / $t1, Hi = $t0 % $t1
mflo $t0           ; Move from Lo register
mfhi $t0           ; Move from Hi register
```

MIPS distinguishes between operations that can cause exceptions (e.g., `add`, which can overflow) and those that don't (e.g., `addu`, which ignores overflow).

#### Logical Operations

```assembly
and $t0, $t1, $t2  ; Bitwise AND
or $t0, $t1, $t2   ; Bitwise OR
xor $t0, $t1, $t2  ; Bitwise XOR
nor $t0, $t1, $t2  ; Bitwise NOR
sll $t0, $t1, 5    ; Shift left logical
srl $t0, $t1, 5    ; Shift right logical
```

#### Comparison and Branching

```assembly
beq $t0, $t1, label ; Branch if equal
bne $t0, $t1, label ; Branch if not equal
slt $t0, $t1, $t2   ; Set if less than ($t0 = 1 if $t1 < $t2, else 0)
slti $t0, $t1, imm  ; Set if less than immediate
blez $t0, label     ; Branch if less than or equal to zero
bgtz $t0, label     ; Branch if greater than zero
```

MIPS doesn't have a dedicated compare instruction; instead, it uses `slt` and similar instructions to set a register based on a comparison, which can then be tested with a branch.

#### Control Flow

```assembly
j label             ; Jump to address
jal label           ; Jump and link (call subroutine)
jr $t0              ; Jump register (often used for returns with $ra)
jalr $t0            ; Jump and link register
```

### MIPS Calling Convention

The standard MIPS calling convention uses:

- First four arguments in $a0-$a3
- Additional arguments on stack
- Return values in $v0-$v1
- Callee must preserve $s0-$s7, $fp, $gp, $sp, and $ra

### MIPS Function Prologues and Epilogues

MIPS functions typically follow this pattern:

```assembly
; Prologue
addiu $sp, $sp, -X    ; Allocate stack frame
sw $ra, (X-4)($sp)    ; Save return address
sw $fp, (X-8)($sp)    ; Save frame pointer
sw $s0, (X-12)($sp)   ; Save preserved registers
...
move $fp, $sp         ; Set frame pointer

; Function body

; Epilogue
move $sp, $fp         ; Restore stack pointer
lw $s0, (X-12)($sp)   ; Restore preserved registers
...
lw $fp, (X-8)($sp)    ; Restore frame pointer
lw $ra, (X-4)($sp)    ; Restore return address
addiu $sp, $sp, X     ; Deallocate stack frame
jr $ra                ; Return
```

The delay slot is a MIPS peculiarity: the instruction immediately following a branch or jump is executed before the branch takes effect. This can make disassembly more confusing for beginners.

## Common Assembly Patterns

Regardless of the specific architecture, certain code patterns appear frequently in disassembled code. Recognizing these patterns can significantly speed up your analysis.

### Function Calls and Returns

Function calls involve saving the return address and transferring control to the target function. Returns restore the previous execution context.

#### x86/x86-64

```assembly
; Call
call function_name

; Return
ret
```

#### ARM

```assembly
; Call
BL function_name

; Return
BX LR      ; 32-bit ARM
RET        ; 64-bit ARM
```

#### MIPS

```assembly
; Call
jal function_name

; Return
jr $ra
```

### Loops

Loops typically involve initializing a counter, comparing it to a limit, and branching conditionally.

#### x86/x86-64 Counting Loop

```assembly
    mov ecx, 10     ; Initialize counter
loop_start:
    ; Loop body
    dec ecx         ; Decrement counter
    jnz loop_start  ; Jump if not zero
```

#### ARM Counting Loop

```assembly
    MOV R0, #10     ; Initialize counter
loop_start:
    ; Loop body
    SUBS R0, R0, #1 ; Decrement counter and update flags
    BNE loop_start  ; Branch if not equal to zero
```

#### MIPS Counting Loop

```assembly
    li $t0, 10      ; Initialize counter
loop_start:
    ; Loop body
    addiu $t0, $t0, -1 ; Decrement counter
    bnez $t0, loop_start ; Branch if not equal to zero
```

### Conditional Statements

Conditional statements (if-then-else) involve comparing values and branching based on the result.

#### x86/x86-64 If-Then-Else

```assembly
    cmp eax, ebx    ; Compare values
    jge else_branch ; Jump if greater or equal
    ; Then branch code
    jmp end_if
else_branch:
    ; Else branch code
end_if:
```

#### ARM If-Then-Else

```assembly
    CMP R0, R1      ; Compare values
    BGE else_branch ; Branch if greater or equal
    ; Then branch code
    B end_if
else_branch:
    ; Else branch code
end_if:
```

#### MIPS If-Then-Else

```assembly
    slt $t0, $a0, $a1 ; Set $t0 to 1 if $a0 < $a1
    beqz $t0, else_branch ; Branch if $t0 equals zero
    ; Then branch code
    j end_if
else_branch:
    ; Else branch code
end_if:
```

### Switch Statements

Switch statements can be implemented in various ways, but often use jump tables for efficiency.

#### x86/x86-64 Jump Table

```assembly
    cmp eax, 5      ; Check if index is in range
    ja default_case ; Jump if above 5
    jmp [jump_table + eax*4] ; Jump to appropriate case

jump_table:
    dd case_0
    dd case_1
    dd case_2
    dd case_3
    dd case_4
    dd case_5

case_0:
    ; Case 0 code
    jmp end_switch
case_1:
    ; Case 1 code
    jmp end_switch
; ...
default_case:
    ; Default case code
end_switch:
```

### String Operations

String processing often involves loops that operate on one character at a time.

#### x86/x86-64 String Length

```assembly
    mov ecx, 0      ; Initialize counter
    mov esi, string_ptr ; Point to string
loop_start:
    mov al, [esi]   ; Load character
    test al, al     ; Check if null terminator
    jz done         ; Jump if zero
    inc ecx         ; Increment counter
    inc esi         ; Move to next character
    jmp loop_start
done:
    ; ECX now contains the string length
```

### Memory Allocation

Dynamic memory allocation typically involves calling system functions like malloc/HeapAlloc.

#### x86/x86-64 Heap Allocation

```assembly
    push 100        ; Size to allocate (32-bit)
    call malloc
    add esp, 4      ; Clean up stack
    ; EAX now contains the allocated pointer

    ; Or in 64-bit code:
    mov rcx, 100    ; Size to allocate
    call malloc
    ; RAX now contains the allocated pointer
```

## Reading Disassembled Code

Now that we've covered the basics of assembly language across different architectures, let's discuss strategies for effectively reading and analyzing disassembled code.

### Identifying Function Boundaries

The first step in analyzing disassembled code is identifying where functions begin and end. Look for:

- Function prologues (stack setup, register saving)
- Function epilogues (register restoration, return instructions)
- References from call instructions

Modern disassemblers like IDA Pro and Ghidra automatically identify functions, but understanding the patterns helps when automatic analysis is incomplete.

### Recognizing Local Variables and Parameters

Local variables and parameters are typically accessed relative to the stack or frame pointer:

- In x86, parameters are often at positive offsets from EBP (`[ebp+8]`, `[ebp+12]`, etc.), while local variables are at negative offsets (`[ebp-4]`, `[ebp-8]`, etc.)
- In x86-64, the first few parameters may be in registers, with additional parameters on the stack
- In ARM, parameters start in registers (R0-R3 or X0-X7), with additional parameters on the stack

Tracking these accesses helps understand the function's data flow.

### Following Control Flow

Control flow analysis involves tracking how execution moves through the code:

1. Start at the function entry point
2. Follow sequential execution until a branch or jump
3. For conditional branches, analyze both paths
4. For function calls, note the call target and continue after the call
5. For returns, identify where execution might resume (call sites)

Drawing a control flow graph (manually or using tools) can help visualize complex functions.

### Understanding Data Transformations

To understand what a function does, focus on how it transforms data:

1. Identify input sources (parameters, global variables, memory reads)
2. Track how these inputs are processed through calculations and operations
3. Identify output destinations (return values, memory writes, global variables)

Pay special attention to patterns that suggest specific algorithms or operations (encryption, hashing, compression, etc.).

### Dealing with Compiler Optimizations

Compiler optimizations can make disassembly more challenging to read:

- **Inlining**: Functions inserted directly at call sites rather than called
- **Register allocation**: Variables kept in registers rather than on the stack
- **Loop unrolling**: Loops expanded to reduce iteration overhead
- **Instruction reordering**: Instructions rearranged for better pipeline efficiency
- **SIMD instructions**: Vector operations that process multiple data elements simultaneously

When facing heavily optimized code, focus on the overall data flow rather than trying to match each instruction to source code constructs.

### Annotating Disassembly

As you analyze disassembled code, maintain annotations to track your understanding:

- Rename functions based on their purpose
- Rename registers or memory locations based on their usage
- Add comments explaining complex operations
- Document identified algorithms or patterns

These annotations transform raw disassembly into a more readable form that captures your analysis insights.

## Architecture-Specific Challenges

Each architecture presents unique challenges for reverse engineers.

### x86/x86-64 Challenges

- **Complex instruction set**: The x86 family has hundreds of instructions with various forms and options
- **Variable instruction length**: Instructions can be 1-15 bytes, making it possible to interpret the same bytes differently depending on alignment
- **Implicit operations**: Some instructions have side effects not explicitly stated in the mnemonic
- **Multiple calling conventions**: Different conventions may be used in the same program

### ARM Challenges

- **Instruction set switching**: Code can switch between ARM and Thumb modes
- **Conditional execution**: Many instructions can be conditionally executed based on flags
- **PC-relative addressing**: Code often uses PC-relative addressing for position-independent execution
- **Thumb-2 mixed-width instructions**: Thumb-2 mixes 16-bit and 32-bit instructions

### MIPS Challenges

- **Delay slots**: The instruction after a branch is executed before the branch takes effect
- **Branch likely instructions**: Conditional branches that nullify the delay slot if not taken
- **Load delay slots**: In some MIPS implementations, the result of a load isn't available in the immediately following instruction
- **Hi/Lo registers**: Division and multiplication use special registers for results

## Practical Analysis Strategies

Let's explore practical strategies for analyzing assembly code across different scenarios.

### Bottom-Up Analysis

Bottom-up analysis starts with individual instructions and builds toward higher-level understanding:

1. Identify basic blocks (straight-line code sequences)
2. Determine the purpose of each basic block
3. Analyze how blocks connect to form larger structures
4. Gradually build a functional understanding

This approach works well for smaller functions or when you need detailed understanding of specific code sections.

### Top-Down Analysis

Top-down analysis starts with program structure and refines understanding progressively:

1. Identify major functions and their relationships
2. Determine the general purpose of each function based on its calls and data access
3. Focus on functions of interest and analyze their internal logic
4. Drill down to instruction-level details only when necessary

This approach is efficient for larger programs where complete analysis of every function isn't feasible.

### Signature-Based Analysis

Signature-based analysis uses known patterns to identify familiar code:

1. Recognize common compiler-generated patterns
2. Identify standard library functions
3. Detect known algorithms (cryptographic functions, compression routines, etc.)
4. Use these identified elements as anchors for further analysis

This approach leverages prior knowledge to accelerate analysis.

### Dynamic-Assisted Analysis

Combining static disassembly with dynamic execution information:

1. Run the program in a debugger
2. Observe actual values in registers and memory
3. Use this runtime information to inform static analysis
4. Iterate between static and dynamic analysis

This approach is particularly effective for complex code or when static analysis alone is insufficient.

## Case Study: Cross-Architecture Analysis

Let's examine a simple function implemented across different architectures to highlight similarities and differences in assembly patterns.

Consider this C function that calculates the factorial of a number:

```c
int factorial(int n) {
    if (n <= 1) {
        return 1;
    } else {
        return n * factorial(n - 1);
    }
}
```

### x86-64 Implementation

```assembly
factorial:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 16
    mov     [rbp-4], edi    ; Store parameter n
    cmp     dword [rbp-4], 1
    jg      .else_branch
    mov     eax, 1          ; Return 1
    jmp     .end
.else_branch:
    mov     eax, [rbp-4]    ; Load n
    sub     eax, 1          ; Calculate n-1
    mov     edi, eax        ; Set parameter for recursive call
    call    factorial
    mov     edx, [rbp-4]    ; Load n again
    imul    eax, edx        ; Multiply result by n
.end:
    leave
    ret
```

### ARM64 Implementation

```assembly
factorial:
    stp     x29, x30, [sp, #-16]!  ; Save FP and LR
    mov     x29, sp                ; Set frame pointer
    cmp     w0, #1                 ; Compare n with 1
    ble     .base_case             ; Branch if n <= 1
    str     w0, [sp, #12]          ; Store n on stack
    sub     w0, w0, #1             ; Calculate n-1
    bl      factorial              ; Recursive call
    ldr     w1, [sp, #12]          ; Load n from stack
    mul     w0, w0, w1             ; Multiply result by n
    b       .end
.base_case:
    mov     w0, #1                 ; Return 1
.end:
    ldp     x29, x30, [sp], #16    ; Restore FP and LR
    ret
```

### MIPS Implementation

```assembly
factorial:
    addiu   $sp, $sp, -8           ; Allocate stack frame
    sw      $ra, 4($sp)            ; Save return address
    sw      $a0, 0($sp)            ; Save parameter n
    ble     $a0, 1, base_case      ; Branch if n <= 1
    addiu   $a0, $a0, -1           ; Calculate n-1
    jal     factorial              ; Recursive call
    lw      $a0, 0($sp)            ; Restore n
    mul     $v0, $a0, $v0          ; Multiply n by factorial(n-1)
    j       end
base_case:
    li      $v0, 1                 ; Return 1
end:
    lw      $ra, 4($sp)            ; Restore return address
    addiu   $sp, $sp, 8            ; Deallocate stack frame
    jr      $ra                    ; Return
```

### Analysis Comparison

Despite the different instruction sets, we can identify common patterns:

1. **Function setup**: Each version saves necessary registers and allocates stack space
2. **Conditional check**: Each tests if n <= 1 and branches accordingly
3. **Base case**: Each returns 1 for the base case
4. **Recursive case**: Each calculates n-1, makes a recursive call, then multiplies the result by n
5. **Function cleanup**: Each restores saved registers and returns

The differences lie in:
- Register usage (based on the architecture's calling convention)
- Instruction syntax and capabilities
- Stack frame organization

This cross-architecture perspective helps develop a more abstract understanding of code patterns that transcends specific instruction sets.

## Summary

In this chapter, we've explored the fundamentals of assembly language across multiple architectures, focusing on the concepts and patterns most relevant to reverse engineering. We've covered:

- The basic computational model underlying assembly language
- Key features of x86/x86-64, ARM, and MIPS architectures
- Common instructions and their purposes
- Calling conventions and function structures
- Recurring code patterns for loops, conditionals, and other constructs
- Strategies for reading and analyzing disassembled code
- Architecture-specific challenges and how to address them

Mastering assembly language is a journey that requires practice and exposure to diverse code examples. As you gain experience, you'll develop an intuition for recognizing patterns and understanding code functionality from its assembly representation.

In the next chapter, we'll build on this foundation to explore static code analysis techniques that help extract meaning from disassembled programs more efficiently.

## Exercises

1. **Register Tracking**: Choose a simple function from a disassembled program and trace how values move between registers and memory. Create a table showing the value of each register at different points in the function's execution.

2. **Pattern Recognition**: Find examples of the following patterns in disassembled code:
   - A loop that iterates a fixed number of times
   - A function that processes a null-terminated string
   - A switch statement with at least three cases
   - A recursive function

3. **Cross-Architecture Translation**: Write a simple C function (e.g., calculating the sum of an array), compile it for different architectures, and compare the resulting assembly. Identify the common logical structure despite the different instruction sets.

4. **Calling Convention Analysis**: Examine a function with multiple parameters in disassembled code. Determine which calling convention it uses and how parameters are passed and returned.

