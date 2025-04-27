# Chapter 6: Static Code Analysis

*Part 2: Disassembly and Analysis*

In this chapter, we'll explore advanced static analysis techniques that help you move beyond basic disassembly to deeper program understanding. We'll examine how to identify functions, analyze control flow, recognize data structures, and detect common algorithms and library code. These techniques will help you work more efficiently and effectively as a reverse engineer.

## Beyond Basic Disassembly

Basic disassembly, as we explored in the previous chapter, converts machine code to assembly language. While essential, this is just the first step in static analysis. To truly understand a program, we need to:

1. **Reconstruct program structure**: Identify functions, basic blocks, and their relationships
2. **Analyze control flow**: Understand how execution moves through the program
3. **Track data flow**: Follow how data is transformed and propagated
4. **Recognize patterns**: Identify common algorithms, library functions, and programming idioms
5. **Infer high-level constructs**: Map assembly patterns back to source-level concepts

Modern disassemblers and static analysis tools automate many of these tasks, but understanding the underlying techniques is crucial for effective reverse engineering, especially when automated analysis falls short.

## Function Identification and Analysis

Functions are the fundamental organizational units in most programs. Identifying function boundaries, parameters, local variables, and return values is a critical first step in static analysis.

### Identifying Function Boundaries

Several techniques help identify where functions begin and end:

#### Prologue and Epilogue Patterns

As we saw in the previous chapter, functions typically begin with a prologue that sets up the stack frame and end with an epilogue that restores the previous state:

**x86-64 Prologue Pattern:**
```assembly
push rbp
mov rbp, rsp
sub rsp, X  ; X is the size of the stack frame
```

**x86-64 Epilogue Pattern:**
```assembly
leave       ; equivalent to: mov rsp, rbp; pop rbp
ret
```

**ARM64 Prologue Pattern:**
```assembly
stp x29, x30, [sp, #-16]!  ; Save frame pointer and link register
mov x29, sp                ; Set frame pointer
```

**ARM64 Epilogue Pattern:**
```assembly
ldp x29, x30, [sp], #16    ; Restore frame pointer and link register
ret
```

Scanning for these patterns helps identify function entry and exit points, though optimized code may use variations or omit frame setup entirely for leaf functions (those that don't call other functions).

#### Call References

Functions are typically targets of call instructions. By identifying all call targets in a binary, you can discover function entry points:

```assembly
call 0x401500  ; 0x401500 is likely a function entry point
```

This approach works well for directly called functions but may miss functions called through pointers or virtual methods.

#### Symbol Information

When available, symbol tables provide direct information about function locations. Even stripped binaries often retain some symbolic information for external functions:

```
0x401500 <_malloc>:       push rbp
0x401501 <_malloc+1>:     mov rbp, rsp
```

#### Heuristic Analysis

Modern disassemblers use sophisticated heuristics to identify functions, including:
- Code reachability analysis
- Return instruction identification
- Stack pointer tracking
- Register usage patterns

These heuristics work together to provide comprehensive function identification, even in complex or obfuscated code.

### Function Signature Recovery

Once you've identified a function, determining its signature (parameters and return value) is the next step.

#### Parameter Identification

Parameters can be identified by analyzing how the function accesses data based on the calling convention:

**x86-64 System V (Linux/macOS):**
Parameters appear in registers RDI, RSI, RDX, RCX, R8, R9, with additional parameters on the stack.

```assembly
mov rax, [rdi]      ; Accessing first parameter
add rsi, 8          ; Modifying second parameter
```

**x86-64 Microsoft (Windows):**
Parameters appear in registers RCX, RDX, R8, R9, with additional parameters on the stack.

```assembly
test rcx, rcx       ; Testing first parameter
mov rax, [rdx+8]    ; Accessing field in second parameter
```

**ARM64:**
Parameters appear in registers X0-X7.

```assembly
cbz x0, .label      ; Checking if first parameter is zero
ldr x1, [x1, #16]   ; Loading from address in second parameter
```

#### Return Value Analysis

Return values are typically placed in specific registers before returning:

- x86-64: RAX (with RDX for larger values)
- ARM64: X0 (with X1 for larger values)
- MIPS: $v0 (with $v1 for larger values)

Tracking what values are placed in these registers before return instructions helps identify the function's return value.

```assembly
; x86-64 function returning a 32-bit integer
mov eax, 42
ret

; ARM64 function returning a pointer
mov x0, x19
ret
```

#### Stack Frame Analysis

Analyzing stack frame setup and access patterns reveals information about local variables and parameters:

```assembly
; x86-64 with frame pointer
push rbp
mov rbp, rsp
sub rsp, 32         ; Allocate 32 bytes for local variables
mov [rbp-8], rdi    ; Store first parameter in local variable
mov rax, [rbp+16]   ; Access parameter passed on stack
```

By tracking these memory accesses, you can reconstruct the function's local variable layout and parameter passing mechanism.

### Function Type Inference

Beyond basic signature recovery, inferring the types of parameters and return values provides deeper insight into a function's purpose.

#### Pointer vs. Value Analysis

How a value is used often reveals whether it's a pointer or a direct value:

```assembly
; Likely a pointer parameter
mov rax, [rdi]      ; Dereferencing rdi suggests it's a pointer

; Likely a numeric parameter
add eax, esi        ; Direct arithmetic on esi suggests it's a value
```

#### Size Inference

The size of registers used in operations can indicate the size of the data type:

```assembly
movzx eax, byte ptr [rdi]  ; Suggests rdi points to a byte (char)
mov eax, dword ptr [rsi]   ; Suggests rsi points to a 32-bit value (int)
```

#### Array and Structure Detection

Access patterns can reveal array or structure usage:

```assembly
; Likely array access with index in rcx
mov rax, [rdi + rcx*8]     ; Accessing 8-byte elements (e.g., pointers)

; Likely structure field access
mov rax, [rdi + 16]        ; Accessing field at offset 16
```

#### String Operation Detection

Certain instruction sequences suggest string operations:

```assembly
; Likely string comparison loop
.loop:
mov al, [rdi]
mov bl, [rsi]
cmp al, bl
jne .different
test al, al
jz .equal
inc rdi
inc rsi
jmp .loop
```

### Function Classification

Classifying functions by their behavior helps prioritize analysis efforts and understand program structure.

#### Utility Functions

Small, frequently called functions often perform utility operations like string manipulation, memory management, or data conversion.

```assembly
; Likely a string length function
xor eax, eax        ; Initialize counter to 0
.loop:
cmp byte ptr [rdi], 0
je .done
inc rdi
inc eax
jmp .loop
.done:
ret
```

#### Wrapper Functions

Functions that perform minimal processing before calling another function are often wrappers that provide a simplified interface or additional checks.

```assembly
; Likely a wrapper function
test rdi, rdi
jz .error
call _internal_function
ret
.error:
xor eax, eax
ret
```

#### Constructor/Destructor Functions

Functions that initialize or clean up data structures often have distinctive patterns:

```assembly
; Likely a constructor
mov rdi, 24         ; Size to allocate
call _malloc
test rax, rax
jz .error
mov qword ptr [rax], 0     ; Initialize fields
mov qword ptr [rax+8], 0
mov dword ptr [rax+16], 1
ret
```

#### Algorithm Implementation Functions

Functions implementing specific algorithms often have recognizable structures like nested loops, table lookups, or mathematical operations.

```assembly
; Likely a hash function (simplified example)
mov eax, 5381       ; Initial hash value
.loop:
movzx ecx, byte ptr [rdi]
test cl, cl
jz .done
inc rdi
imul eax, eax, 33   ; hash = hash * 33
add eax, ecx        ; hash = hash + character
jmp .loop
.done:
ret
```

## Control Flow Analysis

Control flow analysis examines how execution moves through a program, identifying paths, loops, and conditional branches. This analysis is crucial for understanding program logic and behavior.

### Basic Block Identification

A basic block is a sequence of instructions with a single entry point (the first instruction) and a single exit point (the last instruction). Control flow enters at the beginning and exits at the end without halting or branching except at the exit.

Identifying basic blocks involves:
1. Finding leaders (first instructions of basic blocks):
   - The first instruction of the program
   - Instructions targeted by jumps
   - Instructions following jumps or returns
2. Determining where each block ends (at jumps, returns, or before the next leader)

```assembly
; Basic block 1
mov eax, [rdi]
add eax, 5
cmp eax, 10
jg .label1      ; Exit point of block 1

; Basic block 2
mov ebx, 0
jmp .label2     ; Exit point of block 2

; Basic block 3 (.label1)
.label1:
mov ebx, 1

; Basic block 4 (.label2)
.label2:
ret             ; Exit point of blocks 3 and 4
```

### Control Flow Graph Construction

A Control Flow Graph (CFG) represents the program's structure as a directed graph where:
- Nodes are basic blocks
- Edges represent possible control flow between blocks

Constructing a CFG involves:
1. Identifying all basic blocks
2. Adding edges for all possible control transfers:
   - Sequential flow from one block to the next
   - Conditional branches (two outgoing edges)
   - Unconditional jumps
   - Function calls (with edges to the called function and the return point)

Modern disassemblers like IDA Pro and Ghidra automatically generate CFGs, but understanding how to interpret and manually construct them is valuable for complex analysis.

### Loop Detection

Loops are fundamental control structures that often represent important processing in a program. Detecting loops in a CFG involves finding cycles (paths that return to a previously visited node).

Common loop patterns include:

#### Counter-Based Loops

```assembly
; Initialize counter
mov ecx, 10
.loop_start:
; Loop body
dec ecx
jnz .loop_start    ; Jump if not zero
```

#### Condition-Based Loops

```assembly
.loop_start:
; Loop body
cmp byte ptr [rdi], 0
jne .loop_start    ; Continue until null byte
```

#### Nested Loops

```assembly
; Outer loop initialization
mov ecx, 10
.outer_loop:
; Inner loop initialization
mov edx, 5
.inner_loop:
; Inner loop body
dec edx
jnz .inner_loop
; Outer loop continuation
dec ecx
jnz .outer_loop
```

Identifying loop structures helps understand the program's algorithmic patterns and data processing logic.

### Conditional Logic Recovery

Recovering high-level conditional structures (if-then-else, switch-case) from assembly code requires analyzing branch patterns and their targets.

#### If-Then-Else Structures

```assembly
; if (condition) { then_block } else { else_block }
cmp eax, ebx
jne .else_branch
; Then block
...
jmp .end_if
.else_branch:
; Else block
...
.end_if:
```

#### Switch-Case Structures

Switch statements are typically implemented using jump tables or series of comparisons:

**Jump Table Implementation:**
```assembly
; switch(value)
cmp eax, 5          ; Check upper bound
ja .default_case    ; If above, go to default
jmp [.jump_table + eax*4]  ; Jump based on value

.jump_table:
dd .case_0
dd .case_1
dd .case_2
dd .case_3
dd .case_4
dd .case_5

.case_0:
; Case 0 code
jmp .end_switch
.case_1:
; Case 1 code
jmp .end_switch
; ...
.default_case:
; Default case code
.end_switch:
```

**Comparison Chain Implementation:**
```assembly
; switch(value) implemented as if-else chain
cmp eax, 0
je .case_0
cmp eax, 1
je .case_1
cmp eax, 2
je .case_2
; ...
jmp .default_case
```

Recognizing these patterns helps reconstruct the original high-level control structures.

### Exception Handling Analysis

Exception handling mechanisms add complexity to control flow analysis. Different platforms use different approaches:

#### Windows SEH (Structured Exception Handling)

Windows SEH uses registration records and exception handlers:

```assembly
; SEH setup
push handler_address
push fs:[0]         ; Previous handler
mov fs:[0], esp     ; Register new handler

; Protected code
...

; SEH cleanup
pop fs:[0]          ; Restore previous handler
add esp, 4          ; Remove handler address
```

#### C++ Exception Handling

C++ exceptions typically use tables that map code regions to exception handlers:

```assembly
; Function with C++ exception handling
.Ltry_start:
; Try block code
call potentially_throwing_function
.Ltry_end:
jmp .Lnormal_path

.Lcatch:
; Catch block code
...

.Lnormal_path:
; Continuation after try-catch
```

The actual implementation varies significantly between compilers and platforms, often using complex unwinding tables rather than explicit code like the simplified example above.

## Data Flow Analysis

Data flow analysis tracks how data values are created, modified, and used throughout a program. This analysis helps understand the program's logic and identify important algorithms.

### Use-Definition Chains

A use-definition (UD) chain links each use of a variable to all possible definitions (assignments) that could reach that use. In assembly analysis, this involves tracking register and memory values:

```assembly
mov eax, 5          ; Definition of eax
add ebx, eax        ; Use of eax, definition of ebx
mov [rdi], ebx      ; Use of ebx, definition of memory at [rdi]
```

Constructing UD chains helps understand data dependencies and how values propagate through the program.

### Taint Analysis

Taint analysis tracks how "tainted" data (typically user input) flows through a program. This is particularly valuable for security analysis:

```assembly
; Read user input into buffer at [rsp+16]
lea rcx, [rsp+16]   ; First parameter: buffer address
mov edx, 100        ; Second parameter: buffer size
call _read_input

; Use the input without validation
mov rax, [rsp+16]   ; Load first 8 bytes of input
call rax            ; Call address from user input (dangerous!)
```

Identifying such flows helps locate potential vulnerabilities like buffer overflows, format string vulnerabilities, or command injection.

### Constant Propagation

Constant propagation tracks known constant values through the program, which can simplify analysis by resolving computed values statically:

```assembly
mov eax, 5          ; eax = 5
mov ebx, 3          ; ebx = 3
add eax, ebx        ; eax = 8
shl eax, 2          ; eax = 32
mov ecx, [eax+base] ; Access table at base+32
```

Knowing that `eax` contains 32 at the last instruction helps understand that the code is accessing a specific table entry.

### Alias Analysis

Alias analysis determines when different pointers might reference the same memory location. This is crucial for understanding memory access patterns:

```assembly
mov rax, [rbp-8]    ; Load pointer from local variable
mov rcx, [rbp-16]   ; Load another pointer
mov [rax], 42       ; Write to first pointer
mov rdx, [rcx]      ; Read from second pointer - might read 42 if rax and rcx point to same location
```

Identifying potential aliases helps track data flow through memory and understand complex pointer manipulations.

## Pattern Recognition and Signature Matching

Recognizing common code patterns dramatically accelerates reverse engineering by allowing you to identify known functionality rather than analyzing it from scratch.

### Compiler-Specific Patterns

Different compilers generate distinctive code patterns for common operations:

#### Function Prologues and Epilogues

**MSVC x64:**
```assembly
; Typical MSVC x64 function prologue
sub rsp, 40         ; Allocate stack space (with alignment)
mov [rsp+32], rbx   ; Save non-volatile registers
```

**GCC x64:**
```assembly
; Typical GCC x64 function prologue
push rbp
mov rbp, rsp
push rbx            ; Save used callee-saved registers
sub rsp, 24         ; Allocate local variables (with alignment)
```

#### Memory Allocation

**MSVC Heap Allocation:**
```assembly
; malloc(size) in MSVC
mov rcx, size       ; First parameter: size
call malloc
```

**GCC Heap Allocation:**
```assembly
; malloc(size) in GCC
mov rdi, size       ; First parameter: size
call malloc@PLT
```

### Standard Library Function Signatures

Standard library functions have characteristic patterns that can be recognized even when symbol information is stripped:

#### String Functions

**strlen implementation:**
```assembly
; Simplified strlen pattern
xor eax, eax        ; Initialize counter/index
.loop:
cmp byte ptr [rdi+rax], 0  ; Check for null terminator
je .done
inc rax
jmp .loop
.done:
ret                 ; Return length in eax
```

**memcpy implementation:**
```assembly
; Simplified memcpy pattern
xor eax, eax        ; Initialize counter/index
.loop:
cmp rax, rdx        ; Compare counter with size
jge .done
mov cl, [rsi+rax]   ; Read byte from source
mov [rdi+rax], cl   ; Write byte to destination
inc rax
jmp .loop
.done:
mov rax, rdi        ; Return destination pointer
ret
```

#### Memory Management

**malloc/free patterns** often involve specific interactions with heap management functions and data structures.

#### I/O Operations

**File operations** like open, read, write have distinctive parameter patterns and system call usage.

### Cryptographic Algorithm Detection

Cryptographic algorithms have distinctive characteristics that make them recognizable:

#### Constant Tables

Many cryptographic algorithms use predefined constant tables:

```assembly
; AES S-box lookup
movzx eax, byte ptr [rdi]   ; Get input byte
mov al, [.sbox + rax]       ; Look up substitution

.sbox:
db 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, ...
```

#### Bitwise Operations

Cryptographic algorithms typically use extensive bitwise operations:

```assembly
; SHA-256 round operations (simplified)
mov eax, [rdi+0]    ; Load state word
ror eax, 2
xor eax, [rdi+0]
ror eax, 11
xor eax, [rdi+0]
ror eax, 7
```

#### Block Processing Loops

Many algorithms process data in fixed-size blocks with multiple rounds:

```assembly
; Block cipher processing loop
mov rcx, [rbp-8]    ; Load block count
test rcx, rcx
jz .done
.block_loop:
; Process one block
...
dec rcx
jnz .block_loop
```

### Data Structure Recognition

Identifying common data structures helps understand how a program organizes and processes information.

#### Linked Lists

Linked list traversal has a characteristic pattern:

```assembly
; Linked list traversal
mov rax, [list_head]  ; Start with head pointer
.loop:
test rax, rax       ; Check for null (end of list)
jz .done
; Process node
mov rdi, [rax+8]    ; Access node data
call process_data
; Move to next node
mov rax, [rax]      ; rax = rax->next
jmp .loop
```

#### Trees

Tree traversal often involves recursion or an explicit stack:

```assembly
; Binary tree traversal (recursive, simplified)
; rdi = node pointer
traverse_tree:
test rdi, rdi       ; Check for null node
jz .return

; Process current node
push rdi
call process_node

; Traverse left subtree
mov rdi, [rdi+8]    ; rdi = node->left
call traverse_tree

; Traverse right subtree
pop rdi             ; Restore current node
mov rdi, [rdi+16]   ; rdi = node->right
call traverse_tree

.return:
ret
```

#### Hash Tables

Hash table operations involve hash computation followed by bucket access:

```assembly
; Hash table lookup (simplified)
; rdi = hash table, rsi = key
mov rdx, rsi        ; Copy key for hashing
call compute_hash   ; Hash function returns hash in eax
and eax, [rdi+8]    ; Mask with table size-1 (assuming power of 2)
shl eax, 4          ; Multiply by entry size (e.g., 16 bytes)
add rax, [rdi+16]   ; Add bucket array base address
; Now rax points to the bucket
```

## Advanced Static Analysis Techniques

Beyond the fundamental approaches, several advanced techniques can provide deeper insights into program behavior.

### Symbolic Execution

Symbolic execution analyzes a program by tracking symbolic rather than concrete values. Instead of executing with specific inputs, it represents inputs as symbols and builds expressions that describe how outputs relate to inputs.

For example, consider this simple function:

```assembly
; int abs(int x)
; x in edi
abs_function:
  mov eax, edi      ; eax = x
  test eax, eax     ; Set flags based on x
  jge .positive     ; Jump if x >= 0
  neg eax           ; eax = -eax (if x < 0)
.positive:
  ret               ; Return eax
```

Symbolic execution would track:
1. `eax = X` (symbolic input)
2. If `X >= 0`, then result is `X`
3. If `X < 0`, then result is `-X`
4. Therefore, the function returns `|X|` (absolute value)

Tools like KLEE, angr, and Triton provide symbolic execution capabilities for binary analysis.

### Value Set Analysis

Value Set Analysis (VSA) tracks the possible values of registers and memory locations at each program point. Unlike concrete execution, which tracks single values, VSA tracks sets or ranges of values.

For example:

```assembly
mov eax, [user_input]  ; Load user input
and eax, 3             ; Mask with 3
```

VSA would determine that after these instructions, `eax` must be in the set {0, 1, 2, 3}, regardless of the input value.

This analysis helps understand program constraints and identify unreachable code paths.

### Type Reconstruction

Type reconstruction infers data types from usage patterns, helping bridge the gap between assembly and higher-level understanding.

Advanced type reconstruction considers:

#### Size-Based Inference

```assembly
mov eax, [rdi]      ; 4-byte access suggests int or float
movzx ecx, byte ptr [rdi+4]  ; 1-byte access suggests char or bool
```

#### Operation-Based Inference

```assembly
; Pointer arithmetic
shl rsi, 3          ; Multiply index by 8
add rsi, [rbp-16]   ; Add to base address
mov rax, [rsi]      ; Access array of 8-byte elements

; Floating-point operations
movss xmm0, [rdi]   ; Load as float
addss xmm0, xmm1    ; Float addition
```

#### Field Access Patterns

```assembly
; Structure field access pattern
mov rax, [rdi]      ; Access field at offset 0
mov rcx, [rdi+8]    ; Access field at offset 8
mov rdx, [rdi+16]   ; Access field at offset 16
```

By combining these inferences, type reconstruction can produce C-like struct definitions and variable types that make the disassembly more readable.

### Decompilation

Decompilation is the process of converting assembly code back to a higher-level representation, typically C-like pseudocode. Modern decompilers like Hex-Rays, Ghidra's decompiler, and RetDec perform sophisticated analysis to recover source-like code.

The decompilation process typically involves:

1. **Control flow analysis**: Identifying basic blocks and control structures
2. **Data flow analysis**: Tracking variable definitions and uses
3. **Type analysis**: Inferring variable and function types
4. **Structure recovery**: Reconstructing loops, conditionals, and switch statements
5. **Expression propagation**: Combining operations into higher-level expressions

For example, this assembly code:

```assembly
mov eax, [rdi]      ; Load first element
mov ecx, [rdi+4]    ; Load second element
add eax, ecx        ; Add them
mov ecx, [rdi+8]    ; Load third element
imul ecx            ; Multiply by third element
ret                 ; Return result
```

Might decompile to:

```c
int function(int *arr) {
  return (arr[0] + arr[1]) * arr[2];
}
```

Decompilers significantly accelerate reverse engineering but aren't perfect. They may produce confusing or incorrect output for complex code, optimized binaries, or unusual programming patterns. Understanding assembly remains essential for verifying and correcting decompiler output.

## Practical Static Analysis Workflows

Let's explore practical workflows for applying static analysis techniques to real-world reverse engineering tasks.

### Initial Binary Reconnaissance

Before diving into detailed analysis, gather basic information about the binary:

1. **Identify the file type and architecture**
   ```bash
   $ file binary
   binary: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=0123456789abcdef, stripped
   ```

2. **Check for symbols and sections**
   ```bash
   $ nm binary
   nm: binary: no symbols
   $ readelf -S binary
   [Section headers output...]
   ```

3. **Identify imported and exported functions**
   ```bash
   $ objdump -T binary
   [Dynamic symbol table output...]
   ```

4. **Examine strings for clues**
   ```bash
   $ strings binary | grep -i password
   Enter password:
   Password incorrect
   ```

This initial reconnaissance helps focus your analysis on promising areas.

### Function Identification and Prioritization

With the binary loaded in a disassembler:

1. **Review automatically identified functions**
   - Check the function list in IDA Pro, Ghidra, or Binary Ninja
   - Look for descriptive names or patterns in unnamed functions

2. **Identify key functions based on cross-references**
   - Functions referenced by the entry point
   - Functions that reference interesting strings
   - Functions that call important APIs (file, network, crypto)

3. **Prioritize functions for analysis**
   - Start with the main function or program entry point
   - Focus on functions that handle user input or sensitive operations
   - Defer analysis of library or utility functions

### Iterative Function Analysis

For each prioritized function:

1. **Examine function signature and frame**
   - Identify parameters and return value
   - Note local variable usage

2. **Analyze control flow**
   - Review the control flow graph
   - Identify loops and conditional branches
   - Understand the high-level structure

3. **Track key data flows**
   - Follow user input through the function
   - Track how return values are calculated
   - Identify important memory accesses

4. **Annotate the disassembly**
   - Rename variables and functions meaningfully
   - Add comments explaining complex logic
   - Create structure definitions for data types

5. **Review decompiler output**
   - Compare with your assembly analysis
   - Correct any obvious decompiler errors
   - Refine your understanding based on the higher-level view

### Algorithm Identification

When you suspect a function implements a known algorithm:

1. **Look for telltale constants**
   - Cryptographic algorithms often use specific initialization values or tables
   - Hashing functions typically have distinctive constants

2. **Analyze the overall structure**
   - Block processing loops
   - Round functions
   - Characteristic transformations

3. **Compare with reference implementations**
   - Compile known algorithms and compare the assembly
   - Check for matching patterns in cryptographic libraries

4. **Test hypotheses with sample inputs**
   - If possible, run the function with known inputs
   - Compare results with reference implementations

### Collaborative and Iterative Analysis

Complex binaries benefit from collaborative and iterative analysis:

1. **Divide and conquer**
   - Assign different modules or functions to different analysts
   - Share findings regularly

2. **Build a knowledge base**
   - Document identified functions and algorithms
   - Create a dictionary of program-specific terms and structures

3. **Iteratively refine understanding**
   - Revisit previously analyzed functions with new insights
   - Update annotations and documentation

4. **Combine static and dynamic analysis**
   - Use dynamic analysis to verify static findings
   - Update static analysis based on runtime observations

## Case Studies in Static Analysis

Let's examine two case studies that demonstrate static analysis techniques in action.

### Case Study 1: Identifying a Custom Encryption Routine

Consider this simplified assembly function from a proprietary file format parser:

```assembly
custom_encrypt:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    sub rsp, 16
    
    ; Parameters: rdi = input buffer, rsi = output buffer, rdx = length, rcx = key
    mov r12, rdi        ; r12 = input buffer
    mov r13, rsi        ; r13 = output buffer
    mov rbx, rdx        ; rbx = length
    mov [rbp-16], rcx   ; Store key on stack
    
    ; Initialize counter
    xor rax, rax
    
.loop:
    ; Check if we've processed all bytes
    cmp rax, rbx
    jge .done
    
    ; Load input byte
    movzx edx, byte ptr [r12+rax]
    
    ; XOR with key byte (key is 4 bytes, so we cycle through it)
    mov rcx, rax
    and rcx, 3          ; rcx = rax % 4
    movzx ecx, byte ptr [rbp-16+rcx]  ; Load key byte
    xor edx, ecx        ; XOR input byte with key byte
    
    ; Substitute through S-box
    lea rsi, [rip+.sbox]
    movzx edx, byte ptr [rsi+rdx]  ; Substitute
    
    ; Store encrypted byte
    mov [r13+rax], dl
    
    ; Increment counter and continue
    inc rax
    jmp .loop
    
.done:
    add rsp, 16
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
    
.sbox:
    db 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
    db 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
    ; ... rest of S-box (256 bytes total)
```

**Static Analysis Approach:**

1. **Function Signature Analysis**
   - Four parameters: input buffer, output buffer, length, key
   - No return value (void function)

2. **Control Flow Analysis**
   - Single loop processing each byte
   - No complex branching

3. **Algorithm Identification**
   - XOR operation with cycling key bytes
   - Substitution using a 256-byte table
   - The S-box values match the AES S-box

4. **Conclusion**
   - This is a simple substitution-permutation cipher
   - It uses XOR with a 4-byte key followed by AES S-box substitution
   - Not cryptographically strong (short key, no diffusion)

With this understanding, we can document the algorithm and potentially create a decryption routine by reversing the operations.

### Case Study 2: Reconstructing a Proprietary File Format

Consider this function that parses a file header:

```assembly
parse_file_header:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; rdi = file handle, rsi = header struct pointer
    mov [rbp-8], rdi    ; Store file handle
    mov [rbp-16], rsi   ; Store header struct pointer
    
    ; Read magic number (4 bytes)
    mov rdi, [rbp-8]    ; File handle
    mov rsi, [rbp-16]   ; Header struct (first field is magic)
    mov rdx, 4          ; Read 4 bytes
    call read_file
    cmp rax, 4
    jne .error_invalid
    
    ; Check magic number "MYFF"
    mov rsi, [rbp-16]
    cmp dword ptr [rsi], 0x4646594d  ; "MYFF" in little-endian
    jne .error_invalid
    
    ; Read version (2 bytes)
    mov rdi, [rbp-8]
    lea rsi, [rbp-16+4]  ; Header struct + 4 (version field)
    mov rdx, 2
    call read_file
    cmp rax, 2
    jne .error_invalid
    
    ; Read flags (2 bytes)
    mov rdi, [rbp-8]
    lea rsi, [rbp-16+6]  ; Header struct + 6 (flags field)
    mov rdx, 2
    call read_file
    cmp rax, 2
    jne .error_invalid
    
    ; Read entry count (4 bytes)
    mov rdi, [rbp-8]
    lea rsi, [rbp-16+8]  ; Header struct + 8 (entry_count field)
    mov rdx, 4
    call read_file
    cmp rax, 4
    jne .error_invalid
    
    ; Read timestamp (8 bytes)
    mov rdi, [rbp-8]
    lea rsi, [rbp-16+12]  ; Header struct + 12 (timestamp field)
    mov rdx, 8
    call read_file
    cmp rax, 8
    jne .error_invalid
    
    ; Success
    mov eax, 1
    jmp .done
    
.error_invalid:
    xor eax, eax
    
.done:
    leave
    ret
```

**Static Analysis Approach:**

1. **Function Signature Analysis**
   - Two parameters: file handle and header struct pointer
   - Returns 1 on success, 0 on error

2. **Data Structure Analysis**
   - Sequential reads into different offsets of the header struct
   - Field sizes and offsets reveal the structure layout

3. **File Format Reconstruction**
   - Magic number: "MYFF" (4 bytes)
   - Version: 2 bytes
   - Flags: 2 bytes
   - Entry count: 4 bytes
   - Timestamp: 8 bytes
   - Total header size: 20 bytes

4. **Conclusion**
   - We can reconstruct the header struct definition:
     ```c
     struct file_header {
         char magic[4];      // "MYFF"
         uint16_t version;
         uint16_t flags;
         uint32_t entry_count;
         uint64_t timestamp;
     };
     ```

This analysis allows us to understand the file format and potentially create tools to parse or generate compatible files.

## Challenges and Limitations of Static Analysis

While powerful, static analysis faces several challenges and limitations:

### Obfuscation Techniques

Code obfuscation deliberately makes static analysis difficult through techniques like:

- **Control flow obfuscation**: Adding spurious branches and jumps
- **Opaque predicates**: Conditions that always evaluate the same way but are difficult to determine statically
- **Instruction substitution**: Replacing simple operations with complex equivalents
- **Dead code insertion**: Adding code that never executes
- **String encryption**: Encrypting strings and decrypting them at runtime

These techniques can significantly slow down analysis and require combining static and dynamic approaches.

### Anti-Disassembly Tricks

Some binaries employ anti-disassembly techniques that cause disassemblers to produce incorrect output:

- **Overlapping instructions**: Creating valid instruction sequences that can be interpreted differently depending on the entry point
- **Data in code sections**: Inserting data bytes that disassemblers misinterpret as instructions
- **Self-modifying code**: Code that changes itself at runtime
- **Junk byte insertion**: Adding bytes that cause disassembly to go out of sync

Recognizing these techniques requires experience and careful analysis.

### Indirect Jumps and Calls

Indirect control flow through function pointers, virtual methods, or jump tables complicates static analysis:

```assembly
; Indirect call through function pointer
mov rax, [rdi+8]    ; Load function pointer
call rax            ; Call through pointer

; Jump table
mov eax, [rdi]      ; Load index
cmp eax, 5          ; Bounds check
ja .default
jmp [.table+rax*8]  ; Jump based on index
```

These constructs make it difficult to determine all possible execution paths statically.

### Dynamic Code Generation

Some programs generate or modify code at runtime, which is invisible to static analysis:

- JIT (Just-In-Time) compilation
- Runtime code patching
- Self-extracting or self-decrypting code

These techniques require dynamic analysis to fully understand.

### Limitations of Decompilers

Decompilers have inherent limitations:

- **Type recovery limitations**: Complex types may not be accurately reconstructed
- **Optimized code challenges**: Heavily optimized code may decompile to confusing output
- **Custom calling conventions**: Non-standard parameter passing can confuse decompilers
- **Inline assembly**: Assembly blocks in the original code may not decompile cleanly

Always verify decompiler output against the assembly for critical code sections.

## Tools for Static Analysis

Numerous tools support static binary analysis, each with different strengths:

### Disassemblers and Decompilers

- **IDA Pro**: Industry-standard disassembler with powerful analysis capabilities and the Hex-Rays decompiler
- **Ghidra**: NSA-developed open-source disassembler and decompiler with advanced features
- **Binary Ninja**: Modern disassembler with a focus on API and extensibility
- **Radare2/Cutter**: Open-source disassembly framework with a growing feature set
- **RetDec**: Open-source retargetable decompiler

### Specialized Analysis Tools

- **angr**: Python framework for binary analysis with symbolic execution capabilities
- **BARF**: Binary Analysis and Reverse engineering Framework
- **Triton**: Dynamic Binary Analysis framework for building program analysis tools
- **Capstone**: Lightweight multi-platform, multi-architecture disassembly framework
- **Snowman**: Native code to C/C++ decompiler

### Static Analysis Frameworks

- **BAP (Binary Analysis Platform)**: OCaml framework for binary analysis
- **Pharos**: Framework for automated static analysis of binaries
- **CodeSurfer**: Program understanding and analysis tool
- **Jakstab**: Abstract Interpretation-based static analysis for binaries

### Visualization Tools

- **Gephi**: Graph visualization for complex control flow analysis
- **GraphViz**: Graph visualization used by many analysis tools
- **Visjs**: JavaScript visualization library useful for web-based analysis tools

## Summary

Static code analysis is a powerful approach for understanding program behavior without execution. In this chapter, we've explored techniques for analyzing binary code at multiple levels:

- **Function analysis**: Identifying functions, their signatures, and their purposes
- **Control flow analysis**: Understanding how execution moves through the program
- **Data flow analysis**: Tracking how data is transformed and propagated
- **Pattern recognition**: Identifying common algorithms and library code
- **Advanced techniques**: Using symbolic execution, type reconstruction, and decompilation

Effective static analysis combines these techniques with a systematic workflow, moving from initial reconnaissance to detailed function analysis and algorithm identification. While static analysis has limitations, particularly when facing obfuscation or dynamic code generation, it remains a fundamental approach in the reverse engineer's toolkit.

In the next chapter, we'll explore dynamic analysis techniques that complement static analysis by observing program behavior during execution.

## Exercises

1. **Function Signature Recovery**: Choose a stripped binary (with no debugging symbols) and select three functions. Using only static analysis, determine each function's parameters, return value, and purpose. Document your reasoning process.

2. **Control Flow Analysis**: Find a function with complex control flow in a binary of your choice. Draw its control flow graph manually, identifying loops, conditional branches, and exception handling. Compare your manual analysis with the graph generated by a tool like IDA Pro or Ghidra.

3. **Algorithm Identification**: Locate a cryptographic function in an open-source binary (e.g., OpenSSL, GnuPG). Using static analysis, identify which algorithm it implements and key characteristics that led to your conclusion.

4. **Data Structure Reconstruction**: Find a binary that processes a structured file format. Through static analysis of its parsing functions, reconstruct the file format's structure and document it as C struct definitions.

5. **Decompiler Evaluation**: Select a function from a binary with available source code. Decompile it using a tool like Ghidra or Hex-Rays, then compare the decompiled output with the original source. Identify discrepancies and explain why the decompiler might have generated different code.