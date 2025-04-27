---

layout: chapter
title: "Chapter 9: Reverse Engineering Memory Structures"
part: "Part 3: Dynamic Analysis and Debugging"
order: 9
---


Understanding how programs organize and use memory is fundamental to reverse engineering. Memory structures reveal the architecture of a program, its data flow, and often its underlying algorithms. This chapter explores techniques for identifying, analyzing, and manipulating memory structures during dynamic analysis, providing insights that static analysis alone cannot reveal.

## Memory Organization Fundamentals

Before diving into reverse engineering techniques, let's review how programs organize memory and the structures they commonly use.

### Process Memory Layout

Modern operating systems divide a process's virtual address space into distinct regions:

#### Windows Memory Regions

- **Image**: Contains the executable code and static data (.text, .data, .rdata sections)
- **Heap**: Dynamically allocated memory managed by the heap manager
- **Stack**: Local variables and function call information
- **Mapped files**: Shared libraries (DLLs) and memory-mapped files
- **Private memory**: Process-specific allocations via VirtualAlloc

#### Linux/Unix Memory Regions

- **Text segment**: Read-only executable code
- **Data segment**: Initialized global and static variables
- **BSS segment**: Uninitialized global and static variables
- **Heap**: Dynamic memory allocations via malloc/brk
- **Memory mappings**: Shared libraries and mmap allocations
- **Stack**: Function call frames and local variables

Understanding these regions helps focus your analysis on the most relevant areas:

```
# Examining memory regions in GDB (Linux)
(gdb) info proc mappings

# Examining memory regions in WinDbg (Windows)
!address
```

### Common Memory Structures

Programs use various structures to organize data in memory:

#### Primitive Data Types

The building blocks of more complex structures:

- **Integers**: 8, 16, 32, or 64-bit values (signed or unsigned)
- **Floating-point numbers**: Single or double precision
- **Characters**: ASCII, Unicode (UTF-8, UTF-16, etc.)
- **Booleans**: True/false values (often represented as integers)
- **Pointers**: Memory addresses (32 or 64-bit depending on architecture)

#### Composite Structures

Combinations of primitive types and other structures:

- **Arrays**: Contiguous elements of the same type
- **Structures/Records**: Collections of fields of different types
- **Unions**: Overlapping fields sharing the same memory
- **Classes**: Structures with associated methods (in object-oriented languages)

#### Dynamic Structures

Structures that grow or shrink during execution:

- **Linked lists**: Nodes connected by pointers
- **Trees**: Hierarchical structures with parent-child relationships
- **Graphs**: Networks of nodes with arbitrary connections
- **Hash tables**: Arrays of buckets containing key-value pairs
- **Dynamic arrays**: Resizable arrays (vectors, ArrayLists, etc.)

## Identifying Memory Structures

When reverse engineering, you'll need to identify these structures without source code or documentation.

### Pattern Recognition

Certain patterns in memory indicate specific structure types:

#### Pointer Patterns

Sequences of valid memory addresses often indicate linked structures:

- **Linked lists**: A chain of pointers where each points to the next node
- **Trees**: Nodes containing multiple pointers to child nodes
- **Virtual method tables (vtables)**: Arrays of function pointers

Example pattern for a doubly-linked list:
```
Node1: [prev=NULL, next=addr2, data=...]
Node2: [prev=addr1, next=addr3, data=...]
Node3: [prev=addr2, next=NULL, data=...]
```

#### Size and Count Fields

Many structures include metadata about their contents:

- **Arrays**: Often preceded by a length field
- **Strings**: Usually include or end with a length or terminator
- **Collections**: Frequently contain count and capacity fields

Example pattern for a dynamic array:
```
Vector: [count=3, capacity=8, data_ptr=addr1]
addr1: [element1, element2, element3, unused, unused, ...]
```

#### Type Signatures

Programs often include type information in their structures:

- **Magic numbers**: Constant values identifying a structure type
- **Type fields**: Enumerated values indicating the object type
- **Size fields**: Values matching the structure's memory footprint

Example of a type signature in a file format header:
```
Header: [magic="PNG\r\n\x1A\n", width=1024, height=768, ...]
```

### Memory Access Patterns

Observing how code accesses memory reveals structure organization:

#### Array Access

Array access typically involves:

1. A base address
2. An index calculation (index * element_size)
3. Accessing the calculated address

In assembly, this often looks like:
```assembly
; Accessing array[i] where each element is 4 bytes
mov eax, [base_addr + ecx*4]  ; ecx contains the index
```

#### Structure Field Access

Accessing structure fields involves fixed offsets from a base address:

```assembly
; Accessing fields of a structure at address in ebx
mov eax, [ebx]        ; First field (offset 0)
mov ecx, [ebx + 8]    ; Field at offset 8
mov edx, [ebx + 16]   ; Field at offset 16
```

By tracking these offsets, you can reconstruct the structure layout.

#### Linked Structure Traversal

Traversing linked structures involves loading a pointer and following it:

```assembly
; Traversing a linked list
mov ebx, [list_head]  ; Load first node address
loop_start:
test ebx, ebx         ; Check if pointer is NULL
jz loop_end           ; Exit if end of list
; Process node data
mov eax, [ebx + 8]    ; Access node data field
; Move to next node
mov ebx, [ebx]        ; Load next pointer
jmp loop_start        ; Continue traversal
loop_end:
```

### Heap Analysis

The heap contains most dynamic structures and is a rich source of information:

#### Heap Block Metadata

Heap allocators add metadata to each allocation:

- **Block size**: The size of the allocated block
- **Status flags**: Whether the block is allocated or free
- **Adjacent block pointers**: Links to nearby blocks

This metadata helps identify the boundaries of objects:

```
# WinDbg heap block examination
!heap -p -a 0x00d45678  ; Examine block at address
```

#### Allocation Tracking

Monitoring memory allocations reveals structure creation:

```
# Setting breakpoints on allocation functions in GDB
break malloc
command
  printf "malloc(%d) = %p\n", $rdi, $rax
  continue
end
```

Key information to track:
- **Allocation size**: Indicates the structure size
- **Allocation patterns**: Sequences revealing container growth
- **Deallocation order**: Shows object lifetime and relationships

## Analyzing Complex Structures

Once you've identified basic structures, you can analyze more complex arrangements.

### Reconstructing Structure Definitions

Create C-style struct definitions to document your findings:

```c
// Example reconstructed structure
typedef struct _Node {
    struct _Node* next;     // Offset 0x00
    struct _Node* prev;     // Offset 0x08
    int id;                 // Offset 0x10
    char name[32];          // Offset 0x14
    void* data;             // Offset 0x34
    int data_size;          // Offset 0x3C
} Node;  // Total size: 0x40 (64) bytes
```

Tools like WinDbg's `dt` command can help visualize these structures:

```
# Define and use a structure in WinDbg
.struct Node
+0x00 next : Ptr64 Node
+0x08 prev : Ptr64 Node
+0x10 id : Int4B
+0x14 name : [32] UChar
+0x34 data : Ptr64 Void
+0x3c data_size : Int4B

# Use the structure to format memory
dt Node 0x00d45678
```

### Object-Oriented Structures

Object-oriented programs use additional structures:

#### Virtual Method Tables (vtables)

Vtables are arrays of function pointers implementing polymorphism:

```
Object: [vtable_ptr=0x401000, field1, field2, ...]
0x401000 (vtable): [method1_addr, method2_addr, method3_addr, ...]
```

Identifying vtables helps understand class hierarchies:

1. Look for pointers to code sections at the beginning of objects
2. Follow these pointers to find tables of function pointers
3. Analyze the functions to determine their purpose

#### Inheritance Relationships

Derived classes typically embed their parent class structure:

```
BaseClass: [vtable_ptr, base_field1, base_field2]
DerivedClass: [vtable_ptr, base_field1, base_field2, derived_field1, ...]
```

To identify inheritance:

1. Compare object layouts to find common prefixes
2. Look for vtable similarities (derived classes often extend the parent's vtable)
3. Analyze how objects are used interchangeably in the code

### Container Classes

Modern programs use standard container implementations:

#### Standard Template Library (C++)

C++ STL containers have recognizable memory patterns:

- **std::vector**: [size, capacity, data_pointer]
- **std::list**: Doubly-linked nodes with next/prev pointers
- **std::map/std::set**: Red-black trees with parent/child pointers and color flags
- **std::unordered_map**: Hash table with buckets and linked nodes

#### Java Collections

Java collection classes have their own patterns:

- **ArrayList**: Object header, size field, capacity field, element array
- **LinkedList**: Object header with references to first/last nodes
- **HashMap**: Object header, buckets array, size fields, load factor

### String Representations

Strings have various representations depending on the language and encoding:

#### C-style Strings

Null-terminated character arrays:
```
"Hello" = [48 65 6C 6C 6F 00] (ASCII)
```

#### Length-Prefixed Strings

Strings with explicit length information:
```
"Hello" = [05 00 00 00 48 65 6C 6C 6F] (32-bit length + ASCII)
```

#### Object-Based Strings

Strings as objects with metadata:
```
String object: [vtable_ptr, length=5, capacity=8, data_ptr]
data_ptr: [48 65 6C 6C 6F ...] ("Hello")
```

#### Unicode Strings

Multi-byte character representations:
```
"Hello" in UTF-16LE = [48 00 65 00 6C 00 6C 00 6F 00 00 00]
```

## Memory Structure Manipulation

Once you understand memory structures, you can manipulate them to alter program behavior.

### Direct Memory Modification

Changing values in memory can modify program state:

```
# Modifying a structure field in GDB
set {int}0x7fffffffe890 = 42

# Modifying a string in WinDbg
edit -a 0x00d45678 "New string value"
```

Common modifications include:
- **Flag toggles**: Changing boolean values to enable/disable features
- **Counter manipulation**: Altering count fields to bypass limits
- **Pointer redirection**: Changing pointers to reference different objects
- **Data replacement**: Substituting sensitive data with modified values

### Structure Injection

Creating new structures in memory extends program functionality:

1. **Allocate memory**: Find or create space for the new structure
2. **Construct the structure**: Fill the memory with appropriate values
3. **Link into existing structures**: Update pointers to include your structure

Example: Injecting a new node into a linked list
```
# Original list: A -> B -> C

# 1. Allocate memory for new node D
new_node = malloc(sizeof(Node))

# 2. Construct the node
new_node->data = "Injected Data"
new_node->next = B_node_addr
new_node->prev = A_node_addr

# 3. Link into the list
A_node->next = new_node
B_node->prev = new_node

# Result: A -> D -> B -> C
```

### Hooking Object Methods

Replacing methods in vtables allows intercepting object behavior:

1. **Identify the vtable**: Find the object's vtable pointer
2. **Locate the target method**: Determine the method's index in the vtable
3. **Save the original pointer**: Store the original method address
4. **Replace with hook**: Point the vtable entry to your hook function
5. **Implement the hook**: Call the original method as needed

```c
// Pseudocode for vtable hooking
void* original_method = object->vtable[method_index];
object->vtable[method_index] = my_hook_function;

void my_hook_function(Object* this, ...) {
    // Pre-processing
    printf("Method called with arg: %d\n", some_arg);
    
    // Call original method
    original_method(this, ...);
    
    // Post-processing
    printf("Method returned\n");
}
```

## Case Study: Reverse Engineering a Database Format

Let's apply these techniques to reverse engineer a proprietary database file format loaded into memory.

### Initial Reconnaissance

We start by observing the program loading the database:

1. **File I/O monitoring** shows the program reading a 2MB file into memory
2. **Memory allocation tracking** reveals a large allocation followed by many smaller ones
3. **String searches** find table and column names scattered throughout memory

### Structure Identification

By setting breakpoints on memory access and examining patterns:

1. We identify a **header structure** at the beginning of the loaded file:
   ```c
   struct DatabaseHeader {
       char magic[8];        // "PROPDB\0\0"
       uint32_t version;     // Format version (e.g., 0x00010002)
       uint32_t table_count; // Number of tables
       uint32_t flags;       // Various flags
       uint64_t table_offset; // Pointer to table definitions
   };
   ```

2. Following the `table_offset`, we find an array of **table definitions**:
   ```c
   struct TableDef {
       uint32_t id;          // Table identifier
       uint32_t column_count; // Number of columns
       uint32_t row_count;   // Number of rows
       uint32_t flags;       // Table flags
       uint64_t name_offset; // Pointer to table name
       uint64_t column_offset; // Pointer to column definitions
       uint64_t data_offset; // Pointer to row data
   };
   ```

3. Each table has an array of **column definitions**:
   ```c
   struct ColumnDef {
       uint32_t id;          // Column identifier
       uint32_t type;        // Data type (1=int, 2=float, 3=string, etc.)
       uint32_t flags;       // Column flags
       uint32_t offset;      // Offset within row structure
       uint64_t name_offset; // Pointer to column name
   };
   ```

4. The actual **data** is stored in a custom format:
   - Fixed-length rows for numeric data
   - Variable-length strings stored in a separate area with pointers
   - Indexes implemented as B-trees for fast lookups

### Memory Access Analysis

By tracing code that accesses these structures:

1. We discover the **query execution path**:
   - Queries are parsed into an internal representation
   - Table definitions are located by name or ID
   - For indexed queries, the B-tree is traversed
   - For sequential scans, each row is examined
   - Results are collected into a temporary structure

2. We identify the **data modification process**:
   - Changes are first written to a transaction log
   - Modified rows are updated in memory
   - A background thread periodically flushes changes to disk

### Structure Manipulation

With this understanding, we can manipulate the database:

1. **Data modification**: Directly change values in the row data
2. **Schema alteration**: Modify column definitions to change types or flags
3. **Access control bypass**: Change permission flags in table definitions
4. **Query injection**: Insert custom entries into the query processing structures

### Practical Application

This reverse engineering enables several useful capabilities:

1. **Data recovery**: Extract data from corrupted database files
2. **Format conversion**: Create tools to convert to standard formats like SQL
3. **Performance optimization**: Understand and improve inefficient queries
4. **Security assessment**: Identify vulnerabilities in the database implementation

## Advanced Memory Analysis Techniques

Beyond basic structure analysis, several advanced techniques provide deeper insights.

### Memory Forensics

Memory forensics techniques help analyze complex or obfuscated structures:

#### Memory Scanning

Scanning memory for patterns can locate structures:

```python
# Pseudocode for scanning memory for credit card numbers
def scan_for_cc_numbers(memory_dump):
    # Regular expression for common credit card formats
    cc_pattern = re.compile(b'[3-6]\d{3}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}')
    
    # Scan memory in overlapping chunks
    for offset in range(0, len(memory_dump) - 20):
        chunk = memory_dump[offset:offset+20]
        if cc_pattern.match(chunk):
            print(f"Potential credit card at offset {offset}: {chunk}")
```

#### Pool Tag Scanning

On Windows, kernel structures often have identifiable pool tags:

```
# WinDbg pool tag scanning
!poolused 4 Proc  # Find process objects by 'Proc' tag
```

#### Signature-Based Detection

Identifying structures by their unique signatures:

```python
# Pseudocode for finding C++ std::string objects
def find_std_strings(memory_dump):
    # Look for typical std::string layout (simplified)
    # [length(8 bytes), capacity(8 bytes), small string flag(1 byte)]
    for offset in range(0, len(memory_dump) - 17):
        length = struct.unpack("<Q", memory_dump[offset:offset+8])[0]
        capacity = struct.unpack("<Q", memory_dump[offset+8:offset+16])[0]
        
        # Validate potential std::string
        if 0 <= length <= capacity and capacity < 1000000:
            # Likely std::string found
            print(f"Potential std::string at {offset}: len={length}, cap={capacity}")
```

### Heap Profiling

Analyzing heap usage patterns reveals program behavior:

#### Allocation Frequency Analysis

Tracking allocation patterns over time shows program phases:

```python
# Pseudocode for allocation frequency analysis
allocation_timeline = []

def track_allocation(timestamp, size, address):
    allocation_timeline.append((timestamp, size, address))

def analyze_timeline():
    # Group by time intervals
    intervals = {}
    for timestamp, size, _ in allocation_timeline:
        interval = timestamp // 1000  # Group by seconds
        if interval not in intervals:
            intervals[interval] = 0
        intervals[interval] += size
    
    # Plot allocation rate over time
    plot(intervals.keys(), intervals.values())
```

#### Memory Leak Detection

Identifying objects that accumulate without being freed:

```python
# Pseudocode for leak detection
active_allocations = {}

def track_malloc(address, size, callstack):
    active_allocations[address] = (size, callstack, time.time())

def track_free(address):
    if address in active_allocations:
        del active_allocations[address]

def find_leaks():
    # Group by callstack
    leaks_by_callstack = {}
    for address, (size, callstack, timestamp) in active_allocations.items():
        if callstack not in leaks_by_callstack:
            leaks_by_callstack[callstack] = []
        leaks_by_callstack[callstack].append((address, size, timestamp))
    
    # Sort by total size and age
    for callstack, allocations in leaks_by_callstack.items():
        total_size = sum(size for _, size, _ in allocations)
        oldest_age = max(time.time() - timestamp for _, _, timestamp in allocations)
        print(f"Potential leak: {len(allocations)} objects, {total_size} bytes, {oldest_age}s old")
        print(f"Callstack: {callstack}")
```

### Memory Diffing

Comparing memory states before and after operations reveals changes:

```python
# Pseudocode for memory diffing
def capture_memory_state(process, regions_of_interest):
    state = {}
    for start, size in regions_of_interest:
        state[(start, size)] = process.read_memory(start, size)
    return state

def compare_states(before, after):
    changes = []
    for region, before_data in before.items():
        start, size = region
        after_data = after.get(region)
        if after_data:
            # Find differences
            for i in range(size):
                if i < len(before_data) and i < len(after_data) and before_data[i] != after_data[i]:
                    changes.append((start + i, before_data[i], after_data[i]))
    return changes

# Usage
before = capture_memory_state(process, regions)
# Perform operation
after = capture_memory_state(process, regions)
changes = compare_states(before, after)
for address, old_value, new_value in changes:
    print(f"Change at 0x{address:x}: 0x{old_value:02x} -> 0x{new_value:02x}")
```

## Exercises

1. **Basic Structure Identification**:
   - Download a simple open-source program with known data structures
   - Use a debugger to locate these structures in memory
   - Document the memory layout and compare with the source code
   - Create a tool to dump and parse these structures from memory

2. **Linked Structure Navigation**:
   - Write a debugger script that traverses a linked list or tree
   - The script should print each node's content and structure
   - Test it on a program that uses standard container classes
   - Extend it to handle circular references and detect loops

3. **Custom Structure Reconstruction**:
   - Analyze a proprietary file format loaded into memory
   - Identify the header, metadata, and data sections
   - Create C/C++ struct definitions matching the memory layout
   - Write a parser that can extract data from memory dumps

4. **Memory Manipulation Challenge**:
   - Choose a program with a trial limitation or feature restriction
   - Identify the memory structures controlling this limitation
   - Develop a technique to modify these structures at runtime
   - Document the changes needed to bypass the restriction

## Summary

Reverse engineering memory structures is a powerful technique for understanding how programs work at a fundamental level. By analyzing how data is organized and accessed in memory, you can:

- **Reconstruct data structures** without source code
- **Understand algorithms** by observing their data manipulations
- **Modify program behavior** by altering memory contents
- **Extract sensitive information** from running processes
- **Bypass protection mechanisms** by manipulating control structures

Key skills developed in this chapter include:

- Recognizing common memory patterns
- Mapping memory access to high-level structures
- Reconstructing complex data relationships
- Manipulating memory to alter program behavior
- Applying forensic techniques to memory analysis

