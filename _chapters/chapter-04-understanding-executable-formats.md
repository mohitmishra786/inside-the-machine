---

layout: chapter
title: "Chapter 4: Understanding Executable Formats"
part: "Part 2: Disassembly and Analysis"
order: 4
---


Executable formats are the containers that hold program code and data in a structure the operating system can load and execute. They're the bridge between the source code a developer writes and the binary instructions a computer executes. Understanding these formats is fundamental to reverse engineering because they define how to locate and interpret the program's components.

In this chapter, we'll explore the major executable formats across different platforms, examining their structures, components, and the information they provide to reverse engineers. We'll also look at how to extract and analyze this information using practical tools and techniques.

## The Anatomy of Executable Files

Before diving into specific formats, let's understand the common elements that most executable files share, regardless of platform:

### Headers

Headers contain metadata about the executable, including:
- File type and format version
- Target architecture
- Entry point (where execution begins)
- Size and location of various sections
- Required permissions

Headers act as a map to the file's contents, telling the operating system how to interpret and load the executable.

### Code Sections

Code sections (often called text sections) contain the executable instructions that the CPU will execute. These sections typically have read and execute permissions but are not writable during normal execution to prevent code modification attacks.

### Data Sections

Data sections store the program's static data, including:
- Initialized variables (data with predefined values)
- Uninitialized variables (BSS - Block Started by Symbol)
- Constants and literals
- String tables

These sections usually have read and write permissions but are not executable.

### Import and Export Tables

Modern programs rarely operate in isolation. They interact with the operating system and other libraries through:

- **Import tables**: Lists of functions and data the program needs from external libraries
- **Export tables**: Functions and data the program provides for other programs to use

These tables are crucial for understanding a program's external dependencies and functionality.

### Resources

Many executables contain resources such as:
- Icons and images
- Dialog layouts
- Menus and UI elements
- Version information
- Embedded files

Resources provide valuable context about the program's functionality and can contain important clues for reverse engineering.

### Relocation Information

Relocation data helps the loader adjust memory addresses when the program can't be loaded at its preferred base address. This information is particularly important for shared libraries that must work at different memory locations.

### Debug Information

Some executables contain debug information that maps machine code back to source code, including:
- Function names and parameters
- Variable names and types
- Source file names and line numbers

While often stripped from production builds, when present, debug information is invaluable for reverse engineering.

## Portable Executable (PE) Format

The Portable Executable format is the standard executable format for Windows operating systems. It evolved from the earlier Common Object File Format (COFF) and is used for EXE, DLL, SYS, and other executable file types in Windows.

### PE File Structure

A PE file consists of several components arranged in a specific order:

1. **DOS Header and Stub**: A legacy component that displays "This program cannot be run in DOS mode" when the executable is run in MS-DOS.

2. **PE Header**: Contains a signature ("PE\0\0") and the COFF File Header with basic information about the file.

3. **Optional Header**: Despite its name, this header is required for executable files and contains crucial information like:
   - Entry point address
   - Preferred base address
   - Section alignment
   - Required operating system version
   - Subsystem (GUI, console, etc.)

4. **Section Table**: An array of section headers that describe each section's name, size, location, and characteristics.

5. **Sections**: The actual content of the file, organized according to the section table.

Here's a simplified visualization of a PE file structure:

```
┌─────────────────────┐
│     DOS Header      │
├─────────────────────┤
│      DOS Stub       │
├─────────────────────┤
│ PE Signature (PE\0\0)│
├─────────────────────┤
│    COFF Header      │
├─────────────────────┤
│   Optional Header   │
├─────────────────────┤
│    Section Table    │
├─────────────────────┤
│    .text section    │ (Code)
├─────────────────────┤
│    .data section    │ (Initialized data)
├─────────────────────┤
│    .rdata section   │ (Read-only data)
├─────────────────────┤
│    .bss section     │ (Uninitialized data)
├─────────────────────┤
│   .rsrc section     │ (Resources)
├─────────────────────┤
│   Other sections    │
└─────────────────────┘
```

### Common PE Sections

While section names are conventions rather than requirements, most PE files contain these standard sections:

- **.text**: Contains executable code
- **.data**: Contains initialized data
- **.rdata**: Contains read-only data like constants and strings
- **.bss**: Represents uninitialized data (doesn't actually occupy file space)
- **.rsrc**: Contains resources like icons, dialogs, and version information
- **.reloc**: Contains relocation information
- **.idata**: Contains import directory information
- **.edata**: Contains export directory information

### PE Data Directories

The Optional Header includes an array of data directories that point to important structures within the file:

- **Export Table**: Functions and data exported by this module
- **Import Table**: Functions and data imported from other modules
- **Resource Table**: Resources like icons, dialogs, and strings
- **Exception Table**: Exception handling information
- **Certificate Table**: Digital signature information
- **Base Relocation Table**: Address adjustment information
- **Debug**: Debug information
- **TLS Table**: Thread Local Storage data
- **Load Config Table**: Load configuration data
- **Bound Import Table**: Precomputed addresses of imports
- **Import Address Table (IAT)**: Runtime function pointers for imports
- **Delay Import Descriptor**: Information for delayed loading of DLLs
- **CLR Runtime Header**: .NET metadata and entry points

These directories are crucial for understanding how the program interacts with external components and for locating important structures during analysis.

### Analyzing PE Files

Let's examine how to extract and analyze information from PE files using practical tools.

#### Using CFF Explorer

CFF Explorer is a powerful PE file editor and viewer that provides a graphical interface for examining PE structures.

To analyze a PE file with CFF Explorer:

1. Open the executable in CFF Explorer
2. Navigate through the tree view to examine different components:
   - NT Headers > File Header: Basic file information
   - NT Headers > Optional Header: Entry point, base address, etc.
   - Section Headers: Section properties and characteristics
   - Import Directory: Imported functions
   - Export Directory: Exported functions
   - Resources: Embedded resources

CFF Explorer also provides hex and disassembly views, making it a versatile tool for initial PE analysis.

#### Using PEiD for Packer Detection

Packed executables are compressed or encrypted to hinder analysis. PEiD helps identify common packers:

```
PEiD detected: UPX 3.91 [NRV2B] -> Markus Oberhumer, Laszlo Molnar & John Reiser
```

If a packer is detected, you'll typically need to unpack the executable before further analysis.

#### Using DUMPBIN

DUMPBIN is a command-line tool included with Visual Studio that provides detailed information about PE files:

```
> dumpbin /headers program.exe
Microsoft (R) COFF/PE Dumper Version 14.00.24215.1
Copyright (C) Microsoft Corporation.  All rights reserved.


Dump of file program.exe

PE signature found

File Type: EXECUTABLE IMAGE

FILE HEADER VALUES
            8664 machine (x64)
               6 number of sections
        5F0EEFBB time date stamp Tue Jul 14 15:30:35 2020
               0 file pointer to symbol table
               0 number of symbols
              F0 size of optional header
              22 characteristics
                   Executable
                   Application can handle large (>2GB) addresses

OPTIONAL HEADER VALUES
             20B magic # (PE32+)
           14.16 linker version
           12800 size of code
            6600 size of initialized data
               0 size of uninitialized data
            5A90 entry point (0000000140005A90)
            1000 base of code
         140000000 image base (0000000140000000 to 000000014002FFFF)
            1000 section alignment
             200 file alignment
...
```

DUMPBIN offers various switches for examining specific aspects of PE files:

- `/imports`: Lists imported functions
- `/exports`: Lists exported functions
- `/dependents`: Shows dependent DLLs
- `/disasm`: Disassembles code sections
- `/all`: Displays all available information

#### Using PE-bear

PE-bear is another graphical PE analysis tool with a focus on malware analysis. It provides a clean interface for examining PE structures and includes features for detecting anomalies that might indicate malicious modifications.

### PE File Peculiarities and Tricks

Reverse engineers should be aware of several PE format peculiarities that can affect analysis:

#### Base Address Randomization (ASLR)

Address Space Layout Randomization loads executables at different base addresses each time they run, complicating dynamic analysis. You can identify if ASLR is enabled by checking the DLL Characteristics in the Optional Header:

```
DLL Characteristics: 8160 (0x1FE0)
  High Entropy Virtual Address Space
  Dynamic base
  NX compatible
  No structured exception handler
  Control Flow Guard
  Terminal Server aware
```

The "Dynamic base" flag indicates ASLR support.

#### Bound Imports

Bound imports include precomputed addresses for imported functions to speed up loading. However, these bindings become invalid if the referenced DLL changes or loads at a different address. The Bound Import Directory contains this information.

#### Resource Hierarchy

The PE resource section uses a hierarchical structure with three levels:
1. Type (e.g., icons, dialogs, string tables)
2. Name/ID (identifier within the type)
3. Language (for internationalization)

This structure allows efficient organization of resources but can be complex to navigate programmatically.

## ELF (Executable and Linkable Format)

The Executable and Linkable Format is the standard binary format for Unix-like systems, including Linux, BSD, and Solaris. It's used for executables, shared libraries, object files, and core dumps.

### ELF File Structure

An ELF file consists of these main components:

1. **ELF Header**: Contains basic file information, including:
   - Magic number (\x7FELF)
   - File class (32-bit or 64-bit)
   - Data encoding (little or big endian)
   - ELF version
   - Target OS ABI
   - File type (executable, shared object, etc.)
   - Machine type (architecture)
   - Entry point address

2. **Program Header Table**: Describes segments used at runtime, including:
   - Segment type (load, dynamic, interp, etc.)
   - Offset in file
   - Virtual address for loading
   - Segment size in file and memory
   - Required alignment
   - Flags (read, write, execute)

3. **Section Header Table**: Describes sections used for linking and debugging:
   - Section name (index into string table)
   - Section type (program data, symbol table, etc.)
   - Section attributes
   - Memory address
   - Offset in file
   - Section size

4. **Sections/Segments**: The actual content of the file.

Here's a simplified visualization of an ELF file structure:

```
┌─────────────────────┐
│     ELF Header      │
├─────────────────────┤
│ Program Header Table│
├─────────────────────┤
│      Segments       │
│    (.text, .data,   │
│     .rodata, etc.)  │
├─────────────────────┤
│ Section Header Table│
└─────────────────────┘
```

It's important to note that ELF uses two parallel views of the file:
- **Segments** (described by program headers) are used by the loader at runtime
- **Sections** (described by section headers) are used for linking and debugging

A segment typically contains multiple sections with similar attributes.

### Common ELF Sections

Standard ELF sections include:

- **.text**: Executable code
- **.data**: Initialized data
- **.rodata**: Read-only data (constants and strings)
- **.bss**: Uninitialized data
- **.symtab**: Symbol table
- **.strtab**: String table
- **.dynamic**: Dynamic linking information
- **.plt**: Procedure Linkage Table (for resolving imported functions)
- **.got**: Global Offset Table (contains addresses for imported symbols)
- **.init/.fini**: Initialization and finalization code
- **.eh_frame**: Exception handling information

### Analyzing ELF Files

Let's explore tools and techniques for analyzing ELF files.

#### Using readelf

readelf is a command-line tool that displays information about ELF files:

```bash
$ readelf -h executable
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x401040
  Start of program headers:          64 (bytes into file)
  Start of section headers:          13144 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         11
  Size of section headers:           64 (bytes)
  Number of section headers:         30
  Section header string table index: 29
```

readelf offers various options for examining specific aspects of ELF files:

- `-l`: Lists program headers (segments)
- `-S`: Lists section headers
- `-s`: Displays the symbol table
- `-d`: Shows dynamic section information
- `-r`: Displays relocation entries
- `-x <section>`: Dumps the contents of a section as hexadecimal bytes

#### Using objdump

objdump is another powerful command-line tool for analyzing ELF files, with a focus on disassembly:

```bash
$ objdump -d executable

executable:     file format elf64-x86-64

Disassembly of section .text:

0000000000401040 <_start>:
  401040:       31 ed                   xor    %ebp,%ebp
  401042:       49 89 d1                mov    %rdx,%r9
  401045:       5e                      pop    %rsi
  401046:       48 89 e2                mov    %rsp,%rdx
  401049:       48 83 e4 f0             and    $0xfffffffffffffff0,%rsp
  40104d:       50                      push   %rax
  40104e:       54                      push   %rsp
  40104f:       49 c7 c0 10 12 40 00    mov    $0x401210,%r8
  401056:       48 c7 c1 a0 11 40 00    mov    $0x4011a0,%rcx
  40105d:       48 c7 c7 30 11 40 00    mov    $0x401130,%rdi
  401064:       ff 15 66 2f 00 00       callq  *0x2f66(%rip)        # 403fd0 <__libc_start_main@GLIBC_2.2.5>
  40106a:       f4                      hlt    
...
```

Useful objdump options include:

- `-d`: Disassembles executable sections
- `-D`: Disassembles all sections
- `-s`: Displays full contents of all sections
- `-t`: Displays the symbol table
- `-R`: Displays dynamic relocation entries
- `--no-show-raw-insn`: Shows only the disassembly, not the hex bytes

#### Using ldd

ldd identifies the shared libraries an executable depends on:

```bash
$ ldd executable
        linux-vdso.so.1 (0x00007ffcb5563000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f56b33c4000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f56b35c1000)
```

This information helps understand the executable's external dependencies.

#### Using nm

nm lists symbols from object files and executables:

```bash
$ nm executable
0000000000403ff0 B __bss_start
0000000000403ff0 b completed.7698
0000000000403fe0 D __data_start
0000000000403fe0 W data_start
0000000000401070 t deregister_tm_clones
00000000004010e0 t __do_global_dtors_aux
0000000000403de8 t __do_global_dtors_aux_fini_array_entry
0000000000403fe8 D __dso_handle
0000000000403df8 d _DYNAMIC
0000000000403ff0 D _edata
0000000000404000 B _end
00000000004011c4 T _fini
0000000000401100 t frame_dummy
0000000000403de0 t __frame_dummy_init_array_entry
0000000000402154 r __FRAME_END__
0000000000404000 d _GLOBAL_OFFSET_TABLE_
                 w __gmon_start__
0000000000402004 r __GNU_EH_FRAME_HDR
0000000000401000 T _init
0000000000403de8 t __init_array_end
0000000000403de0 t __init_array_start
00000000004011d0 R _IO_stdin_used
                 w _ITM_deregisterTMCloneTable
                 w _ITM_registerTMCloneTable
00000000004011c0 T __libc_csu_fini
0000000000401150 T __libc_csu_init
                 U __libc_start_main@@GLIBC_2.2.5
0000000000401130 T main
00000000004010a0 t register_tm_clones
0000000000401040 T _start
0000000000403ff0 D __TMC_END__
```

The output shows symbol addresses, types, and names. Symbol types include:
- `T/t`: Text (code) section symbol (uppercase for global)
- `D/d`: Initialized data section symbol
- `B/b`: BSS section symbol
- `U`: Undefined symbol (imported)
- `R/r`: Read-only data section symbol

### ELF File Peculiarities and Tricks

Several ELF features are particularly relevant for reverse engineers:

#### Position-Independent Executables (PIE)

PIE executables can be loaded at any address, similar to ASLR in Windows. You can identify PIE executables by checking the ELF header type:

```
Type: DYN (Shared object file)
```

For PIE executables, the type is DYN rather than EXEC, even though they are executables.

#### Symbol Versioning

ELF supports symbol versioning to handle multiple versions of the same function in a shared library. Versioned symbols appear with `@@` or `@` in nm output:

```
U __libc_start_main@@GLIBC_2.2.5
```

This indicates that the program requires version 2.2.5 or newer of this function.

#### RPATH and RUNPATH

ELF executables can specify custom library search paths using RPATH and RUNPATH entries in the dynamic section. These can be viewed with readelf:

```bash
$ readelf -d executable | grep -i path
 0x000000000000001d (RUNPATH)            Library runpath: [/opt/myapp/lib]
```

This information can be important when analyzing executables that use non-standard library locations.

## Mach-O Format

Mach-O (Mach Object) is the executable format used by macOS, iOS, and other Apple operating systems. It evolved from the Mach kernel's object format.

### Mach-O File Structure

A Mach-O file consists of these main components:

1. **Header**: Contains basic file information, including:
   - Magic number (0xFEEDFACE for 32-bit, 0xFEEDFACF for 64-bit)
   - CPU type and subtype
   - File type (executable, dylib, etc.)
   - Number of load commands

2. **Load Commands**: Instructions for the dynamic loader, including:
   - Segment definitions
   - Symbol table location
   - Dynamic linking information
   - Entry point information

3. **Segments and Sections**: The actual content of the file, organized into segments (similar to ELF segments) that contain one or more sections.

Here's a simplified visualization of a Mach-O file structure:

```
┌─────────────────────┐
│    Mach-O Header    │
├─────────────────────┤
│    Load Commands    │
├─────────────────────┤
│      Segments       │
│    (__TEXT, __DATA, │
│     __LINKEDIT)     │
└─────────────────────┘
```

### Common Mach-O Segments and Sections

Standard Mach-O segments include:

- **__TEXT**: Contains executable code and read-only data
  - __text: Executable code
  - __const: Constants
  - __stubs: Stub functions for dynamic linking
  - __stub_helper: Helper functions for stubs

- **__DATA**: Contains writable data
  - __data: Initialized variables
  - __bss: Uninitialized variables
  - __la_symbol_ptr: Lazy symbol pointers
  - __nl_symbol_ptr: Non-lazy symbol pointers

- **__LINKEDIT**: Contains linking information
  - Symbol tables
  - String tables
  - Code signature
  - Relocation entries

### Analyzing Mach-O Files

Let's explore tools and techniques for analyzing Mach-O files.

#### Using otool

otool is a command-line tool for examining Mach-O files on macOS:

```bash
$ otool -h executable
Mach header
      magic cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
 0xfeedfacf 16777223          3  0x80           2    16       1296   0x200085
```

Useful otool options include:

- `-l`: Displays load commands
- `-L`: Shows shared libraries the executable uses
- `-t`: Disassembles the __text section
- `-s <segment> <section>`: Displays the contents of a specific section
- `-v`: Provides verbose output

#### Using nm on macOS

nm works with Mach-O files similar to its ELF counterpart:

```bash
$ nm executable
0000000100000000 T __mh_execute_header
0000000100003f50 T _main
                 U _printf
                 U dyld_stub_binder
```

#### Using MachOView

MachOView is a graphical tool for examining Mach-O files, providing a hierarchical view of the file structure and detailed information about each component.

### Mach-O File Peculiarities and Tricks

Several Mach-O features are particularly relevant for reverse engineers:

#### Fat Binaries

Mach-O supports "fat" or "universal" binaries that contain code for multiple architectures in a single file. You can identify fat binaries using the file command:

```bash
$ file executable
executable: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64:Mach-O 64-bit executable arm64]
```

To examine a specific architecture in a fat binary, use the -arch option with otool:

```bash
$ otool -arch arm64 -h executable
```

#### Code Signing

Mach-O files on modern Apple systems are typically code signed. The signature is stored in the __LINKEDIT segment and can be examined with the codesign tool:

```bash
$ codesign -d -v executable
Executable=/path/to/executable
Identifier=com.example.executable
Format=Mach-O thin (x86_64)
CodeDirectory v=20500 size=12699 flags=0x10000(runtime) hashes=389+5 location=embedded
Signature size=4442
Authority=Developer ID Application: Example Corp (A1B2C3D4E5)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Info.plist=not bound
TeamIdentifier=A1B2C3D4E5
Runtime Version=10.15.0
Designated => identifier "com.example.executable" and certificate leaf [subject.CN] = "Developer ID Application: Example Corp (A1B2C3D4E5)" trusted, signed
```

#### Two-Level Namespace

Mach-O uses a "two-level namespace" for symbols, where each symbol reference includes both the symbol name and the library where it should be found. This helps avoid conflicts between libraries that define the same symbol.

## Android DEX Format

Dalvik Executable (DEX) is the format used for Android applications. While Android apps are typically written in Java or Kotlin, they're compiled to DEX bytecode rather than Java bytecode.

### DEX File Structure

A DEX file consists of these main components:

1. **Header**: Contains basic file information, including:
   - Magic number ("dex\n035\0" for version 35)
   - Checksum and signature
   - File size
   - Endianness tag
   - Offsets to various sections

2. **String Table**: Contains all string literals used in the program

3. **Type Table**: Lists all types (classes) referenced in the program

4. **Prototype Table**: Describes method signatures

5. **Field Table**: Describes class fields

6. **Method Table**: Describes class methods

7. **Class Definitions**: Contains detailed information about each class

8. **Data Section**: Contains the actual bytecode and data

### Analyzing DEX Files

Let's explore tools for analyzing DEX files.

#### Using dexdump

dexdump is a tool included with the Android SDK that displays the contents of DEX files:

```bash
$ dexdump -f classes.dex
Processing 'classes.dex'...
Magic: 'dex\n035\0'
Checksum: 8c78965
Signature: 5881...
File size: 2840 bytes
Header size: 112 bytes
Endian tag: 0x12345678
Link size: 0
Link off: 0
Map off: 2700
String ids size: 55
String ids off: 112
Type ids size: 16
Type ids off: 332
Proto ids size: 15
Proto ids off: 396
Field ids size: 10
Field ids off: 576
Method ids size: 29
Method ids off: 656
Class defs size: 5
Class defs off: 888
Data size: 1752
Data off: 948
```

For more detailed information, including disassembly of the bytecode, use the -d option:

```bash
$ dexdump -d classes.dex
```

#### Using jadx

jadx is a powerful tool that can decompile DEX files back to Java source code:

```bash
$ jadx -d output_directory classes.dex
```

This creates a directory structure with Java source files, making it much easier to understand the application's functionality.

#### Using apktool

For complete Android applications (APK files), apktool can extract and decode resources as well as disassemble DEX files to a more readable format called smali:

```bash
$ apktool d application.apk -o output_directory
```

This extracts the application's resources, manifest, and DEX files (converted to smali format).

### DEX File Peculiarities and Tricks

Several DEX features are particularly relevant for reverse engineers:

#### Multiple DEX Files

Android applications can contain multiple DEX files (classes.dex, classes2.dex, etc.) to overcome the method limit of 65,536 methods per DEX file. When analyzing large applications, you need to examine all DEX files.

#### Obfuscation

Many Android applications use ProGuard or similar tools to obfuscate their code by renaming classes, methods, and fields to meaningless names like a, b, c, etc. This makes reverse engineering more challenging but doesn't change the program's functionality.

#### Native Code

Android applications can include native code (shared libraries) in addition to DEX files. These libraries are typically found in the lib/ directory of the APK and need to be analyzed separately using ELF analysis tools.

## .NET Assemblies

.NET assemblies are the executable format for .NET applications, used on Windows, macOS, and Linux through .NET Core/.NET 5+.

### .NET Assembly Structure

A .NET assembly consists of these main components:

1. **PE/COFF Header**: .NET assemblies use the PE format as a container

2. **CLR Header**: Contains information specific to the Common Language Runtime

3. **Metadata Tables**: Describe the assembly's types, methods, fields, etc.

4. **IL Code**: The actual program code in Intermediate Language (IL) bytecode

5. **Resources**: Embedded resources like images, strings, etc.

6. **Strong Name Signature**: Optional digital signature for the assembly

### Analyzing .NET Assemblies

Let's explore tools for analyzing .NET assemblies.

#### Using ILDASM

ILDASM (IL Disassembler) is a tool included with the .NET SDK that displays the contents of .NET assemblies:

```
> ildasm /text assembly.exe

// Metadata version: v4.0.30319
.assembly extern mscorlib
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 )                         // .z\V.4..
  .ver 4:0:0:0
}
.assembly Sample
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilationRelaxationsAttribute::.ctor(int32) = ( 01 00 08 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.CompilerServices.RuntimeCompatibilityAttribute::.ctor() = ( 01 00 01 00 54 02 16 57 72 61 70 4E 6F 6E 45 78   // ....T..WrapNonEx
                                                                                                             63 65 70 74 69 6F 6E 54 68 72 6F 77 73 01 )       // ceptionThrows.
  .hash algorithm 0x00008004
  .ver 0:0:0:0
}
.module Sample.exe
// MVID: {A67FC21F-23A5-4587-A41A-0F5EBB3A4016}
.imagebase 0x00400000
.file alignment 0x00000200
.stackreserve 0x00100000
.subsystem 0x0003       // WINDOWS_CUI
.corflags 0x00000001    //  ILONLY
// Image base: 0x06DD0000

// =============== CLASS MEMBERS DECLARATION ===================

.class private auto ansi beforefieldinit Sample.Program
       extends [mscorlib]System.Object
{
  .method private hidebysig static void  Main(string[] args) cil managed
  {
    .entrypoint
    // Code size       13 (0xd)
    .maxstack  8
    IL_0000:  nop
    IL_0001:  ldstr      "Hello, World!"
    IL_0006:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_000b:  nop
    IL_000c:  ret
  } // end of method Program::Main

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  nop
    IL_0007:  ret
  } // end of method Program::.ctor

} // end of class Sample.Program
```

#### Using dnSpy

dnSpy is a powerful .NET assembly browser, decompiler, and debugger that provides a graphical interface for examining .NET assemblies. It can decompile IL code to C#, Visual Basic, or IL, and allows editing and debugging of assemblies.

#### Using ILSpy

ILSpy is another popular .NET decompiler that can convert assemblies back to C# or Visual Basic source code:

```bash
$ ilspy assembly.exe -o output_directory
```

This creates a directory with decompiled source files.

### .NET Assembly Peculiarities and Tricks

Several .NET features are particularly relevant for reverse engineers:

#### Metadata

.NET assemblies contain rich metadata that describes all types, methods, fields, and other elements. This metadata makes .NET assemblies relatively easy to reverse engineer compared to native executables.

#### Obfuscation

Many .NET applications use obfuscation tools like Dotfuscator or ConfuseEx to make reverse engineering more difficult. Common obfuscation techniques include:
- Renaming symbols to meaningless or confusing names
- Control flow obfuscation
- String encryption
- Proxy methods
- Invalid metadata that confuses decompilers

#### Native Code Integration

.NET applications can include native code through P/Invoke or by embedding native DLLs. These native components need to be analyzed separately using PE analysis tools.

## Comparing Executable Formats

Let's compare the key characteristics of the executable formats we've discussed:

| Feature | PE | ELF | Mach-O | DEX | .NET Assembly |
|---------|----|----|--------|-----|---------------|
| **Platforms** | Windows | Linux, Unix | macOS, iOS | Android | Cross-platform |
| **Architecture Support** | Multiple | Multiple | Multiple | Dalvik VM | CLR |
| **Code Representation** | Native | Native | Native | Bytecode | IL Bytecode |
| **Metadata** | Limited | Limited | Limited | Extensive | Extensive |
| **Dynamic Linking** | Imports/Exports | PLT/GOT | Stubs/Lazy Binding | Dynamic Invocation | Assembly References |
| **Ease of Reverse Engineering** | Moderate | Moderate | Moderate | Easier | Easiest |

This comparison highlights why different approaches are needed when reverse engineering software on different platforms.

## Practical Techniques for Format Analysis

Regardless of the specific format, several general techniques are valuable for analyzing executable files:

### Identifying the Format and Architecture

The first step in any analysis is identifying the file format and target architecture. The `file` command is invaluable for this purpose:

```bash
$ file unknown_binary
unknown_binary: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32
```

This immediately tells you it's a 64-bit ELF executable for x86-64 architecture.

### Examining Strings

Extracted strings often provide valuable insights into a program's functionality:

```bash
$ strings executable | grep -i password
Enter password:
Password incorrect!
Password accepted.
/etc/passwd
```

Strings can reveal error messages, file paths, URLs, and other valuable information.

### Identifying External Dependencies

Understanding a program's external dependencies helps map its functionality:

- For PE files: Use `depends.exe` or `dumpbin /dependents`
- For ELF files: Use `ldd`
- For Mach-O files: Use `otool -L`
- For .NET assemblies: Use `ildasm` to view assembly references

External dependencies often reveal the program's capabilities (networking, cryptography, database access, etc.).

### Locating the Entry Point

Finding where execution begins provides a starting point for analysis:

- For PE files: The AddressOfEntryPoint field in the Optional Header
- For ELF files: The e_entry field in the ELF header
- For Mach-O files: The LC_MAIN or LC_UNIXTHREAD load command
- For .NET assemblies: The method marked with .entrypoint in IL

From the entry point, you can follow the execution flow to understand the program's initialization and main logic.

### Identifying Compiler Patterns

Different compilers generate distinctive code patterns, especially for program initialization. Recognizing these patterns helps understand the code's structure:

- MSVC executables typically include a complex startup routine that calls the C runtime initialization before main()
- GCC executables have a simpler startup that quickly transfers control to __libc_start_main
- Executables compiled with optimization may have significantly different code patterns than debug builds

Familiarity with these patterns comes with experience and can significantly speed up analysis.

## Summary

In this chapter, we've explored the major executable formats used across different platforms, examining their structures, components, and analysis techniques. Understanding these formats is fundamental to reverse engineering because they define how program code and data are organized and accessed.

Key takeaways include:

- Executable formats serve as containers that organize code, data, and metadata in a structure the operating system can load and execute
- Each platform uses specific formats with unique characteristics: PE for Windows, ELF for Linux/Unix, Mach-O for macOS/iOS, DEX for Android, and .NET assemblies for .NET applications
- Despite their differences, these formats share common elements like headers, code sections, data sections, and linking information
- Various tools are available for analyzing each format, from command-line utilities to sophisticated graphical interfaces
- Understanding format-specific features and peculiarities is essential for effective reverse engineering

With this foundation in executable formats, you're now prepared to dive deeper into the code they contain. In the next chapter, we'll explore assembly language basics, building on this structural understanding to interpret the actual instructions that make up a program.

## Exercises

1. **Format Identification**: Collect executable files from different platforms (Windows, Linux, macOS, Android) and use the `file` command to identify their formats and characteristics. Document the differences you observe in the output.

2. **PE Analysis**: Using a Windows executable of your choice:
   - Identify its imported DLLs and functions using `dumpbin /imports` or a similar tool
   - Locate the entry point address using a PE viewer
   - List the sections and their characteristics
   - Determine if ASLR is enabled

3. **ELF Analysis**: Using a Linux executable of your choice:
   - Identify its shared library dependencies using `ldd`
   - Extract and analyze the symbol table using `nm`
   - Disassemble the main function using `objdump -d`
   - Determine if it's a position-independent executable (PIE)

4. **Cross-Format Comparison**: Choose a simple open-source program that can be compiled for multiple platforms. Compile it for Windows, Linux, and macOS if possible. Compare the resulting executables in terms of:
   - File size
   - Section/segment organization
   - External dependencies
   - Entry point code

5. **Format Manipulation**: Using a hex editor and format documentation:
   - Modify a non-critical field in a PE or ELF header (such as the timestamp)
   - Observe how the change affects the file's behavior and how analysis tools interpret it
   - Restore the original value

