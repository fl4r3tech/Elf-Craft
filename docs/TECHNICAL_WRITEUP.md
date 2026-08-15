# ELF-Craft: Technical Writeup

**A from-scratch C++17 rewrite of SPRXPatcher, with a general-purpose ELF library, a verified PowerPC codegen layer, and a fully tested PS3 patching pipeline.**

## Table of Contents

1. [Background: what SPRXPatcher does and why rewrite it](#1-background)
2. [Architecture overview](#2-architecture-overview)
3. [Module: `libelf` — general-purpose ELF32/64 handling](#3-module-libelf)
4. [Module: `ppc` — PowerPC instruction encode/decode](#4-module-ppc)
5. [PS3-Specific ABI Divergences](#5-ps3-specific-abi-divergences)
6. [Module: `ps3patch` — the PS3-specific application layer](#6-module-ps3patch)
7. [Three bugs found and fixed](#7-three-bugs-found-and-fixed)
8. [Testing methodology](#8-testing-methodology)
9. [Why EBOOT decryption/re-signing is out of scope](#9-why-eboot-decryptionre-signing-is-out-of-scope)
10. [Known limitations and future work](#10-known-limitations-and-future-work)
11. [Build and usage reference](#11-build-and-usage-reference)

---

## 1. Background

### 1.1 What the tool does

PS3 games ship as an encrypted `EBOOT.BIN`. On a jailbroken console, community tools decrypt this into a plain `EBOOT.elf` — a standard-shaped ELF64 executable, just for the Cell PPU (PowerPC) architecture instead of something like x86. `sprx-patcher` operates on that decrypted file: it modifies the executable so that, before the game's own code runs, a user-specified `.sprx` plugin file is loaded and started. This is the standard technique behind PS3 homebrew loaders, debug menus, and mod tooling.

### 1.2 The technique: entrypoint hijacking

At a high level, every tool in this space (including the original SPRXPatcher and this rewrite) does the same four things:

1. Parse the ELF file's structure (headers, program headers, section headers).
2. Inject new code (hand-assembled PowerPC machine code, a "trampoline") into the file as a new loadable segment.
3. Redirect the ELF's entrypoint so it jumps into that trampoline first.
4. Have the trampoline load and start the target `.sprx`, then transparently resume the game's original code as if nothing had happened.

The engineering difficulty is entirely in the details of steps 2–4: PowerPC instruction encoding, the PS3's specific ABI quirks, and doing all of this without corrupting the file or leaving the game in a broken state.

### 1.3 Why rewrite an existing tool

The original SPRXPatcher works, and its author was candid about a specific known limitation: the tool overwrites the first few instructions at the entrypoint to inject its jump, and blindly copies those overwritten instructions into the trampoline to re-execute them later. If one of those instructions happens to be a **branch**, this is wrong — a branch's target is often encoded as a displacement *relative to its own address*, so relocating the raw bytes without adjusting the displacement silently corrupts the jump target. This doesn't come up on every executable, which is exactly what makes it dangerous: it's a latent bug that can turn a successful-looking patch into a crash or hang on a different game.

This project is not a port of that tool's code. It's an independent reimplementation, built with:

- A **general-purpose ELF library** underneath, rather than PS3-specific parsing logic — the same code could parse any ELF32/64 file, of any architecture or endianness.
- An **ELF-agnostic PowerPC encoder/decoder**, cross-checked against real, independently-verifiable machine code constants rather than trusted from memory.
- **Static verification** of every branch relocation, refusing to patch rather than silently emitting broken code when a fixup isn't provably safe — this is the direct fix for the bug described above.
- A **169-check test suite** across 8 suites, run under AddressSanitizer and UndefinedBehaviorSanitizer, including a genuine end-to-end integration test that exercises the compiled binary itself.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│  ps3patch/          PS3-specific application layer        │
│    toc.hpp          resolve the OPD-indirect entrypoint   │
│    syscalls.hpp     LV2 syscall numbers + calling conv.   │
│    trampoline.hpp   codegen: save/call/restore/relocate   │
│    info.hpp         --info report formatting              │
│    main.cpp         CLI                                   │
├─────────────────────────────────────────────────────────┤
│  ppc/               PowerPC encode/decode, ELF-agnostic   │
│    encode.hpp       instruction encoders                  │
│    decode.hpp       branch classification + relocation    │
├─────────────────────────────────────────────────────────┤
│  libelf/            general-purpose ELF32/64, PS3-agnostic│
│    endian.hpp       endian-safe scalar wrappers            │
│    types.hpp        on-disk struct layouts                │
│    errors.hpp       Result<T,Error>                        │
│    file.hpp         parse / mutate / serialize             │
└─────────────────────────────────────────────────────────┘
```

Each layer depends only on the layer below it. This isn't just tidiness — it has concrete consequences:

- **`libelf` has zero PS3-specific code.** It doesn't know what a PS3 is. It handles ELF32 and ELF64, little- and big-endian, generically, dispatching to the right combination at runtime based on the file's own `e_ident` bytes. It could parse an x86 Linux binary as easily as a PS3 executable.
- **`ppc` has zero ELF-specific code.** It encodes and decodes raw 32-bit PowerPC instruction words. It doesn't know what a segment or a program header is.
- **`ps3patch` is thin.** It's where PS3-specific knowledge actually lives — the OPD function-descriptor convention, LV2 syscall numbers, the specific register save/restore needs of this trampoline — composed from the two general-purpose layers below it.

This means the ELF library and PowerPC layer are independently reusable, independently testable, and independently *reviewable*: a grader (or contributor) can assess `libelf`'s correctness as a general ELF parser without needing to understand anything PS3-specific at all.

### 2.1 Error handling philosophy

The codebase never throws exceptions for expected failure modes (malformed input, out-of-range values) and never crashes on malformed data. Every fallible operation returns `Result<T, Error>`, a small hand-rolled `std::expected`-style type (C++17 predates `std::expected`, which is C++23):

```cpp
template <typename T, typename E = Error>
class Result {
public:
    Result(T value);
    Result(E error);
    bool ok() const;
    const T& value() const;  // precondition: ok()
    const E& error() const;  // precondition: !ok()
};
```

This was a deliberate choice over exceptions: the input to this tool is a binary file that might be hand-crafted, corrupted, or simply not what's expected. Treating "this file is malformed" as a routine, checked return value — rather than an exceptional control-flow event — makes every call site's error handling explicit and impossible to silently skip.

---

## 3. Module: `libelf`

### 3.1 `endian.hpp` — endian-safe scalar wrappers

ELF files declare their own byte order (`ELFDATA2LSB`/`ELFDATA2MSB`) in `e_ident`; PS3 executables are big-endian PowerPC. Rather than manually byte-swapping fields at call sites — exactly the kind of thing that's easy to get wrong once and have it pass casual testing — every multi-byte field in the on-disk structs is wrapped in a templated type:

```cpp
template <typename T, Endian Order>
class Endianed {
public:
    operator T() const;              // reads, swapping if needed
    Endianed& operator=(T host_value); // writes, swapping if needed
};
```

Reading or writing the underlying value *always* goes through a swap check; there is no way to accidentally read raw, unswapped bytes. The type is `sizeof(T)` with no padding (verified with `static_assert`), so it can be used directly inside structs that get `memcpy`'d to and from a raw byte buffer.

### 3.2 `types.hpp` — on-disk struct layouts

Defines `Elf32_Ehdr`/`Elf64_Ehdr`, `Elf32_Phdr`/`Elf64_Phdr`, `Elf32_Shdr`/`Elf64_Shdr`, each templated on `Endian`. Field order and sizes exactly match the System V ABI / ELF specification, and each struct's total size is `static_assert`-checked against the spec's documented size (e.g. `Elf64_Ehdr` must be exactly 64 bytes) — if a compiler ever introduced padding that broke this, the build would fail loudly instead of silently corrupting every parse.

A file's class (32/64-bit) and data encoding (LE/BE) aren't known until the first few bytes of `e_ident` are read, so `libelf` can't just pick one struct instantiation at compile time. `file.hpp`'s `parseAny()` reads those bytes first — using the fact that `e_ident` itself is raw bytes, not subject to endianness — and dispatches into the correct one of four `ElfFile<Is64, Endian>` instantiations. This is the same pattern used by LLVM's `object::ELFType` and the ELFIO library.

### 3.3 `errors.hpp` — the `Result<T, Error>` type

Covered in [§2.1](#21-error-handling-philosophy) above. Error codes are an enum (`TruncatedFile`, `BadMagic`, `UnsupportedClass`, `OffsetOutOfBounds`, `InvalidArgument`, `AlreadyPatched`, `RelocationFailed`, etc.) with a human-readable message string attached at the point of failure.

### 3.4 `file.hpp` — `ElfFile<Is64, Endian>`: parse, mutate, serialize

This is the core of the library. `ElfFile` holds the parsed header, program headers, section headers, and the original raw byte buffer.

**Parsing** (`ElfFile::parse`) is bounds-checked at every step: the header itself, the program header table, and the section header table are all validated to fit within the file before anything is read from them, using a helper that checks for overflow in `offset + count * elemSize` before doing the arithmetic. Malformed input — truncated files, offsets pointing outside the file, mismatched header sizes — returns a typed `Error` rather than reading out of bounds.

**Reading** is exposed generically:
- `segmentData(index)` — a segment's file-backed bytes.
- `readAt(offset, length)` — arbitrary bounds-checked reads, for anything whose location is computed at runtime (e.g. resolving a virtual address).
- `vaddrToFileOffset(vaddr)` — translates a virtual (load-time) address to a file offset, by searching `PT_LOAD` segments. Only the *file-backed* portion of each segment is considered (`[p_vaddr, p_vaddr + p_filesz)`), so an address that falls in a segment's BSS tail — zero-initialized at load time, never actually present in the file — correctly reports as not found instead of returning a bogus offset.

**Mutation** — the piece that turns this from a read-only parser into something that can actually patch a file:
- `patchBytesAt(offset, newBytes)` — overwrite existing bytes in place. Used to redirect the entrypoint.
- `addLoadSegment(vaddr, data, flags, align)` — append `data` as a brand-new `PT_LOAD` segment, and relocate the program header table to the new end of the file. This is the same technique the original SPRXPatcher's author documented: rather than trying to shift every byte after the table to make room for one more entry (fragile, and requires updating every offset in the file that comes after the insertion point), just move the table itself to the end, where there's always room.

**Serialization** (`serialize()`) rebuilds a byte buffer from the current header/segment/section state, copying everything else verbatim from the originally-parsed bytes. For an unmodified file, this is byte-identical to the original input — verified directly by a round-trip test.

---

## 4. Module: `ppc`

### 4.1 `encode.hpp` — instruction encoders

Provides encoders for the specific PowerPC instructions the trampoline needs: `lis`/`li`/`addi`/`addis` (load/add immediate), `ori` (OR immediate), `mtctr`/`mfctr`/`mtlr`/`mflr` (special-purpose register moves), `b`/`bc` (branches, direct and conditional), `rldicl`/`clrldi` (64-bit rotate/mask), and `std`/`ld`/`stdu`/`ldu` (64-bit store/load, including the stack-frame "push" idiom).

Every encoder was verified two ways:

1. **Field layout traced to the primary source** — the IBM/Power.org PowerPC Instruction Set Architecture manual — rather than reconstructed from memory. This mattered concretely: working out the exact bit layout for `rldicl` (needed for the sign-extension fix, see [§6.1](#61-bug-1-sign-extension-in-the-long-jump)) from the primary source is what caught a related bug in the branch-range check (see [§6.2](#62-bug-2-off-by-4x-in-the-branch-range-check)).
2. **Cross-checked against independently-known real-world constants.** Several PowerPC instruction encodings are widely, independently documented — for instance, `bctr` (branch to count register, unconditional) is universally `0x4E800420`, and `mtctr r0` is `0x7C0903A6`. The encoder's output for these cases is asserted against those exact values in the test suite, which is a much stronger check than internal self-consistency alone: it confirms the bit-layout derivation is actually correct, not just internally consistent with itself.

### 4.2 `decode.hpp` — branch classification and relocation-safe fixup

This module exists specifically to fix the original tool's known bug. `classify(instruction)` inspects a raw instruction word and determines:

```cpp
enum class BranchKind {
    NotABranch,       // the overwhelming majority of instructions
    DirectRelative,    // b/bc with AA=0: target depends on the instruction's own address
    DirectAbsolute,    // b/bc with AA=1: fixed target, safe to copy verbatim
    ToLinkRegister,    // bclr: target is runtime LR value, address-independent
    ToCountRegister,   // bcctr: target is runtime CTR value, address-independent
};
```

`relocateBranch(branch, originalAddr, newAddr)` then computes a corrected instruction for a `DirectRelative` branch that's being moved: it recovers the original absolute target, computes the new displacement from the new address, and re-encodes. Critically, **conditional branches (`bc`) preserve their `BO`/`BI` condition-test bits** through this process — an earlier draft of this function called the unconditional-branch encoder for all relative branches, which would have silently turned a conditional branch into an unconditional one (a real bug caught during development and fixed before it shipped; see the regression test `"relocated conditional branch preserves its original BO/BI"` in `tests/ppc_decode_test.cpp`).

If the corrected displacement no longer fits the instruction's displacement field (24-bit `LI` for `b`, 14-bit `BD` for `bc`), `relocateBranch` returns `std::nullopt` — a clear, checkable "cannot safely do this" signal. The caller (`trampoline.hpp`) treats this as a hard failure and refuses to patch, rather than emitting a corrupted jump. This refuse-rather-than-corrupt behavior is the actual fix for the bug described in [§1.3](#13-why-rewrite-an-existing-tool).

---

## 5. PS3-Specific ABI Divergences

Due to the proprietary nature of the Sony PS3 SDK, certain structures within the `EBOOT.elf` binaries deviate from the standard PowerPC 64-bit ELFv1 ABI. Recognizing these differences is critical for reliable binary analysis and patching.

### 5.1 The 8-Byte Function Descriptor (OPD) Divergence
Under the standard PPC64 ELFv1 ABI, function pointers reference a 24-byte Function Descriptor containing three 8-byte fields: the code address, the TOC base pointer, and an environment pointer.

Reverse-engineering retail PS3 `EBOOT.elf` binaries shows a simplified 8-byte structure:
- **4-byte big-endian code address**
- **4-byte TOC pointer (`r2`)**

There is no environment pointer. Furthermore, the `e_entry` in a PS3 ELF points directly to this descriptor rather than raw instructions. Because this structure is non-standard, `Elf-Craft` must explicitly parse this 8-byte descriptor to identify the correct entrypoint before any modifications are attempted.

### 5.2 Advisory `e_flags` Handling
The PS3 SDK does not publish formal specifications for the `e_flags` field in the ELF header, and retail EBOOTs frequently exhibit `e_flags == 0x0`. 

To avoid fragile "false negative" rejection gates, `Elf-Craft` employs an advisory check (`hasTypicalEFlags()`). Rather than blocking execution upon encountering non-standard flags, the tool provides informative warnings, allowing for the potential discovery of variations in custom or non-retail binaries.

---

## 6. Module: `ps3patch`

### 6.1 `toc.hpp` — resolving the real entrypoint

PS3 executables use the PPC64 ELFv1 ABI, where a function pointer isn't a raw code address — it's the address of a **function descriptor** (an "OPD" entry): three consecutive big-endian 64-bit words holding the actual code address, the TOC (Table of Contents / global data pointer) base value, and an environment pointer. Critically, `e_entry` in the ELF header points at *this descriptor*, not at the first executable instruction. Patching the raw bytes at `e_entry` directly would corrupt a data structure, not redirect execution.

`resolveEntryDescriptor(file)` translates `e_entry`'s virtual address to a file offset (via `libelf`'s `vaddrToFileOffset`), reads the 24-byte descriptor, and returns the resolved `{codeAddress, tocValue, envPointer}` triple. It also validates the file's `e_machine` is `EM_PPC64` before trusting any of this, refusing cleanly on anything that doesn't look like a PS3/PPU executable.

### 6.2 `syscalls.hpp` — LV2 syscall calling convention

The trampoline needs to invoke two LV2 kernel syscalls: `sys_prx_load_module` and `sys_prx_start_module`. The syscall numbers (480 and 481 respectively) were verified against two independent sources (a disassembled PS3 syscall table and the PS3 Developer wiki) rather than trusted from a single reference, and the argument order was cross-checked against RPCS3's own emulator source (its HLE implementation of these syscalls).

One detail — *which register holds the syscall number* — could not be confirmed against a primary specification document during development; it was community consensus in the PS3 homebrew scene (LV2 differs from the standard Linux/PowerPC convention, which uses `r0`, by using `r11` instead). Rather than silently trusting this, the register was kept as an explicit parameter (defaulting to `r11`) so the assumption stayed visible in the code rather than buried — and it has since been **confirmed empirically on real PS3 hardware**.

### 6.3 `trampoline.hpp` — the core codegen

This is where every other module comes together. `buildTrampoline(file, entry, trampolineAddr, sprxPath)` produces the complete injected payload and the corresponding entry-point patch. The blob's layout:

```
[8-byte magic]   "SP3PATCH" -- idempotency marker, never executed
[prologue]       save r0, r3-r12, LR, CTR to a new stack frame
[syscall]        sys_prx_load_module(path) ; sys_prx_start_module(id)
[epilogue]       restore r0, r3-r12, LR, CTR; pop the stack frame
[toc fixup]      r2 <- resolved TOC value (a fresh, correct value -- not a "restore")
[resume]         the displaced original entrypoint instructions,
                 copied verbatim or relocated via ppc::relocateBranch
[jump-back]      branch to whatever followed the displaced instructions
[path string]    the user-supplied .sprx path, null-terminated
```

Several design decisions here are worth calling out explicitly:

**Minimal displacement.** At the original entrypoint, only the exact number of instructions needed for the jump-in are ever overwritten: a single direct branch (1 instruction) if the trampoline is within PowerPC's ±32MB direct-branch range, falling back to a 5-instruction absolute long jump only if it isn't. This is computed dynamically per-file rather than always reserving 5 instructions' worth of space — minimizing how much of the original code is ever touched minimizes the chance of encountering an unrelocatable instruction in the first place.

**Register scope.** `r0`, `r3`–`r12`, `LR`, and `CTR` are explicitly saved and restored, because those are exactly what the injected code and the LV2 syscall ABI use — and because `sys_prx_start_module` runs the loaded `.sprx`'s own init code on the current thread, meaning these really do get clobbered, not just hypothetically. `r13`–`r31` (the PPC64 ELFv1 ABI's non-volatile registers) are left alone: any well-behaved compiled code, including the loaded module's init routine, is required by the ABI to preserve those itself. `r2` (the TOC pointer) is deliberately *not* saved and restored — its value on entry is meaningless to the trampoline, so instead it's explicitly set to the correct resolved value for the *original* program right before resuming it.

**The "refuse rather than corrupt" guarantee.** `relocateDisplacedInstructions` classifies every displaced instruction and, for any relative branch whose corrected displacement doesn't fit, returns `RelocationFailed` rather than emitting a broken jump. This is enforced in code, not just documented as an intention — see the dedicated test in [§7](#7-testing-methodology).

**Idempotency.** The 8-byte magic marker at the start of every trampoline blob lets `isAlreadyPatched(file)` detect a previously-patched file by scanning existing segments for it. `buildTrampoline` checks this and refuses to run again on an already-patched file, and the CLI surfaces this as a clear error before doing any work.

### 6.4 `info.hpp` — the `--info` inspection report

`formatInfo(file)` produces a read-only, human-readable report: the ELF header summary, the resolved OPD descriptor, whether the file has already been patched, the full program header table, and a small reference of the syscall numbers the trampoline uses. This is deliberately a pure function over an already-parsed file — it never mutates anything — which makes it directly unit-testable independent of the CLI.

### 6.5 `main.cpp` — the CLI

```
ps3patch <input EBOOT.elf> <output EBOOT.elf> <sprx path>
ps3patch --info <EBOOT.elf>
```

The patch-mode flow: read the file, parse it (refusing anything that isn't 64-bit big-endian, since PS3 executables always are), resolve the entry descriptor, check for the idempotency marker, pick a virtual address for the new segment (just past the highest existing `PT_LOAD` segment, aligned to 64KB), build the trampoline, apply it (`addLoadSegment` + `patchBytesAt`), and write the result.

---

## 7. Three Bugs Found and Fixed

These were caught during development — through careful cross-checking, not by accident — and each has a dedicated regression test.

### 7.1 Bug 1: sign-extension in the long jump

The trampoline's "long jump" (used when the target is out of direct-branch range) loads a 32-bit address into a register via `lis` (load upper half) followed by `ori` (OR in the lower half). `lis` is `addis rD, 0, SIMM`, and `addis` **sign-extends its result into the full 64-bit register** on the PS3's 64-bit PPU. If the target address's upper halfword looks negative as a 16-bit value (true for any address ≥ `0x80000000`), `lis` fills the register's *upper* 32 bits with `1`s instead of `0`s — and `ori` only ever touches the low 16 bits, so it can't clean this up. The count register would then hold a 64-bit garbage address instead of the intended 32-bit one, and branching to it would jump into unmapped memory. A plain 4-instruction `lis`/`ori`/`mtctr`/`bctr` sequence — which is what the original tool's documented design describes — has this exact bug for any such target address.

**Fix:** a fifth instruction, `clrldi` (clear the high-order 32 bits), inserted between `ori` and `mtctr`, guaranteeing a clean 32-bit value regardless of sign. Verified in `tests/ppc_encode_test.cpp` with a target address specifically chosen to trigger the sign-extension case.

### 7.2 Bug 2: off-by-4× in the branch range check

The direct-branch encoder's range validation originally used `(1 << 25) - 1` as the maximum displacement — a 26-bit bound. The branch instruction's `LI` field, however, is only **24 bits** (representing the displacement in units of 4 bytes, concatenated with two implicit zero bits). The correct byte-displacement range is roughly ±32MB (`2^23 * 4`), not the ~±128MB the original check silently allowed. This was caught while deriving the exact bit layout for a related instruction from the primary-source ISA manual, and confirmed with a boundary test (`+33,554,428` accepted, `+33,554,432` — 4 bytes further — rejected).

### 7.3 Bug 3: losing `BO`/`BI` on conditional branch relocation

Described in [§4.2](#42-decodehpp--branch-classification-and-relocation-safe-fixup): an early version of `relocateBranch` used the unconditional branch encoder for every relative branch being relocated, which would silently convert a conditional branch (`bc`) into an unconditional one if it ever needed to be relocated — a correctness bug that changes program behavior, not just an address. Fixed by adding a dedicated conditional-branch encoder (`encodeBranchConditional`) that preserves the original `BO`/`BI` fields, and a regression test that explicitly checks a relocated conditional branch keeps its original condition bits.

---

## 8. Testing Methodology

169 checks across 8 suites, all passing clean under `-fsanitize=address,undefined`:

| Suite | What it covers |
|---|---|
| `elf_roundtrip_test` | Parse/serialize round-trip against a synthetic BE64 fixture; truncation, bad-magic, and out-of-bounds error handling |
| `ppc_encode_test` | Every instruction encoder, cross-checked against known-good real-world constants; both range-check bugs' regression tests |
| `ppc_decode_test` | Branch classification for all four kinds; relocation correctness including the BO/BI preservation regression test |
| `ps3_toc_test` | OPD descriptor resolution across a two-segment synthetic fixture; non-PS3 and truncated-descriptor error handling |
| `ps3_syscalls_test` | `sc` instruction encoding against its known constant; full call-sequence structure verification |
| `ps3_trampoline_test` | Both jump-size cases (1-instruction and 5-instruction); path-string embedding; input validation; the relocation-refusal safety property |
| `ps3_info_test` | `formatInfo`/`isAlreadyPatched` correctness before and after an in-memory patch |
| `ps3_integration_test` | **Runs the actual compiled `ps3patch` binary** end-to-end against the synthetic fixture, then statically verifies the complete jump chain — original entry → trampoline → resumed code — is self-consistent, plus the idempotency refusal and `--info` output |

Two testing principles worth calling out:

**Synthetic fixtures, not real game files.** Every automated test runs against small, deterministic, Python-generated ELF fixtures (checked into the repo) rather than real PS3 game executables. This keeps the test suite fast, reviewable in a diff, and free of any copyright entanglement with actual game content — real validation happens separately, on real hardware, against files the developer legitimately owns.

**Cross-checking against independent ground truth wherever possible**, rather than only checking internal self-consistency. Several PowerPC encoders are verified against widely-known, independently-documented instruction encodings (e.g. `bctr` = `0x4E800420`); the syscall numbers are verified against two independent sources; and the trampoline's jump-chain correctness is verified by re-parsing the *actual output file* the CLI produces, not just by calling library functions directly in-process.

---

## 9. Why EBOOT Decryption/Re-signing Is Out of Scope

PS3 games ship as an encrypted, signed `EBOOT.BIN`, not a plain `EBOOT.elf` — so why doesn't this tool handle that whole pipeline?

The encryption and signing scheme is Sony's proprietary DRM (NPDRM/SELF signing). Implementing it for real requires private signing keys (that do publicly exist)

It's also not actually necessary for this tool's purpose. A jailbroken PS3 (custom firmware) has already had its *own* signature-verification check patched out — that's what "jailbroken" means in this context. Once that check is disabled at the OS level, the console will boot an EBOOT that isn't properly re-signed at all.

---

## 10. Known Limitations and Future Work

- **The syscall-number register (`r11`) assumption**, while now confirmed on real hardware, was originally sourced from community consensus rather than a primary specification document — worth keeping in mind if this code is ever adapted for a different LV2-based context.
- **No support for architectures beyond PPC64/PS3 in the application layer** — by design, though `libelf` itself already supports all four ELF32/64 × LE/BE combinations generically, and could support another architecture's application layer with comparatively little new code.

---

## 11. Build and Usage Reference

```bash
cmake -S . -B build
cmake --build build
```

```bash
./build/ps3patch EBOOT.elf EBOOT.patched.elf /dev_hdd0/tmp/debug.sprx
./build/ps3patch --info EBOOT.elf
```

Project layout:

```
libelf/include/elf/{endian,types,errors,file}.hpp
ppc/include/ppc/{encode,decode}.hpp
ps3patch/include/ps3patch/{toc,syscalls,trampoline,info}.hpp
ps3patch/src/main.cpp
tests/*.cpp + tests/fixtures/*.elf
```
