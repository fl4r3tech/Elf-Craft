# ELF-Craft

![Status](https://img.shields.io/badge/status-work%20in%20progress-orange)
![Stage](https://img.shields.io/badge/stage-beta%20%2F%20bug%20testing-blue)

> **⚠️ Notice:** This project is currently in an active **Beta / Work-in-Progress (WIP)** stage. It is published for community visibility, code review, and debugging purposes. Expect breaking changes, unpolished features, and ongoing bug fixes.

---


A from-scratch C++17 rewrite of [SPRXPatcher](https://notnite.com/blog/ps3), a PS3 homebrew tool that patches a decrypted game executable (`EBOOT.elf`) to load a custom `.sprx` plugin at startup.

This isn't a port — it's an independent reimplementation with a general-purpose ELF library underneath, three real correctness bugs found and fixed relative to the original tool, and a test suite (169 checks) that runs clean under AddressSanitizer and UndefinedBehaviorSanitizer. It's built for PS3 homebrew development and reverse-engineering education.

## What it does

```
ps3patch <input EBOOT.elf> <output EBOOT.elf> <sprx path>
ps3patch --info <EBOOT.elf>
```

Given a decrypted PS3 executable and a path to a `.sprx` file (e.g. one you'll place on a USB stick or the console's HDD), `ps3patch` redirects the executable's entrypoint to first load and start that `.sprx`, then transparently resumes the game exactly as if nothing happened.

```bash
$ ps3patch EBOOT.elf EBOOT.patched.elf /dev_hdd0/tmp/debug.sprx
Read 8421376 bytes from EBOOT.elf
Resolved entrypoint: codeAddress=0x1a2b30 tocValue=0x3f8100
Placing trampoline segment at vaddr=0x450000
Trampoline blob: 240 bytes, displaced 1 instruction(s) at the entrypoint
Wrote 8421728 bytes to EBOOT.patched.elf
Patched successfully. On boot, this EBOOT will load and start: /dev_hdd0/tmp/debug.sprx
```

`--info` is a read-only inspection mode — useful for checking whether a file has already been patched, or just for understanding a PS3 executable's structure:

```bash
$ ps3patch --info EBOOT.elf
=== Entry Function Descriptor (OPD) ===
  Code address: 0x1a2b30
  TOC value:    0x3f8100
  ...
```

## Why this exists

The [original SPRXPatcher](https://notnite.com/blog/ps3) works, but has a couple of known sharp edges (documented candidly by its own author) — most notably, it doesn't check whether the instructions it overwrites at the entrypoint happen to include a branch, which can silently produce a broken binary in that case. This project is a ground-up rewrite that:

- Separates concerns into a general-purpose ELF library, an ELF-agnostic PowerPC encoder/decoder, and a thin PS3-specific application layer — so most of the code isn't PS3-specific at all and could be reused for other PPC64 ELF work.
- Fixes that branch-overwrite bug (and two others found during development — see the [technical writeup](docs/TECHNICAL_WRITEUP.md#three-bugs-found-and-fixed) for details) by statically classifying every displaced instruction and refusing to patch rather than emitting broken code when a fixup isn't safe.
- Is tested — 169 checks across 8 suites, including an end-to-end integration test that runs the actual compiled binary and statically verifies the whole entry-redirect-and-resume jump chain.

## Architecture, in short

```
libelf/     general-purpose ELF32/64 parser + mutator, endian-safe, PS3-agnostic
ppc/        PowerPC instruction encoder/decoder, ELF-agnostic
ps3patch/   PS3-specific application layer (TOC resolution, syscalls, trampoline codegen, CLI)
```

Each layer only depends on the one below it. `libelf` doesn't know PS3 exists; `ppc` doesn't know ELF exists. See the [technical writeup](docs/TECHNICAL_WRITEUP.md) for the full rationale and a module-by-module breakdown.

## Building

Requires CMake 3.16+ and a C++17 compiler.

```bash
cmake -S . -B build -DSPRX_ENABLE_SANITIZERS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

The `ps3patch` binary lands in `build/`. `SPRX_ENABLE_SANITIZERS=ON` is recommended for development builds; drop it for a release build.

### Key Technical Features
* Bypasses generic textbook assumptions by implementing Sony's custom 8-byte function descriptor format, verified against retail hardware dumps[cite: 1].
* Handles multi-segment virtual-to-file address translation and safe bounds checking to prevent out-of-bounds reads on truncated or malformed binaries[cite: 3].
* Features non-fatal diagnostics for header flags (`e_flags`) and structural validation tailored specifically to PS3 PPU execution environments[cite: 1, 2, 3].

## Scope and limitations

- **Out of scope by design:** EBOOT.BIN decryption and re-signing. That's Sony's proprietary DRM (NPDRM/SELF signing), and this tool deliberately doesn't touch it — see [why](docs/TECHNICAL_WRITEUP.md#why-eboot-decryptionre-signing-is-out-of-scope) in the writeup. This tool operates on an already-decrypted `EBOOT.elf`, which existing community tools (e.g. `scetool`) produce.
- **Not yet implemented:** PS3-specific `e_flags` validation beyond machine-type checking (planned).
- **Real hardware:** every correctness claim here is backed by static analysis and a synthetic-fixture test suite; final validation against real game executables happens on real PS3 hardware.

## License / attribution

Built as an independent educational reimplementation, referencing the publicly documented behavior of the original SPRXPatcher (credit: NotNite) without reusing its code.
