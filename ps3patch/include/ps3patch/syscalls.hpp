// ps3patch/include/ps3patch/syscalls.hpp
//
// LV2 syscall numbers and calling convention needed to have the injected
// trampoline actually load and start a custom .sprx at runtime, via
// sys_prx_load_module() followed by sys_prx_start_module().
//
// Syscall numbers verified against two independent sources (a disassembled
// PS3 syscall table and the PS3 Developer wiki, which agree):
//   480 (0x1E0) = sys_prx_load_module
//   481 (0x1E1) = sys_prx_start_module
// Argument order confirmed against RPCS3's emulator source (the HLE
// implementations of these syscalls):
//   sys_prx_load_module(path, flags, pOpt)             -> returns module id
//   sys_prx_start_module(id, args, argp, result, flags, pOpt)
//
// CONFIDENCE NOTE on the syscall-number register: PS3's LV2 kernel uses
// r11 for the syscall number, differing from the standard Linux/PowerPC
// "sc" ABI (which uses r0). This was community consensus in the homebrew
// scene at the time this was written, and has since been confirmed
// empirically on real PS3 hardware. The register is still exposed as a
// parameter (defaulting to r11) rather than hardcoded, since that costs
// nothing and keeps the assumption visible rather than buried.

#pragma once

#include <cstdint>
#include <vector>

#include "ppc/encode.hpp"

namespace ps3patch {

constexpr uint32_t SYS_PRX_LOAD_MODULE = 480;
constexpr uint32_t SYS_PRX_START_MODULE = 481;

// makeLoadModuleCall (7) + makeStartModuleCall (7). Exposed as a named
// constant so trampoline.hpp's layout math can't silently drift out of
// sync with the actual instruction count if either sequence changes.
constexpr size_t SYSCALL_SEQUENCE_INSTR_COUNT = 14;

// Registers, per the LV2 syscall calling convention as used throughout the
// PS3 homebrew SDKs (PSL1GHT, etc.): arguments in r3..r10, syscall number
// in r11 (see confidence note above), result returned in r3, trap via "sc".
constexpr uint32_t REG_SYSCALL_NUMBER_DEFAULT = 11;
constexpr uint32_t REG_ARG0 = 3;
constexpr uint32_t REG_ARG1 = 4;
constexpr uint32_t REG_ARG2 = 5;
constexpr uint32_t REG_ARG3 = 6;
constexpr uint32_t REG_ARG4 = 7;
constexpr uint32_t REG_ARG5 = 8;
constexpr uint32_t REG_RETURN = 3; // same register as ARG0 -- matches the real ABI (r3 in, r3 out)

// The "sc" instruction itself: a fixed encoding (opcode 17, LEV=0), the
// same 4 bytes regardless of what's in the registers -- the registers are
// what make it a *specific* syscall.
inline ppc::Instruction encodeSc() {
    return (17u << 26) | (0u << 5) | (1u << 1); // opcode=17, LEV=0, fixed '1' bit at position 30
}

// li rSyscallNum, number ; sc  -- traps into the kernel with whatever
// arguments are already sitting in r3..r10. Building the argument-loading
// instructions is the caller's job (via ppc::encodeLi / ppc::loadImmediate32),
// since which registers need loading depends on the specific syscall.
inline std::vector<ppc::Instruction> makeSyscallTrap(uint32_t syscallNumber,
                                                       uint32_t syscallNumberReg = REG_SYSCALL_NUMBER_DEFAULT) {
    // Syscall numbers here (480, 481, ...) comfortably fit a signed 16-bit
    // immediate, so a plain `li` suffices -- no need for the lis/ori/clrldi
    // dance that's needed for arbitrary 32-bit values.
    return {
        ppc::encodeLi(syscallNumberReg, static_cast<int16_t>(syscallNumber)),
        encodeSc(),
    };
}

// Full instruction sequence for: id = sys_prx_load_module(pathAddress, 0, 0)
// `pathAddress` is the virtual address of a null-terminated path string
// (e.g. "/dev_hdd0/tmp/debug.sprx") that must already be embedded as data
// somewhere reachable in the patched file -- this function only builds the
// code that calls the syscall with a pointer to it, not the string itself.
// After this sequence executes, r3 holds the loaded module's id (or a
// negative error code), matching REG_RETURN.
inline std::vector<ppc::Instruction> makeLoadModuleCall(uint32_t pathAddress) {
    std::vector<ppc::Instruction> out;
    auto pathPtrLoad = ppc::loadImmediate32(REG_ARG0, pathAddress); // r3 = path pointer
    out.insert(out.end(), pathPtrLoad.begin(), pathPtrLoad.end());
    out.push_back(ppc::encodeLi(REG_ARG1, 0)); // r4 = flags = 0
    out.push_back(ppc::encodeLi(REG_ARG2, 0)); // r5 = pOpt = 0 (null)
    auto trap = makeSyscallTrap(SYS_PRX_LOAD_MODULE);
    out.insert(out.end(), trap.begin(), trap.end());
    return out;
}

// Full instruction sequence for:
//   sys_prx_start_module(id, 0, 0, 0, 0, 0)
// `idIsInR3` documents the expected precondition: this is meant to be
// emitted immediately after makeLoadModuleCall(), whose result (the module
// id) is already sitting in r3 -- exactly where sys_prx_start_module
// expects its first argument. No extra move is needed, but the sequence
// still explicitly re-establishes r4..r8 as zero since intervening code
// (there shouldn't be any, but this stays correct even if someone inserts
// some) could have clobbered them.
inline std::vector<ppc::Instruction> makeStartModuleCall() {
    std::vector<ppc::Instruction> out;
    // r3 (id) is assumed already set by a preceding makeLoadModuleCall().
    out.push_back(ppc::encodeLi(REG_ARG1, 0)); // r4 = args = 0
    out.push_back(ppc::encodeLi(REG_ARG2, 0)); // r5 = argp = 0 (null)
    out.push_back(ppc::encodeLi(REG_ARG3, 0)); // r6 = result = 0 (null)
    out.push_back(ppc::encodeLi(REG_ARG4, 0)); // r7 = flags = 0
    out.push_back(ppc::encodeLi(REG_ARG5, 0)); // r8 = pOpt = 0 (null)
    auto trap = makeSyscallTrap(SYS_PRX_START_MODULE);
    out.insert(out.end(), trap.begin(), trap.end());
    return out;
}

// Convenience: the full load-then-start sequence in one call.
inline std::vector<ppc::Instruction> makeLoadAndStartModule(uint32_t pathAddress) {
    auto load = makeLoadModuleCall(pathAddress);
    auto start = makeStartModuleCall();
    load.insert(load.end(), start.begin(), start.end());
    return load;
}

} // namespace ps3patch
