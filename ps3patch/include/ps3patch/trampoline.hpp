// ps3patch/include/ps3patch/trampoline.hpp
//
// Builds the full injected payload that gets the target .sprx loaded and
// started before the game's original code ever runs, then hands control
// back exactly where it would have gone otherwise. This is where libelf,
// ppc (encode + decode), toc.hpp, and syscalls.hpp all come together.
//
// Layout of the injected blob (all addresses relative to trampolineAddr):
//   [magic]        8-byte marker ("SP3PATCH"), used only for idempotency
//                  detection (isAlreadyPatched) -- never executed
//   [prologue]     save r0, r3-r12, LR, CTR to a new stack frame
//   [syscall]      sys_prx_load_module(path) ; sys_prx_start_module(id)
//   [epilogue]     restore r0, r3-r12, LR, CTR; pop the stack frame
//   [toc fixup]    r2 <- resolved TOC value (required before resuming
//                  original TOC-relative code; NOT a "restore" -- nothing
//                  valid was there before we ran)
//   [resume]       the original entrypoint instructions we displaced,
//                  copied verbatim or relocated if one of them is a
//                  relative branch (see relocateDisplacedInstructions)
//   [jump-back]    branch to whatever comes after the displaced instructions
//   [path string]  the user-supplied .sprx path, null-terminated
//
// And at the original entrypoint itself, we only ever overwrite the exact
// number of instructions needed for a jump into the blob above (1
// instruction if a direct branch reaches, 5 if not) -- minimizing how much
// of the original code we ever touch, which minimizes the chance of
// clobbering something we can't safely relocate.
//
// Register scope: we save/restore r0, r3-r12, LR, and CTR because those
// are exactly what our own injected code and the LV2 syscall ABI use.
// r13-r31 are the PPC64 ELFv1 ABI's non-volatile registers -- any
// well-behaved compiled code (including the loaded .sprx's own init
// routine, invoked indirectly via sys_prx_start_module) is required to
// preserve those itself, so we don't need to. r2 (TOC) is deliberately
// NOT saved/restored: its value on entry is meaningless to us, and we set
// it to the correct resolved value for the ORIGINAL program right before
// resuming it, rather than preserving whatever happened to be there.

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "elf/errors.hpp"
#include "elf/file.hpp"
#include "ppc/decode.hpp"
#include "ppc/encode.hpp"
#include "ps3patch/syscalls.hpp"
#include "ps3patch/toc.hpp"

namespace ps3patch {

struct TrampolineResult {
    std::vector<uint8_t> blob;            // full injected payload, to be written at trampolineAddr
    std::vector<uint8_t> entryPatchBytes; // bytes to overwrite at entry.codeAddress (the jump-in)
    uint32_t trampolineAddr;
    uint32_t entryPatchAddr;
    size_t displacedInstructionCount;
};

// A fixed 8-byte marker written at the very start of every trampoline blob
// (before any code), used purely for idempotency detection -- see
// isAlreadyPatched below. Not executed as code; the jump-in target skips
// past it, landing at trampolineAddr + MAGIC.size().
constexpr std::array<uint8_t, 8> TRAMPOLINE_MAGIC = {'S', 'P', '3', 'P', 'A', 'T', 'C', 'H'};

// Scans the file's existing segments for one that starts with
// TRAMPOLINE_MAGIC, meaning this tool has already patched this file. Used
// to refuse re-patching an already-patched EBOOT rather than silently
// stacking a second trampoline on top of the first (which wouldn't crash
// outright, but would leave a redirect-to-a-redirect chain no one asked
// for, and wastes a jump on every future load for no reason).
inline bool isAlreadyPatched(const Ps3ElfFile& file) {
    for (const auto& ph : file.segments()) {
        if (static_cast<uint32_t>(ph.p_type) != elf::PT_LOAD) continue;
        if (static_cast<uint64_t>(ph.p_filesz) < TRAMPOLINE_MAGIC.size()) continue;
        auto bytesResult = file.readAt(ph.p_offset, TRAMPOLINE_MAGIC.size());
        if (!bytesResult.ok()) continue;
        const auto& bytes = bytesResult.value();
        if (std::equal(TRAMPOLINE_MAGIC.begin(), TRAMPOLINE_MAGIC.end(), bytes.begin())) {
            return true;
        }
    }
    return false;
}

namespace detail {

constexpr uint32_t FRAME_SIZE = 256;      // stack frame: 112-byte ABI linkage area + our save slots + margin
constexpr int32_t SAVE_BASE = 128;        // our save slots start here, clear of the 112-byte linkage area
constexpr size_t PROLOGUE_INSTR_COUNT = 16;
constexpr size_t EPILOGUE_INSTR_COUNT = 16;
constexpr size_t TOC_FIXUP_INSTR_COUNT = 3;

inline std::vector<ppc::Instruction> buildPrologue() {
    using namespace ppc;
    return {
        encodeStdu(1, 1, -static_cast<int32_t>(FRAME_SIZE)), // stdu r1, -256(r1) -- push frame, back-chain
        encodeStd(0, 1, SAVE_BASE + 0),                       // save r0
        encodeMflr(0), encodeStd(0, 1, SAVE_BASE + 8),        // save LR (via r0 scratch)
        encodeMfctr(0), encodeStd(0, 1, SAVE_BASE + 16),      // save CTR (via r0 scratch)
        encodeStd(3, 1, SAVE_BASE + 24),  encodeStd(4, 1, SAVE_BASE + 32),
        encodeStd(5, 1, SAVE_BASE + 40),  encodeStd(6, 1, SAVE_BASE + 48),
        encodeStd(7, 1, SAVE_BASE + 56),  encodeStd(8, 1, SAVE_BASE + 64),
        encodeStd(9, 1, SAVE_BASE + 72),  encodeStd(10, 1, SAVE_BASE + 80),
        encodeStd(11, 1, SAVE_BASE + 88), encodeStd(12, 1, SAVE_BASE + 96),
    };
}

inline std::vector<ppc::Instruction> buildEpilogue() {
    using namespace ppc;
    return {
        encodeLd(0, 1, SAVE_BASE + 8), encodeMtlr(0),
        encodeLd(0, 1, SAVE_BASE + 16), encodeMtctr(0),
        encodeLd(3, 1, SAVE_BASE + 24),  encodeLd(4, 1, SAVE_BASE + 32),
        encodeLd(5, 1, SAVE_BASE + 40),  encodeLd(6, 1, SAVE_BASE + 48),
        encodeLd(7, 1, SAVE_BASE + 56),  encodeLd(8, 1, SAVE_BASE + 64),
        encodeLd(9, 1, SAVE_BASE + 72),  encodeLd(10, 1, SAVE_BASE + 80),
        encodeLd(11, 1, SAVE_BASE + 88), encodeLd(12, 1, SAVE_BASE + 96),
        encodeLd(0, 1, SAVE_BASE + 0),
        encodeAddi(1, 1, static_cast<int16_t>(FRAME_SIZE)), // pop frame
    };
}

// Smallest jump that reaches from `fromAddr` to `toAddr`: a single direct
// branch if in range, else the 5-instruction absolute long jump. Always
// succeeds -- makeAbsoluteJump can reach any 32-bit address.
inline std::vector<ppc::Instruction> makeMinimalJump(uint32_t fromAddr, uint32_t toAddr) {
    int64_t disp = static_cast<int64_t>(toAddr) - static_cast<int64_t>(fromAddr);
    if (disp % 4 == 0 && disp >= -33554432 && disp <= 33554428) {
        try {
            return {ppc::encodeBranch(static_cast<int32_t>(disp), /*absolute=*/false, /*link=*/false)};
        } catch (const std::invalid_argument&) {
            // Fall through to the long jump -- shouldn't happen given the range check above.
        }
    }
    auto longJump = ppc::makeAbsoluteJump(toAddr);
    return std::vector<ppc::Instruction>(longJump.begin(), longJump.end());
}

inline std::vector<uint8_t> toBigEndianBytes(const std::vector<ppc::Instruction>& instrs) {
    std::vector<uint8_t> out;
    out.reserve(instrs.size() * 4);
    for (auto instr : instrs) {
        out.push_back(static_cast<uint8_t>(instr >> 24));
        out.push_back(static_cast<uint8_t>(instr >> 16));
        out.push_back(static_cast<uint8_t>(instr >> 8));
        out.push_back(static_cast<uint8_t>(instr));
    }
    return out;
}

} // namespace detail

// Relocates the instructions displaced from the original entrypoint so
// they can run safely at `newBaseAddr` instead of `originalBaseAddr`.
// Returns an error (rather than silently emitting wrong code) if any
// displaced instruction is a relative branch whose corrected displacement
// no longer fits its field -- this is the exact failure mode the original
// tool never checked for.
inline elf::Result<std::vector<ppc::Instruction>, elf::Error> relocateDisplacedInstructions(
    const std::vector<ppc::Instruction>& original, uint32_t originalBaseAddr, uint32_t newBaseAddr) {
    std::vector<ppc::Instruction> out;
    out.reserve(original.size());
    for (size_t i = 0; i < original.size(); ++i) {
        uint32_t originalAddr = originalBaseAddr + static_cast<uint32_t>(i * 4);
        uint32_t newAddr = newBaseAddr + static_cast<uint32_t>(i * 4);
        auto decoded = ppc::classify(original[i]);
        if (decoded.kind == ppc::BranchKind::DirectRelative) {
            auto fixed = ppc::relocateBranch(decoded, originalAddr, newAddr);
            if (!fixed.has_value()) {
                return elf::Error::make(
                    elf::ErrorCode::RelocationFailed,
                    "instruction " + std::to_string(i) +
                        " at the entrypoint is a relative branch whose displacement can't be corrected "
                        "after relocation -- refusing to patch rather than emit a broken jump");
            }
            out.push_back(*fixed);
        } else {
            // NotABranch, DirectAbsolute, ToLinkRegister, and ToCountRegister
            // are all address-independent: safe to copy verbatim.
            out.push_back(original[i]);
        }
    }
    return out;
}

// Builds the complete trampoline blob and the corresponding entry-point
// patch. Does not touch the ELF file itself -- returns byte buffers and
// addresses for the caller (the higher-level patch orchestrator) to write.
inline elf::Result<TrampolineResult, elf::Error> buildTrampoline(const Ps3ElfFile& file,
                                                                    const EntryDescriptor& entry,
                                                                    uint32_t trampolineAddr,
                                                                    const std::string& sprxPath) {
    if (sprxPath.empty()) {
        return elf::Error::make(elf::ErrorCode::InvalidArgument, "sprxPath must not be empty");
    }
    constexpr size_t kMaxPathLength = 1023; // conservative bound; leaves room for the null terminator
    if (sprxPath.size() > kMaxPathLength) {
        return elf::Error::make(elf::ErrorCode::InvalidArgument,
                                 "sprxPath exceeds the maximum supported length (" +
                                     std::to_string(kMaxPathLength) + " bytes)");
    }
    if (trampolineAddr % 4 != 0) {
        return elf::Error::make(elf::ErrorCode::InvalidArgument, "trampolineAddr must be 4-byte aligned");
    }
    if (entry.codeAddress % 4 != 0) {
        return elf::Error::make(elf::ErrorCode::InvalidArgument, "entry.codeAddress must be 4-byte aligned");
    }
    if (isAlreadyPatched(file)) {
        return elf::Error::make(elf::ErrorCode::AlreadyPatched,
                                 "this file already contains a ps3patch trampoline segment -- refusing to patch "
                                 "an already-patched file (use the original, unmodified EBOOT.elf)");
    }

    // All code lives after the 8-byte magic marker at the start of the blob.
    uint32_t codeBaseAddr = trampolineAddr + static_cast<uint32_t>(TRAMPOLINE_MAGIC.size());

    // 1. Jump-in: smallest jump from the original entrypoint into our blob.
    auto jumpIn = detail::makeMinimalJump(static_cast<uint32_t>(entry.codeAddress), codeBaseAddr);
    size_t displacedCount = jumpIn.size();

    // 2. Read the original instructions we're about to displace.
    auto entryOffsetResult = file.vaddrToFileOffset(entry.codeAddress);
    if (!entryOffsetResult.ok()) {
        return elf::Error::make(elf::ErrorCode::OffsetOutOfBounds,
                                 "entry.codeAddress does not resolve to a file-backed segment: " +
                                     entryOffsetResult.error().message);
    }
    auto entryBytesResult = file.readAt(entryOffsetResult.value(), displacedCount * 4);
    if (!entryBytesResult.ok()) {
        return elf::Error::make(elf::ErrorCode::TruncatedFile,
                                 "not enough file data at the entrypoint to read " +
                                     std::to_string(displacedCount) + " instruction(s): " +
                                     entryBytesResult.error().message);
    }
    const auto& entryBytes = entryBytesResult.value();
    std::vector<ppc::Instruction> displacedInstructions;
    displacedInstructions.reserve(displacedCount);
    for (size_t i = 0; i < displacedCount; ++i) {
        uint32_t w = (static_cast<uint32_t>(entryBytes[i * 4 + 0]) << 24) |
                     (static_cast<uint32_t>(entryBytes[i * 4 + 1]) << 16) |
                     (static_cast<uint32_t>(entryBytes[i * 4 + 2]) << 8) |
                     static_cast<uint32_t>(entryBytes[i * 4 + 3]);
        displacedInstructions.push_back(w);
    }

    // 3. Compute fixed-size section lengths (all independent of the path
    //    string's length and of the final path address -- see the header
    //    comment's layout description for why this ordering avoids any
    //    circular dependency between "where is X" and "what does X contain").
    size_t fixedPrefixInstrCount =
        detail::PROLOGUE_INSTR_COUNT + SYSCALL_SEQUENCE_INSTR_COUNT + detail::EPILOGUE_INSTR_COUNT +
        detail::TOC_FIXUP_INSTR_COUNT;
    uint32_t resumeAddr = codeBaseAddr + static_cast<uint32_t>(fixedPrefixInstrCount * 4);

    // 4. Relocate the displaced instructions to live at resumeAddr.
    auto relocated = relocateDisplacedInstructions(displacedInstructions, static_cast<uint32_t>(entry.codeAddress),
                                                     resumeAddr);
    if (!relocated.ok()) return relocated.error();

    // 5. Jump-back: from right after the resume section, to whatever
    //    originally followed the displaced instructions.
    uint32_t jumpBackAddr = resumeAddr + static_cast<uint32_t>(displacedCount * 4);
    uint32_t remainderAddr = static_cast<uint32_t>(entry.codeAddress) + static_cast<uint32_t>(displacedCount * 4);
    auto jumpBack = detail::makeMinimalJump(jumpBackAddr, remainderAddr);

    // 6. Now the total code size is known -- compute where the path string lives.
    size_t totalCodeInstrCount = fixedPrefixInstrCount + displacedCount + jumpBack.size();
    uint32_t pathAddress = codeBaseAddr + static_cast<uint32_t>(totalCodeInstrCount * 4);

    // 7. Build the syscall sequence now that pathAddress is known. Its
    //    instruction COUNT was already fixed and included in
    //    fixedPrefixInstrCount above; this just fills in the real address.
    auto syscallInstrs = makeLoadAndStartModule(pathAddress);
    if (syscallInstrs.size() != SYSCALL_SEQUENCE_INSTR_COUNT) {
        return elf::Error::make(elf::ErrorCode::Unsupported,
                                 "internal inconsistency: syscall sequence length changed unexpectedly");
    }

    // 8. Assemble the full instruction stream.
    std::vector<ppc::Instruction> code;
    code.reserve(totalCodeInstrCount);
    auto prologue = detail::buildPrologue();
    auto epilogue = detail::buildEpilogue();
    auto tocFixup = ppc::loadImmediate32(2, static_cast<uint32_t>(entry.tocValue));

    code.insert(code.end(), prologue.begin(), prologue.end());
    code.insert(code.end(), syscallInstrs.begin(), syscallInstrs.end());
    code.insert(code.end(), epilogue.begin(), epilogue.end());
    code.insert(code.end(), tocFixup.begin(), tocFixup.end());
    code.insert(code.end(), relocated.value().begin(), relocated.value().end());
    code.insert(code.end(), jumpBack.begin(), jumpBack.end());

    if (code.size() != totalCodeInstrCount) {
        return elf::Error::make(elf::ErrorCode::Unsupported,
                                 "internal inconsistency: assembled code size does not match the planned layout");
    }

    // 9. Serialize: magic marker, then code as big-endian instruction
    //    words, then the null-terminated path string.
    TrampolineResult result;
    result.blob.assign(TRAMPOLINE_MAGIC.begin(), TRAMPOLINE_MAGIC.end());
    auto codeBytes = detail::toBigEndianBytes(code);
    result.blob.insert(result.blob.end(), codeBytes.begin(), codeBytes.end());
    result.blob.insert(result.blob.end(), sprxPath.begin(), sprxPath.end());
    result.blob.push_back(0); // null terminator
    while (result.blob.size() % 4 != 0) result.blob.push_back(0); // keep the blob 4-byte aligned overall

    result.entryPatchBytes = detail::toBigEndianBytes(jumpIn);
    result.trampolineAddr = trampolineAddr;
    result.entryPatchAddr = static_cast<uint32_t>(entry.codeAddress);
    result.displacedInstructionCount = displacedCount;
    return result;
}

} // namespace ps3patch
