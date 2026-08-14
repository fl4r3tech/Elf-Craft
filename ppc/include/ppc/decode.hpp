// ppc/include/ppc/decode.hpp
//
// Classifies a raw instruction word as a branch (and which kind), and
// computes how to fix up a *relative* branch that gets moved to a new
// address — the exact case the original SPRXPatcher didn't handle: if the
// first few instructions at the entrypoint (the ones displaced by the
// injected jump) happen to include a branch, blindly copying those bytes
// into the trampoline and re-executing them is wrong, because a relative
// branch's target depends on its own address.
//
// This module only classifies and re-encodes; it does not know anything
// about ELF or about *why* an instruction is being relocated. That
// decision (how many prologue instructions to displace, what to do if a
// branch can't be safely fixed up) belongs to ps3patch/trampoline.hpp.

#pragma once

#include <cstdint>
#include <optional>

#include "ppc/encode.hpp"

namespace ppc {

enum class BranchKind {
    NotABranch,
    DirectRelative,  // b/bc with AA=0: target depends on this instruction's address
    DirectAbsolute,  // b/bc with AA=1: target is a fixed absolute address, safe to copy verbatim
    ToLinkRegister,  // bclr/bclrl: target is whatever's in LR at runtime, not statically known
    ToCountRegister, // bcctr/bcctrl: target is whatever's in CTR at runtime, not statically known
};

struct DecodedBranch {
    BranchKind kind = BranchKind::NotABranch;
    bool link = false;           // LK bit: does this branch set the Link Register?
    bool isConditionalForm = false; // true if this was encoded as B-form (bc/bca), not I-form (b/ba)
    uint32_t bo = 0;             // BO field (B-form only) — which condition to test
    uint32_t bi = 0;             // BI field (B-form only) — which CR bit to test
    int32_t displacement = 0;    // meaningful only for DirectRelative (byte displacement from own address)
    uint32_t absoluteTarget = 0; // meaningful only for DirectAbsolute
};

namespace detail {

inline int32_t signExtend(uint32_t value, int bitWidth) {
    uint32_t signBit = 1u << (bitWidth - 1);
    return static_cast<int32_t>((value ^ signBit) - signBit);
}

} // namespace detail

// Classify a raw instruction word. Anything that isn't one of the four
// branch forms above returns BranchKind::NotABranch — the overwhelming
// majority of instructions, which is exactly why the original tool's
// "just copy N instructions" approach worked *most* of the time and only
// broke on the rarer case where a branch happened to land in that window.
inline DecodedBranch classify(Instruction instr) {
    uint32_t opcode = (instr >> 26) & 0x3F;
    DecodedBranch result;

    if (opcode == 18) { // I-form: b / ba / bl / bla
        bool aa = (instr & 0x2) != 0;
        bool lk = (instr & 0x1) != 0;
        uint32_t liRaw = instr & 0x03FFFFFCu; // bits 2:25 hold LI, low 2 bits already 0
        int32_t li = detail::signExtend(liRaw, 26);
        result.link = lk;
        if (aa) {
            result.kind = BranchKind::DirectAbsolute;
            result.absoluteTarget = static_cast<uint32_t>(li);
        } else {
            result.kind = BranchKind::DirectRelative;
            result.displacement = li;
        }
        return result;
    }

    if (opcode == 16) { // B-form: bc / bca / bcl / bcla
        bool aa = (instr & 0x2) != 0;
        bool lk = (instr & 0x1) != 0;
        uint32_t bo = (instr >> 21) & 0x1F;
        uint32_t bi = (instr >> 16) & 0x1F;
        uint32_t bdRaw = instr & 0x0000FFFCu; // bits 16:29 hold BD, low 2 bits already 0
        int32_t bd = detail::signExtend(bdRaw, 16);
        result.link = lk;
        result.isConditionalForm = true;
        result.bo = bo;
        result.bi = bi;
        if (aa) {
            result.kind = BranchKind::DirectAbsolute;
            result.absoluteTarget = static_cast<uint32_t>(bd);
        } else {
            result.kind = BranchKind::DirectRelative;
            result.displacement = bd;
        }
        return result;
    }

    if (opcode == 19) { // XL-form: bclr[l] (XO=16) / bcctr[l] (XO=528)
        uint32_t xo = (instr >> 1) & 0x3FF;
        bool lk = (instr & 0x1) != 0;
        if (xo == 16) {
            result.kind = BranchKind::ToLinkRegister;
            result.link = lk;
            return result;
        }
        if (xo == 528) {
            result.kind = BranchKind::ToCountRegister;
            result.link = lk;
            return result;
        }
    }

    return result; // NotABranch
}

// Given a DirectRelative branch originally at `originalAddr` that's being
// relocated so it now lives at `newAddr`, produce a re-encoded instruction
// whose displacement is corrected to still hit the same absolute target —
// or std::nullopt if the corrected displacement no longer fits in the
// instruction's field (in which case the caller cannot safely relocate
// this instruction as a direct branch and must refuse rather than emit
// broken code). Conditional (B-form) branches are re-encoded preserving
// their original BO/BI condition bits, not silently widened into an
// unconditional branch.
//
// DirectAbsolute, ToLinkRegister, and ToCountRegister branches need no
// fixup at all: their target doesn't depend on the branch's own address,
// so the raw instruction word can be copied verbatim to the new location.
inline std::optional<Instruction> relocateBranch(const DecodedBranch& branch, uint32_t originalAddr,
                                                   uint32_t newAddr) {
    if (branch.kind != BranchKind::DirectRelative) {
        return std::nullopt; // caller shouldn't be calling this for non-relative branches
    }
    uint32_t originalTarget = originalAddr + static_cast<uint32_t>(branch.displacement);
    int64_t newDisplacement = static_cast<int64_t>(originalTarget) - static_cast<int64_t>(newAddr);
    if (newDisplacement < INT32_MIN || newDisplacement > INT32_MAX) {
        return std::nullopt;
    }
    try {
        if (branch.isConditionalForm) {
            return encodeBranchConditional(branch.bo, branch.bi, static_cast<int32_t>(newDisplacement),
                                            /*absolute=*/false, branch.link);
        }
        return encodeBranch(static_cast<int32_t>(newDisplacement), /*absolute=*/false, branch.link);
    } catch (const std::invalid_argument&) {
        return std::nullopt; // corrected displacement doesn't fit the 24-bit LI / 14-bit BD field
    }
}

} // namespace ppc
