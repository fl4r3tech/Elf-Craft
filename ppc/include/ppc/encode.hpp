// ppc/include/ppc/encode.hpp
//
// Minimal PowerPC instruction encoders — just the subset needed to build a
// trampoline: load an absolute address into a register, jump to it via the
// count register, and (separately) encode a direct relative/absolute branch
// for fixing up any branch instruction we displace from the entrypoint.
//
// Every function here returns a 32-bit instruction word in *host* byte
// order representing the instruction's bit pattern. Converting that word to
// the file's actual byte order (big-endian on PS3) is the caller's job —
// keeping that split means this module has zero dependency on elf::Endian
// and can be tested/reused completely independently of ELF.
//
// Bit-layout references: PowerPC ISA (v.2.06), primary opcodes:
//   18 = b/bl/ba/bla (I-form)
//   15 = addis        (D-form)
//   24 = ori           (D-form)
//   31 = mtspr (XO=467) (XFX-form)
//   19 = bclr(XO=16) / bcctr(XO=528) (XL-form)

#pragma once

#include <array>
#include <cstdint>
#include <stdexcept>

namespace ppc {

using Instruction = uint32_t;

// Special-purpose register numbers (raw, not yet bit-swapped for encoding).
constexpr uint32_t SPR_LR = 8;
constexpr uint32_t SPR_CTR = 9;

namespace detail {

inline uint32_t bits(uint32_t value, int width) {
    return value & ((width >= 32) ? 0xFFFFFFFFu : ((1u << width) - 1u));
}

// SPR numbers are encoded in the instruction with their two 5-bit halves
// swapped relative to the natural register number — an easy detail to get
// wrong silently, so it's isolated here with its own name.
inline uint32_t encodeSprField(uint32_t sprNumber) {
    uint32_t lo5 = sprNumber & 0x1F;
    uint32_t hi5 = (sprNumber >> 5) & 0x1F;
    return (lo5 << 5) | hi5;
}

} // namespace detail

// addi rD, rA, SIMM   (rA=0 form is the "li rD, SIMM" pseudo-op)
inline Instruction encodeAddi(uint32_t rd, uint32_t ra, int16_t simm) {
    return (detail::bits(14, 6) << 26) | (detail::bits(rd, 5) << 21) | (detail::bits(ra, 5) << 16) |
           detail::bits(static_cast<uint16_t>(simm), 16);
}

inline Instruction encodeLi(uint32_t rd, int16_t simm) { return encodeAddi(rd, 0, simm); }

// addis rD, rA, SIMM   (rA=0 form is the "lis rD, SIMM" pseudo-op)
inline Instruction encodeAddis(uint32_t rd, uint32_t ra, int16_t simm) {
    return (detail::bits(15, 6) << 26) | (detail::bits(rd, 5) << 21) | (detail::bits(ra, 5) << 16) |
           detail::bits(static_cast<uint16_t>(simm), 16);
}

inline Instruction encodeLis(uint32_t rd, int16_t simm) { return encodeAddis(rd, 0, simm); }

// ori rA, rS, UIMM
inline Instruction encodeOri(uint32_t ra, uint32_t rs, uint16_t uimm) {
    return (detail::bits(24, 6) << 26) | (detail::bits(rs, 5) << 21) | (detail::bits(ra, 5) << 16) |
           detail::bits(uimm, 16);
}

// mtspr SPR, rS   (used here specifically for mtctr / mtlr)
inline Instruction encodeMtspr(uint32_t rs, uint32_t sprNumber) {
    return (detail::bits(31, 6) << 26) | (detail::bits(rs, 5) << 21) |
           (detail::bits(detail::encodeSprField(sprNumber), 10) << 11) | (detail::bits(467, 10) << 1);
}

// mfspr rT, SPR   (used here specifically for mflr / mfctr)
inline Instruction encodeMfspr(uint32_t rt, uint32_t sprNumber) {
    return (detail::bits(31, 6) << 26) | (detail::bits(rt, 5) << 21) |
           (detail::bits(detail::encodeSprField(sprNumber), 10) << 11) | (detail::bits(339, 10) << 1);
}

inline Instruction encodeMtlr(uint32_t rs) { return encodeMtspr(rs, SPR_LR); }
inline Instruction encodeMflr(uint32_t rt) { return encodeMfspr(rt, SPR_LR); }
inline Instruction encodeMtctrSpr(uint32_t rs) { return encodeMtspr(rs, SPR_CTR); } // alias, see encodeMtctr below
inline Instruction encodeMfctr(uint32_t rt) { return encodeMfspr(rt, SPR_CTR); }

// std rS, D(rA)  /  stdu rS, D(rA)   (DS-form, primary opcode 62; XO=0 plain, XO=1 update)
// Field layout per the PowerPC ISA (Book I, DS-form): OPCD(0:5) RS(6:10) RA(11:15)
// DS(16:29) XO(30:31). D must be a multiple of 4; DS stores D/4 as a signed 14-bit value.
inline Instruction encodeStdForm(uint32_t primaryOpcode, uint32_t xo, uint32_t rsOrRt, uint32_t ra, int32_t d) {
    if (d % 4 != 0) {
        throw std::invalid_argument("std/ld displacement must be a multiple of 4");
    }
    constexpr int32_t kMax = ((1 << 13) - 1) * 4; // 32,764
    constexpr int32_t kMin = -(1 << 13) * 4;      // -32,768
    if (d > kMax || d < kMin) {
        throw std::invalid_argument("std/ld displacement out of range for the 14-bit DS field");
    }
    uint32_t ds14 = detail::bits(static_cast<uint32_t>(d / 4), 14);
    return (detail::bits(primaryOpcode, 6) << 26) | (detail::bits(rsOrRt, 5) << 21) | (detail::bits(ra, 5) << 16) |
           (ds14 << 2) | detail::bits(xo, 2);
}

inline Instruction encodeStd(uint32_t rs, uint32_t ra, int32_t d) { return encodeStdForm(62, 0, rs, ra, d); }
inline Instruction encodeStdu(uint32_t rs, uint32_t ra, int32_t d) { return encodeStdForm(62, 1, rs, ra, d); }
inline Instruction encodeLd(uint32_t rt, uint32_t ra, int32_t d) { return encodeStdForm(58, 0, rt, ra, d); }
inline Instruction encodeLdu(uint32_t rt, uint32_t ra, int32_t d) { return encodeStdForm(58, 1, rt, ra, d); }

// rldicl rA, rS, SH, MB, Rc=0   (MD-form, primary opcode 30, XO=0)
// RA <- ROTL64(rS, SH) & MASK(MB, 63). With SH=0 this is a pure mask, which
// is exactly the "clrldi" extended mnemonic: clear the high-order MB bits.
// Field layout per the PowerPC ISA (Book I, MD-form): OPCD(0:5) RS(6:10)
// RA(11:15) sh<0:4>(16:20) mb(21:26) XO(27:29) sh<5>(30) Rc(31).
inline Instruction encodeRldicl(uint32_t ra, uint32_t rs, uint32_t sh6, uint32_t mb6, bool rc = false) {
    uint32_t shLo5 = sh6 & 0x1F;
    uint32_t shHi1 = (sh6 >> 5) & 0x1;
    return (detail::bits(30, 6) << 26) | (detail::bits(rs, 5) << 21) | (detail::bits(ra, 5) << 16) |
           (detail::bits(shLo5, 5) << 11) | (detail::bits(mb6, 6) << 5) | (detail::bits(0, 3) << 2) |
           (detail::bits(shHi1, 1) << 1) | (rc ? 1u : 0u);
}

// clrldi rA, rS, n  ==  rldicl rA, rS, 0, n  — zero the high-order n bits.
inline Instruction encodeClrldi(uint32_t ra, uint32_t rs, uint32_t n) { return encodeRldicl(ra, rs, 0, n); }

inline Instruction encodeMtctr(uint32_t rs) { return encodeMtspr(rs, SPR_CTR); }

// bcctr with BO=20 (branch always), BI=0, LK=0 — the unconditional "bctr".
inline Instruction encodeBctr() {
    constexpr uint32_t BO_ALWAYS = 0b10100;
    return (detail::bits(19, 6) << 26) | (detail::bits(BO_ALWAYS, 5) << 21) | (detail::bits(0, 5) << 16) |
           (detail::bits(0, 5) << 11) | (detail::bits(528, 10) << 1);
}

// b / ba / bl / bla (I-form). `target` is either an absolute address
// (absolute=true) or a byte displacement relative to this instruction's own
// address (absolute=false). Both must be 4-byte aligned. The LI field
// itself is 24 bits, holding the displacement in units of 4 bytes (it's
// concatenated with an implicit 0b00), so the representable byte range is
// -2^25 .. 2^25-4 (~±32MB) — PowerPC's direct branch simply cannot reach
// further than that, which is exactly why the trampoline below exists for
// jumps to an arbitrary 32-bit code address.
inline Instruction encodeBranch(int32_t target, bool absolute, bool link) {
    if (target % 4 != 0) {
        throw std::invalid_argument("branch target must be 4-byte aligned");
    }
    constexpr int32_t kMaxBytes = (1 << 25) - 4; // (2^23 - 1) * 4 = 33,554,428
    constexpr int32_t kMinBytes = -(1 << 25);    // -2^23 * 4 = -33,554,432
    if (target > kMaxBytes || target < kMinBytes) {
        throw std::invalid_argument("branch target out of range for a direct b/ba instruction");
    }
    uint32_t li = detail::bits(static_cast<uint32_t>(target), 26) & 0xFFFFFFFCu; // mask low 2 bits clean
    return (detail::bits(18, 6) << 26) | li | (absolute ? 0x2u : 0u) | (link ? 0x1u : 0u);
}

// bc / bca / bcl / bcla (B-form). Same target semantics as encodeBranch,
// but the displacement field (BD) is only 14 bits, giving a much shorter
// reach (~±32KB) — and critically, BO/BI select *which* condition is being
// tested, so a relocation fixup must preserve them rather than re-encoding
// as an unconditional I-form branch (which would silently change program
// behavior, not just its address).
inline Instruction encodeBranchConditional(uint32_t bo, uint32_t bi, int32_t target, bool absolute, bool link) {
    if (target % 4 != 0) {
        throw std::invalid_argument("branch target must be 4-byte aligned");
    }
    constexpr int32_t kMaxBytes = (1 << 15) - 4; // (2^13 - 1) * 4 = 32,764
    constexpr int32_t kMinBytes = -(1 << 15);    // -2^13 * 4 = -32,768
    if (target > kMaxBytes || target < kMinBytes) {
        throw std::invalid_argument("branch target out of range for a bc/bca instruction's 14-bit BD field");
    }
    uint32_t bd = detail::bits(static_cast<uint32_t>(target), 16) & 0xFFFCu;
    return (detail::bits(16, 6) << 26) | (detail::bits(bo, 5) << 21) | (detail::bits(bi, 5) << 16) | bd |
           (absolute ? 0x2u : 0u) | (link ? 0x1u : 0u);
}

// Load an arbitrary 32-bit value into a register, guaranteed clean in the
// upper 32 bits of the (64-bit) register regardless of sign -- this is the
// lis/ori/clrldi sequence with the sign-extension fix explained above,
// factored out so both makeAbsoluteJump and anything else that needs to
// materialize a 32-bit address or constant (e.g. the syscall path-pointer
// argument in ps3patch/syscalls.hpp) can reuse it instead of duplicating
// the same bug-prone pattern.
inline std::array<Instruction, 3> loadImmediate32(uint32_t reg, uint32_t value) {
    int16_t hi = static_cast<int16_t>((value >> 16) & 0xFFFF);
    uint16_t lo = static_cast<uint16_t>(value & 0xFFFF);
    return {
        encodeLis(reg, hi),
        encodeOri(reg, reg, lo),
        encodeClrldi(reg, reg, 32),
    };
}

// The trampoline's "long jump": load a 32-bit absolute address into
// `scratchReg`, move it into CTR, then branch to CTR. This is the technique
// the original SPRXPatcher uses because a direct `b` instruction can't
// reach an arbitrary far address.
//
// Correctness note (this is a real bug we're fixing, not just being extra
// careful): `lis` is `addis rD, 0, SIMM`, and addis sign-extends its result
// into the full 64-bit register on the PS3's 64-bit PPU. If bit 15 of the
// target address is set (i.e. targetAddress's upper halfword, as a 16-bit
// value, is >= 0x8000 — true for any address >= 0x80000000, but also
// whenever that halfword alone looks negative), `lis` fills the *upper*
// 32 bits of the register with 1s instead of 0s. `ori` only ever touches
// the low 16 bits, so it can't clean that up. CTR would then hold a
// 64-bit garbage address instead of the intended 32-bit one, and `bctr`
// would branch into unmapped memory and crash. A 4-instruction
// lis/ori/mtctr/bctr sequence — which is what the original tool's blog
// post describes — has this bug for any target address with that bit set.
// loadImmediate32 already includes the clrldi fix, so we just append the
// mtctr/bctr pair here.
inline std::array<Instruction, 5> makeAbsoluteJump(uint32_t targetAddress, uint32_t scratchReg = 12) {
    auto load = loadImmediate32(scratchReg, targetAddress);
    return {
        load[0],
        load[1],
        load[2],
        encodeMtctr(scratchReg),
        encodeBctr(),
    };
}

} // namespace ppc
