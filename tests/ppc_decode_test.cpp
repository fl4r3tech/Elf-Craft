// tests/ppc_decode_test.cpp
//
// Verifies:
//   1. classify() correctly identifies all four branch kinds and NotABranch.
//   2. relocateBranch() correctly recomputes displacement for a relative
//      branch moved to a new address, and that the new instruction still
//      decodes to the same absolute target.
//   3. Conditional (bc) branches keep their BO/BI condition bits through a
//      relocation fixup — the specific bug this module exists to avoid.
//   4. DirectAbsolute / ToLinkRegister / ToCountRegister branches are
//      correctly identified as needing no fixup.
//   5. A relocation whose corrected displacement doesn't fit returns
//      nullopt rather than emitting a wrong instruction.

#include <cstdio>

#include "ppc/decode.hpp"

using namespace ppc;

static int failures = 0;

#define CHECK(cond, msg)                                                                                          \
    do {                                                                                                          \
        if (!(cond)) {                                                                                            \
            std::printf("FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);                                           \
            ++failures;                                                                                           \
        } else {                                                                                                  \
            std::printf("ok:   %s\n", msg);                                                                       \
        }                                                                                                         \
    } while (0)

int main() {
    // --- classify(): NotABranch ---
    CHECK(classify(encodeLis(3, 0x1234)).kind == BranchKind::NotABranch, "lis is classified as NotABranch");
    CHECK(classify(encodeMtctr(12)).kind == BranchKind::NotABranch, "mtctr is classified as NotABranch");

    // --- classify(): I-form unconditional relative/absolute ---
    {
        Instruction rel = encodeBranch(0x40, /*absolute=*/false, /*link=*/false);
        auto d = classify(rel);
        CHECK(d.kind == BranchKind::DirectRelative, "unconditional relative b classifies as DirectRelative");
        CHECK(d.displacement == 0x40, "displacement decoded correctly for relative b");
        CHECK(!d.isConditionalForm, "unconditional b is not flagged as conditional form");

        Instruction abs = encodeBranch(0x8000, /*absolute=*/true, /*link=*/true);
        auto da = classify(abs);
        CHECK(da.kind == BranchKind::DirectAbsolute, "absolute bla classifies as DirectAbsolute");
        CHECK(da.absoluteTarget == 0x8000, "absolute target decoded correctly");
        CHECK(da.link, "link bit decoded correctly for bla");
    }

    // --- classify(): B-form conditional ---
    {
        Instruction bc = encodeBranchConditional(/*bo=*/12, /*bi=*/2, /*target=*/0x20, false, false);
        auto d = classify(bc);
        CHECK(d.kind == BranchKind::DirectRelative, "conditional bc classifies as DirectRelative");
        CHECK(d.isConditionalForm, "bc is flagged as conditional form");
        CHECK(d.bo == 12 && d.bi == 2, "BO/BI decoded correctly for bc");
    }

    // --- classify(): indirect branches ---
    {
        Instruction bclr = (19u << 26) | (20u << 21) | (16u << 1); // blr (BO=always, XO=16, LK=0)
        CHECK(classify(bclr).kind == BranchKind::ToLinkRegister, "blr classifies as ToLinkRegister");
        CHECK(classify(encodeBctr()).kind == BranchKind::ToCountRegister, "bctr classifies as ToCountRegister");
    }

    // --- relocateBranch(): unconditional relative branch, target preserved ---
    {
        uint32_t originalAddr = 0x1000;
        uint32_t originalTarget = 0x1040;
        Instruction original = encodeBranch(static_cast<int32_t>(originalTarget - originalAddr), false, false);
        auto decoded = classify(original);

        uint32_t newAddr = 0x2000; // instruction moved 0x1000 bytes away
        auto fixedUp = relocateBranch(decoded, originalAddr, newAddr);
        CHECK(fixedUp.has_value(), "relocateBranch succeeds for an in-range unconditional relative branch");
        if (fixedUp) {
            auto redecoded = classify(*fixedUp);
            uint32_t newTarget = newAddr + static_cast<uint32_t>(redecoded.displacement);
            CHECK(newTarget == originalTarget, "relocated unconditional branch still hits the original target");
        }
    }

    // --- relocateBranch(): conditional branch keeps BO/BI (the core bug fix) ---
    {
        uint32_t originalAddr = 0x1000;
        uint32_t originalTarget = 0x1020;
        Instruction original =
            encodeBranchConditional(/*bo=*/4, /*bi=*/7, static_cast<int32_t>(originalTarget - originalAddr), false, false);
        auto decoded = classify(original);
        CHECK(decoded.bo == 4 && decoded.bi == 7, "sanity: original bc decodes with BO=4, BI=7");

        uint32_t newAddr = 0x1800;
        auto fixedUp = relocateBranch(decoded, originalAddr, newAddr);
        CHECK(fixedUp.has_value(), "relocateBranch succeeds for an in-range conditional branch");
        if (fixedUp) {
            auto redecoded = classify(*fixedUp);
            CHECK(redecoded.isConditionalForm, "relocated instruction is still B-form, not widened to I-form");
            CHECK(redecoded.bo == 4 && redecoded.bi == 7,
                  "relocated conditional branch preserves its original BO/BI -- this is the fix vs a naive re-encode");
            uint32_t newTarget = newAddr + static_cast<uint32_t>(redecoded.displacement);
            CHECK(newTarget == originalTarget, "relocated conditional branch still hits the original target");
        }
    }

    // --- relocateBranch(): DirectAbsolute / indirect kinds are not this function's job ---
    {
        Instruction abs = encodeBranch(0x100, true, false);
        auto decoded = classify(abs);
        auto result = relocateBranch(decoded, 0x1000, 0x9000);
        CHECK(!result.has_value(), "relocateBranch returns nullopt for DirectAbsolute (caller should copy verbatim instead)");
    }

    // --- relocateBranch(): corrected displacement out of range returns nullopt ---
    {
        // Original branch has a small in-range displacement, but relocating
        // it 64MB away pushes the corrected displacement past the 24-bit
        // LI field's ~32MB reach -- must fail closed, not emit a wrong jump.
        uint32_t originalAddr = 0x1000;
        uint32_t originalTarget = 0x1040;
        Instruction original = encodeBranch(static_cast<int32_t>(originalTarget - originalAddr), false, false);
        auto decoded = classify(original);
        uint32_t farNewAddr = 0x1000 + 64u * 1024u * 1024u;
        auto result = relocateBranch(decoded, originalAddr, farNewAddr);
        CHECK(!result.has_value(), "relocateBranch returns nullopt when the corrected displacement no longer fits");
    }

    std::printf("\n%d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
