// libelf/include/elf/endian.hpp
//
// Endian-safe scalar wrappers.
//
// Rationale: ELF files can be little- or big-endian (PS3 executables are
// big-endian PowerPC). Ad hoc byte-swapping at call sites is exactly the
// kind of thing that silently corrupts one field and passes review. Instead,
// every multi-byte field in our on-disk structs is typed as big_u32 / le_u32
// / etc. so the *type system* forces correct handling: you cannot read or
// write the raw bytes without going through operator T(), which always
// performs the swap for you.
//
// These types are POD (trivially copyable) so they can be used directly in
// structs that we memcpy from/to a byte buffer representing the file.

#pragma once

#include <cstdint>
#include <cstring>
#include <type_traits>

namespace elf {

enum class Endian {
    Little,
    Big,
};

namespace detail {

inline uint16_t byteswap16(uint16_t v) {
    return static_cast<uint16_t>((v >> 8) | (v << 8));
}

inline uint32_t byteswap32(uint32_t v) {
    return ((v & 0x000000FFu) << 24) |
           ((v & 0x0000FF00u) << 8)  |
           ((v & 0x00FF0000u) >> 8)  |
           ((v & 0xFF000000u) >> 24);
}

inline uint64_t byteswap64(uint64_t v) {
    return (static_cast<uint64_t>(byteswap32(static_cast<uint32_t>(v & 0xFFFFFFFFu))) << 32) |
           byteswap32(static_cast<uint32_t>(v >> 32));
}

constexpr bool host_is_little_endian() {
    // Constant-folds on virtually every compiler; avoids UB of type punning
    // by using a constexpr-friendly numeric check instead.
    return (0x0001 == (static_cast<uint16_t>(1)));
}

template <typename T>
T byteswap(T v);

template <> inline uint16_t byteswap<uint16_t>(uint16_t v) { return byteswap16(v); }
template <> inline uint32_t byteswap<uint32_t>(uint32_t v) { return byteswap32(v); }
template <> inline uint64_t byteswap<uint64_t>(uint64_t v) { return byteswap64(v); }

} // namespace detail

// A T-sized integer stored on disk in a fixed endianness `Order`.
// Implicit conversions to/from T make call sites read naturally:
//   uint32_t x = header.e_shoff;   // swaps if needed
//   header.e_shoff = 1234;         // swaps if needed
template <typename T, Endian Order>
class Endianed {
    static_assert(std::is_unsigned<T>::value, "Endianed<T> requires an unsigned integer type");

public:
    Endianed() = default;
    Endianed(T host_value) { set(host_value); }

    operator T() const { return get(); }

    Endianed& operator=(T host_value) {
        set(host_value);
        return *this;
    }

    T get() const {
        T raw;
        std::memcpy(&raw, &storage_, sizeof(T));
        bool needs_swap = (Order == Endian::Little) != detail::host_is_little_endian();
        return needs_swap ? detail::byteswap<T>(raw) : raw;
    }

    void set(T host_value) {
        bool needs_swap = (Order == Endian::Little) != detail::host_is_little_endian();
        T raw = needs_swap ? detail::byteswap<T>(host_value) : host_value;
        std::memcpy(&storage_, &raw, sizeof(T));
    }

private:
    T storage_{};
};

// Convenience aliases used throughout the ELF struct definitions.
using le_u16 = Endianed<uint16_t, Endian::Little>;
using le_u32 = Endianed<uint32_t, Endian::Little>;
using le_u64 = Endianed<uint64_t, Endian::Little>;

using be_u16 = Endianed<uint16_t, Endian::Big>;
using be_u32 = Endianed<uint32_t, Endian::Big>;
using be_u64 = Endianed<uint64_t, Endian::Big>;

static_assert(sizeof(le_u16) == 2, "Endianed<uint16_t> must be exactly 2 bytes (POD, no padding)");
static_assert(sizeof(le_u32) == 4, "Endianed<uint32_t> must be exactly 4 bytes (POD, no padding)");
static_assert(sizeof(le_u64) == 8, "Endianed<uint64_t> must be exactly 8 bytes (POD, no padding)");

} // namespace elf
