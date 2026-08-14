// libelf/include/elf/errors.hpp
//
// Typed errors + a minimal Result<T, Error>, in the spirit of std::expected
// (C++23) but hand-rolled since this project targets C++17. Parsing
// untrusted binary input should never throw or crash on malformed data;
// every fallible operation in this library returns a Result so callers are
// forced to check it.

#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <variant>

namespace elf {

enum class ErrorCode {
    TruncatedFile,        // fewer bytes than a required struct/field needs
    BadMagic,              // e_ident[0..3] != 0x7F 'E' 'L' 'F'
    UnsupportedClass,       // EI_CLASS not ELFCLASS32/64
    UnsupportedDataEncoding, // EI_DATA not ELFDATA2LSB/MSB
    InconsistentHeaderSize,  // e_ehsize/e_phentsize/e_shentsize mismatch spec
    OffsetOutOfBounds,       // e_phoff/e_shoff/etc. points outside the file
    IndexOutOfBounds,        // e.g. e_shstrndx >= e_shnum
    IoError,                 // couldn't read/write the underlying file
    AlreadyPatched,          // ps3patch-level: idempotency guard
    Unsupported,              // operation not valid for this file's class/machine
    InvalidArgument,          // caller-supplied parameter failed validation (e.g. bad path string)
    RelocationFailed,         // a branch in the displaced region couldn't be safely fixed up
};

struct Error {
    ErrorCode code;
    std::string message; // human-readable detail, e.g. "at offset 0x40, need 8 more bytes"

    static Error make(ErrorCode c, std::string msg) {
        return Error{c, std::move(msg)};
    }
};

// A tag type so Result<void, Error> is expressible without specialization games.
struct Unit {};

template <typename T, typename E = Error>
class Result {
public:
    Result(T value) : storage_(std::move(value)) {}
    Result(E error) : storage_(std::move(error)) {}

    bool ok() const { return std::holds_alternative<T>(storage_); }
    explicit operator bool() const { return ok(); }

    // Precondition: ok(). Asserts in debug builds if misused.
    const T& value() const { return std::get<T>(storage_); }
    T& value() { return std::get<T>(storage_); }

    // Precondition: !ok().
    const E& error() const { return std::get<E>(storage_); }

    // Convenience: value_or for call sites that want a fallback instead of
    // branching explicitly.
    T value_or(T fallback) const {
        return ok() ? std::get<T>(storage_) : std::move(fallback);
    }

private:
    std::variant<T, E> storage_;
};

// Specialization for operations that succeed with no payload (e.g. "write
// this file to disk"). Using Unit instead of void keeps Result's interface
// uniform rather than needing a separate class.
using VoidResult = Result<Unit, Error>;

inline VoidResult ok() { return VoidResult(Unit{}); }

} // namespace elf
