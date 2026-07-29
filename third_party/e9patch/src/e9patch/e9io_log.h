#ifndef E9IO_LOG_H
#define E9IO_LOG_H
#include <cstddef>
#include <cstdint>

namespace e9io {
// Set output file paths (optional)
void set_paths(const char* jmp_jsonl, const char* patches_jsonl);
// JSONL append
void append_jmp(uint64_t va, const uint8_t* bytes, size_t n);
void append_patch(uint64_t va, const uint8_t* bytes, size_t n);
// Safe close on shutdown
void shutdown();
void init_session(bool truncate_outputs = true);
} // namespace e9io
#endif // E9IO_LOG_H