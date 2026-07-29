#include "e9io_log.h"
#include <cstdio>
#include <mutex>
#include <cstring>
#include <string>

// JSONL sinks for jmp/patch records: format into a stack buffer, append
// unconditionally, flush only on shutdown.

namespace {
std::mutex g_mu;
// Owned copies — set_paths stores into these so callers' temporaries can die.
static std::string g_jmp_path_buf   = "jmp.jsonl";
static std::string g_patch_path_buf = "patches.jsonl";
const char* g_jmp_path   = g_jmp_path_buf.c_str();
const char* g_patch_path = g_patch_path_buf.c_str();
FILE* g_jmp_fp   = nullptr;
FILE* g_patch_fp = nullptr;

constexpr size_t FILE_BUF_SZ = 1 << 20;

// Shared stack format buffer; a single record must fit in it.
thread_local char t_scratch[256 * 1024];

FILE* ensure_open(FILE*& fp, const char* path, const char* mode = "a") {
    if (!fp) fp = std::fopen(path, mode);
    return fp;
}


void write_jsonl_record(FILE*& fp, const char* path,
                        uint64_t va, const uint8_t* bytes, size_t n) {
    // 1) Build the string (outside the lock)
    //   {"address":"0x%llx","length":%zu,"bytes":[b0,b1,...]}\n
    char* p = t_scratch;
    char* end = t_scratch + sizeof(t_scratch);
    auto rem = [&]( ) { return (size_t)(end - p); };
    auto app = [&](int w){ p += w; };

    int w = std::snprintf(p, rem(), "{\"address\":\"0x%llx\",\"length\":%zu,\"bytes\":[",
                          (unsigned long long)va, n);
    if (w <= 0 || (size_t)w >= rem()) return; app(w);

    for (size_t i = 0; i < n; ++i) {
        if (i) { if (rem() == 0) return; *p++ = ','; }
        w = std::snprintf(p, rem(), "%u", (unsigned)bytes[i]);
        if (w <= 0 || (size_t)w >= rem()) return; app(w);
    }
    if (rem() < 3) return;
    *p++ = ']'; *p++ = '}'; *p++ = '\n';

    const size_t len = (size_t)(p - t_scratch);

    std::lock_guard<std::mutex> lk(g_mu);
    FILE* f = ensure_open(fp, path);
    if (!f) return;

    (void)std::fwrite(t_scratch, 1, len, f);
    // No fflush here! (performed at shutdown)
}
} // namespace

namespace e9io {

void init_session(bool truncate_outputs) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_jmp_fp)   { std::fclose(g_jmp_fp);   g_jmp_fp = nullptr; }
    if (g_patch_fp) { std::fclose(g_patch_fp); g_patch_fp = nullptr; }
    if (truncate_outputs) {
        // Open once with "w" then close to truncate the file contents
        if (FILE* t = std::fopen(g_jmp_path, "w"))   std::fclose(t);
        if (FILE* t = std::fopen(g_patch_path, "w")) std::fclose(t);
    }
}

void set_paths(const char* jmp_jsonl, const char* patches_jsonl) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (jmp_jsonl && *jmp_jsonl) {
        g_jmp_path_buf = jmp_jsonl;
        g_jmp_path     = g_jmp_path_buf.c_str();
    }
    if (patches_jsonl && *patches_jsonl) {
        g_patch_path_buf = patches_jsonl;
        g_patch_path     = g_patch_path_buf.c_str();
    }
}

void append_jmp(uint64_t va, const uint8_t* bytes, size_t n) {
    write_jsonl_record(g_jmp_fp, g_jmp_path, va, bytes, n);
}

void append_patch(uint64_t va, const uint8_t* bytes, size_t n) {
    write_jsonl_record(g_patch_fp, g_patch_path, va, bytes, n);
}

void shutdown() {
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_jmp_fp)   { std::fflush(g_jmp_fp);   std::fclose(g_jmp_fp);   g_jmp_fp = nullptr; }
    if (g_patch_fp) { std::fflush(g_patch_fp); std::fclose(g_patch_fp); g_patch_fp = nullptr; }
}

} // namespace e9io