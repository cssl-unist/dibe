// ===== patcher.cpp =====
// Build: g++ -std=c++17 -O2 -fPIC -shared -Iinclude -I. src/patcher.cpp -o patcher.so -ldl -pthread
//
// Runtime patcher shared object for x86-64 Linux.
// - Trigger: SIGUSR1 loads JSONL patches and applies them in-process.
// - Start-gate: optionally delays main() until patching completes.
// - Mapping server: receives memfd-backed pages via SCM_RIGHTS and maps them at fixed VAs.
// - Rewriting: uses alignment-aware atomic write strategies (8B / 16B CAS / INT3 two-phase fallback).

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <atomic>
#include <mutex>
#include <set>
#include <chrono>
#include <sstream>
#include <ucontext.h>
#include <errno.h>
#include <dlfcn.h>
#include <time.h>
#include <sched.h>
#include <cstddef>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "json.hpp"
#include "third_party/e9patch/src/e9patch/e9patch.h"    // e9_run

using json = nlohmann::json;
#define SOCK_PATH_FMT "/tmp/dibe.sock.%d"
static char g_master_sock_path[256] = {0};

/*************************************************
 * 1) Type definitions
 *************************************************/

/*************************************************
 * 2) Global state
 *************************************************/
// Gate is opened after patch application completes.
static std::atomic<int> g_patch_ready{0};
static char fifo_path[256] = {0};

// Track patcher-owned fds so we can close them in forked children
// (prevents inheriting FIFO/socket fds that interfere with child I/O).
static int g_fifo_fd = -1;
static int g_master_server_fd = -1;


// Used to measure "post-gate" runtime.
static struct timespec g_gate_open_ts;
static std::atomic<int> g_gate_open_recorded{0};

// Used by INT3 two-phase rewrite: threads that hit SIGTRAP will spin until rewrite finishes.
static std::atomic_bool int3_in_progress{false};
static std::atomic<uint64_t> g_trap_hit_count{0};  // # of times a thread hit INT3 during S2 rewrite
static std::atomic<uint64_t> g_trap_spin_cycles{0}; // cumulative spin-wait time in rdtsc cycles
static std::mutex patch_mutex;

// Fork-quiesce: gate any address-space-copying fork()/clone() until in-flight
// multi-site edits complete, so a forked child never snapshots a half-applied
// rewrite. g_edit_in_flight is a nesting counter raised across the whole of
// patcher_apply(); both the pthread_atfork prepare handler and the seccomp/SIGSYS
// handler spin on it. DIBE_FORK_QUIESCE selects the mechanism:
//   0 = off (default), 1 = pthread_atfork prepare only (glibc fork path),
//   2 = also install the seccomp+SIGSYS trap (covers raw clone() syscalls).
static std::atomic<int> g_edit_in_flight{0};
static int g_fork_quiesce = 0;

// DIBE_FORCE_S2=1 routes every overwrite through the S2 (INT3-gated) path.
// Cached at constructor time because some programs wipe the environment before
// getenv() would run inside patcher_apply.
static bool g_force_s2 = false;

extern "C" int e9_run(char* const argv[], int in_fd, int out_fd);

enum FieldPos { First = 0, Middle = 1, Last = 2 };

// Aggregated mapping latency measured in the mapping server.
static std::atomic<uint64_t> g_mapping_time_us{0};
static std::atomic<uint64_t> g_mapping_count{0};

// memfd distribution: master retains FDs received from e9patch for pushing to workers.
static std::mutex g_memfd_store_mutex;
struct MemfdEntry { uint64_t page_base; int fd; };
static std::vector<MemfdEntry> g_memfd_store;

// Pages mapped via memfd (content already correct — skip trampoline memcpy).
// NOTE: Uses pointer + lazy init to avoid static initialization order issues.
// When patcher.so is loaded via LD_PRELOAD, __attribute__((constructor)) threads
// may start before C++ global constructors finish, leaving std::set in a
// zero-initialized (invalid) state.
static std::mutex g_memfd_mapped_mutex;
static std::set<uint64_t>* g_memfd_mapped_pages_ptr = nullptr;
static std::set<uint64_t>& memfd_mapped_pages() {
    if (!g_memfd_mapped_pages_ptr)
        g_memfd_mapped_pages_ptr = new std::set<uint64_t>();
    return *g_memfd_mapped_pages_ptr;
}

static std::set<uint64_t>* g_committed_pages_ptr = nullptr;
static std::set<uint64_t>& committed_pages() {
    if (!g_committed_pages_ptr)
        g_committed_pages_ptr = new std::set<uint64_t>();
    return *g_committed_pages_ptr;
}

// Per-PID mapping server socket path (workers use /tmp/dibe_map.<PID>).
static char g_worker_sock_path[256] = {0};

// Pin calling thread to DIBE_PATCHER_CPU if set. Called at the start of each
// patcher-owned thread so the target's own threads are undisturbed.
static void pin_patcher_thread() {
    const char* env = getenv("DIBE_PATCHER_CPU");
    if (!env) return;
    int cpu = atoi(env);
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) == 0) {
        fprintf(stderr, "[patcher] thread %ld pinned to CPU %d\n",
                (long)gettid(), cpu);
    } else {
        fprintf(stderr, "[patcher] WARN: failed to pin thread to CPU %d: %s\n",
                cpu, strerror(errno));
    }
}

/*************************************************
 * 3) Patch data model
 *************************************************/
// Each entry is (address, raw bytes) produced by an offline patch generator.
struct JEntry { uint64_t addr; std::vector<uint8_t> bytes; }; // overwrite site (e.g., jump bytes)
struct PEntry { uint64_t addr; std::vector<uint8_t> bytes; }; // payload bytes (e.g., trampolines)

std::vector<JEntry> g_jmps;
std::vector<PEntry> g_patches;

/*************************************************
 * 4) Utilities
 *************************************************/
static inline uint64_t align_down(uint64_t x,uint64_t a){return x & ~(a-1);}
static inline uint64_t align_up(uint64_t x,uint64_t a){return (x+a-1)&~(a-1);}

static inline uint64_t ts_to_ns(const struct timespec& t){
    return (uint64_t)t.tv_sec*1000000000ull + t.tv_nsec;
}

static bool is_hex_prefix(const std::string&s){
    return s.size()>2 && s[0]=='0' && (s[1]=='x'||s[1]=='X');
}

// Accept numbers encoded as JSON integer or string ("123" or "0x123").
static uint64_t parse_uint64_auto(const json& v){
    if(v.is_number_unsigned()) return v.get<uint64_t>();
    if(v.is_number_integer())  return (uint64_t)v.get<long long>();
    if(v.is_string()){
        std::string s=v.get<std::string>();
        int base=is_hex_prefix(s)?16:10;
        return std::stoull(s,nullptr,base);
    }
    throw std::runtime_error("invalid number");
}

static uint8_t parse_byte_auto(const json& v){
    if(v.is_number_integer()){
        int x=v.get<int>();
        if(x<0 || x>255) throw std::runtime_error("byte out of range");
        return (uint8_t)x;
    }
    if(v.is_string()){
        std::string s=v.get<std::string>();
        int base=is_hex_prefix(s)?16:10;
        auto x=std::stoul(s,nullptr,base);
        if(x>255) throw std::runtime_error("byte out of range");
        return (uint8_t)x;
    }
    throw std::runtime_error("invalid type for byte");
}

inline void write_csv(const std::string& path, double v, int pos) {
    std::ofstream ofs(path, std::ios::app);
    if (pos != First) ofs << ',';
    ofs << v;
    if (pos == Last) ofs << '\n';
}

// Best-effort check: used to avoid mapping over already-mapped pages.
__attribute__((unused))
static bool is_mapped_page(uintptr_t page_base, size_t page_size) {
    std::ifstream maps("/proc/self/maps");
    if (!maps) return false;
    std::string line;
    while (std::getline(maps, line)) {
        uintptr_t lo = 0, hi = 0;
        std::istringstream iss(line);
        std::string range;
        if (!(iss >> range)) continue;
        auto dash = range.find('-');
        if (dash == std::string::npos) continue;
        try {
            lo = static_cast<uintptr_t>(std::stoull(range.substr(0, dash), nullptr, 16));
            hi = static_cast<uintptr_t>(std::stoull(range.substr(dash + 1), nullptr, 16));
        } catch (...) { continue; }
        if (page_base >= lo && page_base + page_size <= hi) return true;
    }
    return false;
}

// Mapped-page check for validation.
//
// is_mapped_page() above re-parses all of /proc/self/maps per call, which makes
// a whole-binary validation pass O(pages * maps_lines): the mapping server
// installs one MAP_FIXED memfd page per VA page, so a large binary yields tens
// of thousands of single-page mappings.  MappedRanges snapshots /proc/self/maps
// once into a sorted [lo,hi) vector and answers each query with a binary search.
struct MappedRanges {
    std::vector<std::pair<uintptr_t,uintptr_t>> r;   // sorted by lo, non-overlapping after merge
    explicit MappedRanges() {
        std::ifstream maps("/proc/self/maps");
        std::string line;
        while (std::getline(maps, line)) {
            std::istringstream iss(line);
            std::string range;
            if (!(iss >> range)) continue;
            auto dash = range.find('-');
            if (dash == std::string::npos) continue;
            uintptr_t lo = 0, hi = 0;
            try {
                lo = (uintptr_t)std::stoull(range.substr(0, dash), nullptr, 16);
                hi = (uintptr_t)std::stoull(range.substr(dash + 1), nullptr, 16);
            } catch (...) { continue; }
            if (hi > lo) r.emplace_back(lo, hi);
        }
        std::sort(r.begin(), r.end());
        // Merge adjacent/overlapping ranges so a page spanning a (coalesced)
        // boundary is still found.
        std::vector<std::pair<uintptr_t,uintptr_t>> merged;
        for (auto &x : r) {
            if (!merged.empty() && x.first <= merged.back().second)
                merged.back().second = std::max(merged.back().second, x.second);
            else
                merged.push_back(x);
        }
        r.swap(merged);
    }
    bool contains(uintptr_t lo, uintptr_t hi) const {
        // Find the last range whose start <= lo, then test containment.
        size_t a = 0, b = r.size();
        while (a < b) {
            size_t m = (a + b) / 2;
            if (r[m].first <= lo) a = m + 1; else b = m;
        }
        if (a == 0) return false;
        const auto &seg = r[a - 1];
        return lo >= seg.first && hi <= seg.second;
    }
};

/*************************************************
 * 5) JSONL loader
 *************************************************/
// Input format is JSONL (one JSON object per line). Supported schemas:
// - {"address":..., "bytes":[...]}
// - {"jmp_address":..., "jmp_bytes":[...]}
// - {"patch_address":..., "patch_bytes":[...]}
template<typename T>
static bool load_jsonl_generic(const std::string& fn,std::vector<T>& out){
    std::ifstream in(fn);
    if(!in){
        fprintf(stderr, "[patcher] cannot open %s\n", fn.c_str());
        return false;
    }
    std::string line; int ln=0;
    while(std::getline(in,line)){
        ++ln; if(line.empty()) continue;
        json j=json::parse(line);

        uint64_t addr=0; std::vector<uint8_t> b;

        if(j.contains("address") && j.contains("bytes")){
            addr=parse_uint64_auto(j["address"]);
            for(auto& e:j["bytes"]) b.push_back(parse_byte_auto(e));
        }else if(j.contains("jmp_address") && j.contains("jmp_bytes")){
            addr=parse_uint64_auto(j["jmp_address"]);
            for(auto& e:j["jmp_bytes"]) b.push_back(parse_byte_auto(e));
        }else if(j.contains("patch_address") && j.contains("patch_bytes")){
            addr=parse_uint64_auto(j["patch_address"]);
            for(auto& e:j["patch_bytes"]) b.push_back(parse_byte_auto(e));
        }else{
            fprintf(stderr, "[patcher] bad JSONL schema %s:%d\n", fn.c_str(), ln);
            continue;
        }

        T e; e.addr=addr; e.bytes=std::move(b);
        out.push_back(std::move(e));
    }
    return true;
}

static bool load_jmp_jsonl(const std::string& fn){ return load_jsonl_generic<JEntry>(fn,g_jmps); }
static bool load_patches_jsonl(const std::string& fn){ return load_jsonl_generic<PEntry>(fn,g_patches); }

/*************************************************
 * 6) SIGTRAP (INT3) handler
 *************************************************/
// Two-phase rewrite fallback uses an INT3 byte as a temporary "stop-the-world-at-site" marker.
// If any thread executes INT3 during rewrite, it will spin until the rewrite completes,
// then resume execution from the original instruction byte (RIP := RIP-1).
// g_trap_deferred_count counts "deferred" traps: a thread faulted on an S2 INT3
// but the SIGTRAP was delivered after the gate (int3_in_progress) had already
// cleared. By then the rewrite has completed and the byte at the fault site is
// the final jmp, so rewinding and resuming is safe.
static std::atomic<uint64_t> g_trap_deferred_count{0};

static void trap_handler(int /*sig*/, siginfo_t* /*si*/, void* uap){
    ucontext_t* ctx=(ucontext_t*)uap;
    uintptr_t rip = ctx->uc_mcontext.gregs[REG_RIP];
    uintptr_t orig = rip-1;

    if(int3_in_progress.load(std::memory_order_acquire)){
        g_trap_hit_count.fetch_add(1, std::memory_order_relaxed);
        uint32_t lo, hi;
        __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
        uint64_t cyc_start = ((uint64_t)hi << 32) | lo;
        while(int3_in_progress.load(std::memory_order_acquire))
            __asm__ volatile("pause");
        __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
        uint64_t cyc_end = ((uint64_t)hi << 32) | lo;
        g_trap_spin_cycles.fetch_add(cyc_end - cyc_start, std::memory_order_relaxed);
        ctx->uc_mcontext.gregs[REG_RIP]=orig;
        return;
    }

    // Post-gate (int3_in_progress was false). Distinguish a *deferred* DIBE trap
    // from a genuinely external INT3 by the byte at the fault site:
    //   - byte != 0xCC: the S2 rewrite completed between the fault and this
    //     handler running, so the site now holds the final jmp. Rewind RIP and
    //     resume on it.
    //   - byte == 0xCC: still an INT3 we did not write (debugger / other tool).
    //     Re-raise with the default action. (Resuming here would re-execute the
    //     real 0xCC and livelock, which the byte check avoids.)
    if (*(volatile uint8_t*)orig != 0xCC) {
        g_trap_deferred_count.fetch_add(1, std::memory_order_relaxed);
        ctx->uc_mcontext.gregs[REG_RIP]=orig;
        return;
    }

    // Byte is still 0xCC — not ours. Restore default behavior and re-raise.
    signal(SIGTRAP,SIG_DFL);
    ssize_t __attribute__((unused)) rc = write(2,"trap\n",5);
    raise(SIGTRAP);
}

static void install_trap_handler(){
    struct sigaction sa{};
    sa.sa_sigaction = trap_handler;
    sa.sa_flags     = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTRAP,&sa,nullptr);
}

/*************************************************
 * 6b) Fork-quiesce
 *
 * A child forked while a multi-site edit is in flight could COW-snapshot a
 * half-applied rewrite (e.g. an INT3 gate byte, or a torn jmp), and only the
 * forking thread survives in the child. Quiescing fork closes that hazard: any
 * clone that copies the address space (i.e. without CLONE_VM) is held until no
 * edit is in flight. Thread creation (pthread_create -> clone with CLONE_VM) is
 * NOT gated — it shares the address space, so there is no snapshot to tear.
 *
 * Two layers, selected by DIBE_FORK_QUIESCE (see g_fork_quiesce):
 *   (1) pthread_atfork PREPARE handler — runs in the forking thread before the
 *       glibc fork()/vfork() clone; simply waits out the edit. Robust and
 *       async-signal-free; covers the common fork-based-server path.
 *   (2) seccomp + SIGSYS — a classic BPF filter traps address-space-copying
 *       clone()/fork() with SECCOMP_RET_TRAP; the SIGSYS handler waits out the
 *       edit and then re-issues the syscall. This also catches raw clone()
 *       that bypasses glibc (which (1) cannot see). To avoid the re-issued
 *       syscall re-tripping the filter, the BPF whitelists the instruction
 *       pointer of our re-issue site (dibe_reissue_syscall_ret).
 *************************************************/

// RAII marker: edits are in flight for the lifetime of this object.
struct EditInFlightGuard {
    EditInFlightGuard()  { g_edit_in_flight.fetch_add(1, std::memory_order_acq_rel); }
    ~EditInFlightGuard() { g_edit_in_flight.fetch_sub(1, std::memory_order_acq_rel); }
};

// Async-signal-safe: only an atomic load + pause. Bounded so a patcher thread
// that died mid-edit cannot deadlock fork forever (~tens of ms cap).
static inline void fork_quiesce_wait() {
    for (int i = 0; i < 200000000 &&
                    g_edit_in_flight.load(std::memory_order_acquire) != 0; ++i)
        __builtin_ia32_pause();
}

// pthread_atfork PREPARE handler (layer 1).
static void fork_prepare_quiesce() {
    if (g_fork_quiesce >= 1) fork_quiesce_wait();
}

// Re-issue a syscall from the SIGSYS handler (layer 2). The `syscall` instruction
// is labeled (dibe_reissue_syscall_ret marks the following instruction, i.e. the
// RIP seccomp reports) so the BPF filter can whitelist it and not re-trap us.
extern "C" { extern const char dibe_reissue_syscall_ret[]; }
__attribute__((noinline))
static long dibe_reissue_syscall(long nr, long a0, long a1, long a2,
                                 long a3, long a4, long a5) {
    register long rax asm("rax") = nr;
    register long rdi asm("rdi") = a0;
    register long rsi asm("rsi") = a1;
    register long rdx asm("rdx") = a2;
    register long r10 asm("r10") = a3;
    register long r8  asm("r8")  = a4;
    register long r9  asm("r9")  = a5;
    asm volatile(
        "syscall\n\t"
        ".globl dibe_reissue_syscall_ret\n\t"
        "dibe_reissue_syscall_ret:\n\t"
        : "+r"(rax)
        : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory", "cc");
    return rax;
}

static void sigsys_handler(int, siginfo_t* si, void* uctx) {
    ucontext_t* ctx = (ucontext_t*)uctx;
    greg_t* g = ctx->uc_mcontext.gregs;
    fork_quiesce_wait();
    long nr = (long)si->si_syscall;
    long r = dibe_reissue_syscall(nr,
                                  (long)g[REG_RDI], (long)g[REG_RSI], (long)g[REG_RDX],
                                  (long)g[REG_R10], (long)g[REG_R8],  (long)g[REG_R9]);
    g[REG_RAX] = (greg_t)r;   // child sees 0, parent sees child pid; thread resumes past the clone
}

static void install_sigsys_handler() {
    struct sigaction sa{};
    sa.sa_sigaction = sigsys_handler;
    sa.sa_flags = SA_SIGINFO;   // SIGSYS masked inside handler; the re-issue is whitelisted so it won't re-trap
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSYS, &sa, nullptr);
}

// Install the seccomp BPF filter that traps address-space-copying clone()/fork().
static bool install_fork_seccomp() {
    const uint64_t wl = (uint64_t)(uintptr_t)dibe_reissue_syscall_ret;
    const uint32_t wl_lo = (uint32_t)(wl & 0xffffffffu);
    const uint32_t wl_hi = (uint32_t)(wl >> 32);
    struct sock_filter filter[] = {
        /* 0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        /* 1 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        /* 2 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),          // non-x86_64 -> allow
        /* 3 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer)),
        /* 4 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, wl_lo, 0, 2),      // ip_lo == wl_lo ? check hi : nr-check
        /* 5 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer) + 4),
        /* 6 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, wl_hi, 5, 0),      // ip == whitelist -> ALLOW (re-issue)
        /* 7 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        /* 8 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fork, 4, 0),  // fork -> TRAP
        /* 9 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 2), // clone? check flags : ALLOW
        /*10 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        /*11 */ BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_VM, 0, 1),  // CLONE_VM (thread) -> ALLOW; else TRAP
        /*12 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /*13 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    };
    struct sock_fprog prog = {
        (unsigned short)(sizeof(filter) / sizeof(filter[0])), filter
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("[patcher] PR_SET_NO_NEW_PRIVS");
        return false;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) {
        perror("[patcher] PR_SET_SECCOMP (fork-quiesce)");
        return false;
    }
    return true;
}

/*************************************************
 * 7) Patch application
 *************************************************/
static void mprotect_range(uint64_t addr,size_t len,int prot){
    long p = sysconf(_SC_PAGESIZE);
    uint64_t lb=align_down(addr,p);
    uint64_t ub=align_up(addr+len,p);
    mprotect((void*)lb,ub-lb,prot);
}

// Apply payload bytes first, then rewrite original sites.
// Rewriting policy (alignment-aware):
// - S0: if write fits within a single aligned 8-byte word -> single 8B store (atomic on x86-64).
// - S1: if write fits within a single aligned 16-byte region -> cmpxchg16b for atomic 16B update.
// - Fallback: INT3 two-phase rewrite (temporarily install INT3 at site, write tail, then head).
//
// Env override DIBE_FORCE_S2=1 routes EVERY overwrite through the S2 INT3-gated
// path (always-trap activation, regardless of alignment).
// Default (env unset or 0): alignment-aware behavior.
static void patcher_apply() {
    EditInFlightGuard _eifg;  // gate address-space-copying fork() until this edit completes
    auto s0_time  = std::chrono::high_resolution_clock::duration::zero();
    auto s1_time  = std::chrono::high_resolution_clock::duration::zero();
    auto int3_time = std::chrono::high_resolution_clock::duration::zero();

    int s0_count = 0;
    int s1_count = 0;
    int int3_count = 0;

    const bool force_s2 = g_force_s2;
    if (force_s2)
        fprintf(stderr, "[patcher] DIBE_FORCE_S2=1 -- routing every overwrite via S2\n");

    auto t0 = std::chrono::high_resolution_clock::now();

    // 1) Ensure trampoline pages are mapped, then write payload bytes.
    //    The mapping server may have mapped these in a different process
    //    (a fork-based server's master), so workers need to map them locally.
    long page_sz = sysconf(_SC_PAGESIZE);
    fprintf(stderr, "[patcher] patcher_apply: %zu patches, %zu jmps\n",
            g_patches.size(), g_jmps.size());
    {
        std::lock_guard<std::mutex> lk(g_memfd_mapped_mutex);

        // Collect unique pages that need mapping
        std::set<uint64_t> needed_pages;
        for (const auto &p : g_patches) {
            if (p.bytes.empty()) continue;
            uint64_t lo = align_down(p.addr, page_sz);
            uint64_t hi = align_up(p.addr + p.bytes.size(), page_sz);
            for (uint64_t pg = lo; pg < hi; pg += page_sz)
                needed_pages.insert(pg);
        }
        fprintf(stderr, "[patcher] need %zu trampoline pages\n", needed_pages.size());
        int mapped_ok = 0, mapped_foreign = 0, mapped_fail = 0;
        std::vector<uint64_t> fresh_anon_pages;
        for (uint64_t pg : needed_pages) {
            if (memfd_mapped_pages().count(pg) || committed_pages().count(pg)) {
                mapped_ok++;
                continue;
            }
            void *r = mmap((void*)pg, page_sz,
                           PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                           -1, 0);
            if (r != MAP_FAILED) {
                fresh_anon_pages.push_back(pg);
                mapped_ok++;
                continue;
            }
            if (errno == EEXIST) {
                fprintf(stderr, "[patcher] trampoline page 0x%lx is foreign "
                        "(mapped by the target, not DIBE)\n", (unsigned long)pg);
                mapped_foreign++;
            } else {
                fprintf(stderr, "[patcher] trampoline mmap failed at 0x%lx: %s\n",
                        (unsigned long)pg, strerror(errno));
                mapped_fail++;
            }
        }
        fprintf(stderr, "[patcher] trampoline pages: %d ok, %d foreign, %d failed\n",
                mapped_ok, mapped_foreign, mapped_fail);
        if (mapped_foreign > 0 || mapped_fail > 0) {
            for (uint64_t pg : fresh_anon_pages)
                munmap((void*)pg, page_sz);
            fprintf(stderr, "[patcher] APPLY ABORTED: trampoline mapping "
                    "incomplete or unsafe — no bytes written, target unmodified\n");
            return;
        }

        int skip_count = 0;
        for (const auto &p : g_patches) {
            uint64_t addr = p.addr;
            size_t   len  = p.bytes.size();
            if (len == 0) continue;

            // If this page was mapped via memfd (DISTRIBUTE or direct from e9patch),
            // the trampoline content is already correct — skip the memcpy.
            uint64_t pg = align_down(addr, page_sz);
            if (memfd_mapped_pages().count(pg)) {
                skip_count++;
                continue;
            }

            mprotect_range(addr, len, PROT_READ | PROT_WRITE | PROT_EXEC);
            std::memcpy((void*)addr, p.bytes.data(), len);
            mprotect_range(addr, len, PROT_READ | PROT_EXEC);
        }
        if (skip_count > 0)
            fprintf(stderr, "[patcher] skipped %d/%zu trampoline writes (memfd pre-mapped)\n",
                    skip_count, g_patches.size());

        for (uint64_t pg : needed_pages)
            committed_pages().insert(pg);
    }

    // 2) Batch mprotect: collect all code pages that jmp sites touch,
    //    make them writable once, rewrite all sites, then restore.
    {
        std::set<uint64_t> jmp_pages;
        for (const auto &j : g_jmps) {
            if (j.bytes.empty()) continue;
            uint64_t lo = align_down(j.addr, page_sz);
            uint64_t hi = align_up(j.addr + j.bytes.size(), page_sz);
            for (uint64_t pg = lo; pg < hi; pg += page_sz)
                jmp_pages.insert(pg);
        }
        int mprotect_fails = 0;
        for (uint64_t pg : jmp_pages) {
            if (mprotect((void*)pg, page_sz, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                fprintf(stderr, "[patcher] mprotect(0x%lx) FAIL: %s "
                        "— is the target's runtime base correctly detected? "
                        "(common cause: a launcher that forks before exec, so "
                        "DIBE_PIDFILE holds the wrong PID)\n",
                        (unsigned long)pg, strerror(errno));
                mprotect_fails++;
            }
        }
        if (mprotect_fails > 0)
            fprintf(stderr, "[patcher] WARN: %d/%zu jmp pages failed to mprotect; "
                    "subsequent writes will SEGV\n", mprotect_fails, jmp_pages.size());

        // 3) Rewrite original sites using atomic/fallback strategies.
        auto t_jmp_start = std::chrono::high_resolution_clock::now();
        for (const auto &j : g_jmps) {
            uint64_t addr = j.addr;
            const auto &bytes = j.bytes;
            size_t len = bytes.size();
            if (len == 0) continue;

            uintptr_t off8  = addr & 0x7;
            uintptr_t off16 = addr & 0xF;

            // S0: atomic 8-byte store when the update stays within one 8-byte aligned word.
            if (!force_s2 && off8 + len <= 8) {
                auto s0_start = std::chrono::high_resolution_clock::now();
                s0_count++;

                uint64_t *base8 = (uint64_t*)(addr & ~0x7ULL);
                uint64_t expected8;
                std::memcpy(&expected8, base8, 8);
                uint64_t desired8 = expected8;
                std::memcpy(((uint8_t*)&desired8) + off8, bytes.data(), len);

                asm volatile(
                    "movq %1, %0"
                    : "+m"(*base8)
                    : "r"(desired8)
                    : "memory"
                );

                auto s0_end = std::chrono::high_resolution_clock::now();
                s0_time += (s0_end - s0_start);
            }

            // S1: atomic 16-byte update using cmpxchg16b when the update stays within one 16-byte aligned block.
            else if (!force_s2 && off16 + len <= 16) {
                auto s1_start = std::chrono::high_resolution_clock::now();
                s1_count++;

                __int128 *base16 = (__int128*)(addr & ~0xFULL);
                __int128 expected16;
                std::memcpy(&expected16, base16, 16);
                __int128 desired16 = expected16;
                std::memcpy(((uint8_t*)&desired16) + off16, bytes.data(), len);

                asm volatile(
                    "lock cmpxchg16b %0"
                    : "+m"(*base16),
                      "+a"(((uint64_t*)&expected16)[0]),
                      "+d"(((uint64_t*)&expected16)[1])
                    : "b"(((uint64_t*)&desired16)[0]),
                      "c"(((uint64_t*)&desired16)[1])
                    : "cc", "memory"
                );

                auto s1_end = std::chrono::high_resolution_clock::now();
                s1_time += (s1_end - s1_start);
            }

            // Fallback: INT3-gated two-phase rewrite (ensures threads don't execute partially-written bytes).
            else {
                auto int3_start = std::chrono::high_resolution_clock::now();
                int3_count++;

                int3_in_progress.store(true, std::memory_order_release);

                uintptr_t mis16 = addr & 0xF;
                size_t head_size = mis16 ? (16 - mis16) : 0;
                if (head_size > len) head_size = len;
                size_t tail_size = len - head_size;

                uint8_t int3 = 0xCC;
                std::memcpy((void*)addr, &int3, 1);

                if (tail_size) {
                    std::memcpy((void*)(addr + head_size),
                                bytes.data() + head_size,
                                tail_size);
                }
                // DIBE_S2_DEBUG_DELAY_US widens the S2 gate window so traps fire
                // deterministically. Off by default.
                {
                    static long s2_debug_delay = -2;
                    if (s2_debug_delay == -2) {
                        const char* e = getenv("DIBE_S2_DEBUG_DELAY_US");
                        s2_debug_delay = e ? atol(e) : -1;
                    }
                    if (s2_debug_delay > 0) {
                        struct timespec ts = {
                            s2_debug_delay / 1000000,
                            (s2_debug_delay % 1000000) * 1000
                        };
                        nanosleep(&ts, nullptr);
                    }
                }
                if (head_size) {
                    std::memcpy((void*)addr, bytes.data(), head_size);
                }

                int3_in_progress.store(false, std::memory_order_release);

                auto int3_end = std::chrono::high_resolution_clock::now();
                int3_time += (int3_end - int3_start);
            }
        }
        auto t_jmp_end = std::chrono::high_resolution_clock::now();

        // Restore code pages to read+execute
        for (uint64_t pg : jmp_pages)
            mprotect((void*)pg, page_sz, PROT_READ | PROT_EXEC);
    }
    auto t1 = std::chrono::high_resolution_clock::now();

    long s0_us = std::chrono::duration_cast<std::chrono::microseconds>(s0_time).count();
    long s1_us = std::chrono::duration_cast<std::chrono::microseconds>(s1_time).count();
    long int3_us = std::chrono::duration_cast<std::chrono::microseconds>(int3_time).count();
    long patch_us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    long jmp_us = s0_us + s1_us + int3_us;  // pure write time (mprotect batched separately)

    fprintf(stderr, "[patcher] S0 count: %d\n", s0_count);
    fprintf(stderr, "[patcher] S0 time: %ld us\n", s0_us);
    fprintf(stderr, "[patcher] S1 count: %d\n", s1_count);
    fprintf(stderr, "[patcher] S1 time: %ld us\n", s1_us);
    fprintf(stderr, "[patcher] int3 count: %d\n", int3_count);
    fprintf(stderr, "[patcher] int3 time: %ld us\n", int3_us);

    write_csv("result.csv", (double)g_mapping_time_us.load(), First);
    write_csv("result.csv", (double)patch_us, Middle);
    write_csv("result.csv", (double)jmp_us, Middle);
    write_csv("result.csv", (double)int3_count, Middle);
    write_csv("result.csv", (double)g_jmps.size(), Middle);
    write_csv("result.csv", (double)int3_us, Middle);
    write_csv("result.csv", (double)s0_count, Middle);
    write_csv("result.csv", (double)s0_us, Middle);
    write_csv("result.csv", (double)s1_count, Middle);
    write_csv("result.csv", (double)s1_us, Middle);

    fprintf(stderr, "[patcher] mapping time: %.0f us\n", (double)g_mapping_time_us.load());
    fprintf(stderr, "[patcher] patch time: %ld us\n", patch_us);
    fprintf(stderr, "[patcher] jmp_bytes rewriting time: %ld us\n", jmp_us);
    fprintf(stderr, "[patcher] int3 case count: %d / %zu = %zu%%\n",
            int3_count, g_jmps.size(),
            g_jmps.size() > 0 ? 100*int3_count/g_jmps.size() : 0);
    fprintf(stderr, "[patcher] int3 case time: %ld us\n", int3_us);
    fprintf(stderr, "[patcher] trap hits (threads caught by INT3): %lu\n",
            (unsigned long)g_trap_hit_count.load());
    fprintf(stderr, "[patcher] trap spin cycles (cumulative rdtsc): %lu\n",
            (unsigned long)g_trap_spin_cycles.load());
    fprintf(stderr, "[patcher] trap deferred (post-gate races, resumed safely): %lu\n",
            (unsigned long)g_trap_deferred_count.load());
}

/*************************************************
 * 7b) Post-apply validation (DIBE_VALIDATE mode)
 *
 * Reads back patched memory and compares against expected bytes.
 * Enable with: DIBE_VALIDATE=1
 * This is expensive (reads /proc/self/maps, compares every byte)
 * and must NOT be enabled during performance measurement runs.
 *************************************************/
static void patcher_validate() {
    long page_sz = sysconf(_SC_PAGESIZE);
    int patch_ok = 0, patch_fail = 0, patch_skip = 0;
    int jmp_ok = 0, jmp_fail = 0, jmp_skip = 0;
    int page_ok = 0, page_fail = 0;

    fprintf(stderr, "[validate] === patch validation start ===\n");

    // 1) Verify trampoline pages are mapped
    std::set<uint64_t> checked_pages;
    for (const auto &p : g_patches) {
        if (p.bytes.empty()) continue;
        uint64_t lo = align_down(p.addr, page_sz);
        uint64_t hi = align_up(p.addr + p.bytes.size(), page_sz);
        for (uint64_t pg = lo; pg < hi; pg += page_sz)
            checked_pages.insert(pg);
    }
    for (const auto &j : g_jmps) {
        if (j.bytes.empty()) continue;
        uint64_t lo = align_down(j.addr, page_sz);
        uint64_t hi = align_up(j.addr + j.bytes.size(), page_sz);
        for (uint64_t pg = lo; pg < hi; pg += page_sz)
            checked_pages.insert(pg);
    }
    MappedRanges mr;
    for (uint64_t pg : checked_pages) {
        if (mr.contains((uintptr_t)pg, (uintptr_t)pg + (uintptr_t)page_sz)) {
            page_ok++;
        } else {
            page_fail++;
            fprintf(stderr, "[validate] FAIL page unmapped: 0x%lx\n",
                    (unsigned long)pg);
        }
    }
    fprintf(stderr, "[validate] pages: %d mapped, %d unmapped\n",
            page_ok, page_fail);

    // 2) Verify trampoline/payload bytes (patches.jsonl entries)
    for (size_t i = 0; i < g_patches.size(); i++) {
        const auto &p = g_patches[i];
        if (p.bytes.empty()) { patch_skip++; continue; }

        // Check if page is accessible before reading
        if (msync((void*)align_down(p.addr, page_sz), page_sz, MS_ASYNC) != 0) {
            fprintf(stderr, "[validate] SKIP patch[%zu] at 0x%lx: page not accessible\n",
                    i, (unsigned long)p.addr);
            patch_skip++;
            continue;
        }

        const uint8_t *mem = (const uint8_t*)p.addr;
        bool match = true;
        for (size_t b = 0; b < p.bytes.size(); b++) {
            if (mem[b] != p.bytes[b]) {
                match = false;
                fprintf(stderr, "[validate] FAIL patch[%zu] at 0x%lx+%zu: "
                        "expected 0x%02x, got 0x%02x\n",
                        i, (unsigned long)p.addr, b,
                        p.bytes[b], mem[b]);
                break;
            }
        }
        if (match) patch_ok++;
        else patch_fail++;
    }
    fprintf(stderr, "[validate] patches: %d ok, %d fail, %d skip (total %zu)\n",
            patch_ok, patch_fail, patch_skip, g_patches.size());

    // 3) Verify jmp overwrite bytes (jmp.jsonl entries)
    for (size_t i = 0; i < g_jmps.size(); i++) {
        const auto &j = g_jmps[i];
        if (j.bytes.empty()) { jmp_skip++; continue; }

        if (msync((void*)align_down(j.addr, page_sz), page_sz, MS_ASYNC) != 0) {
            fprintf(stderr, "[validate] SKIP jmp[%zu] at 0x%lx: page not accessible\n",
                    i, (unsigned long)j.addr);
            jmp_skip++;
            continue;
        }

        const uint8_t *mem = (const uint8_t*)j.addr;
        bool match = true;
        for (size_t b = 0; b < j.bytes.size(); b++) {
            if (mem[b] != j.bytes[b]) {
                match = false;
                fprintf(stderr, "[validate] FAIL jmp[%zu] at 0x%lx+%zu: "
                        "expected 0x%02x, got 0x%02x\n",
                        i, (unsigned long)j.addr, b,
                        j.bytes[b], mem[b]);
                break;
            }
        }
        if (match) jmp_ok++;
        else jmp_fail++;
    }
    fprintf(stderr, "[validate] jmps: %d ok, %d fail, %d skip (total %zu)\n",
            jmp_ok, jmp_fail, jmp_skip, g_jmps.size());

    // Summary
    bool all_pass = (patch_fail == 0 && jmp_fail == 0 && page_fail == 0);
    fprintf(stderr, "[validate] === %s ===\n", all_pass ? "ALL PASSED" : "FAILURES DETECTED");
}

/*************************************************
 * 8) Exit hook: post-gate runtime measurement
 *************************************************/
static long read_vmhwm_kb() {
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    long hwm = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmHWM:", 6) == 0) {
            hwm = atol(line + 6);
            break;
        }
    }
    fclose(f);
    return hwm;
}

static void dibe_exit_hook(){
    if(!g_gate_open_recorded.load())
        return;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC,&end);
    uint64_t dt=ts_to_ns(end)-ts_to_ns(g_gate_open_ts);
    dprintf(2,"[patcher] Target_program_Runtime=%.6fs\n",(double)dt/1e9);
    write_csv("result.csv", (double)dt / 1e9, Last);

    long hwm = read_vmhwm_kb();
    if (hwm > 0) {
        dprintf(2, "[patcher] VmHWM=%ld kB\n", hwm);
        FILE* mf = fopen("dibe_mem.txt", "w");
        if (mf) { fprintf(mf, "%ld\n", hwm); fclose(mf); }
    }
}

/*************************************************
 * 9) Mapping server (UNIX domain socket + SCM_RIGHTS)
 *************************************************/
// Protocol: client sends (1) a memfd file descriptor (SCM_RIGHTS) and (2) JSON payload containing "page_base".
// The server maps the shared page at a fixed VA using MAP_FIXED to realize a controlled VA->physical mapping.
static void* mapping_server_thread(void* arg) {
    pin_patcher_thread();

    const char* sock_path = (arg ? (const char*)arg : g_master_sock_path);

    int server_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server_fd < 0) {
        perror("[patcher] socket");
        return nullptr;
    }
    // Avoid stealing fd 0/1/2 — constructors run before main() when
    // stdin/stdout/stderr may not be open yet. If the socket lands on
    // a low fd, a program that forks inherits it as stdin, breaking child I/O.
    if (server_fd <= 2) {
        int high = fcntl(server_fd, F_DUPFD_CLOEXEC, 3);
        if (high >= 0) { close(server_fd); server_fd = high; }
    }
    // Track for cleanup in forked children
    if (strcmp(sock_path, g_master_sock_path) == 0)
        g_master_server_fd = server_fd;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path)-1);
    unlink(sock_path);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[patcher] bind");
        return nullptr;
    }
    listen(server_fd, 5);

    while (1) {
        int client = accept(server_fd, NULL, NULL);
        if (client < 0) continue;

        char buf[256];
        struct iovec iov;
        struct msghdr msg;
        char cmsgbuf[CMSG_SPACE(sizeof(int))];

        memset(&msg, 0, sizeof(msg));
        memset(cmsgbuf, 0, sizeof(cmsgbuf));

        iov.iov_base = buf;
        iov.iov_len  = sizeof(buf);
        msg.msg_iov  = &iov;
        msg.msg_iovlen = 1;

        msg.msg_control    = cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);

        ssize_t n = recvmsg(client, &msg, 0);
        if (n <= 0) {
            close(client);
            continue;
        }

        struct timespec ts_start;
        clock_gettime(CLOCK_MONOTONIC, &ts_start);
        buf[n] = '\0';

        int recv_fd = -1;
        struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg && cmsg->cmsg_level == SOL_SOCKET &&
            cmsg->cmsg_type  == SCM_RIGHTS)
        {
            memcpy(&recv_fd, CMSG_DATA(cmsg), sizeof(int));
        }
        if (recv_fd < 0) {
            fprintf(stderr, "[patcher] WARN: no fd received (cmsg=%p, n=%zd, buf=%.*s)\n",
                    (void*)cmsg, n, (int)(n < 60 ? n : 60), buf);
        }

        uint64_t page_base = 0;
        sscanf(buf, "{\"page_base\":%lu}", &page_base);

        int mflags = MAP_SHARED | MAP_FIXED_NOREPLACE;
        void* res = mmap((void*)page_base, 4096,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         mflags,
                         recv_fd, 0);
        if (res == MAP_FAILED) {
            if (errno == EEXIST) {
                bool is_committed;
                {
                    std::lock_guard<std::mutex> lk(g_memfd_mapped_mutex);
                    is_committed = committed_pages().count(page_base) != 0;
                }
                if (is_committed) {
                    fprintf(stderr, "[patcher] mmap at %p collides with a committed page"
                            " — treating as already mapped\n", (void*)page_base);
                    send(client, "K", 1, MSG_NOSIGNAL);
                    close(recv_fd);
                    close(client);
                    continue;
                }
                fprintf(stderr, "[patcher] ERROR: mmap at %p collides with existing mapping"
                        " — rolling back and restarting mapping server\n", (void*)page_base);
            } else {
                fprintf(stderr, "[patcher] ERROR: mmap at %p failed: %s"
                        " — rolling back and restarting mapping server\n",
                        (void*)page_base, strerror(errno));
            }
            send(client, "F", 1, MSG_NOSIGNAL);
            close(recv_fd);
            close(client);

            {
                std::lock_guard<std::mutex> lk(g_memfd_mapped_mutex);
                std::set<uint64_t> keep;
                for (uint64_t pg : memfd_mapped_pages()) {
                    if (committed_pages().count(pg)) {
                        keep.insert(pg);
                        continue;
                    }
                    munmap((void*)pg, 4096);
                }
                memfd_mapped_pages().swap(keep);
            }
            {
                std::lock_guard<std::mutex> lk1(g_memfd_mapped_mutex);
                std::lock_guard<std::mutex> lk2(g_memfd_store_mutex);
                std::vector<MemfdEntry> keep_store;
                for (auto& entry : g_memfd_store) {
                    if (committed_pages().count(entry.page_base)) {
                        keep_store.push_back(entry);
                        continue;
                    }
                    close(entry.fd);
                }
                g_memfd_store.swap(keep_store);
            }
            g_mapping_time_us.store(0, std::memory_order_relaxed);
            g_mapping_count.store(0, std::memory_order_relaxed);

            // Close and re-create the server socket so the next e9patch
            // attempt gets a fresh connection.
            close(server_fd);
            unlink(sock_path);

            server_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
            if (server_fd < 0) { perror("[patcher] socket (restart)"); return nullptr; }
            if (strcmp(sock_path, g_master_sock_path) == 0)
                g_master_server_fd = server_fd;
            memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path)-1);
            if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                perror("[patcher] bind (restart)");
                return nullptr;
            }
            listen(server_fd, 5);
            fprintf(stderr, "[patcher] mapping server restarted, waiting for retry\n");

            // Drain remaining connections from the failed e9patch (it will exit)
            continue;
        }

        struct timespec ts_end;
        clock_gettime(CLOCK_MONOTONIC, &ts_end);

        uint64_t dt_us =
            (ts_end.tv_sec - ts_start.tv_sec) * 1000000ULL +
            (ts_end.tv_nsec - ts_start.tv_nsec) / 1000ULL;

        g_mapping_time_us.fetch_add(dt_us, std::memory_order_relaxed);
        g_mapping_count.fetch_add(1, std::memory_order_relaxed);

        // Track this page as memfd-mapped (content already correct from e9patch pwrite).
        {
            std::lock_guard<std::mutex> lk(g_memfd_mapped_mutex);
            memfd_mapped_pages().insert(page_base);
        }

        // Retain FD for later distribution to workers via DISTRIBUTE command.
        {
            std::lock_guard<std::mutex> lk(g_memfd_store_mutex);
            g_memfd_store.push_back({page_base, recv_fd});
        }
        // Do NOT close recv_fd — workers will need it via DISTRIBUTE.

        send(client, "K", 1, MSG_NOSIGNAL);
        close(client);
    }
    return nullptr;
}

/*************************************************
 * 10) Start gate + exit hook (constructor-based, glibc-version-independent)
 *************************************************/
__attribute__((constructor(102)))
static void ctor_unbuffer_stderr() {
    // Unbuffered stderr so diagnostic messages survive SIGSEGV / abort.
    setvbuf(stderr, NULL, _IONBF, 0);
}

// Returns true if patcher should be inert in this process.
// Used for multi-process programs (e.g., Chrome) where helper subprocesses
// (--type=gpu-process, --type=utility, --type=zygote) inherit LD_PRELOAD
// but should not run the patcher's FIFO / mapping-server / SIGTRAP machinery.
// Selection rule: read /proc/self/cmdline. If any arg starts with the
// DIBE_SKIP_TYPE_PREFIX (default "--type="), skip. The browser/renderer/etc.
// distinction is controlled by DIBE_PATCH_TYPES (comma-separated whitelist
// of --type= values to STILL patch; default empty → patch only the browser,
// i.e. processes without any --type= argument).
static bool dibe_should_skip_self() {
    const char* env_disable = getenv("DIBE_DISABLE_AUTO_SKIP");
    if (env_disable && env_disable[0] == '1') return false;
    // Read cmdline
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return false;
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';
    // Walk null-separated args
    char* p = buf;
    char* end = buf + n;
    const char* type_val = nullptr;
    while (p < end) {
        if (strncmp(p, "--type=", 7) == 0) {
            type_val = p + 7;
            break;
        }
        p += strlen(p) + 1;
    }
    if (!type_val) return false;  // browser process: do not skip
    // It's a helper. Check whitelist.
    const char* whitelist = getenv("DIBE_PATCH_TYPES");
    if (whitelist && *whitelist) {
        // Check if type_val is in comma-separated whitelist
        const char* w = whitelist;
        while (*w) {
            const char* comma = strchr(w, ',');
            size_t len = comma ? (size_t)(comma - w) : strlen(w);
            if (strlen(type_val) == len && strncmp(type_val, w, len) == 0) {
                return false;  // patch this type
            }
            if (!comma) break;
            w = comma + 1;
        }
    }
    return true;  // skip
}

static bool g_dibe_skip = false;
__attribute__((constructor(101)))
static void ctor_detect_helper_process() {
    // Runs first, and silently: later constructors and the pthread_atfork
    // handler bail on g_dibe_skip.
    g_dibe_skip = dibe_should_skip_self();
}

// Check if THIS process matches DIBE_GATE_TYPES (a whitelist of --type= values
// that should honor DIBE_START_GATE). If DIBE_GATE_TYPES is unset/empty, the
// default behavior applies (gate any process where DIBE_START_GATE=1 is set
// and dibe is active). Used in Chrome to gate ONLY the renderer.
static bool dibe_self_in_gate_types() {
    const char* types = getenv("DIBE_GATE_TYPES");
    if (!types || !*types) return true;  // empty -> gate-all default
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return true;
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n <= 0) return true;
    buf[n] = '\0';
    const char* type_val = nullptr;
    char* p = buf;
    char* end = buf + n;
    while (p < end) {
        if (strncmp(p, "--type=", 7) == 0) { type_val = p + 7; break; }
        p += strlen(p) + 1;
    }
    if (!type_val) return false;  // no --type, but DIBE_GATE_TYPES restricts to specific types
    const char* w = types;
    while (*w) {
        const char* comma = strchr(w, ',');
        size_t len = comma ? (size_t)(comma - w) : strlen(w);
        if (strlen(type_val) == len && strncmp(type_val, w, len) == 0) return true;
        if (!comma) break;
        w = comma + 1;
    }
    return false;
}

__attribute__((constructor(104)))
static void ctor_start_gate() {
    if (g_dibe_skip) return;
    const char* gate = getenv("DIBE_START_GATE");
    if (gate && gate[0] == '1' && !dibe_self_in_gate_types()) gate = nullptr;
    if (gate && gate[0] == '1') {
        fprintf(stderr, "[patcher] START_GATE: waiting for patch_ready...\n");
        while (g_patch_ready.load(std::memory_order_acquire) == 0) {
            struct timespec ts = {0, 1000*1000};
            nanosleep(&ts, nullptr);
        }
        fprintf(stderr, "[patcher] START_GATE: gate opened\n");
        // Clear so forked children don't inherit it — the gate is only
        // for the master process before main().
        unsetenv("DIBE_START_GATE");
    }
    clock_gettime(CLOCK_MONOTONIC, &g_gate_open_ts);
    g_gate_open_recorded.store(1, std::memory_order_release);
    atexit(dibe_exit_hook);
}

/*************************************************
 * 10b) memfd distribution helpers
 *************************************************/
// Push a single (page_base, memfd_fd) to a worker's mapping server socket.
static int send_memfd_to_socket(const char* sock_path, uint64_t page_base, int memfd_fd) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) { perror("[patcher] distribute: socket"); return -1; }

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, sock_path, sizeof(sa.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "[patcher] distribute: connect(%s): %s\n",
                sock_path, strerror(errno));
        close(sock);
        return -1;
    }

    char json_buf[128];
    snprintf(json_buf, sizeof(json_buf), "{\"page_base\":%lu}", (unsigned long)page_base);

    struct iovec iov;
    struct msghdr msg;
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    memset(&msg, 0, sizeof(msg));
    memset(cmsgbuf, 0, sizeof(cmsgbuf));

    iov.iov_base = json_buf;
    iov.iov_len  = strlen(json_buf);
    msg.msg_iov    = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control    = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &memfd_fd, sizeof(int));

    ssize_t sent = sendmsg(sock, &msg, 0);
    if (sent < 0) {
        fprintf(stderr, "[patcher] distribute: sendmsg(%s): %s\n",
                sock_path, strerror(errno));
        close(sock);
        return -1;
    }
    char ack = 0;
    ssize_t r = recv(sock, &ack, 1, 0);
    close(sock);
    if (r != 1 || ack != 'K') {
        fprintf(stderr, "[patcher] distribute: %s did not ack page 0x%lx\n",
                sock_path, (unsigned long)page_base);
        return -1;
    }
    return 0;
}

// Push all stored memfd entries to a set of worker mapping servers.
static void distribute_to_workers(const std::string& pids_str) {
    std::vector<pid_t> worker_pids;
    std::istringstream iss(pids_str);
    std::string tok;
    while (iss >> tok) {
        worker_pids.push_back((pid_t)std::stol(tok));
    }
    if (worker_pids.empty()) {
        fprintf(stderr, "[patcher] DISTRIBUTE: no worker PIDs\n");
        return;
    }

    std::vector<MemfdEntry> snapshot;
    {
        std::lock_guard<std::mutex> lk(g_memfd_store_mutex);
        snapshot = g_memfd_store;
    }

    fprintf(stderr, "[patcher] DISTRIBUTE: %zu memfd pages -> %zu workers\n",
            snapshot.size(), worker_pids.size());

    struct timespec ts0;
    clock_gettime(CLOCK_MONOTONIC, &ts0);

    int ok = 0, fail = 0;
    for (pid_t wpid : worker_pids) {
        char sock_path[256];
        snprintf(sock_path, sizeof(sock_path), "/tmp/dibe_map.%d", wpid);
        for (const auto& e : snapshot) {
            if (send_memfd_to_socket(sock_path, e.page_base, e.fd) == 0)
                ok++;
            else
                fail++;
        }
    }

    struct timespec ts1;
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    uint64_t dt_us = (ts1.tv_sec - ts0.tv_sec) * 1000000ULL +
                     (ts1.tv_nsec - ts0.tv_nsec) / 1000ULL;

    fprintf(stderr, "[patcher] DISTRIBUTE: %d ok, %d fail, %lu us\n",
            ok, fail, (unsigned long)dt_us);
}

/*************************************************
 * 11) Patch thread (FIFO)
 *************************************************/
static void* fifo_patch_thread(void* arg){
    pin_patcher_thread();
    const char* fifo = (const char*)arg;
    int fd = open(fifo, O_RDONLY | O_CLOEXEC);
    if(fd < 0){
        perror("[patcher] open FIFO");
        return nullptr;
    }
    if (fd <= 2) {
        int high = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (high >= 0) { close(fd); fd = high; }
    }
    g_fifo_fd = fd;

    fprintf(stderr,"[patcher] FIFO thread started on %s\n", fifo);

    char buf[4096];
    while(1){
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        if(n <= 0) {
            // EOF or error — close and reopen to block until the next writer.
            // Without this, read() returns 0 in a busy loop once the writer
            // closes the FIFO.
            close(fd);
            fd = open(fifo, O_RDONLY | O_CLOEXEC);
            g_fifo_fd = fd;
            if (fd < 0) break;
            continue;
        }
        buf[n] = '\0';

        fprintf(stderr, "[patcher] FIFO read %zd bytes: [%s]\n", n, buf);

        if(strstr(buf,"DISTRIBUTE")){
            // Parse: "DISTRIBUTE <pid1> <pid2> ...\n"
            const char* p = strstr(buf, "DISTRIBUTE") + 10;
            while (*p == ' ') p++;
            std::string pids(p);
            while (!pids.empty() && (pids.back()=='\n'||pids.back()=='\r'||pids.back()==' '))
                pids.pop_back();
            fprintf(stderr, "[patcher] DISTRIBUTE command: workers=[%s]\n", pids.c_str());
            distribute_to_workers(pids);
        }
        else if(strstr(buf,"APPLY")){
            // Parse optional directory from "APPLY /path/to/dir\n"
            std::string jmp_path = "jmp.jsonl";
            std::string patch_path = "patches.jsonl";
            const char* dir = strstr(buf, "APPLY");
            if (dir) {
                dir += 5;  // skip "APPLY"
                while (*dir == ' ') dir++;
                if (*dir && *dir != '\n') {
                    std::string d(dir);
                    // trim trailing whitespace/newline
                    while (!d.empty() && (d.back()=='\n'||d.back()=='\r'||d.back()==' '))
                        d.pop_back();
                    if (!d.empty()) {
                        if (d.back() != '/') d += '/';
                        jmp_path = d + "jmp.jsonl";
                        patch_path = d + "patches.jsonl";
                    }
                }
            }

            fprintf(stderr, "[patcher] APPLY command received (jmp=%s)\n", jmp_path.c_str());

            if ((size_t)n == sizeof(buf)-1 && !memchr(buf, '\n', n)) {
                fprintf(stderr, "[patcher] ERROR: APPLY command truncated "
                        "(%zd bytes, no newline) — ignoring\n", n);
                continue;
            }

            g_jmps.clear(); g_patches.clear();
            if (!load_jmp_jsonl(jmp_path) || !load_patches_jsonl(patch_path)) {
                fprintf(stderr, "[patcher] ERROR: APPLY aborted — patch metadata "
                        "unreadable (jmp=%s)\n", jmp_path.c_str());
                continue;
            }

            patcher_apply();

            // Check for validation mode via env var OR marker file
            if (getenv("DIBE_VALIDATE") ||
                access("/tmp/dibe_validate", F_OK) == 0)
                patcher_validate();

            g_patch_ready.store(1);

            fprintf(stderr, "[patcher] FIFO: gate opened\n");
        }
    }
    return nullptr;
}
/*************************************************
 * 12) Fork support (pthread_atfork)
 *
 * After fork(), child threads are NOT inherited. The FIFO listener
 * thread from the parent is gone in the child, so it is re-created
 * along with the FIFO, letting each forked worker receive APPLY
 * commands independently.
 *************************************************/
static void child_after_fork(){
    // A child has no edit of its own in flight; clear any inherited count so a
    // future fork in this child isn't gated on a phantom edit.
    g_edit_in_flight.store(0, std::memory_order_release);

    // Close inherited patcher fds — they belong to the parent's threads
    // and must not leak into child processes (this causes pipe/select
    // deadlocks in programs that fork for internal work).
    if (g_fifo_fd >= 0)          { close(g_fifo_fd); g_fifo_fd = -1; }
    if (g_master_server_fd >= 0) { close(g_master_server_fd); g_master_server_fd = -1; }

    // Only set up a per-worker FIFO + mapping server for fork-based servers.
    // Programs that fork children for internal work do not need them, and
    // spawning patcher threads in such children risks deadlock (mutexes may
    // be locked at fork time).
    if (!getenv("DIBE_FORK_WORKERS")) return;

    // Re-create FIFO with the child's own PID
    snprintf(fifo_path, sizeof(fifo_path), "/tmp/dibe_ctrl.%d", getpid());
    unlink(fifo_path);
    if(mkfifo(fifo_path, 0666) != 0){
        perror("[patcher] mkfifo(child)");
    } else {
        fprintf(stderr, "[patcher] child FIFO created: %s (pid %d)\n", fifo_path, getpid());
    }

    g_patch_ready.store(0);

    // Reinitialize mutexes — after fork, they may be in a locked state
    // if another thread held them at fork time. POSIX says their state
    // is undefined in the child.
    new (&g_memfd_store_mutex) std::mutex();
    new (&g_memfd_mapped_mutex) std::mutex();

    // Clear inherited memfd state (stale in forked child)
    g_memfd_store.clear();
    memfd_mapped_pages().clear();

    // Spawn a new FIFO listener thread for this child
    pthread_t tid;
    pthread_create(&tid, nullptr, fifo_patch_thread, (void*)fifo_path);
    pthread_detach(tid);

    // Start per-worker mapping server so master can push memfd pages via DISTRIBUTE
    snprintf(g_worker_sock_path, sizeof(g_worker_sock_path),
             "/tmp/dibe_map.%d", getpid());
    unlink(g_worker_sock_path);
    pthread_t map_tid;
    pthread_create(&map_tid, NULL, mapping_server_thread, (void*)g_worker_sock_path);
    pthread_detach(map_tid);
    fprintf(stderr, "[patcher] child mapping server: %s (pid %d)\n",
            g_worker_sock_path, getpid());
}

/*************************************************
 * 13) Constructors / destructors
 *************************************************/
// Writes PID for external controller scripts/tools.
__attribute__((constructor(102)))
static void ctor_pidfile(){
    if (g_dibe_skip) return;
    install_trap_handler();

    // Cache DIBE_FORCE_S2 at ctor time — the environment may be wiped before
    // patcher_apply runs (some servers scrub their workers' env).
    const char* fs2 = getenv("DIBE_FORCE_S2");
    g_force_s2 = (fs2 && fs2[0] == '1');
    if (g_force_s2)
        fprintf(stderr, "[patcher] DIBE_FORCE_S2=1 cached at ctor (pid=%d)\n", getpid());

    const char* fq = getenv("DIBE_FORK_QUIESCE");
    g_fork_quiesce = fq ? atoi(fq) : 0;
    if (g_fork_quiesce >= 1)
        fprintf(stderr, "[patcher] DIBE_FORK_QUIESCE=%d (fork-quiesce) cached at ctor (pid=%d)\n",
                g_fork_quiesce, getpid());

    const char* p=getenv("DIBE_PIDFILE");
    if(!p) p="/tmp/dibe.pid";
    if(FILE*f=fopen(p,"w")){
        fprintf(f,"%d\n",getpid());
        fclose(f);
    }
    g_patch_ready.store(0);

    // Create FIFO for master control
    snprintf(fifo_path, sizeof(fifo_path), "/tmp/dibe_ctrl.%d", getpid());
    unlink(fifo_path);
    if(mkfifo(fifo_path, 0666) != 0){
        perror("[patcher] mkfifo(master)");
    } else {
        fprintf(stderr, "[patcher] master FIFO created: %s\n", fifo_path);
    }

    // Start FIFO thread (master only)
    pthread_t tid;
    pthread_create(&tid, nullptr, fifo_patch_thread, (void*)fifo_path);
    pthread_detach(tid);

    // Register fork handler so children get their own FIFO + listener thread.
    // With DIBE_FORK_QUIESCE>=1 a prepare handler also quiesces in-flight edits
    // before the (glibc) fork proceeds; >=2 additionally installs the seccomp/
    // SIGSYS trap so raw clone() syscalls are gated too.
    pthread_atfork(g_fork_quiesce >= 1 ? fork_prepare_quiesce : nullptr,
                   nullptr, child_after_fork);
    if (g_fork_quiesce >= 2) {
        install_sigsys_handler();
        if (install_fork_seccomp())
            fprintf(stderr, "[patcher] fork-quiesce seccomp/SIGSYS installed (pid=%d)\n", getpid());
        else
            fprintf(stderr, "[patcher] WARN: fork-quiesce seccomp install failed; "
                            "prepare-handler quiesce still active (pid=%d)\n", getpid());
    }
}

// Starts the mapping server early (before main).
__attribute__((constructor(103)))
static void start_mapping_server() {
    if (g_dibe_skip) return;
    snprintf(g_master_sock_path, sizeof(g_master_sock_path), SOCK_PATH_FMT, getpid());
    unlink(g_master_sock_path);
    pthread_t th;
    pthread_create(&th, NULL, mapping_server_thread, (void*)g_master_sock_path);
    pthread_detach(th);
}

__attribute__((destructor))
static void cleanup_socket() {
    // Clean up master mapping socket
    if (g_master_sock_path[0] != '\0')
        unlink(g_master_sock_path);

    // Clean up per-worker mapping socket
    if (g_worker_sock_path[0] != '\0')
        unlink(g_worker_sock_path);

    // Close retained memfd FDs
    {
        std::lock_guard<std::mutex> lk(g_memfd_store_mutex);
        for (auto& e : g_memfd_store) {
            if (e.fd >= 0) close(e.fd);
        }
        g_memfd_store.clear();
    }

    fprintf(stderr, "[patcher] socket cleaned up\n");
}

// The start gate and exit hook are installed from __attribute__((constructor))
// in ctor_start_gate() rather than by hooking __libc_start_main: glibc >= 2.34
// changed that function's signature/internals, so intercepting it via LD_PRELOAD
// is unreliable.
