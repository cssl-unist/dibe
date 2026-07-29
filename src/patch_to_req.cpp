// patch_to_req.cpp
// g++ -std=c++17 -O2 -Wall -Wextra -o patch_to_req patch_to_req.cpp
// ./patch_to_req micro_patch.json target_program patched_program <PID> > req.json

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <variant>
#include <cstring>
#include <regex>

#include <elf.h>        // ELF parsing

// -----------------------------
// Patch Structure
// -----------------------------
struct Patch {
    uint64_t va;                // VA (patch_address)
    uint64_t offset;            // file offset (converted)
    size_t target_length;
    std::vector<std::variant<int, std::string>> bytes;
};

// A single decoded .text instruction (from micro_patch.json "instructions"[]).
// These become the DENSE `instruction{offset,address,length}` stream e9patch
// needs so its pred()/succ() walk + upstream-shift analysis have real Instr
// objects; only the patch SITES additionally get a `patch` message.
struct Insn {
    uint64_t va;
    uint64_t offset;
    size_t   length;
};

// -----------------------------
// Utility Functions
// -----------------------------
static bool is_hex_digit(char c) {
    return std::isxdigit(static_cast<unsigned char>(c));
}

static std::string strtoupper(const std::string &s) {
    std::string r = s;
    for (char &c : r) c = static_cast<char>(std::toupper((unsigned char)c));
    return r;
}

static std::string json_escape(const std::string &s) {
    std::string out; out.reserve(s.size() + 4);
    for (char c : s) {
        switch (c) {
            case '\"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if ((unsigned char)c < 0x20) {
                    char buf[7];
                    snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                    out += buf;
                } else out += c;
        }
    }
    return out;
}

static bool is_all_digits(const std::string& s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), ::isdigit);
}

// -----------------------------
// Atomic Write
// -----------------------------
static bool atomic_write(const std::string& path, const std::string& content) {
    std::string dir = ".";
    auto slash = path.find_last_of("/\\");
    if (slash != std::string::npos) dir = path.substr(0, slash);
    std::string base = (slash == std::string::npos) ? path : path.substr(slash + 1);
    std::string tmp = dir + "/." + base + ".tmp";

    {
        std::ofstream ofs(tmp, std::ios::binary);
        if (!ofs) return false;
        ofs.write(content.data(), content.size());
        if (!ofs) return false;
        ofs.close();
    }
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        std::remove(tmp.c_str());
        return false;
    }
    return true;
}

// -----------------------------
// PID Update
// -----------------------------
static bool update_last_pid_inplace(const std::string& json_path, const std::string& new_pid) {
    std::ifstream ifs(json_path);
    if (!ifs) {
        std::cerr << "Error: cannot open " << json_path << "\n";
        return false;
    }
    std::string content((std::istreambuf_iterator<char>(ifs)), {});

    const std::regex rx(R"regex("pid"\s*:\s*\d+)regex");
    std::sregex_iterator it(content.begin(), content.end(), rx), end;
    if (it == end) {
        std::cerr << "Error: no \"pid\" found in " << json_path << "\n";
        return false;
    }
    std::sregex_iterator last = it;
    for (; it != end; ++it) last = it;
    auto match = *last;

    std::string matched = match.str();
    auto colon_pos = matched.find(':');

    std::string prefix = matched.substr(0, colon_pos + 1);
    std::string spaces;
    size_t i = colon_pos + 1;
    while (i < matched.size() && std::isspace((unsigned char)matched[i])) spaces.push_back(matched[i++]);

    std::string replacement = prefix + spaces + new_pid;

    content.replace(match.position(), match.length(), replacement);

    {
        std::ofstream bak(json_path + ".bak");
        if (bak) {
            std::ifstream ifs2(json_path);
            std::string orig((std::istreambuf_iterator<char>(ifs2)), {});
            bak.write(orig.data(), orig.size());
        }
    }

    return atomic_write(json_path, content);
}

// -----------------------------
// ELF Segment Loader
// -----------------------------
struct Segment {
    uint64_t p_vaddr;
    uint64_t p_offset;
    uint64_t p_filesz;
    uint64_t p_memsz;
};

static std::vector<Segment> load_elf_segments(const std::string& program, bool &is_pie) {
    std::ifstream f(program, std::ios::binary);
    if (!f) {
        std::cerr << "Error: cannot open ELF: " << program << "\n";
        exit(1);
    }

    Elf64_Ehdr eh{};
    f.read((char*)&eh, sizeof(eh));
    if (!f) {
        std::cerr << "Error: failed reading ELF header\n";
        exit(1);
    }

    is_pie = (eh.e_type == ET_DYN); // ET_EXEC -> non-PIE

    f.seekg(eh.e_phoff);

    std::vector<Segment> segs;
    for (int i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr ph{};
        f.read((char*)&ph, sizeof(ph));
        if (!f) {
            std::cerr << "Error: failed reading Program Header #" << i << "\n";
            exit(1);
        }
        if (ph.p_type == PT_LOAD) {
            segs.push_back({ph.p_vaddr, ph.p_offset, ph.p_filesz, ph.p_memsz});
        }
    }
    return segs;
}

// -----------------------------
// VA → File Offset
// -----------------------------
static uint64_t va_to_file_offset(uint64_t va, const std::vector<Segment>& segs, bool /*is_pie*/) {
    // Always walk PT_LOAD segments. For most PIE binaries the first PT_LOAD covers
    // VA 0 with file offset 0, making VA == offset, but this is not guaranteed
    for (auto &s : segs) {
        if (va >= s.p_vaddr && va < s.p_vaddr + s.p_memsz) {
            return (va - s.p_vaddr + s.p_offset);
        }
    }

    std::cerr << "Warning: VA 0x" << std::hex << va << std::dec
              << " not in any PT_LOAD segment\n";
    return va;
}

// -----------------------------
// Parse the optional "instructions" array (dense .text stream).
// Each element is {"address":"<hex>", "length":N}.  Returns the list of
// {va,length} (offset filled in by the caller).  Empty if the key is absent —
// in that case patch_to_req falls back to site-only behavior.
// -----------------------------
static std::vector<Insn> parse_instructions(const std::string& s,
                                            const std::vector<Segment>& segs,
                                            bool is_pie) {
    std::vector<Insn> out;
    size_t key = s.find("\"instructions\"");
    if (key == std::string::npos) return out;
    size_t arr = s.find('[', key);
    if (arr == std::string::npos) return out;
    size_t end = s.find(']', arr);
    if (end == std::string::npos) end = s.size();

    size_t pos = arr;
    while (true) {
        size_t apos = s.find("\"address\"", pos);
        if (apos == std::string::npos || apos > end) break;
        size_t c = s.find(':', apos);
        if (c == std::string::npos) break;
        c++;
        // skip to the value (quoted hex or bare hex)
        while (c < end && (s[c] == ' ' || s[c] == '\t' || s[c] == '\n' ||
                           s[c] == '\r' || s[c] == '"')) c++;
        size_t hs = c;
        if (c + 1 < end && s[c] == '0' && (s[c+1] == 'x' || s[c+1] == 'X')) {
            c += 2; hs = c;
        }
        while (c < end && is_hex_digit(s[c])) c++;
        std::string hex = s.substr(hs, c - hs);
        if (hex.empty()) { pos = apos + 9; continue; }
        uint64_t va = 0;
        try { va = std::stoull(hex, nullptr, 16); } catch (...) { pos = c; continue; }

        // length (search forward within this object, before the next address)
        size_t lpos = s.find("\"length\"", c);
        size_t next_addr = s.find("\"address\"", c);
        size_t length = 1;
        if (lpos != std::string::npos && lpos < end &&
            (next_addr == std::string::npos || lpos < next_addr)) {
            size_t lc = s.find(':', lpos);
            if (lc != std::string::npos) {
                lc++;
                while (lc < end && !isdigit((unsigned char)s[lc])) lc++;
                size_t ls = lc;
                while (lc < end && isdigit((unsigned char)s[lc])) lc++;
                if (ls < lc) {
                    try { length = std::stoul(s.substr(ls, lc - ls)); }
                    catch (...) { length = 1; }
                }
                c = lc;
            }
        }
        uint64_t off = va_to_file_offset(va, segs, is_pie);
        out.push_back({va, off, length});
        pos = c;
    }
    return out;
}

// -----------------------------
// Main
// -----------------------------
int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] 
                  << " <micro_patch.json> <program> <out_binary> <PID>\n";
        return 1;
    }

    const char* json_file = argv[1];
    std::string program = argv[2];
    std::string out_binary = argv[3];
    std::string pid_str = argv[4];

    if (!is_all_digits(pid_str)) {
        std::cerr << "Error: PID must be digits.\n";
        return 1;
    }

    if (!update_last_pid_inplace(json_file, pid_str)) return 1;

    std::ifstream fin(json_file);
    if (!fin) {
        std::cerr << "Error: cannot open " << json_file << "\n";
        return 1;
    }
    std::stringstream buf; buf << fin.rdbuf();
    std::string s = buf.str();

    bool is_pie = false;
    std::vector<Segment> segments = load_elf_segments(program, is_pie);

    // -----------------------------
    // Parse micro_patch.json
    // -----------------------------
    std::vector<Patch> patches;
    size_t pos = 0;

    while (true) {
        pos = s.find("\"patch_address\"", pos);
        if (pos == std::string::npos) break;
        pos = s.find(':', pos);
        if (pos == std::string::npos) break;
        pos++;

        while (pos < s.size() && s[pos] != '0' && !is_hex_digit(s[pos])) pos++;

        size_t start = pos;
        if (pos + 1 < s.size() && s[pos] == '0' && (s[pos+1]=='x'||s[pos+1]=='X')) {
            pos += 2;
            start = pos;
        }

        while (pos < s.size() && is_hex_digit(s[pos])) pos++;
        std::string hex = s.substr(start, pos-start);
        if (hex.empty()) continue;

        uint64_t va = 0;
        try {
            va = std::stoull(hex, nullptr, 16);
        } catch (...) {
            continue;
        }

        uint64_t offset = va_to_file_offset(va, segments, is_pie);

        // target_length
        size_t tpos = s.find("\"target_length\"", pos);
        size_t target_length = 1;
        if (tpos != std::string::npos) {
            tpos = s.find(':', tpos);
            tpos++;
            while (tpos < s.size() && !isdigit((unsigned char)s[tpos])) tpos++;
            size_t ts = tpos;
            while (tpos < s.size() && isdigit((unsigned char)s[tpos])) tpos++;
            if (ts < s.size()) {
                try { target_length = std::stoul(s.substr(ts, tpos-ts)); }
                catch (...) { target_length = 1; }
            }
        }

        // patch_bytes
        pos = s.find("\"patch_bytes\"", pos);
        if (pos == std::string::npos) {
            patches.push_back({va, offset, target_length, {}});
            continue;
        }
        pos = s.find('[', pos);
        pos++;

        std::vector<std::variant<int, std::string>> bytes;

        while (pos < s.size()) {
            while (pos < s.size() && isspace((unsigned char)s[pos])) pos++;
            if (pos >= s.size()) break;
            if (s[pos] == ']') { pos++; break; }

            bool quoted = false;
            if (s[pos] == '"') { quoted = true; pos++; }

            size_t ts = pos;
            while (pos < s.size()) {
                if (quoted) {
                    if (s[pos] == '"') break;
                } else if (s[pos] == ',' || s[pos] == ']' || isspace((unsigned char)s[pos])) break;
                pos++;
            }
            size_t te = pos;
            std::string token = s.substr(ts, te-ts);
            if (quoted && pos < s.size() && s[pos]=='"') pos++;

            while (pos < s.size() && s[pos]!=',' && s[pos]!=']') pos++;
            if (pos < s.size() && s[pos]==',') pos++;

            // trim
            size_t a=0,b=token.size();
            while(a<b && isspace((unsigned char)token[a])) a++;
            while(b>a && isspace((unsigned char)token[b-1])) b--;
            token = token.substr(a,b-a);
            if (token.empty()) continue;

            if (token[0]=='$') {
                bytes.push_back(token);
                continue;
            }

            std::string lower;
            for (char c:token) lower.push_back((char)tolower((unsigned char)c));
            if (lower == "break") {
                bytes.push_back(std::string("$BREAK"));
                continue;
            }

            bool all_hex = false;
            size_t p2=0;
            if (token.size()>2 && token[0]=='0' && (token[1]=='x'||token[1]=='X')) {
                p2=2; all_hex=true;
            } else {
                all_hex = true;
            }
            for (size_t i=p2;i<token.size();i++) {
                if (!is_hex_digit(token[i])) { all_hex=false; break; }
            }
            if (all_hex) {
                long val = strtol(token.c_str()+p2, nullptr, 16);
                bytes.push_back(int(val & 0xff));
                continue;
            }

            bytes.push_back(std::string("$"+strtoupper(token)));
        }

        patches.push_back({va, offset, target_length, bytes});
    }

    std::sort(patches.begin(), patches.end(),
              [](const Patch&a,const Patch&b){return a.offset>b.offset;});

    // -----------------------------
    // Build the DENSE instruction set.
    //
    // e9patch requires one `instruction{offset,address,length}` message per
    // real .text instruction (in REVERSE offset order, no overlaps) so its
    // pred()/succ() walk and the upstream-shift analysis work; a `patch`
    // message is then emitted ONLY for the sites.  When micro_patch.json
    // carries an "instructions"[] array we use it; otherwise we fall back to
    // the site-only stream (every site is its own instruction).
    //
    // Merge rule: the dense list wins on length (both it and the site come
    // from the same objdump line, so they agree for real jump sites).  A site
    // missing from the dense list (e.g. an empty array) is added.  Keyed
    // by file offset.
    // -----------------------------
    // DIBE_SITEONLY=1 emits the site-only stream (ignores the dense
    // "instructions"[] array).
    std::vector<Insn> dense;
    if (getenv("DIBE_SITEONLY") == nullptr)
        dense = parse_instructions(s, segments, is_pie);

    std::map<uint64_t, Insn> insn_by_off;     // offset -> instruction
    for (const auto& in : dense)
        insn_by_off[in.offset] = in;          // dense entries (objdump order)
    for (const auto& p : patches) {
        // Ensure every site has a backing instruction record.  Dense wins.
        if (insn_by_off.find(p.offset) == insn_by_off.end())
            insn_by_off[p.offset] = {p.va, p.offset, p.target_length};
    }

    // Materialize in DESCENDING offset order (e9patch reverse-order contract).
    // Drop any entry that would overlap its already-emitted higher-offset
    // neighbor (defends against a stray data-in-code mis-decode; a dropped
    // instruction just can't be a shift origin/candidate — never a site).
    std::vector<Insn> insns;
    insns.reserve(insn_by_off.size());
    for (auto it = insn_by_off.rbegin(); it != insn_by_off.rend(); ++it)
        insns.push_back(it->second);

    std::vector<Insn> ordered;
    ordered.reserve(insns.size());
    uint64_t prev_off = UINT64_MAX;           // last emitted (higher) offset
    size_t dropped = 0;
    for (const auto& in : insns) {
        if (in.offset + in.length > prev_off) { // overlaps the next instr
            dropped++;
            continue;
        }
        ordered.push_back(in);
        prev_off = in.offset;
    }
    if (dropped > 0)
        std::cerr << "Warning: dropped " << dropped
                  << " overlapping/mis-decoded instruction(s) from dense stream\n";

    // Which offsets are patch sites (get a `patch` message)?
    std::map<uint64_t, const Patch*> site_by_off;
    for (const auto& p : patches)
        site_by_off[p.offset] = &p;

    // -----------------------------
    // Output req.json
    // -----------------------------
    int id = 0;
    // Protocol handshake version stamped into the request. e9patch rejects any
    // request whose "version" does not strcmp-match the tool's own VERSION file;
    // it is a compatibility gate only and does not alter tactic behavior.
    // Override with E9_PROTO_VERSION to drive an e9patch built from a different
    // VERSION string.
    const char *ver_env = getenv("E9_PROTO_VERSION");
    const std::string version = (ver_env && *ver_env) ? ver_env : "1.0.0-rc10";

    // binary line
    std::cout << "{\"jsonrpc\":\"2.0\",\"method\":\"binary\","
              << "\"params\":{\"filename\":\"" << json_escape(program)
              << "\",\"mode\":\"elf.exe\",\"version\":\"" << version
              << "\"},\"id\":" << id++ << "}\n";

    // All instructions (dense, reverse order). Sites among them also get a
    // patch message immediately after, so the patch's offset resolves to the
    // instruction just registered.
    for (const auto& in : ordered) {
        std::cout << "{\"jsonrpc\":\"2.0\",\"method\":\"instruction\","
                  << "\"params\":{\"offset\":" << in.offset
                  << ",\"address\":" << in.va
                  << ",\"length\":" << in.length
                  << "},\"id\":" << id++ << "}\n";

        auto sit = site_by_off.find(in.offset);
        if (sit == site_by_off.end())
            continue;                         // not a site: instruction only
        const Patch* p = sit->second;

        std::cout << "{\"jsonrpc\":\"2.0\",\"method\":\"patch\","
                  << "\"params\":{\"offset\":" << p->offset << ",\"trampoline\":[";
        for (size_t i=0;i<p->bytes.size();i++) {
            if (std::holds_alternative<int>(p->bytes[i]))
                std::cout << std::get<int>(p->bytes[i]);
            else
                std::cout << "\"" << json_escape(std::get<std::string>(p->bytes[i])) << "\"";
            if (i+1 < p->bytes.size()) std::cout << ",";
        }
        std::cout << "]},\"id\":" << id++ << "}\n";
    }

    // emit
    std::cout << "{\"jsonrpc\":\"2.0\",\"method\":\"emit\","
              << "\"params\":{\"filename\":\"" << json_escape(out_binary)
              << "\",\"format\":\"binary\"},\"id\":" << id << "}\n";

    return 0;
}
