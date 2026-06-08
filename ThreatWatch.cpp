#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#define NOMINMAX

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <setupapi.h>
#include <devguid.h>
#include <initguid.h>
#include <commctrl.h>
#include <shellapi.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <regex>
#include <functional>

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comctl32.lib")

#define COL_BG          RGB(10,  10,  14)
#define COL_PANEL       RGB(16,  16,  22)
#define COL_PANEL2      RGB(22,  22,  32)
#define COL_BORDER      RGB(60,  40, 100)
#define COL_BORDER2     RGB(80,  55, 130)
#define COL_PURPLE      RGB(140,  80, 220)
#define COL_PURPLE_LT   RGB(170, 110, 255)
#define COL_PURPLE_DIM  RGB(80,  45, 130)
#define COL_TEXT        RGB(220, 215, 235)
#define COL_TEXT_DIM    RGB(130, 120, 155)
#define COL_TEXT_BRIGHT RGB(245, 240, 255)
#define COL_GREEN       RGB(80,  200, 120)
#define COL_RED         RGB(220,  70,  70)
#define COL_AMBER       RGB(220, 160,  50)
#define COL_CYAN        RGB(80,  200, 210)
#define COL_HEADER_BG   RGB(20,  14,  38)

static HWND g_hwnd = nullptr;
static HINSTANCE g_hInst = nullptr;
static int g_tab = 0; 

struct ProcessEntry {
    DWORD pid;
    std::wstring name;
    std::wstring path;
    std::wstring user;
    SIZE_T memUsage;
    float cpuUsage;
    int threadCount;
    bool hasSuspiciousImports;
    bool isSignedByMS;
    bool hasNetActivity;
};

struct NetEntry {
    std::wstring localAddr;
    USHORT localPort;
    std::wstring remoteAddr;
    USHORT remotePort;
    std::wstring state;
    DWORD pid;
    std::wstring procName;
    std::wstring remoteDomain;
};

struct HardwareEntry {
    std::wstring deviceName;
    std::wstring deviceClass;
    std::wstring deviceID;
    std::wstring manufacturer;
    std::wstring driver;
    bool isPluggedIn;
    FILETIME installDate;
};

struct AnalysisResult {
    std::wstring target;
    std::wstring targetType; 
    int score; 
    std::vector<std::wstring> findings;
    std::vector<std::wstring> recommendations;
    bool complete;
    bool running;
};

static std::vector<ProcessEntry>  g_procs;
static std::vector<NetEntry>      g_nets;
static std::vector<HardwareEntry> g_hw;
static std::mutex g_dataMutex;
static std::atomic<bool> g_refreshing(false);
static std::atomic<bool> g_analyzing(false);

static AnalysisResult g_analysis;
static std::mutex g_analysisMutex;

static int g_selectedProc = -1;
static int g_selectedNet = -1;
static int g_selectedHW = -1;

static HWND g_listProc = nullptr;
static HWND g_listNet = nullptr;
static HWND g_listHW = nullptr;
static HWND g_btnAnalyze = nullptr;
static HWND g_panelAnalysis = nullptr;
static HWND g_lblAnalysis = nullptr;
static HWND g_btnRefresh = nullptr;
static HWND g_statusBar = nullptr;

static HWND g_tabProcess = nullptr;
static HWND g_tabNetwork = nullptr;
static HWND g_tabHW = nullptr;


static std::wstring WideFromA(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, nullptr, 0);
    std::wstring r(n - 1, 0);
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, r.data(), n);
    return r;
}

static std::string NarrowFromW(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_ACP, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string r(n - 1, 0);
    WideCharToMultiByte(CP_ACP, 0, w.c_str(), -1, r.data(), n, nullptr, nullptr);
    return r;
}

static std::wstring FormatBytes(SIZE_T bytes) {
    wchar_t buf[64];
    if (bytes >= 1024ULL * 1024 * 1024)
        swprintf_s(buf, L"%.1f GB", (double)bytes / (1024.0 * 1024 * 1024));
    else if (bytes >= 1024 * 1024)
        swprintf_s(buf, L"%.1f MB", (double)bytes / (1024.0 * 1024));
    else if (bytes >= 1024)
        swprintf_s(buf, L"%.1f KB", (double)bytes / 1024.0);
    else
        swprintf_s(buf, L"%zu B", bytes);
    return buf;
}

static std::wstring IpToWStr(DWORD ip) {
    wchar_t buf[64];
    swprintf_s(buf, L"%u.%u.%u.%u",
        (ip) & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
    return buf;
}

static std::wstring TcpStateStr(DWORD s) {
    switch (s) {
    case MIB_TCP_STATE_CLOSED:      return L"CLOSED";
    case MIB_TCP_STATE_LISTEN:      return L"LISTEN";
    case MIB_TCP_STATE_SYN_SENT:    return L"SYN_SENT";
    case MIB_TCP_STATE_SYN_RCVD:    return L"SYN_RCVD";
    case MIB_TCP_STATE_ESTAB:       return L"ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1:   return L"FIN_WAIT1";
    case MIB_TCP_STATE_FIN_WAIT2:   return L"FIN_WAIT2";
    case MIB_TCP_STATE_CLOSE_WAIT:  return L"CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING:     return L"CLOSING";
    case MIB_TCP_STATE_LAST_ACK:    return L"LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT:   return L"TIME_WAIT";
    case MIB_TCP_STATE_DELETE_TCB:  return L"DELETE_TCB";
    default:                        return L"UNKNOWN";
    }
}

static std::wstring GetProcessPathByPid(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return L"[Access Denied]";
    wchar_t buf[MAX_PATH] = {};
    DWORD sz = MAX_PATH;
    QueryFullProcessImageNameW(h, 0, buf, &sz);
    CloseHandle(h);
    return buf[0] ? buf : L"[Unknown]";
}

static std::wstring GetProcessUser(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return L"[N/A]";
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProc);
        return L"[N/A]";
    }
    DWORD sz = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &sz);
    std::vector<BYTE> buf(sz);
    if (!GetTokenInformation(hToken, TokenUser, buf.data(), sz, &sz)) {
        CloseHandle(hToken); CloseHandle(hProc);
        return L"[N/A]";
    }
    TOKEN_USER* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
    wchar_t name[256] = {}, domain[256] = {};
    DWORD nSz = 256, dSz = 256;
    SID_NAME_USE use;
    LookupAccountSidW(nullptr, tu->User.Sid, name, &nSz, domain, &dSz, &use);
    CloseHandle(hToken); CloseHandle(hProc);
    return std::wstring(domain) + L"\\" + name;
}

static std::wstring ReverseLookup(const std::wstring& ip) {
    std::string ipA = NarrowFromW(ip);
    struct sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ipA.c_str(), &sa.sin_addr);
    char host[NI_MAXHOST] = {};
    if (getnameinfo((sockaddr*)&sa, sizeof(sa), host, NI_MAXHOST, nullptr, 0, NI_NAMEREQD) == 0)
        return WideFromA(host);
    return ip;
}

static const std::vector<std::wstring> SUSP_PROC_NAMES = {
    L"mimikatz", L"pwdump", L"fgdump", L"wce", L"gsecdump",
    L"procdump", L"meterpreter", L"nc.exe", L"ncat", L"netcat",
    L"psexec", L"cobalt", L"empire", L"havoc", L"brute"
};

static const std::vector<std::wstring> SUSP_DIRS = {
    L"\\temp\\", L"\\tmp\\", L"\\appdata\\local\\temp\\",
    L"\\downloads\\", L"\\public\\", L"\\programdata\\"
};

static const std::vector<std::wstring> TRUSTED_PUBLISHERS = {
    L"Microsoft", L"Google", L"Intel", L"NVIDIA", L"AMD",
    L"Realtek", L"Qualcomm", L"Broadcom", L"Apple", L"Adobe"
};

static bool IsSuspiciousProcName(const std::wstring& n) {
    std::wstring lower = n;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    for (auto& s : SUSP_PROC_NAMES)
        if (lower.find(s) != std::wstring::npos) return true;
    return false;
}

static bool IsInSuspDir(const std::wstring& path) {
    std::wstring lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    for (auto& d : SUSP_DIRS)
        if (lower.find(d) != std::wstring::npos) return true;
    return false;
}

static bool IsPrivateIP(const std::wstring& ip) {
    if (ip.substr(0, 3) == L"10.") return true;
    if (ip.substr(0, 8) == L"192.168.") return true;
    if (ip.substr(0, 4) == L"172.") {
        int second = 0;
        swscanf_s(ip.c_str(), L"172.%d.", &second);
        if (second >= 16 && second <= 31) return true;
    }
    if (ip == L"127.0.0.1" || ip == L"::1") return true;
    return false;
}

static bool IsKnownPort(USHORT p) {
    static const std::set<USHORT> known = {
        80, 443, 8080, 8443, 53, 22, 21, 25, 110, 143,
        3389, 445, 139, 135, 1433, 3306, 5432, 27017
    };
    return known.count(p) > 0;
}

static bool IsSuspiciousPort(USHORT p) {
    static const std::set<USHORT> susp = {
        4444, 5555, 1337, 31337, 6666, 9001, 9030, 1080,
        4899, 2222, 6969, 7777, 8888, 9999
    };
    return susp.count(p) > 0;
}


static void CollectProcesses() {
    std::vector<ProcessEntry> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    std::map<DWORD, int> threadCounts;
    THREADENTRY32 te = {}; te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do { threadCounts[te.th32OwnerProcessID]++; } while (Thread32Next(snap, &te));
    }

    PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcessEntry ent;
            ent.pid = pe.th32ProcessID;
            ent.name = pe.szExeFile;
            ent.threadCount = threadCounts[ent.pid];
            ent.path = GetProcessPathByPid(ent.pid);
            ent.hasSuspiciousImports = IsSuspiciousProcName(ent.name) || IsInSuspDir(ent.path);
            ent.isSignedByMS = (ent.path.find(L"\\Windows\\") != std::wstring::npos ||
                ent.path.find(L"\\Microsoft\\") != std::wstring::npos);

            HANDLE hP = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ent.pid);
            ent.memUsage = 0; ent.cpuUsage = 0.0f;
            if (hP) {
                PROCESS_MEMORY_COUNTERS pmc = {};
                if (GetProcessMemoryInfo(hP, &pmc, sizeof(pmc)))
                    ent.memUsage = pmc.WorkingSetSize;
                CloseHandle(hP);
            }
            ent.user = GetProcessUser(ent.pid);
            out.push_back(std::move(ent));
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    std::lock_guard<std::mutex> lk(g_dataMutex);
    g_procs = std::move(out);
}

static void CollectNetwork() {
    std::vector<NetEntry> out;

    std::map<DWORD, std::wstring> pidNames;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe))
                do { pidNames[pe.th32ProcessID] = pe.szExeFile; } while (Process32NextW(snap, &pe));
            CloseHandle(snap);
        }
    }

    ULONG size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<BYTE> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
        for (DWORD i = 0; i < t->dwNumEntries; i++) {
            auto& r = t->table[i];
            NetEntry e;
            e.localAddr = IpToWStr(r.dwLocalAddr);
            e.localPort = ntohs((USHORT)r.dwLocalPort);
            e.remoteAddr = IpToWStr(r.dwRemoteAddr);
            e.remotePort = ntohs((USHORT)r.dwRemotePort);
            e.state = TcpStateStr(r.dwState);
            e.pid = r.dwOwningPid;
            e.procName = pidNames.count(e.pid) ? pidNames[e.pid] : L"[Unknown]";
            if (r.dwState == MIB_TCP_STATE_ESTAB && !IsPrivateIP(e.remoteAddr) && e.remoteAddr != L"0.0.0.0")
                e.remoteDomain = e.remoteAddr; 
            else
                e.remoteDomain = e.remoteAddr;
            out.push_back(std::move(e));
        }
    }

    ULONG udpSz = 0;
    GetExtendedUdpTable(nullptr, &udpSz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    std::vector<BYTE> udpBuf(udpSz);
    if (GetExtendedUdpTable(udpBuf.data(), &udpSz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        auto* t = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(udpBuf.data());
        for (DWORD i = 0; i < t->dwNumEntries; i++) {
            auto& r = t->table[i];
            NetEntry e;
            e.localAddr = IpToWStr(r.dwLocalAddr);
            e.localPort = ntohs((USHORT)r.dwLocalPort);
            e.remoteAddr = L"*";
            e.remotePort = 0;
            e.state = L"UDP";
            e.pid = r.dwOwningPid;
            e.procName = pidNames.count(e.pid) ? pidNames[e.pid] : L"[Unknown]";
            e.remoteDomain = L"*";
            out.push_back(std::move(e));
        }
    }

    std::lock_guard<std::mutex> lk(g_dataMutex);
    g_nets = std::move(out);
}

static void CollectHardware() {
    std::vector<HardwareEntry> out;
    HDEVINFO devInfo = SetupDiGetClassDevsW(nullptr, nullptr, nullptr,
        DIGCF_PRESENT | DIGCF_ALLCLASSES);
    if (devInfo == INVALID_HANDLE_VALUE) return;

    SP_DEVINFO_DATA devData = {}; devData.cbSize = sizeof(devData);
    for (DWORD idx = 0; SetupDiEnumDeviceInfo(devInfo, idx, &devData); idx++) {
        HardwareEntry e;
        e.isPluggedIn = true;

        wchar_t buf[512] = {};
        DWORD reqSz = 0, dataType = 0;

        if (SetupDiGetDeviceRegistryPropertyW(devInfo, &devData, SPDRP_FRIENDLYNAME,
            &dataType, (PBYTE)buf, sizeof(buf), &reqSz))
            e.deviceName = buf;
        else if (SetupDiGetDeviceRegistryPropertyW(devInfo, &devData, SPDRP_DEVICEDESC,
            &dataType, (PBYTE)buf, sizeof(buf), &reqSz))
            e.deviceName = buf;
        else
            e.deviceName = L"[Unknown Device]";

        if (SetupDiGetDeviceRegistryPropertyW(devInfo, &devData, SPDRP_CLASS,
            &dataType, (PBYTE)buf, sizeof(buf), &reqSz))
            e.deviceClass = buf;

        if (SetupDiGetDeviceRegistryPropertyW(devInfo, &devData, SPDRP_MFG,
            &dataType, (PBYTE)buf, sizeof(buf), &reqSz))
            e.manufacturer = buf;

        if (SetupDiGetDeviceInstanceIdW(devInfo, &devData, buf, 512, &reqSz))
            e.deviceID = buf;

        if (SetupDiGetDeviceRegistryPropertyW(devInfo, &devData, SPDRP_DRIVER,
            &dataType, (PBYTE)buf, sizeof(buf), &reqSz))
            e.driver = buf;

        if (!e.deviceName.empty()) out.push_back(std::move(e));
    }

    SetupDiDestroyDeviceInfoList(devInfo);
    std::lock_guard<std::mutex> lk(g_dataMutex);
    g_hw = std::move(out);
}

static void RefreshAll() {
    g_refreshing = true;
    CollectProcesses();
    CollectNetwork();
    CollectHardware();
    g_refreshing = false;
    if (g_hwnd) PostMessageW(g_hwnd, WM_USER + 1, 0, 0);
}


static void AnalyzeProcess(const ProcessEntry& p, AnalysisResult& res) {
    int score = 1;
    std::vector<std::wstring>& f = res.findings;
    std::vector<std::wstring>& r = res.recommendations;

    if (IsSuspiciousProcName(p.name)) {
        score += 4;
        f.push_back(L"[HIGH] Process name matches known offensive tool signature: " + p.name);
        r.push_back(L"Terminate immediately and investigate its origin.");
    }

    if (IsInSuspDir(p.path)) {
        score += 2;
        f.push_back(L"[MEDIUM] Executable running from a high-risk directory: " + p.path);
        r.push_back(L"Legitimate software rarely runs from Temp or Downloads.");
    }

    if (!p.isSignedByMS && p.path.find(L"\\Windows\\") == std::wstring::npos) {
        score += 1;
        f.push_back(L"[LOW] Binary is not in a Microsoft-signed system directory.");
    }

    if (p.threadCount == 0) {
        score += 2;
        f.push_back(L"[MEDIUM] Process has zero threads - possible process hollowing or zombie state.");
    }
    else if (p.threadCount > 200) {
        score += 1;
        f.push_back(L"[LOW] Unusually high thread count (" + std::to_wstring(p.threadCount) + L"). Could indicate thread injection.");
    }

    if (p.memUsage > 512ULL * 1024 * 1024) {
        score += 1;
        f.push_back(L"[LOW] Large memory footprint (" + FormatBytes(p.memUsage) + L"). Potential data staging or unpacking.");
    }

    if (p.pid > 4 && p.pid < 20) {
        score += 3;
        f.push_back(L"[HIGH] Suspicious PID value (" + std::to_wstring(p.pid) + L"). Low PIDs are reserved for system processes.");
    }

    if (p.path.find(L"\\System32\\") != std::wstring::npos ||
        p.path.find(L"\\system32\\") != std::wstring::npos) {
        f.push_back(L"[INFO] Process originates from System32 - lower base risk, but system processes can be hollowed.");
        
    }

    if (p.path == L"[Access Denied]") {
        score += 2;
        f.push_back(L"[MEDIUM] Cannot read process image path - possible protected/rootkit process.");
        r.push_back(L"Run ThreatWatch as Administrator to get full path visibility.");
    }

    std::wstring lower = p.name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    static const std::vector<std::pair<std::wstring, std::wstring>> sysNames = {
        {L"svch0st.exe", L"svchost.exe"}, {L"lsass.exe", L"lsass"},
        {L"exp1orer.exe", L"explorer.exe"}, {L"svchost32.exe", L"svchost"}
    };
    for (auto& [fake, real] : sysNames) {
        if (lower == fake) {
            score += 5;
            f.push_back(L"[CRITICAL] Process name '" + p.name + L"' is spoofing system process '" + WideFromA(NarrowFromW(real)) + L"'. Classic masquerading technique.");
            r.push_back(L"This is almost certainly malicious. Dump memory and terminate.");
            break;
        }
    }

    if (f.empty()) {
        f.push_back(L"[OK] No suspicious indicators found in process name, path, or structure.");
        f.push_back(L"[OK] Thread count and memory usage are within normal bounds.");
    }

    if (r.empty()) {
        r.push_back(L"No immediate action required. Monitor for unusual network connections.");
    }

    score = std::min(score, 10);
    score = std::max(score, 1);
    res.score = score;
}

static void AnalyzeNetwork(const NetEntry& n, AnalysisResult& res) {
    int score = 1;
    std::vector<std::wstring>& f = res.findings;
    std::vector<std::wstring>& r = res.recommendations;

    if (IsPrivateIP(n.remoteAddr) || n.remoteAddr == L"0.0.0.0" || n.remoteAddr == L"*") {
        score = 1;
        f.push_back(L"[OK] Connection is local or unbound - no external network exposure.");
        res.score = 1; return;
    }

    f.push_back(L"[INFO] Remote endpoint: " + n.remoteAddr + L":" + std::to_wstring(n.remotePort));

    if (IsSuspiciousPort(n.remotePort)) {
        score += 4;
        f.push_back(L"[HIGH] Remote port " + std::to_wstring(n.remotePort) + L" is a well-known C2/shell port (e.g. 4444=Metasploit, 1337=Leet, 31337=Elite).");
        r.push_back(L"Block this connection immediately and investigate the originating process.");
    }

    if (IsSuspiciousPort(n.localPort)) {
        score += 2;
        f.push_back(L"[MEDIUM] Local port " + std::to_wstring(n.localPort) + L" matches a suspicious bind - potential reverse shell listener.");
    }

    if (!IsKnownPort(n.remotePort) && n.remotePort > 1024 && !IsSuspiciousPort(n.remotePort)) {
        score += 1;
        f.push_back(L"[LOW] Non-standard remote port " + std::to_wstring(n.remotePort) + L" - could be custom C2 or legitimate application.");
    }

    if (n.procName == L"cmd.exe" || n.procName == L"powershell.exe" || n.procName == L"wscript.exe" || n.procName == L"cscript.exe") {
        score += 3;
        f.push_back(L"[HIGH] Network connection originated from interpreter process '" + n.procName + L"'. Shells should not initiate external connections directly.");
        r.push_back(L"Likely command-and-control or data exfiltration via scripting engine.");
    }

    if (n.procName == L"[Unknown]") {
        score += 2;
        f.push_back(L"[MEDIUM] Cannot identify owning process. The connection may belong to a kernel-level component or a process that has terminated.");
    }

    if (n.state == L"ESTABLISHED") {
        f.push_back(L"[INFO] Connection is fully ESTABLISHED - data is actively being transferred.");
        score += 1;
    }

    if (n.remoteDomain != n.remoteAddr) {
        f.push_back(L"[INFO] Reverse DNS resolves to: " + n.remoteDomain);
        std::wstring domLow = n.remoteDomain;
        std::transform(domLow.begin(), domLow.end(), domLow.begin(), ::towlower);
        if (domLow.find(L".ru") != std::wstring::npos ||
            domLow.find(L".cn") != std::wstring::npos ||
            domLow.find(L".top") != std::wstring::npos ||
            domLow.find(L".xyz") != std::wstring::npos) {
            score += 2;
            f.push_back(L"[MEDIUM] Domain uses a TLD commonly associated with malicious infrastructure.");
        }
        std::wstring hostname = domLow.substr(0, domLow.find(L'.'));
        if (hostname.length() > 16) {
            bool hasMix = false;
            int consCount = 0, maxCons = 0;
            for (auto c : hostname) {
                if (!iswdigit(c)) consCount++; else { maxCons = std::max(maxCons, consCount); consCount = 0; }
            }
            if (hostname.length() > 20 || maxCons > 5) {
                score += 2;
                f.push_back(L"[MEDIUM] Hostname pattern '" + hostname + L"' may be DGA-generated (Domain Generation Algorithm).");
                r.push_back(L"DGA domains are used by malware families to evade static blocklists.");
            }
        }
    }

    if (f.size() == 1) {
        f.push_back(L"[OK] No clear indicators of compromise on this connection.");
        r.push_back(L"Monitor for data volume anomalies or unusual timing patterns.");
    }

    score = std::min(score, 10); score = std::max(score, 1);
    res.score = score;
}

static void AnalyzeHardware(const HardwareEntry& h, AnalysisResult& res) {
    int score = 1;
    std::vector<std::wstring>& f = res.findings;
    std::vector<std::wstring>& r = res.recommendations;

    f.push_back(L"[INFO] Device class: " + (h.deviceClass.empty() ? L"[Unknown]" : h.deviceClass));
    f.push_back(L"[INFO] Manufacturer: " + (h.manufacturer.empty() ? L"[Unknown]" : h.manufacturer));
    f.push_back(L"[INFO] Device ID: " + h.deviceID.substr(0, std::min((int)h.deviceID.size(), 60)));

    if (h.manufacturer.empty() || h.manufacturer == L"[Unknown]") {
        score += 2;
        f.push_back(L"[MEDIUM] Device has no manufacturer string. Legitimate hardware typically identifies itself.");
        r.push_back(L"Investigate this device physically and check Device Manager for driver details.");
    }
    else {
        bool trustedMfg = false;
        for (auto& t : TRUSTED_PUBLISHERS) {
            if (h.manufacturer.find(t) != std::wstring::npos) { trustedMfg = true; break; }
        }
        if (!trustedMfg) {
            score += 1;
            f.push_back(L"[LOW] Manufacturer '" + h.manufacturer + L"' is not in the known-trusted vendor list.");
        }
        else {
            f.push_back(L"[OK] Manufacturer '" + h.manufacturer + L"' is a recognised hardware vendor.");
        }
    }

    std::wstring classLow = h.deviceClass;
    std::transform(classLow.begin(), classLow.end(), classLow.begin(), ::towlower);

    if (classLow.find(L"keyb") != std::wstring::npos || classLow.find(L"hid") != std::wstring::npos) {
        f.push_back(L"[INFO] Input device detected. HID devices like BadUSB or Rubber Ducky emulate keyboards.");
        if (h.manufacturer.empty()) {
            score += 3;
            f.push_back(L"[HIGH] Input device with no manufacturer - potential USB attack device (BadUSB, O.MG Cable, Rubber Ducky).");
            r.push_back(L"Unplug this device immediately if you did not plug it in intentionally.");
        }
    }

    if (classLow.find(L"net") != std::wstring::npos || classLow.find(L"network") != std::wstring::npos) {
        f.push_back(L"[INFO] Network adapter detected. Rogue network adapters can intercept traffic or create hidden tunnels.");
    }

    if (classLow.find(L"usb") != std::wstring::npos) {
        f.push_back(L"[INFO] USB device present. USB devices are a common attack vector.");
        if (h.manufacturer.empty()) {
            score += 1;
            f.push_back(L"[LOW] USB device with no manufacturer info.");
        }
    }

    if (h.deviceID.find(L"VID_") != std::wstring::npos) {
        if (h.deviceID.find(L"VID_03EB") != std::wstring::npos) { 
            score += 2;
            f.push_back(L"[MEDIUM] Vendor ID 03EB (Atmel) detected - microcontroller often used in HID attack devices.");
        }
        if (h.deviceID.find(L"VID_2341") != std::wstring::npos) { 
            score += 1;
            f.push_back(L"[LOW] Arduino-compatible USB device detected. Could be legitimate dev hardware or a crafted attack device.");
        }
    }

    if (h.driver.empty()) {
        score += 1;
        f.push_back(L"[LOW] Device has no associated driver entry - may be unrecognised or using a generic interface.");
    }

    score = std::min(score, 10); score = std::max(score, 1);
    res.score = score;
}

static void RunAnalysis(int tab, int idx) {
    AnalysisResult res;
    res.complete = false;
    res.running = true;

    std::lock_guard<std::mutex> lk(g_analysisMutex);

    {
        std::lock_guard<std::mutex> dk(g_dataMutex);
        if (tab == 0) {
            if (idx < 0 || idx >= (int)g_procs.size()) return;
            res.target = g_procs[idx].name + L" (PID " + std::to_wstring(g_procs[idx].pid) + L")";
            res.targetType = L"Process";
            AnalyzeProcess(g_procs[idx], res);
        }
        else if (tab == 1) {
            if (idx < 0 || idx >= (int)g_nets.size()) return;
            res.target = g_nets[idx].remoteAddr + L":" + std::to_wstring(g_nets[idx].remotePort);
            res.targetType = L"Network";
            AnalyzeNetwork(g_nets[idx], res);
        }
        else {
            if (idx < 0 || idx >= (int)g_hw.size()) return;
            res.target = g_hw[idx].deviceName;
            res.targetType = L"Hardware";
            AnalyzeHardware(g_hw[idx], res);
        }
    }

    res.complete = true;
    res.running = false;
    g_analysis = std::move(res);
    if (g_hwnd) PostMessageW(g_hwnd, WM_USER + 2, 0, 0);
}


static HFONT g_fontMain = nullptr;
static HFONT g_fontMono = nullptr;
static HFONT g_fontBold = nullptr;
static HFONT g_fontSmall = nullptr;
static HBRUSH g_brBg = nullptr;
static HBRUSH g_brPanel = nullptr;
static HBRUSH g_brPanel2 = nullptr;
static HBRUSH g_brPurple = nullptr;
static HPEN   g_penBorder = nullptr;
static HPEN   g_penBorder2 = nullptr;
static HPEN   g_penPurple = nullptr;

static void InitGDI() {
    g_fontMain = CreateFontW(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    g_fontMono = CreateFontW(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    g_fontBold = CreateFontW(-14, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    g_fontSmall = CreateFontW(-12, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    g_brBg = CreateSolidBrush(COL_BG);
    g_brPanel = CreateSolidBrush(COL_PANEL);
    g_brPanel2 = CreateSolidBrush(COL_PANEL2);
    g_brPurple = CreateSolidBrush(COL_PURPLE_DIM);
    g_penBorder = CreatePen(PS_SOLID, 1, COL_BORDER);
    g_penBorder2 = CreatePen(PS_SOLID, 1, COL_BORDER2);
    g_penPurple = CreatePen(PS_SOLID, 1, COL_PURPLE);
}


#define ID_TAB_PROC    1001
#define ID_TAB_NET     1002
#define ID_TAB_HW      1003
#define ID_BTN_ANALYZE 1010
#define ID_BTN_REFRESH 1011
#define ID_LIST_PROC   2001
#define ID_LIST_NET    2002
#define ID_LIST_HW     2003
#define ID_ANALYSIS_WND 3001
#define IDT_AUTOREFRESH 4001

static LRESULT CALLBACK ListSubclassProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
    UINT_PTR uid, DWORD_PTR data);

static void StyleListView(HWND lv) {
    ListView_SetBkColor(lv, COL_PANEL);
    ListView_SetTextBkColor(lv, COL_PANEL);
    ListView_SetTextColor(lv, COL_TEXT);
    DWORD exStyle = LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER;
    ListView_SetExtendedListViewStyle(lv, exStyle);
}

static void PopulateProcessList() {
    if (!g_listProc) return;
    std::lock_guard<std::mutex> lk(g_dataMutex);
    SendMessageW(g_listProc, WM_SETREDRAW, FALSE, 0);
    int sel = ListView_GetNextItem(g_listProc, -1, LVNI_SELECTED);
    ListView_DeleteAllItems(g_listProc);
    int i = 0;
    for (auto& p : g_procs) {
        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT | LVIF_PARAM;
        lvi.iItem = i;
        lvi.lParam = (LPARAM)p.pid;
        lvi.pszText = (LPWSTR)p.name.c_str();
        ListView_InsertItem(g_listProc, &lvi);

        auto pidStr = std::to_wstring(p.pid);
        auto memStr = FormatBytes(p.memUsage);
        auto thrStr = std::to_wstring(p.threadCount);
        auto pathStr = p.path;
        ListView_SetItemText(g_listProc, i, 1, (LPWSTR)pidStr.c_str());
        ListView_SetItemText(g_listProc, i, 2, (LPWSTR)memStr.c_str());
        ListView_SetItemText(g_listProc, i, 3, (LPWSTR)thrStr.c_str());
        ListView_SetItemText(g_listProc, i, 4, (LPWSTR)p.user.c_str());
        ListView_SetItemText(g_listProc, i, 5, (LPWSTR)pathStr.c_str());
        i++;
    }
    if (sel >= 0 && sel < ListView_GetItemCount(g_listProc))
        ListView_SetItemState(g_listProc, sel, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    SendMessageW(g_listProc, WM_SETREDRAW, TRUE, 0);
    RedrawWindow(g_listProc, nullptr, nullptr, RDW_INVALIDATE | RDW_UPDATENOW);
}

static void PopulateNetList() {
    if (!g_listNet) return;
    std::lock_guard<std::mutex> lk(g_dataMutex);
    SendMessageW(g_listNet, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_listNet);
    int i = 0;
    for (auto& n : g_nets) {
        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = i;
        lvi.pszText = (LPWSTR)n.procName.c_str();
        ListView_InsertItem(g_listNet, &lvi);

        auto pidStr = std::to_wstring(n.pid);
        auto localStr = n.localAddr + L":" + std::to_wstring(n.localPort);
        auto remStr = n.remoteAddr + L":" + std::to_wstring(n.remotePort);
        ListView_SetItemText(g_listNet, i, 1, (LPWSTR)pidStr.c_str());
        ListView_SetItemText(g_listNet, i, 2, (LPWSTR)localStr.c_str());
        ListView_SetItemText(g_listNet, i, 3, (LPWSTR)remStr.c_str());
        ListView_SetItemText(g_listNet, i, 4, (LPWSTR)n.state.c_str());
        i++;
    }
    SendMessageW(g_listNet, WM_SETREDRAW, TRUE, 0);
    RedrawWindow(g_listNet, nullptr, nullptr, RDW_INVALIDATE | RDW_UPDATENOW);
}

static void PopulateHWList() {
    if (!g_listHW) return;
    std::lock_guard<std::mutex> lk(g_dataMutex);
    SendMessageW(g_listHW, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_listHW);
    int i = 0;
    for (auto& h : g_hw) {
        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = i;
        lvi.pszText = (LPWSTR)h.deviceName.c_str();
        ListView_InsertItem(g_listHW, &lvi);
        ListView_SetItemText(g_listHW, i, 1, (LPWSTR)h.deviceClass.c_str());
        ListView_SetItemText(g_listHW, i, 2, (LPWSTR)h.manufacturer.c_str());
        ListView_SetItemText(g_listHW, i, 3, (LPWSTR)h.driver.c_str());
        i++;
    }
    SendMessageW(g_listHW, WM_SETREDRAW, TRUE, 0);
    RedrawWindow(g_listHW, nullptr, nullptr, RDW_INVALIDATE | RDW_UPDATENOW);
}

static void UpdateAnalysisPanel() {
    std::lock_guard<std::mutex> lk(g_analysisMutex);
    if (!g_analysis.complete) return;

    std::wostringstream ss;
    ss << L"TARGET: " << g_analysis.target << L"\r\n";
    ss << L"TYPE:   " << g_analysis.targetType << L"\r\n";
    ss << L"─────────────────────────────────────────────────────────\r\n";

    int sc = g_analysis.score;
    std::wstring scoreBar;
    for (int i = 0; i < 10; i++) scoreBar += (i < sc) ? L"█" : L"░";

    ss << L"THREAT SCORE:  " << sc << L"/10  [" << scoreBar << L"]\r\n";
    std::wstring verdict;
    if (sc <= 2) verdict = L"CLEAN - No significant threats detected.";
    else if (sc <= 4) verdict = L"LOW RISK - Minor suspicious traits. Monitor.";
    else if (sc <= 6) verdict = L"MODERATE RISK - Investigate further.";
    else if (sc <= 8) verdict = L"HIGH RISK - Strong indicators of compromise.";
    else              verdict = L"CRITICAL - Likely malicious. Act immediately.";
    ss << L"VERDICT:       " << verdict << L"\r\n";
    ss << L"─────────────────────────────────────────────────────────\r\n\r\n";

    ss << L"FINDINGS:\r\n";
    for (auto& f : g_analysis.findings)
        ss << L"  " << f << L"\r\n";

    if (!g_analysis.recommendations.empty()) {
        ss << L"\r\nRECOMMENDATIONS:\r\n";
        for (auto& rec : g_analysis.recommendations)
            ss << L"  >> " << rec << L"\r\n";
    }

    SetWindowTextW(g_lblAnalysis, ss.str().c_str());
}


static HWND g_analysisWnd = nullptr;

static COLORREF ScoreColour(int s) {
    if (s <= 2) return COL_GREEN;
    if (s <= 5) return COL_AMBER;
    if (s <= 7) return RGB(220, 120, 50);
    return COL_RED;
}

static LRESULT CALLBACK AnalysisWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        HWND edit = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            0, 0, 1, 1, hwnd, (HMENU)1, g_hInst, nullptr);
        SendMessageW(edit, WM_SETFONT, (WPARAM)g_fontMono, TRUE);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)edit);
        return 0;
    }
    case WM_SIZE: {
        HWND edit = (HWND)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        if (edit) MoveWindow(edit, 8, 8, LOWORD(lp) - 16, HIWORD(lp) - 16, TRUE);
        return 0;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wp;
        SetTextColor(hdc, COL_TEXT);
        SetBkColor(hdc, COL_PANEL2);
        return (LRESULT)g_brPanel2;
    }
    case WM_USER + 2: {
        HWND edit = (HWND)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        std::lock_guard<std::mutex> lk(g_analysisMutex);
        if (!g_analysis.complete) break;

        std::wostringstream ss;
        ss << L"TARGET:  " << g_analysis.target << L"\r\n";
        ss << L"TYPE:    " << g_analysis.targetType << L"\r\n";
        ss << L"─────────────────────────────────────────────────────────────────\r\n";

        int sc = g_analysis.score;
        std::wstring scoreBar;
        for (int i = 0; i < 10; i++) scoreBar += (i < sc) ? L"■" : L"□";
        ss << L"THREAT:  [" << scoreBar << L"]  " << sc << L"/10\r\n";

        std::wstring verdict;
        if (sc <= 2) verdict = L"CLEAN";
        else if (sc <= 4) verdict = L"LOW RISK";
        else if (sc <= 6) verdict = L"MODERATE RISK";
        else if (sc <= 8) verdict = L"HIGH RISK";
        else              verdict = L"CRITICAL";
        ss << L"VERDICT: " << verdict << L"\r\n";
        ss << L"─────────────────────────────────────────────────────────────────\r\n\r\n";
        ss << L"FINDINGS\r\n";
        ss << L"────────\r\n";
        for (auto& f : g_analysis.findings)  ss << L"  " << f << L"\r\n";
        if (!g_analysis.recommendations.empty()) {
            ss << L"\r\nRECOMMENDATIONS\r\n";
            ss << L"───────────────\r\n";
            for (auto& r : g_analysis.recommendations) ss << L"  >> " << r << L"\r\n";
        }
        if (edit) SetWindowTextW(edit, ss.str().c_str());
        break;
    }
    case WM_ERASEBKGND: {
        HDC hdc = (HDC)wp;
        RECT rc; GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_brPanel2);
        return 1;
    }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}


static void CreateControls(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    int W = rc.right, H = rc.bottom;

    int tabY = 36, tabH = 28;
    CreateWindowExW(0, L"BUTTON", L"[ Processes ]",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        8, tabY, 130, tabH, hwnd, (HMENU)ID_TAB_PROC, g_hInst, nullptr);
    CreateWindowExW(0, L"BUTTON", L"[ Network ]",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        142, tabY, 130, tabH, hwnd, (HMENU)ID_TAB_NET, g_hInst, nullptr);
    CreateWindowExW(0, L"BUTTON", L"[ Hardware ]",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        276, tabY, 130, tabH, hwnd, (HMENU)ID_TAB_HW, g_hInst, nullptr);

    CreateWindowExW(0, L"BUTTON", L"[ Refresh ]",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        W - 120, tabY, 112, tabH, hwnd, (HMENU)ID_BTN_REFRESH, g_hInst, nullptr);

    int listTop = tabY + tabH + 4;
    int analyzeH = 36;
    int analyzeTop = H - analyzeH - 28;
    int listH = analyzeTop - listTop - 4;
    int splitX = (W * 55) / 100;

    g_listProc = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        8, listTop, splitX - 12, listH, hwnd, (HMENU)ID_LIST_PROC, g_hInst, nullptr);
    StyleListView(g_listProc);
    {
        struct { LPCWSTR n; int w; } cols[] = {
            {L"Name",    160}, {L"PID", 60}, {L"Memory", 90},
            {L"Threads", 60},  {L"User", 140}, {L"Path", 400}
        };
        for (int i = 0; i < 6; i++) {
            LVCOLUMNW lvc = {}; lvc.mask = LVCF_TEXT | LVCF_WIDTH;
            lvc.pszText = (LPWSTR)cols[i].n; lvc.cx = cols[i].w;
            ListView_InsertColumn(g_listProc, i, &lvc);
        }
    }

    g_listNet = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        8, listTop, splitX - 12, listH, hwnd, (HMENU)ID_LIST_NET, g_hInst, nullptr);
    StyleListView(g_listNet);
    {
        struct { LPCWSTR n; int w; } cols[] = {
            {L"Process", 140}, {L"PID", 55}, {L"Local", 170}, {L"Remote", 200}, {L"State", 100}
        };
        for (int i = 0; i < 5; i++) {
            LVCOLUMNW lvc = {}; lvc.mask = LVCF_TEXT | LVCF_WIDTH;
            lvc.pszText = (LPWSTR)cols[i].n; lvc.cx = cols[i].w;
            ListView_InsertColumn(g_listNet, i, &lvc);
        }
    }

    g_listHW = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        8, listTop, splitX - 12, listH, hwnd, (HMENU)ID_LIST_HW, g_hInst, nullptr);
    StyleListView(g_listHW);
    {
        struct { LPCWSTR n; int w; } cols[] = {
            {L"Device Name", 240}, {L"Class", 110}, {L"Manufacturer", 160}, {L"Driver", 180}
        };
        for (int i = 0; i < 4; i++) {
            LVCOLUMNW lvc = {}; lvc.mask = LVCF_TEXT | LVCF_WIDTH;
            lvc.pszText = (LPWSTR)cols[i].n; lvc.cx = cols[i].w;
            ListView_InsertColumn(g_listHW, i, &lvc);
        }
    }

    static const wchar_t* ANA_CLASS = L"ThreatAnalysisPanel";
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = AnalysisWndProc;
    wc.hInstance = g_hInst;
    wc.lpszClassName = ANA_CLASS;
    wc.hbrBackground = g_brPanel2;
    RegisterClassExW(&wc);

    g_analysisWnd = CreateWindowExW(WS_EX_CLIENTEDGE, ANA_CLASS, L"",
        WS_CHILD | WS_VISIBLE,
        splitX, listTop, W - splitX - 8, listH,
        hwnd, (HMENU)ID_ANALYSIS_WND, g_hInst, nullptr);

    g_btnAnalyze = CreateWindowExW(0, L"BUTTON", L"[ Analyze Selected ]",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        8, analyzeTop, 220, analyzeH, hwnd, (HMENU)ID_BTN_ANALYZE, g_hInst, nullptr);

    g_statusBar = CreateWindowExW(0, STATUSCLASSNAMEW, L"Ready.",
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0, hwnd, nullptr, g_hInst, nullptr);

    auto setFont = [&](HWND h) { SendMessageW(h, WM_SETFONT, (WPARAM)g_fontMain, TRUE); };
    EnumChildWindows(hwnd, [](HWND ch, LPARAM) -> BOOL {
        SendMessageW(ch, WM_SETFONT, (WPARAM)g_fontMain, TRUE);
        return TRUE;
        }, 0);
}

static void SwitchTab(int tab) {
    g_tab = tab;
    ShowWindow(g_listProc, tab == 0 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_listNet, tab == 1 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_listHW, tab == 2 ? SW_SHOW : SW_HIDE);
    InvalidateRect(g_hwnd, nullptr, FALSE);
}

static void PaintButton(HWND hwnd, HDC hdc, RECT& rc, bool pressed, bool active) {
    HBRUSH br = active ? g_brPurple : g_brPanel;
    FillRect(hdc, &rc, br);
    HPEN pen = active ? g_penPurple : g_penBorder;
    HPEN old = (HPEN)SelectObject(hdc, pen);
    Rectangle(hdc, rc.left, rc.top, rc.right, rc.bottom);
    SelectObject(hdc, old);

    wchar_t txt[128] = {};
    GetWindowTextW(hwnd, txt, 128);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, active ? COL_PURPLE_LT : COL_TEXT);
    SelectObject(hdc, g_fontMain);
    DrawTextW(hdc, txt, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}


static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE:
        InitGDI();
        InitCommonControls();
        WSAData wsaData; WSAStartup(MAKEWORD(2, 2), &wsaData);
        CreateControls(hwnd);
        SwitchTab(0);
        SetTimer(hwnd, IDT_AUTOREFRESH, 8000, nullptr);
        std::thread([] { RefreshAll(); }).detach();
        return 0;

    case WM_SIZE: {
        if (wp == SIZE_MINIMIZED) return 0;
        int W = LOWORD(lp), H = HIWORD(lp);
        int tabY = 36, tabH = 28;
        int listTop = tabY + tabH + 4;
        int analyzeH = 36;
        int analyzeTop = H - analyzeH - 28;
        int listH = analyzeTop - listTop - 4;
        int splitX = (W * 55) / 100;

        MoveWindow(g_listProc, 8, listTop, splitX - 12, listH, TRUE);
        MoveWindow(g_listNet, 8, listTop, splitX - 12, listH, TRUE);
        MoveWindow(g_listHW, 8, listTop, splitX - 12, listH, TRUE);
        MoveWindow(g_analysisWnd, splitX, listTop, W - splitX - 8, listH, TRUE);
        MoveWindow(g_btnAnalyze, 8, analyzeTop, 220, analyzeH, TRUE);
        SendMessageW(g_statusBar, WM_SIZE, 0, 0);

        HWND hRef = GetDlgItem(hwnd, ID_BTN_REFRESH);
        if (hRef) MoveWindow(hRef, W - 120, tabY, 112, tabH, TRUE);
        return 0;
    }

    case WM_ERASEBKGND: {
        HDC hdc = (HDC)wp;
        RECT rc; GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_brBg);
        return 1;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc; GetClientRect(hwnd, &rc);

        RECT hdr = { 0, 0, rc.right, 34 };
        FillRect(hdc, &hdr, (HBRUSH)GetStockObject(BLACK_BRUSH));
        HPEN oldPen = (HPEN)SelectObject(hdc, g_penPurple);
        MoveToEx(hdc, 0, 34, nullptr);
        LineTo(hdc, rc.right, 34);
        SelectObject(hdc, oldPen);

        SetBkMode(hdc, TRANSPARENT);
        SelectObject(hdc, g_fontBold);
        SetTextColor(hdc, COL_PURPLE_LT);
        RECT titleRc = { 10, 6, 300, 32 };
        DrawTextW(hdc, L"ThreatWatch", -1, &titleRc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        SetTextColor(hdc, COL_TEXT_DIM);
        SelectObject(hdc, g_fontSmall);
        RECT subtitleRc = { 145, 10, 500, 30 };
        DrawTextW(hdc, L"by gigachad - v1.0", -1, &subtitleRc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        int tabY = 36, tabH = 28;
        RECT sepRc = { 0, tabY + tabH + 2, rc.right, tabY + tabH + 3 };
        FillRect(hdc, &sepRc, g_brPurple);

        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_CTLCOLORBTN: {
        HDC hdc = (HDC)wp;
        HWND ctrl = (HWND)lp;
        int id = GetDlgCtrlID(ctrl);
        SetBkMode(hdc, TRANSPARENT);
        bool active = (id == ID_TAB_PROC && g_tab == 0) ||
            (id == ID_TAB_NET && g_tab == 1) ||
            (id == ID_TAB_HW && g_tab == 2);
        SetTextColor(hdc, active ? COL_PURPLE_LT : COL_TEXT);
        return (LRESULT)(active ? g_brPurple : g_brPanel);
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wp;
        SetTextColor(hdc, COL_TEXT_DIM);
        SetBkColor(hdc, COL_BG);
        return (LRESULT)g_brBg;
    }

    case WM_DRAWITEM: {
        return 0;
    }

    case WM_NOTIFY: {
        NMHDR* nm = (NMHDR*)lp;
        if (nm->code == NM_CUSTOMDRAW) {
            NMLVCUSTOMDRAW* cd = (NMLVCUSTOMDRAW*)lp;
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT)
                return CDRF_NOTIFYITEMDRAW;
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                bool selected = (cd->nmcd.uItemState & CDIS_SELECTED) != 0;
                cd->clrTextBk = selected ? COL_PURPLE_DIM : COL_PANEL;
                cd->clrText = selected ? COL_TEXT_BRIGHT : COL_TEXT;

                if (nm->idFrom == ID_LIST_PROC) {
                    std::lock_guard<std::mutex> lk(g_dataMutex);
                    int idx = (int)cd->nmcd.dwItemSpec;
                    if (idx < (int)g_procs.size() && g_procs[idx].hasSuspiciousImports && !selected)
                        cd->clrTextBk = RGB(40, 15, 15);
                }
                if (nm->idFrom == ID_LIST_NET) {
                    std::lock_guard<std::mutex> lk(g_dataMutex);
                    int idx = (int)cd->nmcd.dwItemSpec;
                    if (idx < (int)g_nets.size()) {
                        auto& n = g_nets[idx];
                        if (!IsPrivateIP(n.remoteAddr) && n.state == L"ESTABLISHED" && !selected)
                            cd->clrTextBk = RGB(25, 20, 10);
                    }
                }
                return CDRF_NEWFONT;
            }
        }
        if (nm->code == LVN_ITEMCHANGED) {
            NMLISTVIEW* nmlv = (NMLISTVIEW*)lp;
            if ((nmlv->uChanged & LVIF_STATE) && (nmlv->uNewState & LVIS_SELECTED)) {
                if (nm->idFrom == ID_LIST_PROC) g_selectedProc = nmlv->iItem;
                if (nm->idFrom == ID_LIST_NET)  g_selectedNet = nmlv->iItem;
                if (nm->idFrom == ID_LIST_HW)   g_selectedHW = nmlv->iItem;
            }
        }
        return 0;
    }

    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == ID_TAB_PROC) { SwitchTab(0); InvalidateRect(hwnd, nullptr, FALSE); }
        if (id == ID_TAB_NET) { SwitchTab(1); InvalidateRect(hwnd, nullptr, FALSE); }
        if (id == ID_TAB_HW) { SwitchTab(2); InvalidateRect(hwnd, nullptr, FALSE); }

        if (id == ID_BTN_REFRESH) {
            if (!g_refreshing) {
                SetWindowTextW(g_statusBar, L"Refreshing...");
                std::thread([] { RefreshAll(); }).detach();
            }
        }

        if (id == ID_BTN_ANALYZE) {
            int sel = -1;
            if (g_tab == 0) sel = g_selectedProc;
            if (g_tab == 1) sel = g_selectedNet;
            if (g_tab == 2) sel = g_selectedHW;

            if (sel < 0) {
                MessageBoxW(hwnd, L"Please select an item from the list first.", L"ThreatWatch", MB_ICONINFORMATION);
                return 0;
            }
            if (!g_analyzing) {
                g_analyzing = true;
                SetWindowTextW(g_statusBar, L"Analyzing...");
                int tab = g_tab;
                std::thread([tab, sel] {
                    RunAnalysis(tab, sel);
                    g_analyzing = false;
                    }).detach();
            }
        }
        return 0;
    }

    case WM_TIMER:
        if (wp == IDT_AUTOREFRESH && !g_refreshing)
            std::thread([] { RefreshAll(); }).detach();
        return 0;

    case WM_USER + 1:
        PopulateProcessList();
        PopulateNetList();
        PopulateHWList();
        {
            std::lock_guard<std::mutex> lk(g_dataMutex);
            wchar_t status[256];
            swprintf_s(status, L"Last refresh: %zu processes  |  %zu connections  |  %zu devices",
                g_procs.size(), g_nets.size(), g_hw.size());
            SetWindowTextW(g_statusBar, status);
        }
        return 0;

    case WM_USER + 2: 
        PostMessageW(g_analysisWnd, WM_USER + 2, 0, 0);
        SetWindowTextW(g_statusBar, L"Analysis complete.");
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, IDT_AUTOREFRESH);
        WSACleanup();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nShow) {
    g_hInst = hInst;
    SetProcessDPIAware();

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.lpszClassName = L"ThreatWatchMain";
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hIconSm = LoadIconW(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    g_hwnd = CreateWindowExW(WS_EX_APPWINDOW,
        L"ThreatWatchMain",
        L"ThreatWatch",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        1400, 820,
        nullptr, nullptr, hInst, nullptr);

    ShowWindow(g_hwnd, nShow);
    UpdateWindow(g_hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return (int)msg.wParam;
}
