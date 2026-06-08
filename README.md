# ThreatWatch

Advanced threat analysis tool for Windows. Monitors running processes, active network connections, and plugged-in hardware devices in real time — with a built-in analysis engine that scores each item for suspicious behaviour and explains its reasoning.

Built entirely with native Win32 APIs and standard C++17. No dependencies, no frameworks, no runtime installs.

```
single file  |  ~1400 lines  |  zero external dependencies  |  Windows 7+
```

---

## Features

### Process Monitor
- Live snapshot of all running processes via `CreateToolhelp32Snapshot`
- Shows: name, PID, working set memory, thread count, owning user account, full image path
- Suspicious processes are automatically tinted red in the list before you even run an analysis

### Network Monitor
- Reads all TCP and UDP connections with owning PID via `GetExtendedTcpTable` / `GetExtendedUdpTable`
- Shows: owning process, local endpoint, remote endpoint, connection state
- External established connections are highlighted to draw attention

### Hardware Monitor
- Enumerates all present devices via `SetupDiGetClassDevs`
- Shows: friendly name, device class, manufacturer, driver key
- Covers USB, HID, network adapters, storage, and everything else Windows knows about

### Analysis Engine
Select any item in any tab and hit **Analyse Selected**. The engine performs a deep inspection and returns a threat score from 1 to 10, a verdict, a list of findings with severity tags, and actionable recommendations.

**Score guide:**

| Score | Verdict |
|-------|---------|
| 1 – 2 | Clean — no significant threats |
| 3 – 4 | Low risk — monitor |
| 5 – 6 | Moderate risk — investigate |
| 7 – 8 | High risk — strong indicators of compromise |
| 9 – 10 | Critical — likely malicious, act immediately |

---

## What the Analyser Checks

### Processes
- Name matched against known offensive tool signatures (Mimikatz, Meterpreter, PSExec, Cobalt Strike, etc.)
- Image path running from high-risk directories (`\Temp\`, `\Downloads\`, `\Public\`, `\ProgramData\`)
- Zero thread count — indicator of process hollowing or a zombie state
- Abnormally high thread count — potential thread injection
- Very low PID values that shouldn't belong to user processes
- System process name spoofing (`svch0st.exe`, `exp1orer.exe`, `svchost32.exe`, etc.)
- Access-denied path — possible rootkit or kernel-level process hiding

### Network Connections
- Remote port matched against known C2 and reverse-shell ports (4444, 1337, 31337, 5555, 9001, etc.)
- Local port bound to a suspicious value — potential reverse shell listener
- Connection originated from an interpreter process (`cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`)
- Unknown owning process — possible kernel-level or terminated process
- Suspicious TLDs on reverse-DNS result (`.ru`, `.cn`, `.top`, `.xyz`)
- DGA hostname detection — long consonant-heavy hostnames that match domain generation algorithm patterns

### Hardware Devices
- Input/HID device with no manufacturer string — classic BadUSB / Rubber Ducky / O.MG Cable indicator
- Known attacker USB Vendor IDs: Atmel `03EB` (used in many HID attack boards), Arduino `2341`
- Network adapter with missing manufacturer — potential rogue intercept adapter
- Device with no associated driver entry
- Manufacturer checked against a trusted vendor list (Microsoft, Intel, NVIDIA, Realtek, Qualcomm, etc.)

---

## Build

### MinGW / GCC (recommended)

```bash
g++ -o ThreatWatch.exe ThreatWatch.cpp \
    -lgdi32 -lws2_32 -lpsapi -liphlpapi -lsetupapi -lole32 -lcomctl32 \
    -std=c++17 -mwindows
```

### MSVC

```bat
cl ThreatWatch.cpp /std:c++17 ^
    /link gdi32.lib ws2_32.lib psapi.lib iphlpapi.lib setupapi.lib ole32.lib comctl32.lib
```

No CMake, no vcpkg, no NuGet. One file in, one `.exe` out.

---

## Usage

1. **Run as Administrator** — required for full process path and user account visibility. Without elevation some paths will show `[Access Denied]` and some PIDs will be invisible to the tool.
2. The tool auto-refreshes every 8 seconds. Hit **[ Refresh ]** to force an immediate update.
3. Click any row in Processes, Network, or Hardware.
4. Click **[ Analyse Selected ]**.
5. The right-hand panel updates with the full report.

---

## Requirements

| Requirement | Detail |
|-------------|--------|
| OS | Windows 7 or later (x86 or x64) |
| Compiler | GCC 8+ / MSVC 2019+ with C++17 |
| Privileges | Administrator recommended |
| Dependencies | None — Win32 APIs only |

---

## Architecture

Everything lives in `ThreatWatch.cpp`. Sections are clearly delimited with banner comments:

```
Colour palette       — all RGB constants in one place
Helpers              — string conversion, byte formatting, IP utilities
Known indicators     — suspicious names, dirs, ports, VIDs
Data collection      — CollectProcesses / CollectNetwork / CollectHardware
Analysis engine      — AnalyzeProcess / AnalyzeNetwork / AnalyzeHardware
GDI setup            — fonts, brushes, pens
UI layout            — CreateControls, list column definitions
Main window proc     — MainWndProc, tab switching, button handling
Entry point          — wWinMain
```

Data collection and analysis run on background threads. The UI thread receives `WM_USER+1` (refresh done) and `WM_USER+2` (analysis done) messages and updates the lists and panel without blocking.

---

## Limitations

- IPv4 only for network connections (IPv6 table enumeration not currently implemented)
- Reverse DNS lookups are not performed during the scan — the remote address is shown as-is
- CPU usage per process is not tracked (would require two samples with a sleep between them; planned for a future pass)
- No packet capture — this tool reads OS connection tables, not raw traffic
- Analysis is heuristic-based and can produce false positives on developer machines (Atmel boards, Arduino, Netcat for legitimate testing, etc.)

---

## Disclaimer

ThreatWatch is a defensive monitoring tool intended for use on systems you own or have explicit authorisation to inspect. The findings it produces are heuristic indicators, not definitive proof of compromise. Always correlate with other evidence before taking action against a process or device.

---

## Licence

MIT — do whatever you want with it, just don't remove the attribution.
