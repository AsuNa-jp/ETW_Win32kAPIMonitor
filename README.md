# ETW_Win32kAPIMonitor
## Introduction

**ETW_Win32kAPIMonitor** is a Windows-based C++ application that leverages Event Tracing for Windows (ETW) to monitor and capture specific Win32k API events in real time. 
The tool focuses on tracking the following Win32k events which are related to keylogging:

* `RegisterRawInputDevices (Event Id: 1001)`
* `SetWindowsHookEx  (Event Id: 1002)`
* `GetAsyncKeyState (Event Id: 1003)`

This tool demonstrates how to set up an ETW trace session, enable the Microsoft-Windows-Win32k provider with event id filtering, and process event records.

## Usage
Run the tool from the command line by specifying the duration (in seconds) for which the ETW session should capture events:

```
ETW_Win32kAPIMonitor.exe <duration_in_seconds>
```

For example, to monitor events for 60 seconds:

```
ETW_Win32kAPIMonitor.exe 60
```

Below is an example of execution.

```
C:\Users\vagrant>ETW_Win32kAPIMonitor.exe 30
[+] Starting an ETW trace..
[+] Collecting events for 30 seconds...
======================================================
======== GetAsyncKeyState API Event Captured =========
======================================================
[Process Id]: 7520
[Thread  Id]: 10524
------------------------------------------------------
PID: 7520
MsSinceLastKeyEvent: 0
BackgroundCallCount: 2
------------------------------------------------------
======================================================
======== SetWindowsHookEx API Event Captured =========
======================================================
[Process Id]: 8420
[Thread  Id]: 21192
------------------------------------------------------
FilterType: 0x3
pstrLib: C:\Windows\system32\UIRibbon.dll
hmod: 0x00007FFB01BE0000
pfnFilterProc: 0x00007FFB01BF3400
ReturnValue: 0x1618016F
------------------------------------------------------
======================================================
======== SetWindowsHookEx API Event Captured =========
======================================================
[Process Id]: 8420
[Thread  Id]: 21192
------------------------------------------------------
FilterType: 0x4
pstrLib: C:\Windows\system32\UIRibbon.dll
hmod: 0x00007FFB01BE0000
pfnFilterProc: 0x00007FFB01BF3620
ReturnValue: 0x54F07C1
------------------------------------------------------
======================================================
====== RegisterRawInputDevie API Event Captured ======
======================================================
[Process Id]: 7520
[Thread  Id]: 10524
------------------------------------------------------
ReturnValue: 0x1
UsagePage: 1
Usage: 6
Flags: 256
hwndTarget: 0x0000000000310826
ThreadStartAddress: 0x00007FF6DA2E1358
ThreadCreateTime: 2025-02-13 07:42:01.128 (UTC)
ThreadId: 10524
cWindows: 2
cVisWindows: 0
ThreadInfoFlags: 16
ProcessId: 7520
ProcessCreateTime: 2025-02-13 07:42:01.128 (UTC)
ProcessStartKey: 63331869759902040
ThreadStartAddressMappedModuleName: \Device\HarddiskVolume3\Users\vagrant\.pyenv\pyenv-win\versions\3.9.0\python3.exe
ThreadStartAddressQueryResult: 0
ThreadStartAddressVadAllocationBase: 0x00007FF6DA2E0000
ThreadStartAddressVadAllocationProtect: 128
ThreadStartAddressVadRegionType: 16777216
ThreadStartAddressVadRegionSize: 0x0000000000002000
ThreadStartAddressVadProtect: 32
------------------------------------------------------
```

## Disclamer
* This tool is provided for educational and testing purposes only.
* This tool has been tested only on Windows 10 version 22H2 (OS Build 19045.5487). It has not been tested on other versions, so it may not work properly on different Windows builds.
* Use at Your Own Risk: Running this tool is entirely at your own risk. I disclaim all responsibility for any consequences, damages, or disruptions resulting from the use of this tool.

## License
This project is licensed under the MIT License. See the LICENSE file for details.