#pragma once

#include <Windows.h>
#include <Ole2.h>
#include <strsafe.h>

#include <cstdlib>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <memory>
#include <vector>

#include <evntrace.h>
#include <tdh.h>
#pragma comment(lib, "tdh.lib")


#define LOGGER_NAME L"Win32kAPIMonitoringSession"
#define MAXIMUM_SESSION_NAME 1024
#define EVENT_TRACE_BUFFER_SIZE 512     // Use 512KB trace buffers

/* 
 * Microsoft-Windows-Win32k ETW Provider GUID
 *  https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-17134/Microsoft-Windows-Win32k.xml
 *  https://github.com/nasbench/EVTX-ETW-Resources/blob/main/ETWProvidersManifests/Windows10/2004/W10_2004_Pro_20200416_19041.208/WEPExplorer/Microsoft-Windows-Win32k.xml
*/
const GUID ETW_WIN32K_GUID = { 0x8c416c79, 0xd49b, 0x4f01, {0xa4, 0x67, 0xe5, 0x6d, 0x3a, 0xa8, 0x23, 0x4c} };

/*
 * Win32k ETW Target Event keyword and IDs
*/
constexpr ULONGLONG ETW_WIN32K_KEYWORD_AUDIT_API_CALLS = 0x400;
enum Win32kEventId : USHORT
{
    ETW_WIN32K_INVALID = 0,
    ETW_WIN32K_REGISTER_RAW_INPUT_DEVICES = 1001,
    ETW_WIN32K_SET_WINDOWS_HOOKEX = 1002,
    ETW_WIN32K_GET_ASYNC_KEY_STATE = 1003,
};

/*
 This XML snippet is a reference from the Microsoft-Windows-Win32k ETW provider manifest for Windows 10 (22H2).
 It shows the data schema for the following three Win32k API events:
 
 - RegisterRawInputDevice (Event ID 1001)
 - SetWindowsHookEx (Event ID 1002)
 - GetAsyncKeyState (Event ID 1003)

 Reference:
 https://github.com/nasbench/EVTX-ETW-Resources/blob/main/ETWProvidersManifests/Windows10/22H2/W10_22H2_Pro_20230321_19045.2728/WEPExplorer/Microsoft-Windows-Win32k.xml

[RegisterRawInputDevice (Event ID 1001)]
  <data name="ReturnValue" inType="win:UInt32" outType="win:HexInt32"/>
  <data name="UsagePage" inType="win:UInt16" outType="xs:unsignedShort"/>
  <data name="Usage" inType="win:UInt16" outType="xs:unsignedShort"/>
  <data name="Flags" inType="win:UInt32" outType="xs:unsignedInt"/>
  <data name="hwndTarget" inType="win:Pointer" outType="win:HexInt64"/>
  <data name="ThreadStartAddress" inType="win:Pointer" outType="win:HexInt64"/>
  <data name="ThreadCreateTime" inType="win:FILETIME" outType="xs:dateTime"/>
  <data name="ThreadId" inType="win:UInt32" outType="xs:unsignedInt"/>
  <data name="cWindows" inType="win:UInt32" outType="xs:unsignedInt"/>
  <data name="cVisWindows" inType="win:UInt32" outType="xs:unsignedInt"/>
  <data name="ThreadInfoFlags" inType="win:UInt64" outType="xs:unsignedLong"/>
  <data name="ProcessId" inType="win:UInt32" outType="xs:unsignedInt"/>
  <data name="ProcessCreateTime" inType="win:FILETIME" outType="xs:dateTime"/>
  <data name="ProcessStartKey" inType="win:UInt64" outType="xs:unsignedLong"/>
  <data name="ThreadStartAddressMappedModuleName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="ThreadStartAddressQueryResult" inType="win:UInt32" outType="win:NTStatus"/>
  <data name="ThreadStartAddressVadAllocationBase" inType="win:Pointer" outType="win:HexInt64"/>
  <data name="ThreadStartAddressVadAllocationProtect" inType="win:UInt32" outType="xs:unsignedInt"/>
  <data name="ThreadStartAddressVadRegionType" inType="win:UInt32" outType="xs:unsignedInt"/>
  <data name="ThreadStartAddressVadRegionSize" inType="win:Pointer" outType="win:HexInt64"/>
  <data name="ThreadStartAddressVadProtect" inType="win:UInt32" outType="xs:unsignedInt"/>

  [SetWindowsHookEx (Event ID 1002)]
  <data name="FilterType" inType="win:UInt32" outType="win:HexInt32"/>
  <data name="pstrLib" inType="win:UnicodeString" outType="xs:string"/>
  <data name="hmod" inType="win:Pointer" outType="win:HexInt64"/>
  <data name="pfnFilterProc" inType="win:Pointer" outType="win:HexInt64"/>
  <data name="ReturnValue" inType="win:UInt32" outType="win:HexInt32"/>

  [GetAsyncKeyState (Event ID 1003)]
  <data name="PID" inType="win:UInt32" outType="xs:unsignedInt"/>
  <data name="MsSinceLastKeyEvent" inType="win:UInt32" outType="xs:unsignedInt"/>
  <data name="BackgroundCallCount" inType="win:UInt32" outType="xs:unsignedInt"/>

  */
