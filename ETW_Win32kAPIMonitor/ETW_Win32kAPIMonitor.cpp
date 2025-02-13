#include "ETW_Constants.h"

/*
* Parses and prints an ETW event property's value from the user data buffer.
* See ETW_Constants.h for more details of the each event fields (InType/OutType)
* 
* References:
*  https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-event_property_info
*  https://learn.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-_tdh_in_type
*  https://learn.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-_tdh_out_type
*/
void 
PrintEventRecord(
    const PEVENT_RECORD pEventRecord,
    const EVENT_PROPERTY_INFO& propInfo,
    const LPCWSTR propName,
    BYTE* userData,
    const ULONG userDataLen,
    ULONG& offset)
{

    USHORT inType = propInfo.nonStructType.InType;
    USHORT outType = propInfo.nonStructType.OutType;
    ULONG length = propInfo.length;
    
    switch (inType) 
    {
    case TDH_INTYPE_UNICODESTRING:
    {
        // Wide-character string (null-terminated)
        LPCWSTR str = reinterpret_cast<LPCWSTR>(userData + offset);
        size_t maxChars = (userDataLen - offset) / sizeof(WCHAR);

        // Ensure string is null-terminated within the buffer
        size_t actualLen = wcsnlen(str, maxChars);
        if (actualLen == maxChars) {
            std::wcerr << L"Warning: Unterminated Unicode string in " << propName << std::endl;
            actualLen = (maxChars > 0) ? maxChars - 1 : 0;
        }

        std::wcout << propName << L": ";
        std::wcout.write(str, actualLen);
        std::wcout << std::endl;

        // advance offset by the length of the string plus the null terminator
        offset += static_cast<ULONG>((actualLen + 1) * sizeof(WCHAR));
        break;
    }
    case TDH_INTYPE_UINT16:
    {
        USHORT val = *reinterpret_cast<USHORT*>(userData + offset);
        std::wcout << propName << L": " << val << std::endl;
        offset += sizeof(val);
        break;
    }
    case TDH_INTYPE_UINT32:
    {
        ULONG val = *reinterpret_cast<ULONG*>(userData + offset);
        // Check if OutType suggests hex formatting
        if (outType == TDH_OUTTYPE_HEXINT32) {
            std::wcout << propName << L": 0x"
                << std::hex << std::uppercase << val << std::dec << std::nouppercase
                << std::endl;
        }
        else {
            std::wcout << propName << L": " << val << std::endl;
        }
        offset += sizeof(val);
        break;
    }
    case TDH_INTYPE_UINT64:
    {
        ULONGLONG val = *reinterpret_cast<ULONGLONG*>(userData + offset);
        if (outType == TDH_OUTTYPE_HEXINT64) {
            std::wcout << propName << L": 0x"
                << std::hex << std::uppercase << val << std::dec << std::nouppercase
                << std::endl;
        }
        else {
            std::wcout << propName << L": " << val << std::endl;
        }
        offset += sizeof(val);
        break;
    }
    case TDH_INTYPE_POINTER:
    {
        // Pointer-sized value (size depends on architecture of the event source)
        BOOL is32bit = ((pEventRecord->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER)
            == EVENT_HEADER_FLAG_32_BIT_HEADER);
        if (is32bit) {
            DWORD ptrVal = *reinterpret_cast<DWORD*>(userData + offset);
            std::wcout << propName << L": 0x"
                << std::hex << std::uppercase << std::setw(8) << std::setfill(L'0')
                << ptrVal << std::dec << std::nouppercase << std::endl;
            offset += sizeof(DWORD);
        }
        else {
            ULONGLONG ptrVal = *reinterpret_cast<ULONGLONG*>(userData + offset);
            std::wcout << propName << L": 0x"
                << std::hex << std::uppercase << std::setw(16) << std::setfill(L'0')
                << ptrVal << std::dec << std::nouppercase << std::endl;
            offset += sizeof(ULONGLONG);
        }
        break;
    }
    case TDH_INTYPE_FILETIME:
    {
        if (offset + sizeof(FILETIME) <= userDataLen) {
            FILETIME ft = *reinterpret_cast<FILETIME*>(userData + offset);
            offset += static_cast<ULONG>(sizeof(FILETIME));
            // Convert FILETIME to human-readable time
            SYSTEMTIME st;
            if (FileTimeToSystemTime(&ft, &st)) {
                std::wcout << propName << L": "
                    << st.wYear << L"-" << std::setw(2) << std::setfill(L'0') << st.wMonth << L"-"
                    << std::setw(2) << std::setfill(L'0') << st.wDay << L" "
                    << std::setw(2) << std::setfill(L'0') << st.wHour << L":"
                    << std::setw(2) << std::setfill(L'0') << st.wMinute << L":"
                    << std::setw(2) << std::setfill(L'0') << st.wSecond << L"."
                    << std::setw(3) << std::setfill(L'0') << st.wMilliseconds
                    << L" (UTC)" << std::endl;
            }
            else {
                std::wcerr << propName << L": Failed to convert FILETIME to SYSTEMTIME." << std::endl;
            }
        }
        else {
            std::wcerr << propName << L": FILETIME data out of bounds" << std::endl;
        }
        break;
    }
    default:
    {
        std::wcout << propName << L": [Type " << inType << L" not explicitly handled]" << std::endl;
        offset += (length > 0 ? length : 0);
    }
    }
}

/* 
* Displays header information, including event name and process / thread IDs,
* for the given ETW event record.
* Reference:
*  https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
*/
void
ShowHeaderInfo(
    const PEVENT_RECORD& pEventRecord)
{
    const auto& eventPid = pEventRecord->EventHeader.ProcessId;
    const auto& eventTid = pEventRecord->EventHeader.ThreadId;
    const auto& id = (Win32kEventId)pEventRecord->EventHeader.EventDescriptor.Id;

    switch (id)
    {
    case ETW_WIN32K_REGISTER_RAW_INPUT_DEVICES:
        std::wcout << "====================================================== " << std::endl;
        std::wcout << "====== RegisterRawInputDevie API Event Captured ====== " << std::endl;
        std::wcout << "====================================================== " << std::endl;
        break;
    case ETW_WIN32K_SET_WINDOWS_HOOKEX:
        std::wcout << "====================================================== " << std::endl;
        std::wcout << "======== SetWindowsHookEx API Event Captured ========= " << std::endl;
        std::wcout << "====================================================== " << std::endl;
        break;
    case ETW_WIN32K_GET_ASYNC_KEY_STATE:
        std::wcout << "====================================================== " << std::endl;
        std::wcout << "======== GetAsyncKeyState API Event Captured ========= " << std::endl;
        std::wcout << "====================================================== " << std::endl;
        break;
    default:
        std::wcout << "[-] Unknown Event Id: " << id << std::endl;
    }
    std::wcout << "[Process Id]: " << eventPid << std::endl;
    std::wcout << "[Thread  Id]: " << eventTid << std::endl;
}


/* 
* Callback function to process and display Win32k ETW event records.
* References:
*  https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
*  https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhgeteventinformation
*  https://learn.microsoft.com/en-us/windows/win32/etw/retrieving-event-metadata
*  https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/ETW/using-tdhgetproperty-to-consume-event-data.md
*  https://learn.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-decoding_source
*  https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-event_property_info
*/

void CALLBACK
Win32kETWEventCallback(
    _In_ PEVENT_RECORD pEventRecord)
{
    ULONG bufferSize = 0;
    PTRACE_EVENT_INFO pEventInfo = nullptr;

    // Verify that the event is coming from the expected provider.
    // (This should not happen, but check the GUID just in case)
    const auto& eventGuid = pEventRecord->EventHeader.ProviderId;
    if (!IsEqualGUID(eventGuid, ETW_WIN32K_GUID))
    {
        std::wcerr << "[-] This is not a Win32k event... " << std::endl;
        return;
    }

    // Display event header information.
    ShowHeaderInfo(pEventRecord);

    // First call to determine the required buffer size.
    if (ERROR_INSUFFICIENT_BUFFER != 
        TdhGetEventInformation(pEventRecord, 0, NULL, pEventInfo, &bufferSize))
    {
        return;
    }

    // Allocate a buffer to hold the event metadata.
    std::vector<std::byte> buffer(bufferSize);
    pEventInfo = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.data());
    TDHSTATUS status = TdhGetEventInformation(pEventRecord, 0, NULL, pEventInfo, &bufferSize);
    if ((ERROR_SUCCESS != status) || (DecodingSourceXMLFile != pEventInfo->DecodingSource))
    {
        // This should not happen, but check it just in case
        std::wcerr << "[-] This is not an expected event... " << std::endl;
        return;
    }

    // Retrieve the event's user data.
    ULONG offset = 0;  // track position in the userData buffer
    BYTE* userData = (BYTE*)pEventRecord->UserData;
    ULONG userDataLen = pEventRecord->UserDataLength;

    std::wcout << "------------------------------------------------------ " << std::endl;
    for (USHORT index = 0; index < pEventInfo->TopLevelPropertyCount; ++index)
    {
        PEVENT_PROPERTY_INFO pPropertyInfo = &pEventInfo->EventPropertyInfoArray[index];
        LPCWSTR propName = (LPCWSTR)((BYTE*)pEventInfo + pPropertyInfo->NameOffset);
        PrintEventRecord(pEventRecord, *pPropertyInfo, propName, userData, userDataLen, offset);
    }
    std::wcout << "------------------------------------------------------ " << std::endl;

}

/*
* Allocates and initializes an EVENT_TRACE_PROPERTIES structure for an ETW trace session.
* Reference:
* https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
*/

std::unique_ptr<std::byte[]>
InitializeTraceSessionProperties()
{
    // [1] Allocate memory for the trace session properties. 
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (MAXIMUM_SESSION_NAME + MAX_PATH) * sizeof(WCHAR);
    auto buffer = std::make_unique<std::byte[]>(bufferSize);
    PEVENT_TRACE_PROPERTIES pTraceProperties = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buffer.get());
    ZeroMemory(pTraceProperties, bufferSize);

    // [2] Configure the session settings
    //     EVENT_TRACE_PROPERTIES structure contains information about an event tracing session.
    pTraceProperties->Wnode.BufferSize = bufferSize;
    pTraceProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pTraceProperties->BufferSize = EVENT_TRACE_BUFFER_SIZE;
    pTraceProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pTraceProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    StringCchCopyW((LPWSTR)((PCHAR)pTraceProperties + pTraceProperties->LoggerNameOffset),
        sizeof(LOGGER_NAME), LOGGER_NAME);

    return std::move(buffer);
}

/*
* Returns an EVENT_FILTER_DESCRIPTOR pointer configured to filter specific Win32k event IDs.
* Reference:
*   https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor
*/

template <int N>
struct EVENT_FILTER_EVENT_IDS : EVENT_FILTER_EVENT_ID
{
    USHORT EventsBuffer[N - 1];
};

PEVENT_FILTER_DESCRIPTOR
EtwWin32kEventIdFilter()
{
    constexpr auto count = 3;
    static EVENT_FILTER_EVENT_IDS<count> filterEventId{};
    filterEventId.FilterIn = TRUE;
    filterEventId.Count = count;
    filterEventId.Events[0] = ETW_WIN32K_REGISTER_RAW_INPUT_DEVICES;
    filterEventId.Events[1] = ETW_WIN32K_SET_WINDOWS_HOOKEX;
    filterEventId.Events[2] = ETW_WIN32K_GET_ASYNC_KEY_STATE;

    static EVENT_FILTER_DESCRIPTOR filterDesc{};
    filterDesc.Ptr = reinterpret_cast<ULONGLONG>(&filterEventId);
    filterDesc.Size = sizeof(filterEventId);
    filterDesc.Type = EVENT_FILTER_TYPE_EVENT_ID;

    return &filterDesc;
}

/*
* ETW tracing thread function that processes ETW events.
* References:
*  https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracew
*  https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace
*/

static DWORD WINAPI 
EtwTracingThread(
    _In_ LPVOID pContext)
{
    UNREFERENCED_PARAMETER(pContext);

    // [1] Trace data source information which we want to open.
    //     Whenever we get an event, the following user defined callback 
    //     (Win32kETWEventCallback) function is called.
    EVENT_TRACE_LOGFILEW loggerInfo{};
    loggerInfo.LoggerName          = (LPWSTR)LOGGER_NAME;
    loggerInfo.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | 
                                     PROCESS_TRACE_MODE_EVENT_RECORD | 
                                     PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    loggerInfo.EventRecordCallback = (PEVENT_RECORD_CALLBACK)Win32kETWEventCallback;

    // [2] Open the trace session.
    TRACEHANDLE hTrace = OpenTraceW(&loggerInfo);
    if (INVALID_PROCESSTRACE_HANDLE == hTrace)
    {
        std::wcerr << "[-] OpenTrace() failed with " << GetLastError() << std::endl;
        return FALSE;
    }

    // [3] Process trace events. 
    ULONG status = ProcessTrace(&hTrace, 1, 0, 0); 
    if (ERROR_SUCCESS != status)
    {
        std::wcerr << "[-] ProcessTrace() failed with " << status << std::endl;
        (void)CloseTrace(hTrace);
        hTrace = INVALID_PROCESSTRACE_HANDLE;
        return FALSE;
    }
    
    // Once processing is complete, close the trace handle.
    (void)CloseTrace(hTrace);
    hTrace = INVALID_PROCESSTRACE_HANDLE;
    return TRUE;
}

/*
* Stop the ETW trace session
* Reference:
*  https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew
*/
BOOL
StopETWTrace(
    _Inout_ PTRACEHANDLE phSession,
    _In_ PEVENT_TRACE_PROPERTIES pTraceProperties)
{
    if (!phSession || !pTraceProperties)
    {
        std::wcerr << L"[-] StopETWTrace: Invalid parameter(s) provided." << std::endl;
        return FALSE;
    }

    NTSTATUS status = ControlTraceW(*phSession, LOGGER_NAME, pTraceProperties, EVENT_TRACE_CONTROL_STOP);
    if (ERROR_SUCCESS != status)
    {
        std::wcerr << "[-] ControlTraceW() failed with " << status << std::endl;
        return FALSE;
    }
    return TRUE;
}

/*
* Initializes and starts an ETW trace session for monitoring Win32k events.
* References:
*  https://www.geoffchappell.com/studies/windows/win32/advapi32/api/etw/logapi/starttrace.htm
*  https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew
*  https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew
*/

std::unique_ptr<std::byte[]>
StartETWTrace(
    _Inout_ PTRACEHANDLE phSession)
{

    ULONG status;

    // [1] Initialize and start a new ETW session.
    auto pTraceProperties = InitializeTraceSessionProperties();
    PEVENT_TRACE_PROPERTIES pProperties = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(pTraceProperties.get());
    status = StartTraceW(phSession, LOGGER_NAME, pProperties);
    if (ERROR_SUCCESS != status)
    {
        std::wcerr << "[-] Error to start a new session. " << std::endl;
        // If the session already exists, stop the current session and restart it.
        if (ERROR_ALREADY_EXISTS == status) 
        {
            std::wcerr << "[-] Session already exists! Restarting the session..." << std::endl;
            ControlTraceW(0, LOGGER_NAME, pProperties, EVENT_TRACE_CONTROL_STOP);
            if (ERROR_SUCCESS != StartTraceW(phSession, LOGGER_NAME, pProperties))
            {
                std::wcout << "[-] Session restart failed.."<< std::endl;
                return nullptr;
            }
        }
        else
        {
            std::wcout << "[-] StartTraceW() failed with " << status << std::endl;
            return nullptr;
        }
    }

    // [2] Configure and enable the Win32k ETW provider.
    ENABLE_TRACE_PARAMETERS enableParameters{};
    ZeroMemory(&enableParameters, sizeof(enableParameters));
    enableParameters.Version           = ENABLE_TRACE_PARAMETERS_VERSION_2;
    enableParameters.EnableProperty    = 0; 
    enableParameters.ControlFlags      = 0; // Reserved. Set to 0.
    enableParameters.SourceId          = ETW_WIN32K_GUID;
    enableParameters.FilterDescCount   = 1;
    enableParameters.EnableFilterDesc  = EtwWin32kEventIdFilter();

    status = EnableTraceEx2(
        *phSession,                         // [in] TRACEHANDLE TraceHandle,
        &ETW_WIN32K_GUID,                   // [in] LPCGUID     ProviderId,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, // [in] ULONG       ControlCode,
        TRACE_LEVEL_INFORMATION,            // [in] UCHAR       Level,
        ETW_WIN32K_KEYWORD_AUDIT_API_CALLS, // [in] ULONGLONG   MatchAnyKeyword,
        0,                                  // [in] ULONGLONG   MatchAllKeyword,
        0,                                  // [in] ULONG       Timeout,
        &enableParameters);                 // [in, optional] PENABLE_TRACE_PARAMETERS EnableParameters

    if (ERROR_SUCCESS != status) 
    {
        std::wcerr << "[-] EnableTraceEx2() failed with " << status << std::endl;
        ControlTraceW(0, LOGGER_NAME, pProperties, EVENT_TRACE_CONTROL_STOP);
        return nullptr;
    }

    // [3] Create a new thread to process ETW trace events
    DWORD threadId;
    HANDLE threadHandle = CreateThread(nullptr, 0, EtwTracingThread, nullptr, 0, &threadId);
    if (NULL == threadHandle)
    {
        std::wcerr << "[-] Failed to create ETW tracing thread." << std::endl;
        ControlTraceW(0, LOGGER_NAME, pProperties, EVENT_TRACE_CONTROL_STOP);
        return nullptr;
    }        
    CloseHandle(threadHandle);
    return std::move(pTraceProperties);
}

// Monitors ETW events for Win32k APIs over a specified duration in seconds.
BOOL
RunETWWin32kAPIMonitoring(
    _In_ const unsigned long& execSeconds)
{
    TRACEHANDLE hSession = INVALID_PROCESSTRACE_HANDLE;

    // Start Microsoft-Windows-Win32k provider trace
    // Logger name: Win32kAPIMonitoringSession
    std::wcout << "[+] Starting an ETW trace.." << std::endl;
    auto pEventTraceProperties = StartETWTrace(&hSession);
    if (nullptr == pEventTraceProperties || INVALID_PROCESSTRACE_HANDLE == hSession)
    {
        std::wcerr << "[-] StartETWTrace() failed!" << std::endl;
        return FALSE;
    }

    std::wcout << "[+] Collecting events for " << execSeconds << " seconds..." << std::endl;
    Sleep(execSeconds * 1000);
    std::wcout << "[+] Stopping the ETW trace.." << std::endl;

    if (!StopETWTrace(&hSession, (PEVENT_TRACE_PROPERTIES)pEventTraceProperties.get()))
    {
        std::wcerr << "[-] StopETWTrace() failed!" << std::endl;
        return FALSE;
    }
    return TRUE;
}

int wmain(int argc, wchar_t* argv[])
{
    if (2 != argc) {
        std::wcout << "Usage: " << argv[0] << " <duration_in_seconds>" << std::endl;
        return EXIT_FAILURE;
    }
    unsigned long execTime = std::wcstoul(argv[1], nullptr, 10);
    if (ERANGE == errno || 0 == execTime) {
        std::wcerr << "[-] Error: Enter a valid execution time." << std::endl;
        return EXIT_FAILURE;
    }

    if (!RunETWWin32kAPIMonitoring(execTime))
    {
        std::wcerr << "[-] RunETWWin32kMonitoring() failed!" << std::endl;
        return EXIT_FAILURE;
    }

    std::wcerr << "[+] Finished the trace!" << std::endl;
    return EXIT_SUCCESS;
}