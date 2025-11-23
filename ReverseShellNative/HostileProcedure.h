#pragma once
#include "HostileType.h"
#include "HostileStructures.h"


#if defined(_WIN64)
#pragma intrinsic(__readgsqword)
#else
#pragma intrinsic(__readfsdword)
#endif

FORCEINLINE size_t _wcslen(const WCHAR* str) {
    volatile const WCHAR* p = str;
    while (*p != L'\0') {
        p++;
    }
    return (size_t)(p - str);
}

FORCEINLINE size_t _strlen(const char* str) {
    volatile const CHAR* ptr = str;
    while (*ptr != '\0') {
        ptr++;
    }
    return ptr - str;
}

FORCEINLINE INT StringLengthA(char* str)
{
    int length;
    for (length = 0; str[length] != '\0'; length++) {}
    return length;
}

FORCEINLINE INT StringLengthW(WCHAR* str) {
    int length;
    for (length = 0; str[length] != L'\0'; length++) {}
    return length;
}

FORCEINLINE WCHAR ToLowerW(WCHAR ch)
{
    if (ch > 0x40 && ch < 0x5B)
    {
        return ch + 0x20;
    }
    return ch;
}

FORCEINLINE char ToLowerA(char ch)
{
    if (ch > 96 && ch < 123)
    {
        ch -= 32;
    }
    return ch;
}


FORCEINLINE BOOLEAN C CompareUnicode(PWSTR u1, PWSTR u2)
{
    for (int i = 0; i < StringLengthW(u1); i++)
    {
        if (ToLowerW(u1[i]) != ToLowerW(u2[i]))
            return FALSE;
    }
    return TRUE;
}

FORCEINLINE BOOLEAN CompareAnsi(char* u1, char* u2)
{
    for (int i = 0; i < StringLengthA(u1); i++)
    {
        if (ToLowerA(u1[i]) != ToLowerA(u2[i]))
            return FALSE;
    }
    return TRUE;
}


FORCEINLINE VOID RtlInitUnicodeStringInline(_Out_ PUNICODE_STRING DestinationString, _In_opt_z_ PCWSTR SourceString)
{
    if (SourceString)
        DestinationString->MaximumLength = (DestinationString->Length = (USHORT)(_wcslen(SourceString) * sizeof(WCHAR))) + sizeof(UNICODE_NULL);
    else
        DestinationString->MaximumLength = DestinationString->Length = 0;

    DestinationString->Buffer = (PWCH)SourceString;
}

FORCEINLINE VOID RtlInitAnsiString(_Out_ PANSI_STRING DestinationString, _In_opt_ PCSTR SourceString)
{
    if (SourceString)
        DestinationString->MaximumLength = (DestinationString->Length = (USHORT)_strlen(SourceString)) + sizeof(ANSI_NULL);
    else
        DestinationString->MaximumLength = DestinationString->Length = 0;

    DestinationString->Buffer = (PCHAR)SourceString;
}


static PVOID PEBAddress = NULL;

FORCEINLINE LPVOID NtCurrentPeb(VOID)
{
#if defined(_WIN64)
    if (PEBAddress == NULL)
        PEBAddress = (PVOID)__readgsqword(0x60);
    return PEBAddress;
#else
    if (PEBAddress == NULL)
        PEBAddress = (PVOID)__readfsdword(0x30);
    return PEBAddress;
#endif
}

static PVOID TEBAddress = NULL;

FORCEINLINE LPVOID NtCurrentTIBOrTEB(VOID)
{
#if defined(_WIN64)
    if (TEBAddress == NULL)
        TEBAddress = (LPVOID)__readgsqword(0x30);
    return TEBAddress;
#else
    if (TEBAddress == NULL)
        TEBAddress = (LPVOID)__readfsdword(0x18);
    return TEBAddress;
#endif
}

FORCEINLINE PIMAGE_NT_HEADERS ImageCurrentNTHeader(LPVOID address)
{
    IMAGE_DOS_HEADER* dosAddress = (IMAGE_DOS_HEADER*)address;
    return (PIMAGE_NT_HEADERS)((ULONG_PTR)address + dosAddress->e_lfanew);
}

//could be used for junk code
FORCEINLINE BOOLEAN CheckPESignature(LPVOID address)
{
    IMAGE_DOS_HEADER* dosAddress = (IMAGE_DOS_HEADER*)address;
    IMAGE_NT_HEADERS* ntAddress = (IMAGE_NT_HEADERS*)((ULONG_PTR)address + dosAddress->e_lfanew);

    if (dosAddress->e_magic != IMAGE_DOS_SIGNATURE || ntAddress->Signature != IMAGE_NT_SIGNATURE)
        return 0;
    return 1;
}

FORCEINLINE PVOID GetModuleBaseAddress(PWSTR name)
{
    PPEB p_peb = (PPEB)NtCurrentPeb();
    PPEB_LDR_DATA pLdrData = (PPEB_LDR_DATA)p_peb->Ldr;

    for (PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)pLdrData->InLoadOrderModuleList.Flink; pLdrDataEntry->DllBase != NULL; pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)pLdrDataEntry->InLoadOrderLinks.Flink)
    {
        if (CompareUnicode(name, pLdrDataEntry->BaseDllName.Buffer))
            return pLdrDataEntry->DllBase;
    }
    return NULL;
}

FORCEINLINE PLDR_DATA_TABLE_ENTRY GetCurrentModuleLdr(VOID)
{
    PPEB pPeb = (PPEB)NtCurrentPeb();
    PPEB_LDR_DATA pLdrData = (PPEB_LDR_DATA)pPeb->Ldr;

    for (PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)pLdrData->InLoadOrderModuleList.Flink; pLdrDataEntry->DllBase != NULL; pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)pLdrDataEntry->InLoadOrderLinks.Flink)
    {
        if (pPeb->ImageBaseAddress == pLdrDataEntry->DllBase)
            return pLdrDataEntry;
    }
    return (PLDR_DATA_TABLE_ENTRY)NULL;
}

/// <summary>
/// Could be done comparing each char until reaching \0
/// </summary>
/// <param name="sProcName"></param>
/// <returns></returns>
__declspec(noinline)  LPVOID GetProcedureAddressNt(char* function_name)
{
    WCHAR nt[] = { 'n','t','d','l','l','.','d','l','l','\0' };
    DWORD_PTR module_address = (DWORD_PTR)GetModuleBaseAddress(nt);//L"ntdll.dll\0"
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module_address;
    IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)(module_address + dos_header->e_lfanew);
    IMAGE_OPTIONAL_HEADER* optional_header = &nt_header->OptionalHeader;
    IMAGE_DATA_DIRECTORY* export_data_directory = (IMAGE_DATA_DIRECTORY*)(&optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    IMAGE_EXPORT_DIRECTORY* export_data_header = (IMAGE_EXPORT_DIRECTORY*)(module_address + export_data_directory->VirtualAddress);

    DWORD* export_address_table = (DWORD*)(module_address + export_data_header->AddressOfFunctions);
    DWORD* function_name_table = (DWORD*)(module_address + export_data_header->AddressOfNames);
    WORD* ordinal_name_table = (WORD*)(module_address + export_data_header->AddressOfNameOrdinals);

    if (((DWORD_PTR)function_name >> 16) == 0)
    {
        WORD ordinal = (WORD)function_name & 0xFFFF;
        DWORD base = export_data_header->Base;

        if (ordinal < base || ordinal >= base + export_data_header->NumberOfFunctions)
            return NULL;

        return (PVOID)(module_address + (DWORD_PTR)export_address_table[ordinal - base]);
    }
    else
    {
        for (DWORD i = 0; i < export_data_header->NumberOfNames; i++)
        {
            char* current_function_name = (char*)(module_address + (DWORD_PTR)function_name_table[i]);

            if (CompareAnsi(function_name, current_function_name) == TRUE)
            {
                return (LPVOID)(module_address + (DWORD_PTR)export_address_table[ordinal_name_table[i]]);
            }
        }
    }
    return NULL;
}

__declspec(noinline) PVOID MallocCustom(PSIZE_T size)
{
    char ntAllocate[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', '\0' };
    PNtAllocateVirtualMemory pNtAllocate = (PNtAllocateVirtualMemory)GetProcedureAddressNt(ntAllocate);//"NtAllocateVirtualMemory\0"
    PVOID pAllocated = NULL;
    pNtAllocate((HANDLE)(-1), &pAllocated, 0, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return pAllocated;
}

FORCEINLINE VOID MemZero(PVOID add, INT size)
{
    CHAR* byte = (CHAR*)add;
    for (INT i = 0; i < size; i++)
    {
        byte[i] = '\0';
    }
    return;
}

static unsigned long int next = 1;

FORCEINLINE INT rand_(void) // RAND_MAX assumed to be 32767
{
    next = next * 1103515245 + 12345;
    return (UINT)(next / 65536) % 32768;
}

FORCEINLINE VOID srand_(UINT seed)
{
    next = seed;
}

FORCEINLINE INT random_int(INT min, INT max)
{
    return min + rand_() % (max + 1 - min);
}