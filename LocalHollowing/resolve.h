#pragma once
#include <Windows.h>
#include <winternl.h>

static DWORD HW(const WCHAR* s) {
    DWORD h = 0x4E67C6A7;
    while (*s) { WCHAR c = *s; if (c >= L'A' && c <= L'Z') c += 0x20; h = ((h<<7)+h)^c; s++; }
    return h;
}

static DWORD HA(const char* s) {
    DWORD h = 0x4E67C6A7;
    while (*s) { h = ((h<<7)+h)^(*s); s++; }
    return h;
}

static HMODULE GetModH(DWORD hash) {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY head = &pPeb->Ldr->InMemoryOrderModuleList;
    for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
        PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (mod->FullDllName.Buffer) {
            WCHAR* n = mod->FullDllName.Buffer;
            WCHAR* sl = n;
            for (WCHAR* p = n; *p; p++) if (*p == L'\\' || *p == L'/') sl = p+1;
            if (HW(sl) == hash) return (HMODULE)mod->DllBase;
        }
    }
    return NULL;
}

static FARPROC GetExpH(HMODULE m, DWORD hash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)m;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)m + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY ed = nt->OptionalHeader.DataDirectory[0];
    if (!ed.VirtualAddress) return NULL;
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)m + ed.VirtualAddress);
    PDWORD names = (PDWORD)((ULONG_PTR)m + exp->AddressOfNames);
    PWORD ords = (PWORD)((ULONG_PTR)m + exp->AddressOfNameOrdinals);
    PDWORD funcs = (PDWORD)((ULONG_PTR)m + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (HA((const char*)((ULONG_PTR)m + names[i])) == hash)
            return (FARPROC)((ULONG_PTR)m + funcs[ords[i]]);
    }
    return NULL;
}

