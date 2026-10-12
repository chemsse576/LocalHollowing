# LocalHollowing

Local process hollowing loader with full dynamic evasion for authorized penetration testing engagements.

## Features

- PEB walking with API hashing (DJB2 variant)
- Indirect syscalls via MASM stubs
- Module stomping (clrjit.dll)
- Stack spoofing trampoline
- CryptoAPI AES-256 payload decryption
- Rich header swap + PE timestamp copy
- NTDLL unhooking from disk (server-side shellcode)
- ETW patch (EtwEventWrite)
- Full interactive console I/O support

## Build

Requires Visual Studio 2022+ with C++ desktop workload and Windows SDK.

```
python build_final.py
```

## Disclaimer

**This tool is provided for authorized security testing and educational purposes only.**

This software is intended to be used by security professionals during authorized penetration testing engagements, red team operations, and security research. Unauthorized use of this tool against systems you do not own or have explicit written permission to test is illegal and unethical.

The author assumes no liability for misuse of this software. By using this tool, you agree that you are solely responsible for your actions and that you will comply with all applicable local, state, national, and international laws.

## License

For educational and authorized security testing use only.
