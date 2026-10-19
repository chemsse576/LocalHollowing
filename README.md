# LocalHollowing

PE loader for authorized penetration testing. Loads payloads in-memory via module stomping with full EDR evasion.

## Features

- Module stomping (dbghelp.dll as sacrificial DLL)
- PEB walking with API hashing (DJB2 variant)
- Indirect syscalls via MASM stubs
- AES-256 payload decryption (CryptoAPI)
- ETW patch (EtwEventWrite → xor eax,eax; ret)
- Stack spoofing trampoline
- Multi-EDR process filters (obfuscated stack strings)
- Hash unique per build (`__DATE__ __TIME__`)
- Full interactive console I/O
- `@file` support — read commands from file, delete immediately

## Usage

```
ConfigHost.exe <payload.bin> [commands...] [exit]
ConfigHost.exe <payload.bin> @commands.txt
```

### Examples

```
ConfigHost.exe cipher_mimikatz_latest.bin "pv::dbg" "tk::elv" "sk::lp" exit
```

Or with a command file (deleted after reading):
```
ConfigHost.exe cipher_mimikatz_latest.bin @cmds.txt
```

## Command Reference

Commands have been renamed from their original names:

| Original | Renamed | Module |
|----------|---------|--------|
| sekurlsa | sk | Credential extraction |
| logonPasswords | lp | Dump logon passwords |
| pth | ph | Pass the hash |
| privilege | pv | Privilege management |
| debug | dbg | Enable debug privilege |
| token | tk | Token manipulation |
| elevate | elv | Token elevation |
| lsadump | ld | LSA database dump |
| sam | sm | SAM dump |
| secrets | sc | LSA secrets |
| dcsync | ds | DCSync |
| dcshadow | dh | DCShadow |
| lsa | la | LSA operations |
| zerologon | zl | Zerologon |
| vault | vt | Credential vault |
| cred | cr | Vault credentials |
| kerberos | kb | Kerberos operations |
| ptt | pt | Pass the ticket |
| golden | gd | Golden ticket |
| list | ls | List tickets |
| ask | ak | TGS request |
| tgt | tg | TGT operations |
| purge | pg | Purge tickets |
| hash | hs | Hash operations |

## Build

Requires Visual Studio 2022+ with C++ desktop workload and Windows SDK.

Build chain uses `build.bat` / `rebuild_all.bat` in the confighost_build directory (ml64 + cl + link).

## Release

Download the latest release for a ready-to-run package — no build required:
- `ConfigHost.exe` — the loader
- `cipher_mimikatz_latest.bin` — encrypted payload (current)
- `cipher_printspoofer.bin` — PrintSpoofer payload
- `cipher_revsocks.bin` — RevSocks payload
- `command_mapping.txt` — full command name mapping reference

## Disclaimer

**This tool is provided for authorized security testing and educational purposes only.**

This software is intended to be used by security professionals during authorized penetration testing engagements, red team operations, and security research. Unauthorized use of this tool against systems you do not own or have explicit written permission to test is illegal and unethical.

The author assumes no liability for misuse of this software. By using this tool, you agree that you are solely responsible for your actions and that you will comply with all applicable local, state, national, and international laws.

## License

For educational and authorized security testing use only.
