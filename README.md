# LocalHollowing

PE loader for authorized penetration testing. Loads payloads in-memory via module stomping with full EDR evasion.

## Features

- Module stomping (sacrificial DLL)
- PEB walking with API hashing (DJB2 variant)
- Indirect syscalls via MASM stubs
- AES-256 payload decryption (CryptoAPI)
- ETW patch
- Stack spoofing trampoline
- Multi-EDR process filters (obfuscated stack strings)
- Hash unique per build
- Full interactive console I/O
- `/log:file` — write output to file (for WinRM/non-interactive)
- `@file` support — read commands from file, delete immediately

## Usage

```
ConfigHost.exe <payload.bin> [/log:file] [commands...] [exit]
ConfigHost.exe <payload.bin> @commands.txt [/log:file]
```

### Examples

```
ConfigHost.exe cipher_module1.bin "pv::dbg" "tk::elv" "sk::lp" exit
ConfigHost.exe cipher_module1.bin /log:out.txt "pv::dbg" "sk::lp" exit
ConfigHost.exe cipher_module1.bin @cmds.txt /log:C:\temp\out.txt
```

## Command Reference

| Alias | Module |
|-------|--------|
| sk::lp | Credential extraction |
| pv::dbg | Enable debug privilege |
| tk::elv | Token elevation |
| ld::sm | SAM dump |
| ld::sc | LSA secrets |
| ld::ds | DCSync |
| vt::cr | Vault credentials |
| kb::pt | Pass the ticket |
| kb::gd | Golden ticket |
| kb::ls | List tickets |

See `command_mapping.txt` in the release for the full mapping.

## Payloads

| File | Description |
|------|-------------|
| cipher_module1.bin | Primary credential module |
| cipher_module2.bin | Privilege escalation module |
| cipher_module3.bin | Privilege escalation (alt) |
| cipher_module4.bin | Reverse SOCKS module |

## Build

Requires Visual Studio 2022+ with C++ desktop workload and Windows SDK.

## Release

Download the latest release — password-protected zip (`infected`), no build required.

## Disclaimer

**This tool is provided for authorized security testing and educational purposes only.**

This software is intended to be used by security professionals during authorized penetration testing engagements, red team operations, and security research. Unauthorized use of this tool against systems you do not own or have explicit written permission to test is illegal and unethical.

The author assumes no liability for misuse of this software.
