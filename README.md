<img align="center" width="1000" height="100%" src="img/stars-only.png" alt="obsidian logo">

# obsidian community edition - x64 pe packer

### obsidian pro is here!

**where to find: [obsidian.st](https://obsidian.st)**

**pro edition-v1.0:**

* SPECK 128/128 CTR encryption
* aPlib compression (--compress)
* resource encryption
* extensive syscall anti-debug (--ultra)
* anti-sandbox
* hmac integrity checks
* [ollvm-22](https://github.com/vertigo6622/ollvm-22) obfuscated

---

## introduction:

obsidian is a custom x64 pe packer / executable protector written in C. it is designed to be paired with a loader stub that decrypts and executes the packed payload. 

a compiled stub example is available in the stubs folder that uses rolling xor obfuscation with shifts and does not contain any anti-debugging mechanisms.

this packer/stub has been tested to work on putty.exe, strings.exe, and can even pack itself, and then pack other executables from the packed state.

every pe stub/loader gets burned the moment its source becomes public. the only way to stay ahead of this is to write your own custom one. there is an included a template for you to fill out with your own code. 

---

<img align="center" width="1000" height="100%" src="img/splash.gif" alt="obsidian splashscreen">

---

## features:

**community edition-v1.2:**
* improved xor algorithm
* hash-based import lookups
* compiled xorshift64+ stub (stubs/stub.bin)
* high entropy ASLR support
* stub template (BYOS - bring your own stub)
* extensive debug output (-DDEBUG & --debug flags)
* randomized config marker
* zeroed out optional headers
* secure key generation
* checksum recalculation
* pe section manipulation
* progress bar and colors

## to-do:

**community and pro edition:**
* pyinstaller support
* arm64 support
* remain updated to keep ahead of av detection
* next-gen SGN encoding (pro)

**commercial edition(future):**
* gui
* license support/hardware binding
* online key provisioning
* DRM-like protections

## usage:
`.\obsidian.exe [--debug] program.exe packed.exe`

<img align="center" width="1000" height="100%" src="img/putty.png" alt="putty debugging output">
<img align="center" width="1000" height="100%" src="img/die.png" alt="detect-it-easy">
<img align="center" width="1000" height="100%" src="img/die2.png" alt="detect-it-easy">

---

## stub reference sheet:

| | stub.bin | stub.Oz.bin | stub.obfuscated.bin | stub.full.obf.bin |
| :--- | :--- | :--- | :--- | :--- |
| description: | no optimization | aggressive size optimization | control flow flattening + instruction substitution | fully obfuscated (bogus control flow, splitting, flattening, substitution) | 
| size: | 17kb | 13kb | 17kb | 57kb |
| tools: | clang/llvm | clang/llvm + Oz | clang/llvm + Oz + [ollvm-22](https://github.com/vertigo6622/ollvm-22) | clang/llvm + Oz + [ollvm-22](https://github.com/vertigo6622/ollvm-22) |
| note: | basic | smallest/fastest | balanced | largest/slowest |

## compile:
**requirements:** 
* mingw64 tool suite available at `https://winlibs.com/`
* windbg or other debugger
* python interpreter for `clean.py`

**commands:**
* `.\gcc.exe stub.c -o stub.o [-DDEBUG] -fno-asynchronous-unwind-tables -fno-ident -fno-stack-protector`
* `.\ld.exe stub.o -o stub.exe -nostdlib --build-id=none -s --entry=_start`
* `.\objcopy.exe -O binary stub.exe stub.bin`
* `.\windres.exe resource.rc -o resource.o`
* `.\gcc.exe obsidian.c resource.o -o obsidian.exe -lbcrypt`

## license:
this software is licensed under a modified ACSL 1.4 license.





