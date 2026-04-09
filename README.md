**obsidian pro is almost here!**

**release date: 1200 UTC, Mon 20th April 2026**

**where to find: url in repo sidebar**

---

# obsidian x64 pe packer
signal: vertigo.66

## introduction:

obsidian is a custom x64 pe packer / executable protector written in C. it is designed to be paired with a loader stub that decrypts and executes the packed payload. 

a compiled stub example is available in the stubs folder that uses rolling xor obfuscation with shifts and does not contain any anti-debugging mechanisms.

this packer/stub has been tested to work on putty.exe, strings.exe, and can even pack itself, and then pack other executables from the packed state.

every pe stub/loader gets burned the moment its source becomes public. the only way to stay ahead of this is to write your own custom one. there is an included a template for you to fill out with your own code. 

---

<img align="center" width="1000" height="100%" src="img/splash.gif" alt="obsidian splashscreen">

---

## features:

**community edition-v1.1:**
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

**pro edition-v0.8:**

***coming soon***

* SPECK 128/128 CTR encryption
* aPlib compression
* resource encryption
* extensive syscall anti-debug (--ultra)
* anti-sandbox
* hmac integrity checks
* [ollvm-22](https://github.com/vertigo6622/ollvm-22) obfuscated

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





