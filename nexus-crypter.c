/*
*
*   __  _  ____ __  __ __ __  ____  ____ _____ __  _______  _____  ____ _____ 
*  |  \| || ===|\ \/ /|  |  |(_ (_`/ (__`| () )\ \/ /| ()_)|_   _|| ===|| () )
*  |_|\__||____|/_/\_\ \___/.__)__)\____)|_|\_\ |__| |_|     |_|  |____||_|\_\ v8
*   x64 pe packer - signal: vertigo.66
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

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

typedef enum _PROCESSINFOCLASS {
    ProcessDebugPort = 7
} PROCESSINFOCLASS;

typedef LONG NTSTATUS;
typedef unsigned long DWORD;
typedef unsigned long long DWORD_PTR;
typedef unsigned char BYTE;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STUB_BIN 100

static int g_debug = 0;

// ============================================================================
// DEBUG MACROS
// ============================================================================

#define DBG(fmt, ...) do { if (g_debug) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__); } while(0)
#define DBG_HEX(name, val) do { if (g_debug) printf("[DEBUG] %-30s = 0x%llX\n", name, (unsigned long long)(val)); } while(0)
#define DBG_DEC(name, val) do { if (g_debug) printf("[DEBUG] %-30s = %llu\n", name, (unsigned long long)(val)); } while(0)
#define DBG_STR(name, val) do { if (g_debug) printf("[DEBUG] %-30s = %s\n", name, (val)); } while(0)

#define INFO(fmt, ...) printf("[*] " fmt "\n", ##__VA_ARGS__)
#define SUCCESS(fmt, ...) printf("[+] " fmt "\n", ##__VA_ARGS__)
#define ERR(fmt, ...) fprintf(stderr, "[-] " fmt "\n", ##__VA_ARGS__)
#define WARN(fmt, ...) printf("[!] " fmt "\n", ##__VA_ARGS__)

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

void hexdump(const char* desc, const void* data, size_t len) {
    if (!g_debug) return;
    
    printf("[DEBUG] %s (%zu bytes):\n", desc, len);
    const uint8_t* p = (const uint8_t*)data;
    for (size_t i = 0; i < len; i += 16) {
        printf("        %04zX: ", i);
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            printf("%02X ", p[i + j]);
        }
        printf("\n");
    }
}

uint32_t align_up(uint32_t value, uint32_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

// ============================================================================
// ENCRYPTION
// ============================================================================

void encrypt_data(uint8_t* data, size_t size, uint64_t key) {
    DBG("Encrypting %zu bytes with key 0x%016llX", size, (unsigned long long)key);
    // your encryption here...
}

void verify_encryption(uint8_t* original, uint8_t* encrypted, size_t size, uint64_t key) {
    if (!g_debug) return;

    uint8_t* test = (uint8_t*)malloc(size);
    memcpy(test, encrypted, size);
    // your decryption here...
    
    if (memcmp(original, test, size) == 0) {
        SUCCESS("Encryption verification PASSED");
    } else {
        ERR("Encryption verification FAILED!");
        for (size_t i = 0; i < size && i < 32; i++) {
            if (original[i] != test[i]) {
                DBG("Mismatch at byte %zu: expected 0x%02X, got 0x%02X", 
                    i, original[i], test[i]);
            }
        }
    }
    free(test);
}

// ============================================================================
// KEY GENERATION
// ============================================================================

uint64_t generate_key(void) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status;
    uint8_t entropy[32];
    uint8_t hash[32];
    uint64_t key = 0;
    
    DBG("Generating encryption key...");
    
    status = BCryptGenRandom(NULL, entropy, sizeof(entropy), 
                             BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!NT_SUCCESS(status)) {
        WARN("BCryptGenRandom failed (0x%08X), using fallback", status);
        LARGE_INTEGER perf;
        QueryPerformanceCounter(&perf);
        key = perf.QuadPart ^ GetTickCount64() ^ (uint64_t)&key;
        return key;
    }
    
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (NT_SUCCESS(status)) {
        BCRYPT_HASH_HANDLE hHash = NULL;
        status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
        if (NT_SUCCESS(status)) {
            BCryptHashData(hHash, entropy, sizeof(entropy), 0);
            BCryptFinishHash(hHash, hash, sizeof(hash), 0);
            BCryptDestroyHash(hHash);
            memcpy(&key, hash, sizeof(key));
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    
    SecureZeroMemory(entropy, sizeof(entropy));
    SecureZeroMemory(hash, sizeof(hash));
    
    if (key == 0) {
        key ^= 0x123456789ABCDEF0ULL;
    }
    
    DBG_HEX("Generated key", key);
    return key;
}

// ============================================================================
// STUB HANDLING
// ============================================================================

#pragma pack(push, 1)
typedef struct _STUB_CONFIG {
    uint64_t key;
    // your stub config struct here...
} STUB_CONFIG;
#pragma pack(pop)

// backup function to load from file if not using resources
uint8_t* load_stub_binary(size_t* out_size) {
    DBG("Loading stub binary from 'stub.bin'...");
    
    FILE* f = fopen("stub.bin", "rb");
    if (!f) {
        ERR("Failed to open stub.bin - compile stub.c first");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size == 0) {
        ERR("stub.bin is empty");
        fclose(f);
        return NULL;
    }

    uint8_t* stub = (uint8_t*)malloc(size);
    if (!stub) {
        ERR("malloc failed for stub");
        fclose(f);
        return NULL;
    }

    if (fread(stub, 1, size, f) != size) {
        ERR("Failed to read stub.bin");
        free(stub);
        fclose(f);
        return NULL;
    }

    fclose(f);
    *out_size = size;
    
    DBG_HEX("Stub binary size", size);
    return stub;
}

// ============================================================================
// PE VALIDATION
// ============================================================================

int validate_pe(uint8_t* pe, size_t size, IMAGE_NT_HEADERS** out_nt) {
    DBG("Validating PE structure...");
    
    if (size < sizeof(IMAGE_DOS_HEADER)) {
        ERR("File too small for DOS header");
        return 0;
    }
    
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe;
    
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        ERR("Invalid DOS signature: 0x%04X", dos->e_magic);
        return 0;
    }
    DBG("DOS signature OK");
    
    if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > size) {
        ERR("e_lfanew points outside file: 0x%X", dos->e_lfanew);
        return 0;
    }
    DBG_HEX("e_lfanew", dos->e_lfanew);
    
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(pe + dos->e_lfanew);
    
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        ERR("Invalid NT signature: 0x%08X", nt->Signature);
        return 0;
    }
    DBG("NT signature OK");
    
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        ERR("Not x64 PE: Machine = 0x%04X", nt->FileHeader.Machine);
        return 0;
    }
    DBG("Machine type: x64");
    
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        ERR("Not PE32+: Magic = 0x%04X", nt->OptionalHeader.Magic);
        return 0;
    }
    DBG("PE32+ format OK");
    
    uint16_t num_sections = nt->FileHeader.NumberOfSections;
    DBG_DEC("Number of sections", num_sections);
    
    if (num_sections == 0 || num_sections > 96) {
        ERR("Invalid section count: %u", num_sections);
        return 0;
    }
    
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    
    for (uint16_t i = 0; i < num_sections; i++) {
        char name[9] = {0};
        memcpy(name, sections[i].Name, 8);
        DBG("Section %u: %-8s VA=0x%08X Size=0x%08X RawOff=0x%08X RawSize=0x%08X",
            i, name, 
            sections[i].VirtualAddress,
            sections[i].Misc.VirtualSize,
            sections[i].PointerToRawData,
            sections[i].SizeOfRawData);
    }
    
    *out_nt = nt;
    SUCCESS("PE validation passed");
    return 1;
}

// ============================================================================
// PE SECTION OPERATIONS
// ============================================================================

IMAGE_SECTION_HEADER* add_section(uint8_t** pe_data, size_t* pe_size, 
                                   size_t content_size, const char* name) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)*pe_data;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(*pe_data + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* dirs = nt->OptionalHeader.DataDirectory;
    
    uint32_t file_align = nt->OptionalHeader.FileAlignment;
    uint32_t sect_align = nt->OptionalHeader.SectionAlignment;
    
    DBG_HEX("FileAlignment", file_align);
    DBG_HEX("SectionAlignment", sect_align);
    
    size_t section_table_end = dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) +
                               (nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    
    IMAGE_SECTION_HEADER* first_sec = IMAGE_FIRST_SECTION(nt);
    size_t first_section_data = first_sec->PointerToRawData;
    
    DBG_HEX("Section table ends at", section_table_end);
    DBG_HEX("First section data at", first_section_data);

    // shift headers along if not enough space for new section
    if (section_table_end + sizeof(IMAGE_SECTION_HEADER) > first_section_data) { 
        DBG("Not enough header space, shifting sections...");
        
        uint32_t shift = file_align;
        size_t new_size = *pe_size + shift;
        
        uint8_t* new_pe = (uint8_t*)realloc(*pe_data, new_size);
        if (!new_pe) {
            ERR("realloc failed");
            return NULL;
        }
        *pe_data = new_pe;
        
        dos = (IMAGE_DOS_HEADER*)*pe_data;
        nt = (IMAGE_NT_HEADERS*)(*pe_data + dos->e_lfanew);
        first_sec = IMAGE_FIRST_SECTION(nt);
        
        memmove(*pe_data + first_section_data + shift,
                *pe_data + first_section_data,
                *pe_size - first_section_data);
        
        memset(*pe_data + first_section_data, 0, shift);
        
        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (first_sec[i].PointerToRawData != 0) {
                first_sec[i].PointerToRawData += shift;
            }
        }
        
        nt->OptionalHeader.SizeOfHeaders += shift;
        *pe_size = new_size;
        
        DBG("Shifted sections by 0x%X bytes", shift);
    }
    
    uint32_t raw_size = align_up((uint32_t)content_size, file_align);
    uint32_t virt_size = align_up((uint32_t)content_size, sect_align);
    
    DBG_HEX("Content size", content_size);
    DBG_HEX("Aligned raw size", raw_size);
    DBG_HEX("Aligned virt size", virt_size);
    
    size_t current_size = *pe_size;
    uint32_t padding = (file_align - (current_size % file_align)) % file_align;
    size_t new_size = current_size + padding + raw_size;
    
    DBG_HEX("Current file size", current_size);
    DBG_HEX("Padding needed", padding);
    DBG_HEX("New file size", new_size);
    
    uint8_t* new_pe = (uint8_t*)realloc(*pe_data, new_size);
    if (!new_pe) {
        ERR("realloc failed");
        return NULL;
    }
    *pe_data = new_pe;
    
    memset(*pe_data + current_size, 0, new_size - current_size);
    
    dos = (IMAGE_DOS_HEADER*)*pe_data;
    nt = (IMAGE_NT_HEADERS*)(*pe_data + dos->e_lfanew);
    first_sec = IMAGE_FIRST_SECTION(nt);
    
    IMAGE_SECTION_HEADER* last_sec = first_sec + (nt->FileHeader.NumberOfSections - 1);
    
    uint32_t new_rva = align_up(
        last_sec->VirtualAddress + 
        (last_sec->Misc.VirtualSize ? last_sec->Misc.VirtualSize : last_sec->SizeOfRawData),
        sect_align
    );
    
    uint32_t new_raw_offset = (uint32_t)(current_size + padding);
    
    DBG_HEX("New section RVA", new_rva);
    DBG_HEX("New section raw offset", new_raw_offset);
    
    IMAGE_SECTION_HEADER* new_sec = first_sec + nt->FileHeader.NumberOfSections;
    memset(new_sec, 0, sizeof(IMAGE_SECTION_HEADER));
    
    memcpy(new_sec->Name, name, strlen(name) > 8 ? 8 : strlen(name));
    new_sec->Misc.VirtualSize = (uint32_t)content_size;
    new_sec->VirtualAddress = new_rva;
    new_sec->SizeOfRawData = raw_size;
    new_sec->PointerToRawData = new_raw_offset;
    new_sec->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
    
    nt->FileHeader.NumberOfSections++;
    nt->OptionalHeader.SizeOfImage = new_rva + virt_size;
    
    *pe_size = new_size;
    
    SUCCESS("Added section '%s': RVA=0x%08X, Size=0x%08X", name, new_rva, raw_size);
    
    return new_sec;
}

// ============================================================================
// MAIN PACKING LOGIC
// ============================================================================

int pack_pe(uint8_t** pe_data, size_t* pe_size, uint8_t* stub, size_t stub_size) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)*pe_data;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(*pe_data + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* dirs = nt->OptionalHeader.DataDirectory;

    INFO("Beginning PE packing process...");
    DBG("=== STEP 1: Collecting PE information ===");

    struct {
        uint64_t Key;
        uint32_t EncryptedSize;
        uint32_t EncryptStartOffset;
        uint32_t OriginalOEP;
        uint32_t SectionsRVA;
        uint64_t OriginalImageBase;
        uint32_t TLSRVA;
        uint32_t ImportRVA;
        uint32_t ImportSize;
        uint32_t ResourceRVA;
        uint32_t ResourceSize;
        uint32_t TLSSize;
        uint32_t ExceptionRVA;
        uint32_t ExceptionSize;
        uint32_t RelocRVA;
        uint32_t RelocSize;
    } meta = {0};

    meta.OriginalOEP = nt->OptionalHeader.AddressOfEntryPoint;
    meta.OriginalImageBase = nt->OptionalHeader.ImageBase;
    meta.TLSRVA = dirs[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    meta.ImportRVA = dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    meta.ImportSize = dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    meta.ResourceRVA = dirs[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
    meta.ResourceSize = dirs[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
    meta.TLSSize = dirs[IMAGE_DIRECTORY_ENTRY_TLS].Size;
    meta.ExceptionRVA = dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    meta.ExceptionSize = dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    meta.RelocRVA = dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    meta.RelocSize = dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    DBG_HEX("Original Entry Point", meta.OriginalOEP);
    DBG_HEX("Original ImageBase", meta.OriginalImageBase);

    DBG("=== STEP 2: Modifying PE directories ===");
    dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
    DBG("Zeroed Import directory");
    dirs[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
    DBG("Zeroed Bound Import directory");
    dirs[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
    DBG("Zeroed IAT directory");
    if (meta.TLSRVA) {
        dirs[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
        dirs[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;
        DBG("Zeroed TLS directory");
    }
    dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
    DBG("Zeroed Relocation Directory");
    dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = 0;
    DBG("Zeroed Exception Directory");
    dirs[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = 0;
    DBG("Zeroed Resource Directory");
    dirs[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
    DBG("Zeroed Debug directory");
    dirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
    DBG("Zeroed Load Config directory");
    dirs[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;
    DBG("Zeroed Security Directory");
    nt->FileHeader.PointerToSymbolTable = 0;
    nt->FileHeader.NumberOfSymbols = 0;
    DBG("Zeroed COFF symbol table pointers");

    DBG("=== STEP 3: Determining encryption region ===");
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    uint32_t sections_rva = sections[0].VirtualAddress;
    uint32_t header_size = nt->OptionalHeader.SizeOfHeaders;
    size_t encrypt_start = header_size;
    size_t encrypt_size = *pe_size - encrypt_start;
    meta.SectionsRVA = sections_rva;
    meta.EncryptedSize = (uint32_t)encrypt_size;
    meta.EncryptStartOffset = (uint32_t)encrypt_start;

    DBG_HEX("Sections RVA", sections_rva);
    DBG_HEX("Header size", header_size);
    DBG_HEX("Encrypt start (file offset)", encrypt_start);
    DBG_HEX("Encrypt size", encrypt_size);
    DBG_HEX("Import RVA", meta.ImportRVA);
    DBG_HEX("Import size", meta.ImportSize);
    DBG_HEX("Resource RVA", meta.ResourceRVA);
    DBG_HEX("Resource size", meta.ResourceSize);
    DBG_HEX("TLS RVA", meta.TLSRVA);
    DBG_HEX("TLS Size", meta.TLSSize);
    DBG_HEX("Exception RVA", meta.ExceptionRVA);
    DBG_HEX("Exception Size", meta.ExceptionSize);
    DBG_HEX("Relocation RVA", meta.RelocRVA);
    DBG_HEX("Relocation Size", meta.RelocSize);

    DBG("=== STEP 4: Key generation ===");
    uint64_t key = generate_key();
    meta.Key = key;

    uint8_t* backup = NULL;
    if (g_debug) {
        backup = (uint8_t*)malloc(encrypt_size);
        memcpy(backup, *pe_data + encrypt_start, encrypt_size);
        DBG("Created backup for verification");
    }

    DBG("=== STEP 5: Encrypting payload ===");
    INFO("Encrypting %zu bytes...", encrypt_size);
    encrypt_data(*pe_data + encrypt_start, encrypt_size, key);

    if (backup) {
        verify_encryption(backup, *pe_data + encrypt_start, encrypt_size, key);
        free(backup);
    }

    DBG("=== STEP 6: Adding stub section ===");
    size_t total_stub_size = stub_size + sizeof(STUB_CONFIG);
    DBG_HEX("Stub code size", stub_size);
    DBG_HEX("Config size", sizeof(STUB_CONFIG));
    DBG_HEX("Total stub section content", total_stub_size);
    
    IMAGE_SECTION_HEADER* stub_sec = add_section(pe_data, pe_size, total_stub_size, ".nexus");
    if (!stub_sec) {
        ERR("Failed to add stub section");
        return 0;
    }

    dos = (IMAGE_DOS_HEADER*)*pe_data;
    nt = (IMAGE_NT_HEADERS*)(*pe_data + dos->e_lfanew);

    nt->OptionalHeader.DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    nt->OptionalHeader.DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
    nt->OptionalHeader.DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
    DBG("Enabled high entropy ASLR");
    DBG_HEX("DllCharacteristics", nt->OptionalHeader.DllCharacteristics);

    DBG("=== STEP 7: Writing stub and config ===");
    uint8_t* stub_location = *pe_data + stub_sec->PointerToRawData;
    // choose where to store your config...

    // write to your config here...
    DBG("Wrote config at file offset 0x%zX", (size_t)((uint8_t*)config_location - *pe_data));

    // random config marker
    uint32_t config_marker;
    BCryptGenRandom(NULL, (PUCHAR)&config_marker, sizeof(uint32_t), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    // marker bytes to patch in stub
    uint8_t pattern[] = {0xEF, 0xBE, 0xAD, 0xDE};
    for (size_t i = 0; i < stub_size - 4; i++) {
        if (stub[i] == pattern[0] && stub[i+1] == pattern[1] && stub[i+2] == pattern[2] && stub[i+3] == pattern[3]) {
            DBG("Static config marker variable located");
            memcpy((uint8_t*)stub + i, &config_marker, 4);
            break;
        }
    }

    memcpy(stub_location, stub, stub_size);
    DBG("Wrote stub code at file offset 0x%X", stub_sec->PointerToRawData);

    // write randomized marker
    memcpy((uint8_t*)config_location + sizeof(STUB_CONFIG), &config_marker, 4);
    DBG_HEX("Wrote randomized stub config marker", config_marker);
    
    DBG("=== STEP 8: Locating entry point signature ===");
    uint32_t entry_offset = 0;
    uint8_t sig[] = {0x42, 0x59, 0x4F, 0x53};
    int found = 0;
    for (size_t i = 0; i < stub_size - sizeof(sig); i++) {
        if (stub_location[i] == sig[0] && stub_location[i+1] == sig[1] && stub_location[i+2] == sig[2] && stub_location[i+3] == sig[3]) {
            entry_offset = (uint32_t)i + 4;
            found = 1;
            DBG("Found entry signature at stub offset 0x%X", entry_offset);
            break;
        }
    }

    if (!found) {
        ERR("Failed to find entry signature in stub!");
        return 0;
    }

    uint32_t new_ep = stub_sec->VirtualAddress + entry_offset;
    nt->OptionalHeader.AddressOfEntryPoint = new_ep;
    DBG_HEX("Old entry point", meta.OriginalOEP);
    DBG_HEX("New entry point", new_ep);

    DBG("=== STEP 9: Recalculating PE checksum ===");
    nt->OptionalHeader.CheckSum = 0;
    
    uint16_t* words = (uint16_t*)*pe_data;
    size_t num_words = *pe_size / 2;
    uint32_t sum = 0;
    
    for (size_t i = 0; i < num_words; i++) {
        sum += words[i];
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }
    
    if (*pe_size & 1) {
        sum += ((uint8_t*)*pe_data)[*pe_size - 1];
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }
    
    sum += (uint32_t)*pe_size;
    nt->OptionalHeader.CheckSum = sum;
    DBG_HEX("New checksum", sum);

    SUCCESS("PE packing completed successfully!");
    INFO("=== PACKING SUMMARY ===");
    INFO("Original Entry Point: 0x%08X", meta.OriginalOEP);
    INFO("New Entry Point: 0x%08X", new_ep);
    INFO("Encryption Key: 0x%016llX", (unsigned long long)key);
    INFO("Encrypted Size: %u bytes", meta.EncryptedSize);
    INFO("Stub Section: RVA=0x%08X Size=0x%08X", stub_sec->VirtualAddress, stub_sec->SizeOfRawData);
    INFO("Config Offset: %zu bytes", sizeof(STUB_CONFIG));
    INFO("Final PE Size: %zu bytes", *pe_size);
    return 1;
}

// ============================================================================
// MAIN
// ============================================================================

void print_usage(const char* prog) {
    printf("Usage: %s [--debug] [--ultra] <input.exe> <output.exe>\n", prog);
    printf("\nOptions:\n");
    printf("  --debug    Enable verbose debug output\n");
    printf("  --ultra    Enable anti-debugging protections\n");
    printf("\nExample:\n");
    printf("  %s program.exe packed.exe\n", prog);
    printf("  %s --debug program.exe packed.exe\n", prog);
    printf("  %s --ultra program.exe packed.exe\n");

}

int main(int argc, char* argv[]) {
    printf("\n __  _  ____ __  __ __ __  ____  ____ _____ __  _______  _____  ____ _____ \n");
    printf("|  \\| || ===|\\ \\/ /|  |  |(_ (_`/ (__`| () )\\ \\/ /| ()_)|_   _|| ===|| () )\n");
    printf("|_|\\__||____|/_/\\_\\ \\___/.__)__)\\____)|_|\\_\\ |__| |_|     |_|  |____||_|\\_\\ v8\n");
    printf(" x64 pe packer - signal: vertigo.66\n");
    printf("----------------------------------------------------------------------------\n\n");
    
    int arg_offset = 1;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0) {
            g_debug = 1;
            INFO("Debug mode enabled");
            arg_offset++;
        } else {
            break;
        }
    }
    
    if (argc - arg_offset != 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char* input_file = argv[arg_offset];
    const char* output_file = argv[arg_offset + 1];
    
    INFO("Input:  %s", input_file);
    INFO("Output: %s", output_file);
    INFO("Loading compiled stub binary...");
    
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(100), RT_RCDATA);
    if (!hRes) {
        ERR("Failed to find stub resource");
        return 1;
    }

    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) {
        ERR("Failed to load stub resource");
        return 1;
    }

    DWORD stub_size = SizeofResource(NULL, hRes);
    uint8_t* stub = (uint8_t*)LockResource(hData);
    if (!stub) {
        ERR("Failed to lock stub resource");
        return 1;
    }

    SUCCESS("Loaded stub from resource: %zu bytes", stub_size);
    INFO("Loading input PE file...");
    
    FILE* f = fopen(input_file, "rb");
    if (!f) {
        ERR("Cannot open input file: %s", input_file);
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    size_t pe_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t* pe_data = (uint8_t*)malloc(pe_size);
    if (!pe_data) {
        ERR("malloc failed for PE data");
        fclose(f);
        free(stub);
        return 1;
    }
    
    if (fread(pe_data, 1, pe_size, f) != pe_size) {
        ERR("Failed to read input file");
        fclose(f);
        free(pe_data);
        free(stub);
        return 1;
    }
    fclose(f);
    
    SUCCESS("Loaded PE: %zu bytes", pe_size);
    IMAGE_NT_HEADERS* nt;
    if (!validate_pe(pe_data, pe_size, &nt)) {
        ERR("PE validation failed");
        free(pe_data);
        free(stub);
        return 1;
    }
    
    uint8_t* stub_copy = (uint8_t*)malloc(stub_size);
    memcpy(stub_copy, stub, stub_size);

    if (!pack_pe(&pe_data, &pe_size, stub_copy, stub_size)) {
        ERR("Packing failed");
        free(pe_data);
        free(stub);
        return 1;
    }
    
    INFO("Writing output file...");
    
    f = fopen(output_file, "wb");
    if (!f) {
        ERR("Cannot create output file: %s", output_file);
        free(pe_data);
        free(stub);
        free(stub_copy);
        return 1;
    }
    
    if (fwrite(pe_data, 1, pe_size, f) != pe_size) {
        ERR("Failed to write output file");
        fclose(f);
        free(pe_data);
        free(stub);
        free(stub_copy);
        return 1;
    }
    fclose(f);
    
    SUCCESS("Output written: %zu bytes", pe_size);
    
    free(pe_data);
    free(stub);
    free(stub_copy);
    
    printf("\n");
    SUCCESS("Packing complete: %s", output_file);
    
    return 0;
}
