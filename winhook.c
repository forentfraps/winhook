#include "winhook.h"

int i2h(long long n, unsigned char* buf) {
    if (buf == NULL) {
        return -1;
    }
    buf[0] = (unsigned char)(n & 0xFF);
    buf[1] = (unsigned char)((n >> 8) & 0xFF);
    buf[2] = (unsigned char)((n >> 16) & 0xFF);
    buf[3] = (unsigned char)((n >> 24) & 0xFF);
    buf[4] = (unsigned char)((n >> 32) & 0xFF);
    buf[5] = (unsigned char)((n >> 40) & 0xFF);
    buf[6] = (unsigned char)((n >> 48) & 0xFF);
    buf[7] = (unsigned char)((n >> 56) & 0xFF);
    return 0;
}

int InstallHook(void* pf_victim, void* pf_hook, HookInfo* _hook_info){
    unsigned char instruction_buf[32];
    HookInfo hi;
    memset(&hi, 0, sizeof(HookInfo));
    memset(instruction_buf, 0, 32);
    ZyanU64 after_hook_addr = (unsigned long long)pf_victim;
    LPVOID catalyst = NULL;
    ZydisDisassembledInstruction instruction;
    int offset = 0;
    DWORD oldprotect = 0;
    memcpy(instruction_buf, pf_victim, 32);
    while (ZYAN_SUCCESS(ZydisDisassembleIntel(
        /* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
        /* after_hook_addr: */ after_hook_addr,
        /* buffer:          */ instruction_buf + offset,
        /* length:          */ sizeof(instruction_buf) - offset,
        /* instruction:     */ &instruction
    )) && offset < LEN_IMPLANT) {
        // printf("%016" PRIX64 "  %s\n", after_hook_addr, instruction.text);
        offset += instruction.info.length;
        after_hook_addr += instruction.info.length;
    }
    catalyst = VirtualAlloc(NULL,52 + offset , MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!catalyst){
        return -1;
    }
    unsigned char* temp_storage = malloc(52 + offset );
    memset(temp_storage, 0x90, 52 + offset);
    unsigned char hook_start[] ={0x48, 0x89, 0xF0, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5E, 0x48, 0x89, 0x46, 0x17, 0x48, 0x83, 0xC6, 0x15, 0x48, 0xB8, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xFF, 0xE0, 0x48, 0xBE, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00} ;
    memcpy(temp_storage, hook_start, sizeof(hook_start));
    if (i2h((unsigned long long)pf_hook, temp_storage + 19)){
        return -1;
    }
    // 39
    memcpy(temp_storage + 39, instruction_buf, offset);
    // 39 +  offset
    temp_storage[39 + offset + 0] = 0x49;
    temp_storage[39 + offset + 1] = 0xbe;
    // 41 + offset
    if (i2h((unsigned long long)after_hook_addr, temp_storage + 41 + offset)){
        return -1;
    }
    // 49 + offset
    temp_storage[49 + offset] = 0x41;
    temp_storage[49 + offset + 1] = 0xff;
    temp_storage[49 + offset + 2] = 0xe6;
    // 52 + offset
    memcpy(catalyst, temp_storage, offset + 52);
    temp_storage[0] = 0x48;
    temp_storage[1] = 0xb8;
    temp_storage[10] = 0xff;
    temp_storage[11] = JMP;
    if (i2h((unsigned long long)catalyst, temp_storage + 2)){
        return -1;
    }
    if (!VirtualProtect(pf_victim, LEN_IMPLANT, PAGE_EXECUTE_READWRITE, (PDWORD)&oldprotect)){
        return -1;
    }
    memcpy(pf_victim, temp_storage, LEN_IMPLANT);
    if (!VirtualProtect(pf_victim, LEN_IMPLANT, PAGE_EXECUTE_READ, (PDWORD)&oldprotect)){
        return -1;
    }
    free(temp_storage);
    memcpy(hi.bytes, instruction_buf, LEN_IMPLANT);
    hi.catalyst = catalyst;
    memcpy(_hook_info, &hi, sizeof(HookInfo));
    return 0;
}

int RemoveHook(void* pf_victim, HookInfo* h){
    DWORD oldprotect;
    if (!VirtualProtect(pf_victim, LEN_IMPLANT, PAGE_EXECUTE_READWRITE, (PDWORD)&oldprotect)){
        return -1;
    }
    memcpy(pf_victim, h->bytes, LEN_IMPLANT);
    if (!VirtualProtect(pf_victim, LEN_IMPLANT, PAGE_EXECUTE_READ, (PDWORD)&oldprotect)){
        return -1;
    }
    VirtualFree(h->catalyst, 0, MEM_RELEASE);
}