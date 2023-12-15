#ifndef _winhook_h_
#define _winhook_h_


#include <Windows.h>
#include <winternl.h>
#include <inttypes.h>
#include "Zydis.h"



#define CALL 0xd0
#define JMP 0xe0
#define LEN_IMPLANT 12

/* DEFINE INPUT PARAMETERS BASED ON HOOKED FUNCTIONS*/
extern void decoy(int);

extern void decoy1(void);
extern void decoy2(void);
extern void decoy3(void);
extern void decoy4(void);
extern void decoy5(void);
extern void decoy6(void);

typedef struct hook_info{
    LPVOID catalyst;
    unsigned char bytes[LEN_IMPLANT];
} HookInfo;

int InstallHook(void* pf_victim, void* pf_hook, HookInfo* _hook_info);
int RemoveHook(void* pf_victim, HookInfo* h);

#endif